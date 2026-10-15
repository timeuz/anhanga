import asyncio
import contextlib
import logging
import os
from pathlib import Path

import yaml
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from anhanga.engine.models import ProbeResult
from anhanga.engine.probe import execute_probe
from anhanga.metrics.exporter import record_probe_metrics, render_prometheus_metrics

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("anhanga")

# Cache em memória dos últimos resultados para alimentar a UI instantaneamente
STATE_CACHE: dict[str, ProbeResult] = {}

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "web" / "templates"))


def load_targets_config() -> dict:
    """Carrega alvos declarativos do targets.yaml de forma robusta."""
    possible_paths = [
        Path(os.getenv("ANHANGA_CONFIG", "targets.yaml")),
        Path("targets.yaml"),
        BASE_DIR.parent.parent / "targets.yaml",  # Se rodando de src/anhanga/
        Path.cwd() / "targets.yaml",
    ]

    config_path = None
    for p in possible_paths:
        if p.exists():
            config_path = p
            break

    if not config_path:
        return {"interval_seconds": 60, "allow_private": False, "targets": []}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception as exc:
        logger.error(f"Falha ao ler {config_path}: {exc}")
        return {"interval_seconds": 60, "allow_private": False, "targets": []}


async def background_guardian_loop():
    """Loop assíncrono que sonda os alvos do targets.yaml concorrentemente."""
    config = load_targets_config()
    targets: list[str] = config.get("targets", [])
    interval: int = config.get("interval_seconds", 60)
    allow_private: bool = config.get("allow_private", False)

    if not targets:
        logger.info("Nenhum targets.yaml detectado. Operando apenas em modo On-Demand/API.")
        return

    logger.info(f"Anhangá vigiando {len(targets)} alvos a cada {interval}s...")
    while True:
        try:
            # Dispara todas as sondas em paralelo no event loop
            tasks = [execute_probe(url, allow_private=allow_private) for url in targets]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for res in results:
                if isinstance(res, ProbeResult):
                    STATE_CACHE[res.target_url] = res
                    record_probe_metrics(res)
        except asyncio.CancelledError:
            logger.info("Desligando loop de vigilância do Anhangá.")
            break
        except Exception as exc:
            logger.error(f"Erro no loop de background: {exc}")

        await asyncio.sleep(interval)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(background_guardian_loop())
    yield
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


app = FastAPI(
    title="Anhangá",
    description="Spectral Edge, TLS & Latency Auditor for SRE and DevSecOps",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/healthz", tags=["System"])
async def healthcheck():
    """Liveness/Readiness probe para Kubernetes."""
    return {"status": "alive", "monitored_targets": len(STATE_CACHE)}


@app.get("/api/v1/scan", response_model=ProbeResult, tags=["Diagnostics"])
async def api_scan_url(
    url: str = Query(..., description="URL ou hostname alvo para inspeção profunda"),
    timeout: float = Query(5.0, ge=1.0, le=30.0),
    allow_private: bool = Query(False, description="Permite IPs de rede interna (Lab/Infra)"),
    record_metrics: bool = Query(False, description="Se True, grava no /metrics do Prometheus"),
):
    """Executa diagnóstico instantâneo de DNS, TCP, TLS, TTFB e Security Headers."""
    if not url.strip():
        raise HTTPException(status_code=400, detail="O parâmetro 'url' é obrigatório.")

    result = await execute_probe(url, timeout=timeout, allow_private=allow_private)
    STATE_CACHE[result.target_url] = result

    # Evita alta cardinalidade por padrão em scans avulsos
    if record_metrics:
        record_probe_metrics(result)

    return result


@app.get("/api/v1/targets", response_model=list[ProbeResult], tags=["Diagnostics"])
async def list_cached_targets():
    """Retorna o último estado conhecido de todos os alvos monitorados."""
    return list(STATE_CACHE.values())


@app.get("/metrics", tags=["Observability"])
async def prometheus_metrics():
    """Endpoint padrão de scrape para Prometheus / Grafana Alloy / VictoriaMetrics."""
    payload, content_type = render_prometheus_metrics()
    return Response(content=payload, media_type=content_type)


@app.get("/probe", tags=["Observability"])
async def blackbox_compatible_probe(
    target: str = Query(..., description="URL alvo no estilo Blackbox Exporter"),
    allow_private: bool = Query(False),
):
    """Compatível com relabel_configs do Prometheus Blackbox Exporter."""
    result = await execute_probe(target, allow_private=allow_private)
    record_probe_metrics(result)
    payload, content_type = render_prometheus_metrics()
    return Response(content=payload, media_type=content_type)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def web_dashboard(request: Request):
    """Renderiza a interface Dark/Fogo do Anhangá."""
    index_file = BASE_DIR / "web" / "templates" / "index.html"
    if not index_file.exists():
        return HTMLResponse(
            "<h1>Anhangá Engine Online</h1><p>Acesse <a href='/docs'>/docs</a> ou <a href='/metrics'>/metrics</a>.</p>"
        )
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"cached_results": list(STATE_CACHE.values())},
    )