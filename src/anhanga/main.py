import asyncio
import contextlib
import hmac
import ipaddress
import logging
import os
from pathlib import Path

import re
from typing import Any, Literal
import yaml
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from anhanga import __version__
from anhanga.engine.models import ProbeResult
from anhanga.engine.probe import (
    ABSOLUTE_MAX_BODY_BYTES,
    DEFAULT_MAX_BODY_BYTES,
    SSRFBlockedError,
    execute_probe,
)
from anhanga.engine.security import RATE_LIMITER
from anhanga.engine.webhooks import send_webhook_alert
from anhanga.metrics.exporter import (
    record_probe_metrics,
    render_adhoc_probe_metrics,
    render_prometheus_metrics,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("anhanga")

# Cache em memória dos últimos resultados e série histórica de latências para alimentar a UI
STATE_CACHE: dict[str, ProbeResult] = {}
HISTORY_CACHE: dict[str, list[float]] = {}
MAX_HISTORY_POINTS = 30


class WebhookNotifyRequest(BaseModel):
    webhook_url: str = Field(
        ..., description="URL de destino. Deve estar declarada em 'webhooks' no targets.yaml (allowlist)."
    )
    url: str = Field(..., description="URL alvo a ser sondada pelo servidor para compor o alerta")
    provider: Literal["auto", "slack", "teams", "telegram"] = Field(default="auto")
    chat_id: str | None = Field(default=None, description="Chat ID para Telegram")
    violations: list[str] = Field(default_factory=list)
    timeout: float = Field(default=5.0, ge=1.0, le=30.0)


BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "web" / "templates"))


def _extract_client_ip(request: Request | None) -> str:
    if request is None:
        return "127.0.0.1"
    remote_addr = request.client.host if request.client else "127.0.0.1"
    xff = request.headers.get("x-forwarded-for")
    return RATE_LIMITER.extract_client_ip(remote_addr=remote_addr, x_forwarded_for=xff)


def _allow_private_api() -> bool:
    """Política SSRF das rotas HTTP: decidida pelo OPERADOR (env), jamais pelo cliente."""
    return os.getenv("ANHANGA_ALLOW_PRIVATE", "").strip().lower() in {"1", "true", "yes"}


def _is_loopback_direct(request: Request) -> bool:
    """Cliente loopback sem indício de proxy reverso (que mascararia o cliente real)."""
    if request.client is None:
        return False
    try:
        if not ipaddress.ip_address(request.client.host).is_loopback:
            return False
    except ValueError:
        return False
    return not any(h in request.headers for h in ("x-forwarded-for", "forwarded", "x-real-ip"))


def _is_authorized(request: Request) -> bool:
    api_key = os.getenv("ANHANGA_API_KEY", "")
    if not api_key:
        # Fail-closed: sem chave configurada, apenas acesso loopback direto.
        return _is_loopback_direct(request)
    auth = request.headers.get("authorization", "")
    supplied = auth[7:].strip() if auth.lower().startswith("bearer ") else request.headers.get("x-api-key", "")
    return hmac.compare_digest(supplied.encode(), api_key.encode())


# error_code -> status HTTP. O que é achado da sondagem (5xx do alvo, asserção, TLS inválido) segue como 200.
_ERROR_STATUS: dict[str, int] = {
    "invalid_url": 400,
    "ssrf_blocked": 403,
    "dns_error": 502,
    "connect_error": 502,
    "tls_error": 502,
    "timeout": 504,
}


def _raise_for_unreachable(result: ProbeResult) -> None:
    """Falhas em que não houve resposta HTTP do alvo viram 4xx/5xx com erro estruturado."""
    status = _ERROR_STATUS.get(result.error_code or "")
    if status is not None:
        raise HTTPException(
            status_code=status,
            detail={
                "error_code": result.error_code,
                "message": result.error,
                "target_url": result.target_url,
            },
        )


PROTECTED_PREFIXES: tuple[str, ...] = ("/api/", "/probe", "/metrics")


def _enforce_rate_limit(request: Request | None, cost: int = 1) -> None:
    client_ip = _extract_client_ip(request)
    allowed, retry_after = RATE_LIMITER.check(client_ip, cost=cost)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=(
                f"Rate limit excedido para o IP '{client_ip}' "
                f"(máximo {RATE_LIMITER.max_requests} req/min). Aguarde {retry_after}s."
            ),
            headers={"Retry-After": str(retry_after)},
        )


def _update_state_and_history(result: ProbeResult, is_continuous: bool = False) -> ProbeResult:
    """Atualiza o cache de estado e a série histórica de latências (sparkline) do alvo."""
    key = result.target_url
    if not is_continuous:
        # Scans avulsos (alvos arbitrários) não persistem estado: memória e cardinalidade limitadas aos alvos configurados.
        result.history_ms = [result.timings.total_ms] if result.timings.total_ms > 0 else []
        return result
    history = HISTORY_CACHE.setdefault(key, [])

    # Apenas observações da vigilância contínua ou o primeiro ponto mediano de um novo scan entram na série histórica,
    # prevenindo que rajadas manuais (ex: 10 amostras instantâneas) poluam a linha de tendência temporal (sparkline).
    headline_ms = (
        result.sampling.headline_total_ms
        if result.sampling and result.sampling.headline_total_ms > 0
        else result.timings.total_ms
    )
    if is_continuous:
        if headline_ms > 0:
            history.append(headline_ms)
    else:
        if not history and headline_ms > 0:
            history.append(headline_ms)

    if len(history) > MAX_HISTORY_POINTS:
        del history[:-MAX_HISTORY_POINTS]

    result.history_ms = list(history)
    if is_continuous:
        STATE_CACHE[key] = result
    return result


def _interpolate_env_vars(obj: Any) -> Any:
    """Interpola recursivamente variáveis de ambiente ${VAR_NAME} em strings e dicionários."""
    if isinstance(obj, str):
        return re.sub(
            r"\$\{([A-Za-z0-9_]+)\}",
            lambda m: os.getenv(m.group(1), ""),
            obj,
        )
    if isinstance(obj, list):
        return [_interpolate_env_vars(item) for item in obj]
    if isinstance(obj, dict):
        return {k: _interpolate_env_vars(v) for k, v in obj.items()}
    return obj


def load_targets_config() -> dict:
    """Carrega alvos declarativos do targets.yaml interpolando variáveis de ambiente ${ENV_VAR}."""
    possible_paths = [
        Path(os.getenv("ANHANGA_CONFIG", "targets.yaml")),
        Path("targets.yaml"),
        BASE_DIR.parent.parent / "targets.yaml",
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
            raw_cfg = yaml.safe_load(f) or {}
            return _interpolate_env_vars(raw_cfg)
    except Exception as exc:
        logger.error(f"Falha ao ler {config_path}: {exc}")
        return {"interval_seconds": 60, "allow_private": False, "targets": []}


async def _dispatch_configured_webhooks(
    res: ProbeResult, webhooks_cfg: list[Any], allow_private: bool = False
) -> None:
    if not webhooks_cfg:
        return
    should_alert = res.health != "up" or bool(res.tls and res.tls.alert_expiring)
    if not should_alert:
        return

    for wh in webhooks_cfg:
        try:
            if isinstance(wh, str):
                await send_webhook_alert(
                    webhook_url=wh, result=res, allow_private=allow_private
                )
            elif isinstance(wh, dict) and wh.get("url"):
                await send_webhook_alert(
                    webhook_url=str(wh["url"]),
                    result=res,
                    provider=str(wh.get("provider", "auto")),
                    chat_id=wh.get("chat_id"),
                    allow_private=bool(wh.get("allow_private", allow_private)),
                )
        except Exception as exc:
            logger.warning(f"Falha ao enviar alerta de webhook para {res.target_url}: {exc}")


async def background_guardian_loop():
    """Loop assíncrono que sonda os alvos do targets.yaml concorrentemente."""
    config = load_targets_config()
    targets: list[str] = config.get("targets", [])
    interval: int = config.get("interval_seconds", 60)
    allow_private: bool = config.get("allow_private", False)
    samples: int = config.get("samples", 1)
    webhooks_cfg: list[Any] = config.get("webhooks", [])

    if not targets:
        logger.info("Nenhum targets.yaml detectado. Operando apenas em modo On-Demand/API.")
        return

    logger.info(f"Anhangá vigiando {len(targets)} alvos a cada {interval}s...")
    while True:
        try:
            # Dispara todas as sondas em paralelo no event loop
            tasks = [
                execute_probe(url, allow_private=allow_private, samples=samples)
                for url in targets
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for res in results:
                if isinstance(res, ProbeResult):
                    _update_state_and_history(res, is_continuous=True)
                    record_probe_metrics(res)
                    if webhooks_cfg:
                        await _dispatch_configured_webhooks(
                            res, webhooks_cfg, allow_private=allow_private
                        )
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
    version=__version__,
    lifespan=lifespan,
)


app.mount("/static", StaticFiles(directory=str(BASE_DIR / "web" / "static")), name="static")


@app.middleware("http")
async def api_key_guard(request: Request, call_next):
    if request.url.path.startswith(PROTECTED_PREFIXES) and not _is_authorized(request):
        return JSONResponse(
            status_code=401,
            content={
                "detail": "Não autorizado. Envie 'Authorization: Bearer <ANHANGA_API_KEY>' "
                "(sem chave configurada, apenas acesso loopback direto é aceito)."
            },
            headers={"WWW-Authenticate": "Bearer"},
        )
    return await call_next(request)


@app.get("/healthz", tags=["System"])
async def healthcheck():
    """Liveness/Readiness probe para Kubernetes."""
    return {"status": "alive", "monitored_targets": len(STATE_CACHE)}


@app.get("/api/v1/scan", response_model=ProbeResult, tags=["Diagnostics"])
async def api_scan_url(
    request: Request,
    url: str = Query(..., description="URL ou hostname alvo para inspeção profunda"),
    timeout: float = Query(5.0, ge=1.0, le=30.0),
    samples: int = Query(1, ge=1, le=20, description="Quantidade de amostras para cálculo de P50/P95/P99 e Jitter"),
    max_body_bytes: int = Query(
        DEFAULT_MAX_BODY_BYTES,
        ge=1024,
        le=ABSOLUTE_MAX_BODY_BYTES,
        description="Limite máximo de bytes lidos do corpo da resposta (máx 5 MiB)",
    ),
    fail_if_body_not_matches_regexp: str | None = Query(None, description="Regexp que DEVE estar presente no corpo"),
    fail_if_body_matches_regexp: str | None = Query(None, description="Regexp que NÃO PODE estar presente no corpo"),
    min_payload_bytes: int | None = Query(None, description="Tamanho mínimo de payload em bytes"),
    max_payload_bytes: int | None = Query(None, description="Tamanho máximo de payload em bytes"),
    assert_final_url: str | None = Query(None, description="URL final esperada após redirects"),
):
    """Executa diagnóstico instantâneo de DNS, TCP, TLS, TTFB, Redirects, Asserções e Security Headers."""
    _enforce_rate_limit(request, cost=samples)
    if not url.strip():
        raise HTTPException(status_code=400, detail="O parâmetro 'url' é obrigatório.")

    result = await execute_probe(
        url,
        timeout=timeout,
        allow_private=_allow_private_api(),
        samples=samples,
        max_body_bytes=max_body_bytes,
        fail_if_body_not_matches_regexp=fail_if_body_not_matches_regexp,
        fail_if_body_matches_regexp=fail_if_body_matches_regexp,
        min_payload_bytes=min_payload_bytes,
        max_payload_bytes=max_payload_bytes,
        assert_final_url=assert_final_url,
    )
    _raise_for_unreachable(result)
    return _update_state_and_history(result, is_continuous=False)


@app.post("/api/v1/webhooks/notify", tags=["Alerting"])
async def api_notify_webhook(request: Request, body: WebhookNotifyRequest):
    """Dispara alerta formatado para Slack, Microsoft Teams ou Telegram com proteção Anti-SSRF."""
    _enforce_rate_limit(request)
    cfg = load_targets_config()
    entries = {
        str(w if isinstance(w, str) else w.get("url", "")): (w if isinstance(w, dict) else {})
        for w in cfg.get("webhooks", [])
        if isinstance(w, (str, dict))
    }
    if body.webhook_url not in entries:
        raise HTTPException(
            status_code=403,
            detail="webhook_url não consta na allowlist ('webhooks' do targets.yaml).",
        )
    probe_res = STATE_CACHE.get(body.url) or await execute_probe(
        body.url, timeout=body.timeout, allow_private=_allow_private_api()
    )

    try:
        delivery = await send_webhook_alert(
            webhook_url=body.webhook_url,
            result=probe_res,
            provider=body.provider,
            violations=body.violations,
            chat_id=body.chat_id,
            allow_private=bool(
                entries[body.webhook_url].get("allow_private", cfg.get("allow_private", False))
            ),
            timeout=body.timeout,
        )
        return delivery
    except SSRFBlockedError as ssrf_err:
        raise HTTPException(status_code=403, detail=str(ssrf_err)) from ssrf_err
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err)) from val_err
    except Exception as exc:
        raise HTTPException(
            status_code=502, detail=f"Erro ao enviar webhook: {exc}"
        ) from exc


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
    request: Request,
    target: str = Query(..., description="URL alvo no estilo Blackbox Exporter"),
    module: str = Query("http_2xx", description="Módulo compatível com Blackbox Exporter"),
    samples: int = Query(1, ge=1, le=20),
):
    """Compatível com relabel_configs do Prometheus Blackbox Exporter."""
    _enforce_rate_limit(request, cost=samples)
    result = await execute_probe(target, allow_private=_allow_private_api(), samples=samples)
    payload, content_type = render_adhoc_probe_metrics(result)
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
        context={"cached_results": list(STATE_CACHE.values()), "app_version": __version__},
    )