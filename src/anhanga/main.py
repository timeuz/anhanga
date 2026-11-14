import asyncio
import contextlib
import hmac
import ipaddress
import logging
import os
from pathlib import Path

import time
from typing import Any, Literal
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from anhanga import __version__
from anhanga.engine.alerting import AlertEvent, AlertManager
from anhanga.engine.config import MonitorConfig, WebhookSpec, find_config_path, load_config
from anhanga.engine.models import ProbeResult
from anhanga.engine.probe import (
    ABSOLUTE_MAX_BODY_BYTES,
    DEFAULT_MAX_BODY_BYTES,
    SSRFBlockedError,
    _normalize_and_validate_scheme,
    execute_probe,
)
from anhanga.engine.security import RATE_LIMITER
from anhanga.engine.webhooks import send_webhook_alert
from anhanga.metrics.exporter import (
    ALERT_NOTIFICATIONS_TOTAL,
    forget_target,
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


_CONFIG: MonitorConfig | None = None
_BACKGROUND_TASKS: set[asyncio.Task] = set()  # referência forte: evita coleta de tasks de notificação
WEBHOOK_DELIVERY_TIMEOUT = 10.0


def _config_path() -> Path | None:
    return find_config_path([BASE_DIR.parent.parent / "targets.yaml"])


def _current_config() -> MonitorConfig:
    """Config vigente (a do loop de vigilância; carrega sob demanda se o loop ainda não rodou)."""
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = load_config(_config_path())
    return _CONFIG


def _log_config_issues(cfg: MonitorConfig, path: Path | None) -> None:
    origin = f" ({path})" if path else ""
    for msg in cfg.errors:
        logger.error(f"Configuração{origin}: {msg}")
    for msg in cfg.warnings:
        logger.warning(f"Configuração{origin}: {msg}")


async def _deliver_event(event: AlertEvent, result: ProbeResult, webhooks: list[WebhookSpec]) -> None:
    """Entrega um evento a todos os webhooks em paralelo, com timeout e uma nova tentativa."""

    async def _one(wh: WebhookSpec) -> bool:
        for attempt in (1, 2):
            try:
                await asyncio.wait_for(
                    send_webhook_alert(
                        webhook_url=wh.url,
                        result=result,
                        provider=wh.provider,
                        violations=event.messages,
                        chat_id=wh.chat_id,
                        allow_private=wh.allow_private,
                        timeout=WEBHOOK_DELIVERY_TIMEOUT / 2,
                        event=event.kind,
                    ),
                    timeout=WEBHOOK_DELIVERY_TIMEOUT,
                )
                return True
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    f"Webhook {event.kind} para {event.target} falhou (tentativa {attempt}/2): {exc}"
                )
                if attempt == 1:
                    await asyncio.sleep(2.0)
        return False

    outcomes = await asyncio.gather(*(_one(wh) for wh in webhooks))
    for ok in outcomes:
        ALERT_NOTIFICATIONS_TOTAL.labels(kind=event.kind, result="sent" if ok else "failed").inc()


def _dispatch_events(events: list[AlertEvent], result: ProbeResult, webhooks: list[WebhookSpec]) -> None:
    """Agenda a entrega em background: webhook lento nunca atrasa o ciclo de sondagem."""
    if not webhooks:
        return
    for event in events:
        logger.info(f"Alerta [{event.kind}] {event.target}: {'; '.join(event.messages)}")
        task = asyncio.create_task(_deliver_event(event, result, webhooks))
        _BACKGROUND_TASKS.add(task)
        task.add_done_callback(_BACKGROUND_TASKS.discard)


async def background_guardian_loop():
    """Loop assíncrono que sonda os alvos do targets.yaml, avalia alertas com estado e recarrega a config."""
    global _CONFIG
    path = _config_path()
    cfg = load_config(path)
    _CONFIG = cfg
    _log_config_issues(cfg, path)
    mtime = path.stat().st_mtime if path else None
    manager = AlertManager(cfg.policy)

    if not cfg.targets and path is None:
        logger.info("Nenhum targets.yaml detectado. Operando apenas em modo On-Demand/API.")

    while True:
        cycle_start = time.monotonic()
        try:
            # Recarga a quente: só quando o arquivo mudou (stat é barato).
            new_path = _config_path()
            new_mtime = new_path.stat().st_mtime if new_path else None
            if new_path is not None and (new_path, new_mtime) != (path, mtime):
                path, mtime = new_path, new_mtime
                cfg = load_config(path)
                _CONFIG = cfg
                _log_config_issues(cfg, path)
                logger.info(f"Configuração recarregada: {len(cfg.targets)} alvo(s), {len(cfg.webhooks)} webhook(s).")
                manager.policy = cfg.policy

            if cfg.targets:
                results = await asyncio.gather(
                    *(
                        execute_probe(t.url, allow_private=t.allow_private, samples=t.samples)
                        for t in cfg.targets
                    ),
                    return_exceptions=True,
                )
                for spec, res in zip(cfg.targets, results):
                    if not isinstance(res, ProbeResult):
                        logger.error(f"Sonda de {spec.url} falhou de forma inesperada: {res!r}")
                        continue
                    _update_state_and_history(res, is_continuous=True)
                    record_probe_metrics(res)
                    _dispatch_events(manager.evaluate(res, spec.rules), res, cfg.webhooks)

            # Alvos removidos da config somem do dashboard, das métricas e do estado de alertas.
            expected = {_normalize_and_validate_scheme(t.url)[0] for t in cfg.targets}
            for stale in [k for k in STATE_CACHE if k not in expected]:
                STATE_CACHE.pop(stale, None)
                HISTORY_CACHE.pop(stale, None)
                forget_target(stale)
            manager.forget(expected)
        except asyncio.CancelledError:
            logger.info("Desligando loop de vigilância do Anhangá.")
            break
        except Exception as exc:  # noqa: BLE001
            logger.error(f"Erro no loop de background: {exc}")

        # Taxa fixa: o intervalo conta do início do ciclo (não acumula a duração das sondas).
        elapsed = time.monotonic() - cycle_start
        await asyncio.sleep(max(1.0, cfg.interval_seconds - elapsed))


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
    entries = {w.url: w for w in _current_config().webhooks}
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
            allow_private=entries[body.webhook_url].allow_private,
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