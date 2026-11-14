import asyncio
import contextlib
import hmac
import ipaddress
import logging
import os
from pathlib import Path

import time
from datetime import datetime, timezone
from typing import Any, Literal
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from anhanga import __version__
from anhanga.engine.alerting import AlertEvent, AlertManager, Evaluation
from anhanga.engine.config import MonitorConfig, WebhookSpec, find_config_path, load_config
from anhanga.engine.models import ProbeResult
from anhanga.engine import revocation, tlsenum
from anhanga.engine.probe import (
    ABSOLUTE_MAX_BODY_BYTES,
    DEFAULT_MAX_BODY_BYTES,
    MONITORED_PROBE,
    SSRFBlockedError,
    _normalize_and_validate_scheme,
    execute_probe,
)
from anhanga.engine.security import RATE_LIMITER, cancel_extras_background
from anhanga.engine.webhooks import send_webhook_alert
from anhanga.storage import Store, webhook_key
from anhanga.metrics.exporter import (
    ALERT_NOTIFICATIONS_TOTAL,
    ALERT_OUTBOX_PENDING,
    STORAGE_ERRORS_TOTAL,
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


_LOOPBACK_HOSTNAMES = {"localhost", "127.0.0.1", "::1"}


def _host_header_is_loopback(request: Request) -> bool:
    """O cabeçalho Host também precisa ser loopback: um proxy reverso na mesma máquina (que aparece como
    127.0.0.1) encaminha o Host público, e isso o distingue de um acesso local de verdade."""
    host = request.headers.get("host", "").strip().lower()
    if host.startswith("["):  # [::1]:8000
        host = host[1:].split("]", 1)[0]
    elif host.count(":") == 1:  # nome:porta (IPv6 sem colchetes não tem porta)
        host = host.split(":", 1)[0]
    return host in _LOOPBACK_HOSTNAMES


def _is_loopback_direct(request: Request) -> bool:
    """Cliente loopback sem indício de proxy reverso (que mascararia o cliente real)."""
    if request.client is None or not _host_header_is_loopback(request):
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
    if headline_ms > 0:  # só a vigilância contínua chega aqui (scans avulsos retornam acima)
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
SHUTDOWN_DRAIN_SECONDS = 5.0


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


_STORE: Store | None = None
_OUTBOX_RUNNING = False
_LAST_PRUNE = 0.0
PRUNE_INTERVAL_SECONDS = 3600.0


async def _store_try(fn, *args) -> tuple[bool, object]:
    """Executa uma operação do SQLite fora do event loop -> (ok, valor). Nunca propaga exceção."""
    if _STORE is None:
        return False, None
    try:
        return True, await asyncio.to_thread(fn, *args)
    except Exception as exc:  # noqa: BLE001
        STORAGE_ERRORS_TOTAL.inc()
        logger.error(f"Persistência SQLite falhou ({getattr(fn, '__name__', fn)}): {exc}")
        return False, None


async def _store_call(fn, *args):
    """Como `_store_try`, mas devolve só o valor (None se falhou ou se não há persistência)."""
    return (await _store_try(fn, *args))[1]


async def _send_to_webhook(
    wh: WebhookSpec, kind: str, messages: list[str], result: ProbeResult, timeout: float
) -> None:
    """Levanta se a entrega falhar. `send_webhook_alert` NÃO levanta em resposta HTTP não-2xx (devolve
    `sent: False`): sem checar, um Slack respondendo 500/429/404 contava como entregue e o alerta se perdia."""
    delivery = await asyncio.wait_for(
        send_webhook_alert(
            webhook_url=wh.url,
            result=result,
            provider=wh.provider,
            violations=messages,
            chat_id=wh.chat_id,
            allow_private=wh.allow_private,
            timeout=timeout / 2,
            event=kind,
        ),
        timeout=timeout,
    )
    if not delivery.get("sent"):
        raise RuntimeError(f"webhook respondeu HTTP {delivery.get('status_code')} (esperado 2xx)")


async def _deliver_event(event: AlertEvent, result: ProbeResult, webhooks: list[WebhookSpec]) -> None:
    """Entrega um evento a todos os webhooks em paralelo (timeout + 1 nova tentativa).

    Quem falhar vai para a outbox persistente e é reenviado com backoff: o alerta não se perde."""

    def _enqueue_now(wh: WebhookSpec) -> bool:
        """Síncrono de propósito: precisa funcionar mesmo durante o cancelamento do desligamento."""
        if _STORE is None:
            return False
        try:
            _STORE.enqueue(webhook_key(wh.url), event.target, event.kind, event.messages, result.model_dump_json())
            return True
        except Exception as exc:  # noqa: BLE001
            logger.error(f"Falha ao salvar notificação na outbox: {exc}")
            return False

    async def _one(wh: WebhookSpec) -> str:
        try:
            return await _one_inner(wh)
        except asyncio.CancelledError:
            _enqueue_now(wh)  # desligando com a entrega em voo: não perder o alerta
            raise

    async def _one_inner(wh: WebhookSpec) -> str:
        for attempt in (1, 2):
            try:
                await _send_to_webhook(wh, event.kind, event.messages, result, WEBHOOK_DELIVERY_TIMEOUT)
                return "sent"
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    f"Webhook {event.kind} para {event.target} falhou (tentativa {attempt}/2): {exc}"
                )
                if attempt == 1:
                    await asyncio.sleep(2.0)
        if _STORE is not None:
            ok, _ = await _store_try(
                _STORE.enqueue, webhook_key(wh.url), event.target, event.kind, event.messages, result.model_dump_json()
            )
            if ok:
                return "queued"
        return "failed"

    for outcome in await asyncio.gather(*(_one(wh) for wh in webhooks)):
        ALERT_NOTIFICATIONS_TOTAL.labels(kind=event.kind, result=outcome).inc()


async def _process_outbox(cfg: MonitorConfig) -> None:
    """Reenvia notificações pendentes que já venceram o backoff. Uma execução por vez."""
    global _OUTBOX_RUNNING
    if _STORE is None or _OUTBOX_RUNNING:
        return
    _OUTBOX_RUNNING = True
    try:
        rows = await _store_call(_STORE.due) or []
        by_key = {webhook_key(w.url): w for w in cfg.webhooks}
        for row in rows:
            kind = row["kind"]
            wh = by_key.get(row["webhook_key"])
            try:
                result = ProbeResult.model_validate_json(row["result_json"])
            except ValueError:
                result = None
            if wh is None or result is None:  # destino removido da config ou item corrompido
                await _store_call(_STORE.mark_done, row["id"])
                ALERT_NOTIFICATIONS_TOTAL.labels(kind=kind, result="dropped").inc()
                continue
            created = datetime.fromtimestamp(row["created_ts"], timezone.utc).strftime("%H:%M:%SZ")
            messages = [f"⏱ Reenvio: entrega original falhou (alerta gerado às {created})", *row["messages"]]
            try:
                await _send_to_webhook(wh, kind, messages, result, WEBHOOK_DELIVERY_TIMEOUT)
            except Exception as exc:  # noqa: BLE001
                gave_up = await _store_call(_STORE.reschedule, row["id"])
                logger.warning(f"Reenvio de {kind} ({row['target']}) falhou: {exc}")
                if gave_up:
                    ALERT_NOTIFICATIONS_TOTAL.labels(kind=kind, result="dropped").inc()
                    logger.error(f"Desistindo de {kind} para {row['target']}: tentativas esgotadas ou alerta antigo.")
            else:
                await _store_call(_STORE.mark_done, row["id"])
                ALERT_NOTIFICATIONS_TOTAL.labels(kind=kind, result="sent").inc()
        size = await _store_call(_STORE.outbox_size)
        ALERT_OUTBOX_PENDING.set(size or 0)
    finally:
        _OUTBOX_RUNNING = False


async def _monitored_probe(url: str, **kwargs) -> ProbeResult:
    """Sondagem da vigilância contínua (habilita a heurística de falha de modo comum)."""
    token = MONITORED_PROBE.set(True)
    try:
        return await execute_probe(url, **kwargs)
    finally:
        MONITORED_PROBE.reset(token)


def _spawn(coro) -> None:
    task = asyncio.create_task(coro)
    _BACKGROUND_TASKS.add(task)
    task.add_done_callback(_BACKGROUND_TASKS.discard)


def _dispatch_events(events: list[AlertEvent], result: ProbeResult, webhooks: list[WebhookSpec]) -> None:
    """Agenda a entrega em background: webhook lento nunca atrasa o ciclo de sondagem."""
    for event in events:
        logger.info(f"Alerta [{event.kind}] {event.target}: {'; '.join(event.messages)}")
        if webhooks:
            _spawn(_deliver_event(event, result, webhooks))


def _persist_batch(store: Store, items: list[tuple[ProbeResult, Evaluation, list[dict]]], now: float) -> None:
    """Grava, numa única passagem, histórico + incidentes + estado de alertas do ciclo."""
    for res, ev, snapshot in items:
        store.record_probe(res)
        for problem, message, started in ev.opened:
            store.open_incident(res.target_url, problem, started, message)
        for problem in ev.closed:
            store.close_incident(res.target_url, problem, now)
        store.save_alert_state(res.target_url, snapshot)


async def _open_store(cfg: MonitorConfig, manager: AlertManager) -> None:
    """Abre a persistência (só quando há alvos monitorados) e repovoa sparkline e estado de alertas."""
    global _STORE
    if _STORE is not None or not cfg.storage.enabled or not cfg.targets:
        return
    try:
        store = await asyncio.to_thread(Store, cfg.storage.path, cfg.storage.retention_days)
    except Exception as exc:  # noqa: BLE001
        STORAGE_ERRORS_TOTAL.inc()
        logger.error(f"Persistência desativada: não foi possível abrir '{cfg.storage.path}': {exc}")
        return
    _STORE = store
    expected = [_normalize_and_validate_scheme(t.url)[0] for t in cfg.targets]
    for url in expected:
        totals = await _store_call(store.recent_totals, url, MAX_HISTORY_POINTS)
        if totals:
            HISTORY_CACHE[url] = list(totals)
    rows = await _store_call(store.load_alert_state) or []
    manager.restore(rows)
    pending = await _store_call(store.outbox_size) or 0
    ALERT_OUTBOX_PENDING.set(pending)
    logger.info(
        f"Persistência SQLite ativa em '{cfg.storage.path}' (retenção {cfg.storage.retention_days}d): "
        f"{len(rows)} estado(s) de alerta restaurado(s), {pending} notificação(ões) pendente(s)."
    )


async def background_guardian_loop():
    """Loop assíncrono que sonda os alvos do targets.yaml, avalia alertas com estado e recarrega a config."""
    global _CONFIG, _LAST_PRUNE
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
                new_cfg = load_config(path)
                _log_config_issues(new_cfg, path)
                if new_cfg.load_failed:
                    # YAML quebrado/meio salvo não é "zero alvos": manter a config anterior, senão o ciclo
                    # seguinte apagaria alvos, estado de alertas e fecharia incidentes como recuperados.
                    logger.error("Recarga rejeitada: configuração inválida; mantendo a configuração anterior.")
                else:
                    logger.info(
                        f"Configuração recarregada: {len(new_cfg.targets)} alvo(s), {len(new_cfg.webhooks)} webhook(s)."
                    )
                    if new_cfg.storage != cfg.storage and _STORE is not None:
                        logger.warning("Configuração 'storage' alterada: requer reiniciar o servidor para valer.")
                    cfg = new_cfg
                    _CONFIG = cfg
                    manager.policy = cfg.policy

            await _open_store(cfg, manager)

            if cfg.targets:
                results = await asyncio.gather(
                    *(
                        _monitored_probe(t.url, allow_private=t.allow_private, samples=t.samples)
                        for t in cfg.targets
                    ),
                    return_exceptions=True,
                )
                batch: list[tuple[ProbeResult, Evaluation, list[dict]]] = []
                for spec, res in zip(cfg.targets, results):
                    if not isinstance(res, ProbeResult):
                        logger.error(f"Sonda de {spec.url} falhou de forma inesperada: {res!r}")
                        continue
                    _update_state_and_history(res, is_continuous=True)
                    record_probe_metrics(res)
                    ev = manager.evaluate_full(res, spec.rules)
                    _dispatch_events(ev.events, res, cfg.webhooks)
                    batch.append((res, ev, manager.snapshot(res.target_url)))
                if batch and _STORE is not None:
                    await _store_call(_persist_batch, _STORE, batch, time.time())

            # Alvos removidos da config somem do dashboard, das métricas, do estado de alertas e dos incidentes abertos.
            expected = {_normalize_and_validate_scheme(t.url)[0] for t in cfg.targets}
            for stale in [k for k in STATE_CACHE if k not in expected]:
                STATE_CACHE.pop(stale, None)
                HISTORY_CACHE.pop(stale, None)
                forget_target(stale)
            removed = manager.forget(expected)
            if removed and _STORE is not None:
                await _store_call(_STORE.forget_targets, removed)

            if _STORE is not None:
                _spawn(_process_outbox(cfg))
                if time.monotonic() - _LAST_PRUNE >= PRUNE_INTERVAL_SECONDS:
                    _LAST_PRUNE = time.monotonic()
                    deleted = await _store_call(_STORE.prune)
                    if deleted:
                        logger.info(f"Retenção: {deleted} registro(s) de histórico expirado(s) removido(s).")
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
    global _STORE
    task = asyncio.create_task(background_guardian_loop())
    yield
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    revocation.cancel_background()
    tlsenum.cancel_background()
    cancel_extras_background()
    # Entregas em voo: dá uma janela para concluir; as que não acabarem são canceladas e se salvam na
    # outbox (ver `_deliver_event`) ANTES de o banco fechar.
    pending = [t for t in _BACKGROUND_TASKS if not t.done()]
    if pending:
        _, still = await asyncio.wait(pending, timeout=SHUTDOWN_DRAIN_SECONDS)
        for t in still:
            t.cancel()
        if still:
            await asyncio.wait(still, timeout=5.0)
    if _STORE is not None:
        store, _STORE = _STORE, None
        await asyncio.to_thread(store.close)


def _docs_enabled() -> bool:
    """/docs, /redoc e /openapi.json só existem com ANHANGA_DOCS=1 (o esquema descreve a superfície da API)."""
    return os.getenv("ANHANGA_DOCS", "").strip().lower() in {"1", "true", "yes", "on"}


_DOCS = _docs_enabled()
app = FastAPI(
    title="Anhangá",
    description="Spectral Edge, TLS & Latency Auditor for SRE and DevSecOps",
    version=__version__,
    lifespan=lifespan,
    docs_url="/docs" if _DOCS else None,
    redoc_url="/redoc" if _DOCS else None,
    openapi_url="/openapi.json" if _DOCS else None,
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
    """Liveness/Readiness probe (público: não expõe nada além de "vivo")."""
    return {"status": "alive"}


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


def _require_store() -> Store:
    if _STORE is None:
        raise HTTPException(
            status_code=503,
            detail="Persistência indisponível (desabilitada, sem alvos configurados ou falha ao abrir o banco).",
        )
    return _STORE


@app.get("/api/v1/history", tags=["Persistence"])
async def api_history(
    target: str = Query(..., description="target_url exatamente como aparece em /api/v1/targets"),
    hours: float = Query(24.0, ge=0.1, le=24 * 365),
    max_points: int = Query(300, ge=10, le=2000),
):
    """Série histórica agregada (checks, up/degraded/down e latência média/mín/máx por bucket)."""
    store = _require_store()
    until = time.time()
    points = await asyncio.to_thread(store.history, target, until - hours * 3600, until, max_points)
    return {"target": target, "hours": hours, "points": points}


@app.get("/api/v1/uptime", tags=["Persistence"])
async def api_uptime(target: str | None = Query(None, description="Omitir = todos os alvos monitorados")):
    """Uptime (health=up) e disponibilidade HTTP (up+degraded) em 24h, 7d e 30d, com a cobertura real dos dados."""
    store = _require_store()
    targets = [target] if target else sorted(STATE_CACHE)
    data = await asyncio.to_thread(lambda: {t: store.uptime(t) for t in targets})
    return {"targets": data}


@app.get("/api/v1/incidents", tags=["Persistence"])
async def api_incidents(
    target: str | None = Query(None),
    open_only: bool = Query(False),
    limit: int = Query(100, ge=1, le=1000),
):
    """Incidentes (alertas que passaram do limiar) abertos e encerrados, com duração."""
    store = _require_store()
    return {"incidents": await asyncio.to_thread(store.incidents, target, open_only, limit)}


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
            "<h1>Anhangá Engine Online</h1><p>Interface indisponível; use <code>/api/v1/</code> e <code>/metrics</code> com a chave da API.</p>"
        )
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        # O HTML é público (a UI pede a chave e busca os dados via /api/), mas o estado em cache não pode
        # vazar sem autorização: alvos, IPs, notas e latências só vão no render para quem está autorizado.
        context={
            "cached_results": list(STATE_CACHE.values()) if _is_authorized(request) else [],
            "app_version": __version__,
            "docs_enabled": _DOCS,
        },
    )