from datetime import datetime, timezone
from urllib.parse import urlparse

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

from anhanga.engine.models import ProbeResult

# Registry dedicado para manter as métricas limpas e previsíveis
REGISTRY = CollectorRegistry(auto_describe=True)

# ==============================================================================
# 1. Série padrão compatível com Prometheus Blackbox Exporter (em segundos)
# ==============================================================================
BLACKBOX_PROBE_SUCCESS = Gauge(
    "probe_success",
    "Displays whether or not the probe was a success (1 = UP, 0 = DOWN)",
    ["target", "instance"],
    registry=REGISTRY,
)

BLACKBOX_PROBE_DURATION_SECONDS = Gauge(
    "probe_duration_seconds",
    "Returns how long the probe took to complete in seconds",
    ["target", "instance"],
    registry=REGISTRY,
)

BLACKBOX_PROBE_HTTP_DURATION_SECONDS = Gauge(
    "probe_http_duration_seconds",
    "Duration of http request by phase, summed over all redirects in seconds",
    ["phase", "target", "instance"],
    registry=REGISTRY,
)

BLACKBOX_PROBE_HTTP_STATUS_CODE = Gauge(
    "probe_http_status_code",
    "Response HTTP status code",
    ["target", "instance"],
    registry=REGISTRY,
)

BLACKBOX_PROBE_HTTP_REDIRECTS = Gauge(
    "probe_http_redirects",
    "The number of redirects",
    ["target", "instance"],
    registry=REGISTRY,
)

BLACKBOX_PROBE_HTTP_SSL = Gauge(
    "probe_http_ssl",
    "Indicates if SSL was used for the final request (1 = valid TLS/HTTPS, 0 = otherwise)",
    ["target", "instance"],
    registry=REGISTRY,
)

BLACKBOX_PROBE_SSL_EARLIEST_CERT_EXPIRY = Gauge(
    "probe_ssl_earliest_cert_expiry",
    "Returns earliest SSL cert expiry in unixtime",
    ["target", "instance"],
    registry=REGISTRY,
)

BLACKBOX_PROBE_HTTP_VERSION = Gauge(
    "probe_http_version",
    "Returns the version of HTTP of the probe response",
    ["target", "instance"],
    registry=REGISTRY,
)

# ==============================================================================
# 2. Série estendida do Anhangá (em segundos)
# ==============================================================================
PROBE_UP = Gauge(
    "anhanga_probe_up",
    "Indica se o alvo respondeu com sucesso (1 = UP, 0 = DOWN)",
    ["target"],
    registry=REGISTRY,
)

PROBE_STATUS_CODE = Gauge(
    "anhanga_probe_http_status_code",
    "Último HTTP Status Code retornado pelo alvo",
    ["target", "http_version"],
    registry=REGISTRY,
)

PROBE_DURATION_SECONDS = Gauge(
    "anhanga_probe_duration_seconds",
    "Decomposição de latência da sondagem em segundos por fase",
    ["target", "phase"],
    registry=REGISTRY,
)

PROBE_LATENCY_QUANTILE_SECONDS = Gauge(
    "anhanga_probe_latency_quantile_seconds",
    "Quantis estatísticos de latência total da sondagem em segundos (P50, P95, P99)",
    ["target", "quantile"],
    registry=REGISTRY,
)

PROBE_JITTER_SECONDS = Gauge(
    "anhanga_probe_jitter_seconds",
    "Jitter médio entre amostras consecutivas em segundos",
    ["target"],
    registry=REGISTRY,
)

PROBE_CONNECTION_COLD_SECONDS = Gauge(
    "anhanga_probe_connection_cold_seconds",
    "Latência total da primeira amostra (conexão fria com DNS+TCP+TLS) em segundos",
    ["target"],
    registry=REGISTRY,
)

PROBE_CONNECTION_WARM_SECONDS = Gauge(
    "anhanga_probe_connection_warm_seconds",
    "Latência média das amostras subsequentes (conexão Keep-Alive reaproveitada) em segundos",
    ["target"],
    registry=REGISTRY,
)

PROBE_TLS_EXPIRY_DAYS = Gauge(
    "anhanga_probe_tls_cert_expiry_days",
    "Dias restantes até a expiração do certificado TLS/SSL",
    ["target", "issuer", "protocol"],
    registry=REGISTRY,
)

ALERT_NOTIFICATIONS_TOTAL = Counter(
    "anhanga_alert_notifications_total",
    "Notificações de alerta aos webhooks (kind: alert|reminder|recovery; "
    "result: sent|queued (falhou, na outbox p/ reenvio)|dropped (desistiu)|failed (falhou, sem persistência))",
    ["kind", "result"],
    registry=REGISTRY,
)

ALERT_OUTBOX_PENDING = Gauge(
    "anhanga_alert_outbox_pending",
    "Notificações aguardando reenvio na outbox persistente",
    registry=REGISTRY,
)

STORAGE_ERRORS_TOTAL = Counter(
    "anhanga_storage_errors_total",
    "Erros de leitura/escrita na persistência SQLite (o monitoramento continua sem persistir)",
    registry=REGISTRY,
)

PROBE_TLS_VALID = Gauge(
    "anhanga_probe_tls_valid",
    "1 se a cadeia/hostname/validade do certificado TLS foram validados com sucesso",
    ["target"],
    registry=REGISTRY,
)

PROBE_SECURITY_SCORE = Gauge(
    "anhanga_probe_security_score",
    "Pontuação de auditoria de headers de segurança DevSecOps (0 a 100)",
    ["target", "grade"],
    registry=REGISTRY,
)

PROBE_REDIRECTS = Gauge(
    "anhanga_probe_redirect_hops",
    "Quantidade de redirecionamentos (301/302/307/308) seguidos",
    ["target"],
    registry=REGISTRY,
)

PROBE_EXECUTIONS_TOTAL = Counter(
    "anhanga_probe_executions_total",
    "Total de sondagens executadas pelo motor do Anhangá",
    ["target", "result"],
    registry=REGISTRY,
)

PROBE_ASSERTIONS_NOT_EVALUATED_TOTAL = Counter(
    "anhanga_assertions_not_evaluated_total",
    "Asserções de corpo (regex) que o Anhangá NÃO conseguiu avaliar (falha do monitor, não do alvo). Alerte em rate() > 0",
    ["target"],
    registry=REGISTRY,
)

PROBE_DURATION_HISTOGRAM_SECONDS = Histogram(
    "anhanga_probe_duration_seconds_histogram",
    "Histograma de distribuição de latência total da sondagem em segundos para uso com histogram_quantile()",
    ["target"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
    registry=REGISTRY,
)

PROBE_SERVER_PROCESSING_SECONDS = Gauge(
    "anhanga_probe_server_processing_seconds",
    "Tempo estimado de processamento do servidor (TTFB − RTT) em segundos",
    ["target"],
    registry=REGISTRY,
)

PROBE_ESTIMATED_RTT_SECONDS = Gauge(
    "anhanga_probe_estimated_rtt_seconds",
    "RTT físico de rede estimado (handshake TCP / TLS) em segundos",
    ["target"],
    registry=REGISTRY,
)


def _parse_http_version_number(http_version: str | None) -> float:
    """Converte strings como 'HTTP/1.1' ou 'HTTP/2' para float (1.1, 2.0)."""
    if not http_version:
        return 0.0
    cleaned = http_version.strip().upper()
    if cleaned.startswith("HTTP/"):
        cleaned = cleaned[5:].strip()
    try:
        return float(cleaned)
    except ValueError:
        return 0.0


def _resolve_instance_label(result: ProbeResult, instance: str | None = None) -> str:
    if instance:
        return instance
    try:
        parsed = urlparse(result.target_url)
    except ValueError:  # URL malformada (ex.: colchete IPv6): sem netloc utilizável
        return result.target_url
    if parsed.netloc:
        return parsed.netloc
    return result.resolved_ip or result.target_url


def _remove_series(gauge: Gauge, target: str) -> None:
    """Remove as séries de um Gauge para o alvo (evita séries obsoletas e valores 0 falsos)."""
    try:
        idx = list(gauge._labelnames).index("target")  # noqa: SLF001
        for key in [k for k in list(gauge._metrics) if k[idx] == target]:  # noqa: SLF001
            gauge.remove(*key)
    except (ValueError, KeyError, AttributeError):
        pass


def forget_target(target: str) -> None:
    """Remove TODAS as séries (gauges, counters e histogramas) de um alvo retirado da configuração."""
    for collector in set(REGISTRY._names_to_collectors.values()):  # noqa: SLF001
        labelnames = getattr(collector, "_labelnames", ())
        if "target" not in labelnames:
            continue
        idx = list(labelnames).index("target")
        for key in [k for k in list(collector._metrics) if k[idx] == target]:  # noqa: SLF001
            collector.remove(*key)


def _clear_measurements(target: str) -> None:
    """Alvo sem resposta: não existe latência, status, nota nem TLS a reportar (e 0 seria mentira)."""
    for g in (
        BLACKBOX_PROBE_DURATION_SECONDS, BLACKBOX_PROBE_HTTP_DURATION_SECONDS,
        BLACKBOX_PROBE_HTTP_STATUS_CODE, BLACKBOX_PROBE_HTTP_REDIRECTS, BLACKBOX_PROBE_HTTP_SSL,
        BLACKBOX_PROBE_SSL_EARLIEST_CERT_EXPIRY, BLACKBOX_PROBE_HTTP_VERSION,
        PROBE_STATUS_CODE, PROBE_REDIRECTS, PROBE_DURATION_SECONDS, PROBE_LATENCY_QUANTILE_SECONDS,
        PROBE_JITTER_SECONDS, PROBE_CONNECTION_COLD_SECONDS, PROBE_CONNECTION_WARM_SECONDS,
        PROBE_TLS_EXPIRY_DAYS, PROBE_TLS_VALID, PROBE_SECURITY_SCORE,
        PROBE_SERVER_PROCESSING_SECONDS, PROBE_ESTIMATED_RTT_SECONDS,
    ):
        _remove_series(g, target)


def record_probe_metrics(result: ProbeResult, instance: str | None = None) -> None:
    """Atualiza os Gauges e Counters do Prometheus (padrão blackbox_exporter + série estendida Anhangá)."""
    target = result.target_url
    inst = _resolve_instance_label(result, instance)
    status_label = "success" if result.is_up else "failure"
    up_val = 1 if result.is_up else 0
    # probe_success segue a semântica do blackbox: certificado inválido = falha.
    success_val = 1 if result.health == "up" else 0

    if result.status_code is None:
        BLACKBOX_PROBE_SUCCESS.labels(target=target, instance=inst).set(0)
        PROBE_EXECUTIONS_TOTAL.labels(target=target, result=status_label).inc()
        PROBE_UP.labels(target=target).set(0)
        _clear_measurements(target)
        return

    if result.assertions.not_evaluated:
        PROBE_ASSERTIONS_NOT_EVALUATED_TOTAL.labels(target=target).inc(len(result.assertions.not_evaluated))

    dns_s = round(result.timings.dns_ms / 1000.0, 6)
    tcp_s = round(result.timings.tcp_ms / 1000.0, 6)
    tls_s = round(result.timings.tls_ms / 1000.0, 6)
    ttfb_s = round(result.timings.ttfb_ms / 1000.0, 6)
    transfer_s = round(result.timings.transfer_ms / 1000.0, 6)
    total_s = round(result.timings.total_ms / 1000.0, 6)

    # 1. Série compatível com blackbox_exporter
    BLACKBOX_PROBE_SUCCESS.labels(target=target, instance=inst).set(success_val)
    BLACKBOX_PROBE_DURATION_SECONDS.labels(target=target, instance=inst).set(total_s)

    blackbox_phases = {
        "resolve": dns_s,
        "connect": tcp_s,
        "tls": tls_s,
        "processing": ttfb_s,
        "transfer": transfer_s,
    }
    for phase_name, seconds in blackbox_phases.items():
        BLACKBOX_PROBE_HTTP_DURATION_SECONDS.labels(
            phase=phase_name, target=target, instance=inst
        ).set(seconds)

    BLACKBOX_PROBE_HTTP_STATUS_CODE.labels(target=target, instance=inst).set(
        result.status_code or 0
    )
    BLACKBOX_PROBE_HTTP_REDIRECTS.labels(target=target, instance=inst).set(
        result.redirect_hops
    )

    is_ssl = 1 if (result.tls is not None and result.tls.valid) else 0
    BLACKBOX_PROBE_HTTP_SSL.labels(target=target, instance=inst).set(is_ssl)

    # Sem certificado observado neste ciclo (último salto http, TLS não inspecionado), a série antiga não pode ficar:
    # alertas sobre `probe_ssl_earliest_cert_expiry - time()` usariam um certificado que não é mais visto.
    _remove_series(BLACKBOX_PROBE_SSL_EARLIEST_CERT_EXPIRY, target)
    if result.tls and result.tls.expires_at is not None:
        expiry_ts = result.tls.expires_at.timestamp()
        BLACKBOX_PROBE_SSL_EARLIEST_CERT_EXPIRY.labels(
            target=target, instance=inst
        ).set(round(expiry_ts, 2))
    elif result.tls and result.tls.valid and result.tls.days_remaining is not None:
        approx_expiry = (
            datetime.now(timezone.utc).timestamp() + (result.tls.days_remaining * 86400)
        )
        BLACKBOX_PROBE_SSL_EARLIEST_CERT_EXPIRY.labels(
            target=target, instance=inst
        ).set(round(approx_expiry, 2))

    BLACKBOX_PROBE_HTTP_VERSION.labels(target=target, instance=inst).set(
        _parse_http_version_number(result.http_version)
    )

    # 2. Série estendida do Anhangá
    PROBE_EXECUTIONS_TOTAL.labels(target=target, result=status_label).inc()
    PROBE_UP.labels(target=target).set(up_val)
    PROBE_REDIRECTS.labels(target=target).set(result.redirect_hops)

    if result.status_code:
        _remove_series(PROBE_STATUS_CODE, target)  # http_version pode mudar entre ciclos
        http_ver = result.http_version or "unknown"
        PROBE_STATUS_CODE.labels(target=target, http_version=http_ver).set(
            result.status_code
        )

    # Conversão de ms para segundos (Padrão OpenMetrics) com fases canônicas e aliases blackbox
    anhanga_phases = {
        "dns": dns_s,
        "tcp": tcp_s,
        "tls": tls_s,
        "ttfb": ttfb_s,
        "transfer": transfer_s,
        "total": total_s,
        "resolve": dns_s,
        "connect": tcp_s,
        "processing": ttfb_s,
    }
    for phase, seconds in anhanga_phases.items():
        PROBE_DURATION_SECONDS.labels(target=target, phase=phase).set(seconds)

    # Quantis P50 / P95 / P99, Jitter e Conexão Fria vs Quente em segundos
    has_samples = bool(result.sampling and result.sampling.raw_samples)
    p50_ms = (
        result.sampling.p50_ms
        if (has_samples or result.sampling.p50_ms > 0)
        else result.timings.total_ms
    )
    cold_ms = (
        result.sampling.cold_total_ms
        if (has_samples or result.sampling.cold_total_ms > 0)
        else result.timings.total_ms
    )
    warm_ms = (
        result.sampling.warm_avg_total_ms
        if result.sampling.warm_avg_total_ms is not None
        else cold_ms
    )
    jitter_ms = result.sampling.jitter_ms if result.sampling else 0.0

    PROBE_LATENCY_QUANTILE_SECONDS.labels(target=target, quantile="0.5").set(
        round(p50_ms / 1000.0, 6)
    )
    # P95/P99 só existem com amostras suficientes (n >= 20 / n >= 100, a mesma regra da UI e do CLI). Abaixo disso o
    # "percentil" seria só o máximo do ciclo; a série é removida em vez de exportar um número sem significado.
    # Para a cauda ao longo do tempo, use anhanga_probe_duration_seconds_histogram com histogram_quantile().
    for quantile, valid, value_ms in (
        ("0.95", bool(result.sampling and result.sampling.p95_valid), result.sampling.p95_ms if result.sampling else 0.0),
        ("0.99", bool(result.sampling and result.sampling.p99_valid), result.sampling.p99_ms if result.sampling else 0.0),
    ):
        try:
            PROBE_LATENCY_QUANTILE_SECONDS.remove(target, quantile)
        except KeyError:
            pass
        if valid:
            PROBE_LATENCY_QUANTILE_SECONDS.labels(target=target, quantile=quantile).set(round(value_ms / 1000.0, 6))
    PROBE_JITTER_SECONDS.labels(target=target).set(round(jitter_ms / 1000.0, 6))
    PROBE_CONNECTION_COLD_SECONDS.labels(target=target).set(round(cold_ms / 1000.0, 6))
    PROBE_CONNECTION_WARM_SECONDS.labels(target=target).set(round(warm_ms / 1000.0, 6))

    # Métricas de Certificado TLS
    _remove_series(PROBE_TLS_EXPIRY_DAYS, target)
    _remove_series(PROBE_TLS_VALID, target)
    if result.tls is not None:
        PROBE_TLS_VALID.labels(target=target).set(1 if result.tls.valid else 0)
    # Dias restantes são exportados mesmo com certificado inválido (negativo = expirado) para permitir alertas
    if result.tls and result.tls.days_remaining is not None:
        PROBE_TLS_EXPIRY_DAYS.labels(
            target=target,
            issuer=result.tls.issuer or "Unknown",
            protocol=result.tls.protocol or "Unknown",
        ).set(result.tls.days_remaining)

    # Métricas de Auditoria de Segurança
    _remove_series(PROBE_SECURITY_SCORE, target)  # o label grade muda entre ciclos
    PROBE_SECURITY_SCORE.labels(target=target, grade=result.security.grade).set(
        result.security.score
    )

    # Física de Rede e Processamento de Servidor (TTFB - RTT)
    if result.timings.server_processing_ms is None:
        _remove_series(PROBE_SERVER_PROCESSING_SECONDS, target)
    else:
        PROBE_SERVER_PROCESSING_SECONDS.labels(target=target).set(
            round(result.timings.server_processing_ms / 1000.0, 6)
        )
    PROBE_ESTIMATED_RTT_SECONDS.labels(target=target).set(
        round(result.timings.estimated_rtt_ms / 1000.0, 6)
    )

    # Histograma em segundos para histogram_quantile() no Grafana
    if result.sampling and result.sampling.raw_samples:
        for s in result.sampling.raw_samples:
            PROBE_DURATION_HISTOGRAM_SECONDS.labels(target=target).observe(
                round(s.timings.total_ms / 1000.0, 6)
            )
    elif result.timings.total_ms > 0:
        PROBE_DURATION_HISTOGRAM_SECONDS.labels(target=target).observe(
            round(result.timings.total_ms / 1000.0, 6)
        )


def render_prometheus_metrics() -> tuple[bytes, str]:
    """Gera o payload de texto plano no formato Prometheus."""
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST

def render_adhoc_probe_metrics(result: ProbeResult) -> tuple[bytes, str]:
    """Métricas estilo Blackbox de UMA sondagem avulsa, em registry descartável.

    Nunca toca o REGISTRY global: alvos arbitrários não criam séries permanentes (anti-cardinalidade).
    """
    reg = CollectorRegistry()

    def gauge(name: str, doc: str, value: float, labels: dict[str, str] | None = None) -> None:
        g = Gauge(name, doc, list(labels or {}), registry=reg)
        (g.labels(**labels) if labels else g).set(value)

    t = result.timings
    gauge("probe_success", "1 se a sondagem foi bem-sucedida (HTTP ok e TLS válido)", 1.0 if result.health == "up" else 0.0)
    if result.status_code is None:
        return generate_latest(reg), CONTENT_TYPE_LATEST
    gauge("probe_duration_seconds", "Duração total da sondagem", round(t.total_ms / 1000.0, 6))
    gauge("probe_http_status_code", "Código HTTP final", float(result.status_code or 0))
    gauge("probe_http_redirects", "Quantidade de redirecionamentos", float(result.redirect_hops))
    gauge("probe_http_ssl", "1 se a conexão final usou TLS válido", 1.0 if (result.tls and result.tls.valid) else 0.0)
    phases = {
        "resolve": t.dns_ms,
        "connect": t.tcp_ms,
        "tls": t.tls_ms,
        "processing": t.ttfb_ms,
        "transfer": t.transfer_ms,
    }
    g = Gauge("probe_http_duration_seconds", "Duração por fase", ["phase"], registry=reg)
    for phase, ms in phases.items():
        g.labels(phase=phase).set(round(ms / 1000.0, 6))
    return generate_latest(reg), CONTENT_TYPE_LATEST
