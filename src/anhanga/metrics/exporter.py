from datetime import datetime, timezone
from urllib.parse import urlparse

from prometheus_client import (
     CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
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
    parsed = urlparse(result.target_url)
    if parsed.netloc:
        return parsed.netloc
    return result.resolved_ip or result.target_url


def record_probe_metrics(result: ProbeResult, instance: str | None = None) -> None:
    """Atualiza os Gauges e Counters do Prometheus (padrão blackbox_exporter + série estendida Anhangá)."""
    target = result.target_url
    inst = _resolve_instance_label(result, instance)
    status_label = "success" if result.is_up else "failure"
    up_val = 1 if result.is_up else 0

    dns_s = round(result.timings.dns_ms / 1000.0, 6)
    tcp_s = round(result.timings.tcp_ms / 1000.0, 6)
    tls_s = round(result.timings.tls_ms / 1000.0, 6)
    ttfb_s = round(result.timings.ttfb_ms / 1000.0, 6)
    transfer_s = round(result.timings.transfer_ms / 1000.0, 6)
    total_s = round(result.timings.total_ms / 1000.0, 6)

    # 1. Série compatível com blackbox_exporter
    BLACKBOX_PROBE_SUCCESS.labels(target=target, instance=inst).set(up_val)
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
    p95_ms = (
        result.sampling.p95_ms
        if (has_samples or result.sampling.p95_ms > 0)
        else result.timings.total_ms
    )
    p99_ms = (
        result.sampling.p99_ms
        if (has_samples or result.sampling.p99_ms > 0)
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
    PROBE_LATENCY_QUANTILE_SECONDS.labels(target=target, quantile="0.95").set(
        round(p95_ms / 1000.0, 6)
    )
    PROBE_LATENCY_QUANTILE_SECONDS.labels(target=target, quantile="0.99").set(
        round(p99_ms / 1000.0, 6)
    )
    PROBE_JITTER_SECONDS.labels(target=target).set(round(jitter_ms / 1000.0, 6))
    PROBE_CONNECTION_COLD_SECONDS.labels(target=target).set(round(cold_ms / 1000.0, 6))
    PROBE_CONNECTION_WARM_SECONDS.labels(target=target).set(round(warm_ms / 1000.0, 6))

    # Métricas de Certificado TLS
    if result.tls and result.tls.valid and result.tls.days_remaining is not None:
        PROBE_TLS_EXPIRY_DAYS.labels(
            target=target,
            issuer=result.tls.issuer or "Unknown",
            protocol=result.tls.protocol or "Unknown",
        ).set(result.tls.days_remaining)

    # Métricas de Auditoria de Segurança
    PROBE_SECURITY_SCORE.labels(target=target, grade=result.security.grade).set(
        result.security.score
    )


def render_prometheus_metrics() -> tuple[bytes, str]:
    """Gera o payload de texto plano no formato Prometheus."""
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST