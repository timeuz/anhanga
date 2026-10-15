from prometheus_client import CollectorRegistry, Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST
from anhanga.engine.models import ProbeResult

# Registry dedicado para manter as métricas limpas e previsíveis
REGISTRY = CollectorRegistry(auto_describe=True)

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


def record_probe_metrics(result: ProbeResult) -> None:
    """Atualiza os Gauges e Counters do Prometheus com o resultado da sondagem."""
    target = result.target_url
    status_label = "success" if result.is_up else "failure"

    PROBE_EXECUTIONS_TOTAL.labels(target=target, result=status_label).inc()
    PROBE_UP.labels(target=target).set(1 if result.is_up else 0)
    PROBE_REDIRECTS.labels(target=target).set(result.redirect_hops)

    if result.status_code:
        http_ver = result.http_version or "unknown"
        PROBE_STATUS_CODE.labels(target=target, http_version=http_ver).set(result.status_code)

    # Conversão de ms para segundos (Padrão OpenMetrics)
    phases = {
        "dns": result.timings.dns_ms / 1000.0,
        "tcp": result.timings.tcp_ms / 1000.0,
        "tls": result.timings.tls_ms / 1000.0,
        "ttfb": result.timings.ttfb_ms / 1000.0,
        "transfer": result.timings.transfer_ms / 1000.0,
        "total": result.timings.total_ms / 1000.0,
    }
    for phase, seconds in phases.items():
        PROBE_DURATION_SECONDS.labels(target=target, phase=phase).set(round(seconds, 5))

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