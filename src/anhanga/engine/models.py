from datetime import datetime, timezone
from typing import Any, Literal
from pydantic import BaseModel, Field


PHASE_SLO_THRESHOLDS: dict[str, tuple[float, float]] = {
    "dns": (50.0, 150.0),
    "tcp": (60.0, 150.0),
    "tls": (100.0, 250.0),
    "ttfb": (200.0, 500.0),
    "transfer": (150.0, 400.0),
}

PHASE_LABELS: dict[str, str] = {
    "dns": "DNS Lookup",
    "tcp": "TCP Handshake",
    "tls": "TLS Handshake",
    "ttfb": "TTFB (Espera do Servidor)",
    "transfer": "Transferência de Conteúdo",
}


class PhaseOffset(BaseModel):
    phase: Literal["dns", "tcp", "tls", "ttfb", "transfer"]
    label: str
    start_ms: float = 0.0
    duration_ms: float = 0.0
    end_ms: float = 0.0
    slo_status: Literal["ok", "warning", "critical"] = "ok"
    is_dominant: bool = False


class TimingBreakdown(BaseModel):
    dns_ms: float = 0.0
    tcp_ms: float = 0.0
    tls_ms: float = 0.0
    ttfb_ms: float = 0.0
    transfer_ms: float = 0.0
    total_ms: float = 0.0
    dominant_phase: str | None = None
    phases: list[PhaseOffset] = Field(default_factory=list)
    # Bônus físico da rede (Seção 1.2 do MELHORIAS.txt)
    estimated_rtt_ms: float = 0.0
    server_processing_ms: float = 0.0
    reference_sample: str = "Amostra 1 (Conexão Fria)"


def _classify_phase_slo(phase: str, duration_ms: float) -> Literal["ok", "warning", "critical"]:
    ok_limit, warn_limit = PHASE_SLO_THRESHOLDS.get(phase, (100.0, 300.0))
    if duration_ms < ok_limit:
        return "ok"
    if duration_ms < warn_limit:
        return "warning"
    return "critical"


def build_timing_breakdown(
    dns_ms: float = 0.0,
    tcp_ms: float = 0.0,
    tls_ms: float = 0.0,
    ttfb_ms: float = 0.0,
    transfer_ms: float = 0.0,
    reference_sample: str = "Amostra 1 (Conexão Fria)",
) -> TimingBreakdown:
    """Constrói um TimingBreakdown real e não-cumulativo com offsets exatos para o Waterfall."""
    d_dns = round(max(0.0, dns_ms), 2)
    d_tcp = round(max(0.0, tcp_ms), 2)
    d_tls = round(max(0.0, tls_ms), 2)
    d_ttfb = round(max(0.0, ttfb_ms), 2)
    d_transfer = round(max(0.0, transfer_ms), 2)

    raw_phases: list[tuple[Literal["dns", "tcp", "tls", "ttfb", "transfer"], float]] = [
        ("dns", d_dns),
        ("tcp", d_tcp),
        ("tls", d_tls),
        ("ttfb", d_ttfb),
        ("transfer", d_transfer),
    ]

    dominant_phase: str | None = None
    max_duration = 0.0
    for p_name, p_dur in raw_phases:
        if p_dur > max_duration:
            max_duration = p_dur
            dominant_phase = p_name

    cursor = 0.0
    phases_list: list[PhaseOffset] = []
    for p_name, p_dur in raw_phases:
        start = round(cursor, 2)
        end = round(cursor + p_dur, 2)
        cursor = end
        phases_list.append(
            PhaseOffset(
                phase=p_name,
                label=PHASE_LABELS[p_name],
                start_ms=start,
                duration_ms=p_dur,
                end_ms=end,
                slo_status=_classify_phase_slo(p_name, p_dur),
                is_dominant=(p_name == dominant_phase and p_dur > 0.0),
            )
        )

    total_ms = round(d_dns + d_tcp + d_tls + d_ttfb + d_transfer, 2)
    estimated_rtt = d_tcp if d_tcp > 0 else (d_tls / 2.0 if d_tls > 0 else 0.0)
    server_processing = max(0.0, round(d_ttfb - estimated_rtt, 2))

    return TimingBreakdown(
        dns_ms=d_dns,
        tcp_ms=d_tcp,
        tls_ms=d_tls,
        ttfb_ms=d_ttfb,
        transfer_ms=d_transfer,
        total_ms=total_ms,
        dominant_phase=dominant_phase,
        phases=phases_list,
        estimated_rtt_ms=round(estimated_rtt, 2),
        server_processing_ms=server_processing,
        reference_sample=reference_sample,
    )


class PhasePercentiles(BaseModel):
    p50_ms: float = 0.0
    p95_ms: float = 0.0
    p99_ms: float = 0.0
    min_ms: float = 0.0
    max_ms: float = 0.0
    mean_ms: float = 0.0
    jitter_ms: float = 0.0


class SampleMeasurement(BaseModel):
    sample_index: int
    connection_reused: bool = False
    status_code: int | None = None
    timings: TimingBreakdown = Field(default_factory=TimingBreakdown)


class SamplingStats(BaseModel):
    samples_count: int = 1
    headline_total_ms: float = 0.0
    headline_label: str = "Latência Total (Mediana P50)"
    cold_total_ms: float = 0.0
    warm_avg_total_ms: float | None = None
    p50_ms: float = 0.0
    p95_ms: float = 0.0
    p99_ms: float = 0.0
    min_ms: float = 0.0
    max_ms: float = 0.0
    mean_ms: float = 0.0
    stdev_ms: float = 0.0
    jitter_ms: float = 0.0
    # Regra de n do MELHORIAS.txt: P95 só com n >= 20, P99 só com n >= 100
    p95_valid: bool = False
    p99_valid: bool = False
    sample_size_notice: str | None = None
    phase_stats: dict[str, PhasePercentiles] = Field(default_factory=dict)
    raw_samples: list[SampleMeasurement] = Field(default_factory=list)


class RedirectHop(BaseModel):
    hop: int
    url: str
    target_url: str | None = None
    resolved_ip: str | None = None
    status_code: int
    location: str | None = None
    protocol: str | None = None
    timings: TimingBreakdown = Field(default_factory=TimingBreakdown)


class X509ChainLink(BaseModel):
    """Informações detalhadas de cada certificado na cadeia X.509."""
    common_name: str | None = None
    organization: str | None = None
    issuer: str | None = None
    not_before: datetime | None = None
    expires_at: datetime | None = None
    days_remaining: int | None = None
    serial_number: str | None = None
    fingerprint_sha256: str | None = None


class TLSInspection(BaseModel):
    valid: bool = False
    protocol: str | None = None
    deprecated_protocol: bool = False
    tls10_11_accepted: bool = False
    cipher: str | None = None
    cipher_bits: int | None = None
    issuer: str | None = None
    subject: str | None = None
    serial_number: str | None = None
    fingerprint_sha256: str | None = None
    not_before: datetime | None = None
    expires_at: datetime | None = None
    days_remaining: int | None = None
    total_validity_days: int | None = None
    relative_validity_percent_remaining: float | None = None
    alert_expiring: bool = False
    alert_relative_expiring: bool = False
    sans: list[str] = Field(default_factory=list)
    cert_chain: list[str] = Field(default_factory=list)
    cert_chain_details: list[X509ChainLink] = Field(default_factory=list)
    ocsp_stapling: bool = False
    ocsp_status: str = "Não detectado"


class CookieAuditItem(BaseModel):
    name: str
    secure: bool = False
    httponly: bool = False
    samesite: str | None = None
    issues: list[str] = Field(default_factory=list)


class CORSInspection(BaseModel):
    tested: bool = False
    status: str = "Não testado"
    reflects_origin: bool = False
    wildcard: bool = False
    allow_credentials: bool = False
    vulnerable: bool = False
    details: str = ""


class SecurityFinding(BaseModel):
    id: str = ""
    header: str
    category: str = "header"
    severity: Literal["critical", "high", "medium", "low", "info"] = "medium"
    weight: int
    description: str
    remediation: str
    snippets: dict[str, str] = Field(default_factory=dict)
    progressive_steps: list[dict[str, str]] = Field(default_factory=list)
    safe_default: str | None = None


class SecurityAudit(BaseModel):
    grade: Literal["A+", "A", "B", "C", "D", "F"] = "F"
    score: int = Field(default=0, ge=0, le=100)
    ruleset: str = "v3"
    # Pontuações separadas por dimensão (Seção 1.4 do MELHORIAS.txt)
    transport_score: int = Field(default=0, ge=0, le=40)
    headers_score: int = Field(default=0, ge=0, le=40)
    hygiene_score: int = Field(default=0, ge=0, le=20)
    present_headers: dict[str, str] = Field(default_factory=dict)
    missing_findings: list[SecurityFinding] = Field(default_factory=list)
    leaked_tech: list[str] = Field(default_factory=list)
    cookies_audited: list[CookieAuditItem] = Field(default_factory=list)
    cors_wildcard: bool = False
    cors_audit: CORSInspection = Field(default_factory=CORSInspection)
    hsts_max_age: int | None = None
    hsts_include_subdomains: bool = False
    hsts_preload_opt_in: bool = False
    hsts_affected_sans: list[str] = Field(default_factory=list)
    csp_frame_ancestors: bool = False
    permissions_camera_restricted: bool = False


class ContentAssertionsResult(BaseModel):
    passed: bool = True
    failures: list[str] = Field(default_factory=list)


class ProbeResult(BaseModel):
    target_url: str
    final_url: str | None = None
    resolved_ip: str | None = None
    all_resolved_ips: list[str] = Field(default_factory=list)
    dns_resolver: str | None = None
    probe_origin: str = "Sonda Local"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_up: bool = False
    http_version: str | None = None
    status_code: int | None = None
    redirect_hops: int = 0
    redirect_chain: list[RedirectHop] = Field(default_factory=list)
    http_port_80_status: str | None = None
    timings: TimingBreakdown = Field(default_factory=TimingBreakdown)
    sampling: SamplingStats = Field(default_factory=SamplingStats)
    tls: TLSInspection | None = None
    security: SecurityAudit = Field(default_factory=SecurityAudit)
    assertions: ContentAssertionsResult = Field(default_factory=ContentAssertionsResult)
    common_mode_failure_warning: str | None = None
    payload_bytes: int = 0
    payload_truncated: bool = False
    http2_supported: bool = False
    http3_alt_svc: str | None = None
    compression: str | None = None
    history_ms: list[float] = Field(default_factory=list)
    error: str | None = None