from datetime import datetime, timezone
import re
from typing import Any, Literal
from pydantic import BaseModel, Field, model_validator


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
    # None = indisponível (ex.: TTFB frio em HTTP/2, que embute ~1 RTT de handshake e não mede o servidor)
    server_processing_ms: float | None = 0.0
    reference_sample: str = "Amostra 1 (Conexão Fria)"
    timing_notes: list[str] = Field(default_factory=list)


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
    phase_stats_note: str | None = None
    raw_samples: list[SampleMeasurement] = Field(default_factory=list)


class RedirectHop(BaseModel):
    hop: int
    url: str
    target_url: str | None = None
    resolved_ip: str | None = None
    status_code: int
    location: str | None = None
    protocol: str | None = None
    insecure: bool = False  # hop servido em texto claro (http://)
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


class RevocationInspection(BaseModel):
    """Resultado da checagem de revogação do certificado folha (OCSP ativo, com CRL de fallback)."""

    # good = não revogado; revoked = revogado; unknown = o respondedor não conhece o serial;
    # unavailable = não foi possível checar (sem endpoint/emissor/openssl); error = endpoints falharam.
    status: Literal["good", "revoked", "unknown", "unavailable", "error"] = "unavailable"
    method: Literal["ocsp", "crl"] | None = None
    detail: str | None = None
    revoked_at: datetime | None = None
    responder: str | None = None
    next_update: datetime | None = None


class TLSProtocolResult(BaseModel):
    protocol: str
    status: Literal["accepted", "rejected", "unknown", "untestable"]
    ciphers: list[str] = Field(default_factory=list)
    ciphers_complete: bool = True  # False: lista truncada (teto de handshakes) ou interrompida
    weak_ciphers: list[str] = Field(default_factory=list)
    no_forward_secrecy: list[str] = Field(default_factory=list)


class TLSEnumeration(BaseModel):
    protocols: list[TLSProtocolResult] = Field(default_factory=list)
    tested_at: float | None = None

    def get(self, name: str) -> TLSProtocolResult | None:
        return next((p for p in self.protocols if p.protocol == name), None)


class TLSInspection(BaseModel):
    valid: bool = False
    validation_error: str | None = None  # motivo da falha de validação (expirado, hostname, raiz não confiável…)
    protocol: str | None = None
    deprecated_protocol: bool = False
    tls10_11_accepted: bool = False
    enumeration: TLSEnumeration | None = None
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
    chain_source: str | None = None  # "verificada" | "enviada pelo servidor" | None (indisponível)
    revocation: RevocationInspection | None = None
    ocsp_stapling: bool | None = None  # None = não verificado
    ocsp_status: str = "Não verificado"


class CookieAuditItem(BaseModel):
    name: str
    sensitive: bool = False  # cookie de sessão/autenticação (HttpOnly passa a ser exigido)
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


class CSPIssue(BaseModel):
    id: str
    severity: Literal["high", "medium", "low"]
    directive: str
    message: str


class CSPAnalysis(BaseModel):
    """Qualidade da Content-Security-Policy (não basta existir: 'unsafe-inline' e '*' anulam a proteção)."""

    present: bool = False
    enforced: bool = False  # False = só Report-Only (não bloqueia nada) ou ausente
    strength: Literal["none", "report-only", "weak", "moderate", "strong"] = "none"
    issues: list[CSPIssue] = Field(default_factory=list)
    uses_nonce_or_hash: bool = False
    strict_dynamic: bool = False
    policies: int = 0


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
    evaluated_url: str | None = None  # resposta sobre a qual os cabeçalhos foram avaliados
    csp_analysis: CSPAnalysis | None = None


class ContentAssertionsResult(BaseModel):
    passed: bool = True
    failures: list[str] = Field(default_factory=list)
    # Asserções que NÃO puderam ser avaliadas por falha do próprio Anhangá (ex.: o subprocesso do avaliador de
    # regex não subiu). Não são falha do alvo: não reprovam `passed` nem disparam alerta, mas ficam visíveis.
    not_evaluated: list[str] = Field(default_factory=list)


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
    error_code: str | None = None
    # up = HTTP ok e TLS válido; degraded = HTTP ok mas TLS inválido; down = falha
    health: Literal["up", "degraded", "down"] = "down"
    # Tempo total decorrido incluindo todos os hops de redirect (o waterfall mostra só a resposta final)
    end_to_end_ms: float | None = None

    @model_validator(mode="after")
    def _derive_health_and_error_code(self) -> "ProbeResult":
        https_final = bool(self.final_url and self.final_url.lower().startswith("https://")) or (
            self.final_url is None and self.target_url.lower().startswith("https://")
        )
        if not self.is_up:
            self.health = "down"
        elif https_final and self.tls is not None and not self.tls.valid:
            self.health = "degraded"
        else:
            self.health = "up"
        if self.error_code is None:
            if self.error:
                self.error_code = classify_error_message(self.error)
            elif not self.is_up and self.status_code is not None:
                self.error_code = "http_status"
        return self


_TLS_ERROR_MARKERS = (
    "[ssl", "sslerror", "sslcertverificationerror", "certificate verify failed", "certificate_verify_failed",
    "handshake", "tls alert", "ssl/tls alert", "wrong version number", "_ssl.c",
    "eof occurred in violation of protocol", "bad dh value", "unsupported protocol", "certificate has expired",
    "self-signed certificate", "hostname mismatch", "unable to get local issuer",
)
# "tlsv13 alert certificate required", "sslv3 alert handshake failure", "tlsv1.2 alert ...": versão variável
_TLS_ALERT_RE = re.compile(r"\b(?:tls|ssl)v?\d+(?:\.\d+)? alert\b")


def classify_error_message(message: str) -> str:
    """Código estável e legível por máquina para a mensagem de erro de uma sondagem."""
    m = message.lower()
    if m.startswith("bloqueado pelo guardião"):
        return "ssrf_blocked"
    if m.startswith("url inválida"):
        return "invalid_url"
    if m.startswith("erro de dns"):
        return "dns_error"
    if m.startswith("timeout"):
        return "timeout"
    if m.startswith("falha em content assertion"):
        return "assertion_failed"
    if m.startswith("limite máximo de redirecionamentos"):
        return "redirect_loop"
    # Marcadores específicos de erro de TLS, não substring solta: um hostname "classless.example" ou
    # "tls-proxy.example" numa falha de conexão não pode virar `tls_error`.
    if any(k in m for k in _TLS_ERROR_MARKERS) or _TLS_ALERT_RE.search(m):
        return "tls_error"
    if m.startswith("erro http/conexão"):
        return "connect_error"
    return "unknown_error"