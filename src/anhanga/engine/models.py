from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field

class TimingBreakdown(BaseModel):
    dns_ms: float = 0.0
    tcp_ms: float = 0.0
    tls_ms: float = 0.0
    ttfb_ms: float = 0.0
    transfer_ms: float = 0.0
    total_ms: float = 0.0

class TLSInspection(BaseModel):
    valid: bool = False
    protocol: str | None = None
    cipher: str | None = None
    issuer: str | None = None
    subject: str | None = None
    expires_at: datetime | None = None
    days_remaining: int | None = None
    alert_expiring: bool = False

class SecurityFinding(BaseModel):
    header: str
    weight: int
    description: str
    remediation: str

class SecurityAudit(BaseModel):
    grade: Literal["A+", "A", "B", "C", "D", "F"] = "F"
    score: int = Field(default=0, ge=0, le=100)
    present_headers: dict[str, str] = {}
    missing_findings: list[SecurityFinding] = []
    leaked_tech: list[str] = []

class ProbeResult(BaseModel):
    target_url: str
    final_url: str | None = None
    resolved_ip: str | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    is_up: bool = False
    http_version: str | None = None
    status_code: int | None = None
    redirect_hops: int = 0
    timings: TimingBreakdown = Field(default_factory=TimingBreakdown)
    tls: TLSInspection | None = None
    security: SecurityAudit = Field(default_factory=SecurityAudit)
    error: str | None = None