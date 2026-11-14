import os

# Nenhum teste pode depender (nem vazar) o .env do desenvolvedor.
os.environ["ANHANGA_ENV_FILE"] = os.devnull

import pytest

from anhanga.engine.models import (
    PhasePercentiles,
    ProbeResult,
    SamplingStats,
    SecurityAudit,
    TLSInspection,
    build_timing_breakdown,
)


def make_result(
    url: str = "https://t.example",
    *,
    up: bool = True,
    status: int | None = 200,
    error: str | None = None,
    tls_valid: bool = True,
    tls_days: int = 90,
    ttfb_ms: float = 50.0,
    total_ms: float = 120.0,
    grade: str = "A",
    samples: int = 1,
    ttfb_p50: float | None = None,
) -> ProbeResult:
    timings = build_timing_breakdown(dns_ms=10, tcp_ms=20, tls_ms=20, ttfb_ms=ttfb_ms, transfer_ms=total_ms - 50 - ttfb_ms)
    sampling = SamplingStats(samples_count=samples, headline_total_ms=total_ms)
    if ttfb_p50 is not None:
        sampling.phase_stats["ttfb"] = PhasePercentiles(p50_ms=ttfb_p50)
    tls = None
    if url.startswith("https://") and status is not None:
        tls = TLSInspection(
            valid=tls_valid,
            validation_error=None if tls_valid else "certificate has expired",
            days_remaining=tls_days,
            alert_expiring=tls_days < 15,
        )
    return ProbeResult(
        target_url=url,
        final_url=url if status is not None else None,
        is_up=up,
        status_code=status,
        error=error,
        timings=timings,
        sampling=sampling,
        tls=tls,
        security=SecurityAudit(grade=grade, score=80),
    )


@pytest.fixture
def mk():
    return make_result
