import asyncio
import json
import socket
import time
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
import httpx
import pytest

from anhanga.cli import SARIF_SCHEMA_URI, main
from anhanga.engine.models import (
    ProbeResult,
    SampleMeasurement,
    TLSInspection,
    build_timing_breakdown,
)
from anhanga.engine.probe import (
    InstrumentedPinnedNetworkBackend,
    SSRFBlockedError,
    _build_sampling_stats,
    _compute_jitter,
    _percentile,
    execute_probe,
    resolve_and_validate_host,
)
from anhanga.engine.security import (
    RATE_LIMITER,
    SlidingWindowRateLimiter,
    audit_http_security,
    is_ssrf_safe,
)
from anhanga.engine.webhooks import build_telegram_payload
from anhanga.main import HISTORY_CACHE, STATE_CACHE, app
from anhanga.metrics.exporter import record_probe_metrics

client = TestClient(app)


@pytest.fixture(autouse=True)
def _clean_global_state():
    STATE_CACHE.clear()
    HISTORY_CACHE.clear()
    RATE_LIMITER.reset()


def test_statistical_calculations_p50_p95_p99_jitter_and_cold_vs_warm():
    """
    Valida a precisão matemática dos percentis (P50, P95, P99), jitter_ms e separação
    entre conexão fria (amostra 1) e conexões quentes/reaproveitadas (amostras 2..N).
    """
    raw_totals = [200.0, 100.0, 110.0, 90.0, 120.0]
    samples = []
    for idx, total_val in enumerate(raw_totals, start=1):
        reused = idx > 1
        tb = build_timing_breakdown(
            dns_ms=20.0 if not reused else 0.0,
            tcp_ms=30.0 if not reused else 0.0,
            tls_ms=50.0 if not reused else 0.0,
            ttfb_ms=total_val - (110.0 if not reused else 10.0),
            transfer_ms=10.0,
        )
        assert tb.total_ms == total_val
        samples.append(
            SampleMeasurement(
                sample_index=idx,
                connection_reused=reused,
                status_code=200,
                timings=tb,
            )
        )

    stats = _build_sampling_stats(samples)
    assert stats.samples_count == 5
    assert stats.cold_total_ms == 200.0
    # Média das amostras quentes (100, 110, 90, 120) = 105.0
    assert stats.warm_avg_total_ms == 105.0
    assert stats.min_ms == 90.0
    assert stats.max_ms == 200.0
    assert stats.mean_ms == 124.0

    # Ordenados: [90.0, 100.0, 110.0, 120.0, 200.0]
    assert stats.p50_ms == 110.0
    assert stats.p95_ms == _percentile([90.0, 100.0, 110.0, 120.0, 200.0], 95.0)
    assert stats.p95_ms == 184.0
    assert stats.p99_ms == _percentile([90.0, 100.0, 110.0, 120.0, 200.0], 99.0)
    assert stats.p99_ms == 196.8

    # Jitter: média das diferenças absolutas consecutivas:
    # |100-200|=100, |110-100|=10, |90-110|=20, |120-90|=30 -> (100+10+20+30)/4 = 40.0
    assert _compute_jitter(raw_totals) == 40.0
    assert stats.jitter_ms == 40.0


@pytest.mark.asyncio
async def test_ssrf_dns_rebinding_single_resolution_and_malicious_redirect_to_admin():
    """
    Valida:
    1. Bloqueio de todos os vetores SSRF exigidos (Loopback, RFC1918, Link-Local, CGNAT, ULA,
       IPv4-mapped ::ffff:127.0.0.1, 6to4, Teredo e esquemas proibidos file:// e gopher://).
    2. Prevenção de DNS Rebinding (resolução única por salto + IP pinning no backend de rede).
    3. Bloqueio de redirect malicioso (302 -> http://127.0.0.1/admin) com allow_private=False.
    """
    for blocked_ip in (
        "127.0.0.1",
        "::1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "fe80::1%eth0",
        "100.64.0.1",
        "fd00::1",
        "::ffff:127.0.0.1",
        "2002:7f00:0001::1",
        "2001:0000:4136:e378:8000:63bf:3fff:fdd2",
    ):
        assert is_ssrf_safe(blocked_ip, allow_private=False) is False

    for bad_scheme_url in ("file:///etc/shadow", "gopher://127.0.0.1:6379/_INFO"):
        res_scheme = await execute_probe(bad_scheme_url, allow_private=False)
        assert res_scheme.is_up is False
        assert "Anti-SSRF" in (res_scheme.error or "")

    # Simulação de tentativa de DNS Rebinding:
    # Se um domínio retornar simultaneamente um IP público e um IP privado (ou mudar no segundo lookup),
    # resolve_and_validate_host rejeita se qualquer registro for privado e fixa o IP resolvido no backend.
    loop = asyncio.get_running_loop()
    rebinding_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80)),
    ]
    with patch.object(
        loop, "getaddrinfo", new=AsyncMock(return_value=rebinding_addrinfo)
    ):
        with pytest.raises(SSRFBlockedError):
            await resolve_and_validate_host("rebind.attacker.example", 80, allow_private=False)

    # Verifica IP Pinning no InstrumentedPinnedNetworkBackend (não re-resolve o hostname no connect_tcp)
    backend = InstrumentedPinnedNetworkBackend(allow_private=False)
    backend.pinned_ips["trusted.example.com"] = "127.0.0.1"
    with pytest.raises(SSRFBlockedError):
        await backend.connect_tcp("trusted.example.com", 80)

    # Verifica bloqueio de redirect malicioso: 302 -> http://127.0.0.1/admin
    async def _redirect_to_local_admin(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            while True:
                line = await reader.readline()
                if not line or line in (b"\r\n", b"\n"):
                    break
            resp = (
                "HTTP/1.1 302 Found\r\n"
                "Location: http://127.0.0.1/admin\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n\r\n"
            )
            writer.write(resp.encode("latin1"))
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(_redirect_to_local_admin, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        orig_is_safe = is_ssrf_safe
        call_count = 0

        def _allow_first_hop_then_enforce(ip_str: str, allow_private: bool = False) -> bool:
            nonlocal call_count
            call_count += 1
            # Permite apenas o 1º salto (3 checagens: literal IP check, getaddrinfo check e connect_tcp)
            if call_count <= 3 and ip_str == "127.0.0.1":
                return True
            return orig_is_safe(ip_str, allow_private)

        with patch(
            "anhanga.engine.probe.is_ssrf_safe",
            side_effect=_allow_first_hop_then_enforce,
        ):
            res_redir = await execute_probe(
                f"http://127.0.0.1:{port}/start", allow_private=False
            )
            assert res_redir.is_up is False
            assert res_redir.redirect_hops == 1
            assert res_redir.redirect_chain[0].location == "http://127.0.0.1/admin"
            assert "Anti-SSRF" in (res_redir.error or "")
            assert res_redir.resolved_ip == "127.0.0.1"
    finally:
        server.close()
        await server.wait_closed()


def test_security_audit_multiple_cookies_samesite_none_and_hsts_without_preload():
    """
    Valida:
    - HSTS progressivo (max-age=2592000) atingindo 100/100 e nota A+ sem exigir preload.
    - Equivalência CSP frame-ancestors para X-Frame-Options.
    - Permissions-Policy camera=().
    - Múltiplos cabeçalhos Set-Cookie, incluindo detecção de SameSite=None sem Secure.
    - CORS wildcard com Access-Control-Allow-Credentials: true e vazamentos Server/X-Powered-By.
    """
    valid_tls = TLSInspection(valid=True, protocol="TLSv1.3")

    # 1. Endpoint seguro com HSTS 30 dias (sem preload) e CSP frame-ancestors (sem X-Frame-Options)
    secure_headers = httpx.Headers(
        [
            ("Strict-Transport-Security", "max-age=2592000; includeSubDomains"),
            ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
            ("Permissions-Policy", "camera=(), microphone=()"),
            ("Set-Cookie", "auth=ok; Secure; HttpOnly; SameSite=Strict"),
        ]
    )
    audit_ok = audit_http_security(secure_headers, is_https=True, tls=valid_tls)
    assert audit_ok.score == 100
    assert audit_ok.grade == "A+"
    assert audit_ok.hsts_preload_opt_in is False
    assert audit_ok.csp_frame_ancestors is True
    assert audit_ok.permissions_camera_restricted is True
    assert len(audit_ok.missing_findings) == 0
    assert len(audit_ok.cookies_audited) == 1
    assert audit_ok.cookies_audited[0].issues == []

    # 2. Múltiplos Set-Cookie com SameSite=None sem Secure + CORS wildcard + Server/X-Powered-By
    multi_cookie_headers = httpx.Headers(
        [
            ("Strict-Transport-Security", "max-age=2592000; includeSubDomains"),
            ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
            ("Permissions-Policy", "camera=()"),
            ("Set-Cookie", "session=1; Secure; HttpOnly; SameSite=Lax"),
            ("Set-Cookie", "cross_track=2; HttpOnly; SameSite=None"),
            ("Access-Control-Allow-Origin", "*"),
            ("Access-Control-Allow-Credentials", "true"),
            ("Server", "Apache/2.4.58"),
            ("X-Powered-By", "PHP/8.3"),
        ]
    )
    audit_issues = audit_http_security(
        multi_cookie_headers, is_https=True, tls=valid_tls
    )
    assert len(audit_issues.cookies_audited) == 2
    c1, c2 = audit_issues.cookies_audited
    assert c1.name == "session"
    assert c1.issues == []
    assert c2.name == "cross_track"
    assert "Ausência da flag Secure" in c2.issues
    assert "SameSite=None exige a flag Secure" in c2.issues
    assert audit_issues.cors_wildcard is True
    assert len(audit_issues.leaked_tech) == 2


def test_cross_review_fixes_telegram_html_escape_and_rate_limiter_eviction():
    """
    Valida os 2 ajustes apontados na Revisão Cruzada (Cross-Code-Review):
    1. Escape HTML em URLs com '&' (?a=1&b=2) e violações com '<'/'>' em build_telegram_payload.
    2. Limpeza de chaves expiradas/vazias no SlidingWindowRateLimiter sob ataques de IP spoofing.
    """
    sample = ProbeResult(
        target_url="https://api.example.com/search?a=1&b=2&tag=<script>",
        is_up=False,
        status_code=500,
        http_version="HTTP/1.1",
        timings=build_timing_breakdown(10.0, 15.0, 25.0, 120.0, 5.0),
    )
    tg = build_telegram_payload(
        sample,
        violations=["TTFB > 100ms & < 500ms em ?a=1&b=2"],
        chat_id="123456",
    )
    assert tg["parse_mode"] == "HTML"
    text = tg["text"]
    assert "https://api.example.com/search?a=1&amp;b=2&amp;tag=&lt;script&gt;" in text
    assert "TTFB &gt; 100ms &amp; &lt; 500ms em ?a=1&amp;b=2" in text
    assert "?a=1&b=2" not in text

    # Valida limpeza de chaves expiradas no SlidingWindowRateLimiter contra IP spoofing
    limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=0.05)
    for idx in range(250):
        assert limiter.is_allowed(f"203.0.113.{idx}") is True
    assert len(limiter._hits) == 250

    time.sleep(0.07)
    # Nova checagem após a janela expirar deve limpar todas as 250 chaves antigas
    assert limiter.is_allowed("198.51.100.99") is True
    assert list(limiter._hits.keys()) == ["198.51.100.99"]


def test_end_to_end_prometheus_and_cli_sarif_integration(capsys):
    """
    Valida a integração entre sondagem, métricas Prometheus compatíveis com blackbox_exporter
    e geração de relatório SARIF v2.1.0 pela CLI.
    """
    probe_res = ProbeResult(
        target_url="https://prod.example.com",
        final_url="https://prod.example.com/",
        resolved_ip="93.184.216.34",
        is_up=True,
        http_version="HTTP/2",
        status_code=200,
        redirect_hops=0,
        timings=build_timing_breakdown(10.0, 20.0, 30.0, 50.0, 15.0),
    )
    record_probe_metrics(probe_res)
    metrics_resp = client.get("/metrics")
    assert metrics_resp.status_code == 200
    for phase in ("resolve", "connect", "tls", "processing", "transfer"):
        assert (
            f'probe_http_duration_seconds{{instance="prod.example.com",phase="{phase}",target="https://prod.example.com"}}'
            in metrics_resp.text
        )

    # Verifica bloqueio SSRF na CLI gerando SARIF v2.1.0 válido com exit code 2
    exit_code = main(["check", "http://127.0.0.1:8080/admin", "--format", "sarif"])
    out = capsys.readouterr().out
    assert exit_code == 2
    sarif = json.loads(out)
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"] == SARIF_SCHEMA_URI
    assert sarif["runs"][0]["results"][0]["ruleId"] == "ANHANGA-SSRF-OR-DNS"
