"""Lote 3 da 2ª revisão: mensagens duplicadas, s_client sem cache/limite, cookies CSRF, retry/classificação de erros."""

import asyncio
import time

import httpx
import pytest

from anhanga.engine import probe as P
from anhanga.engine import security as S
from anhanga.engine import webhooks as W
from anhanga.engine.alerting import detect_problems
from anhanga.engine.models import classify_error_message


# ---- 1. mensagens de TLS não se duplicam nos payloads ---------------------------------------------------------
def _msgs(mk, **kw):
    """Mensagens que o AlertManager enviaria + as que o payload monta a partir delas."""
    res = mk(**kw)
    from anhanga.engine.config import SLORules

    manager_msgs = list(detect_problems(res, SLORules()).values())
    return res, manager_msgs


def test_invalid_cert_line_not_duplicated(mk):
    res, msgs = _msgs(mk, tls_valid=False)
    assert any("Certificado TLS inválido" in m for m in msgs)
    out = W._collect_violations(res, msgs, "alert")
    assert sum("Certificado TLS inválido" in m for m in out) == 1


def test_expiring_cert_line_not_duplicated_despite_different_wording(mk):
    res, msgs = _msgs(mk, tls_days=5)
    assert any("expira em 5 dias" in m for m in msgs)
    out = W._collect_violations(res, msgs, "alert")
    assert sum("TLS" in m and "5 dias" in m for m in out) == 1, out


@pytest.mark.parametrize("event", ["recovery", "reminder"])
def test_recovery_and_reminder_add_nothing_from_current_state(mk, event):
    res = mk(tls_valid=False, tls_days=-3)
    assert W._collect_violations(res, ["Certificado TLS inválido: resolvido"], event) == ["Certificado TLS inválido: resolvido"]


def test_standalone_use_still_completes_from_state(mk):
    out = W._collect_violations(mk(tls_valid=False, tls_days=-10))
    assert any("inválido" in x for x in out) and any("expirado há 10" in x for x in out)


# ---- 2. fetch_tls_extras: cache e limite de concorrência -------------------------------------------------------
def test_extras_cached_and_invalidated_on_renewal(monkeypatch):
    S.clear_extras_cache()
    calls = []

    async def fake(ip, port, host, timeout=4.0):
        calls.append(host)
        return [b"LEAF-" + str(len(calls)).encode(), b"CA"], True

    monkeypatch.setattr(S, "_fetch_tls_extras_uncached", fake)

    async def scenario():
        a = await S.fetch_tls_extras("203.0.113.1", 443, "a.test", expected_leaf=b"LEAF-1")
        b = await S.fetch_tls_extras("203.0.113.1", 443, "a.test", expected_leaf=b"LEAF-1")  # cache
        c = await S.fetch_tls_extras("203.0.113.1", 443, "a.test", expected_leaf=b"LEAF-2")  # renovado (o servidor passa a enviar LEAF-2)
        return a, b, c

    a, b, c = asyncio.run(scenario())
    assert a == b and len(calls) == 2 and c[0][0] == b"LEAF-2"
    S.clear_extras_cache()


def test_extras_failures_are_not_cached(monkeypatch):
    S.clear_extras_cache()
    calls = []

    async def fake(ip, port, host, timeout=4.0):
        calls.append(1)
        return [], None

    monkeypatch.setattr(S, "_fetch_tls_extras_uncached", fake)

    async def scenario():
        await S.fetch_tls_extras("203.0.113.1", 443, "a.test")
        await S.fetch_tls_extras("203.0.113.1", 443, "a.test")

    asyncio.run(scenario())
    assert len(calls) == 2
    S.clear_extras_cache()


def test_extras_concurrency_is_bounded(monkeypatch):
    S.clear_extras_cache()
    running = {"now": 0, "max": 0}

    async def fake(ip, port, host, timeout=4.0):
        running["now"] += 1
        running["max"] = max(running["max"], running["now"])
        await asyncio.sleep(0.05)
        running["now"] -= 1
        return [b"X" + host.encode()], None

    monkeypatch.setattr(S, "_fetch_tls_extras_uncached", fake)

    async def scenario():
        await asyncio.gather(*(S.fetch_tls_extras("203.0.113.1", 443, f"h{i}.test") for i in range(40)))

    asyncio.run(scenario())
    assert running["max"] <= S.EXTRAS_MAX_CONCURRENCY, running
    S.clear_extras_cache()


# ---- 3. cookies CSRF e regex inválida --------------------------------------------------------------------------
def test_csrf_double_submit_cookies_do_not_require_httponly():
    h = httpx.Headers([("set-cookie", "XSRF-TOKEN=abc; Path=/; Secure; SameSite=Lax"),
                       ("set-cookie", "csrftoken=abc; Path=/; Secure; SameSite=Lax"),
                       ("set-cookie", "sessionid=abc; Path=/; Secure; SameSite=Lax")])
    by = {c.name: c for c in S._audit_cookies(h, True)}
    assert not by["XSRF-TOKEN"].sensitive and not by["csrftoken"].sensitive
    assert not any("HttpOnly" in i for i in by["XSRF-TOKEN"].issues + by["csrftoken"].issues)
    assert by["sessionid"].sensitive and any("HttpOnly" in i for i in by["sessionid"].issues)


def test_invalid_operator_regex_does_not_break_import():
    """Import REAL em processo separado: antes, re.error no import derrubava o módulo (e a app inteira)."""
    import os
    import subprocess
    import sys

    out = subprocess.run(
        [sys.executable, "-c", "import anhanga.engine.security as s; print(s._is_sensitive_cookie('sessionid'))"],
        env={**os.environ, "ANHANGA_SENSITIVE_COOKIE_REGEX": "([unclosed"}, capture_output=True, text=True, timeout=60,
    )
    assert out.returncode == 0, out.stderr[-400:]
    assert out.stdout.strip() == "True" and "ANHANGA_SENSITIVE_COOKIE_REGEX inválida" in out.stderr


def test_valid_operator_regex_is_used():
    rx, custom = S._compile_sensitive_cookie_regex("^mycookie$")
    assert custom and rx.search("MYCOOKIE") and not rx.search("sessionid")


# ---- 4. classificação de erros por marcador, não por substring --------------------------------------------------
@pytest.mark.parametrize("msg", [
    "Erro HTTP/Conexão: [Errno 111] Connection refused to classless.example",
    "Erro HTTP/Conexão: All connection attempts failed (tls-proxy.example:443)",
    "Erro HTTP/Conexão: ssl.example.com unreachable",
])
def test_hostnames_with_tls_words_are_not_tls_errors(msg):
    assert classify_error_message(msg) == "connect_error"


@pytest.mark.parametrize("msg", [
    "Erro HTTP/Conexão: [SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure",
    "Erro HTTP/Conexão: falha no handshake TLS (servidor aceita apenas: TLSv1). Detalhe: x",
    "Erro HTTP/Conexão: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed",
    "Erro HTTP/Conexão: [SSL: WRONG_VERSION_NUMBER] wrong version number",
])
def test_real_tls_errors_still_classified(msg):
    assert classify_error_message(msg) == "tls_error"


def test_failure_result_maps_timeout_and_ssrf_like_the_first_pass():
    r = P._failure_result("https://x.test", asyncio.TimeoutError(), 5.0)
    assert r.error.startswith("Timeout rígido excedido (5.0s)") and r.error_code == "timeout"
    assert P._failure_result("https://x.test", httpx.ReadTimeout("slow"), 5.0).error_code == "timeout"
    s = P._failure_result("https://x.test", P.SSRFBlockedError("10.0.0.1", "Bloqueado pelo Guardião Anti-SSRF: x"), 5.0)
    assert s.error_code == "ssrf_blocked" and s.resolved_ip == "10.0.0.1"
    assert P._failure_result("https://x.test", ValueError("x"), 5.0) is None


def test_invalid_cert_retry_timeout_is_a_timeout_and_respects_total_budget(monkeypatch):
    """Cert inválido + retry lento: 504/timeout (não 502 com mensagem vazia) e sem dobrar o prazo total."""
    import ssl

    calls = []

    async def fake_session(**kw):
        calls.append(kw["verify_ssl"])
        if kw["verify_ssl"]:
            await asyncio.sleep(4.0)  # o 1º passe gasta parte do prazo antes de falhar na verificação
            raise ssl.SSLCertVerificationError("certificate verify failed: self-signed certificate")
        await asyncio.sleep(30)

    monkeypatch.setattr(P, "_run_probe_session", fake_session)
    monkeypatch.setattr(P, "_normalize_and_validate_scheme", lambda u: (u, None))
    t0 = time.monotonic()
    # timeout=0.5 => overall_timeout = 9.5 s. 1º passe gasta 4 s; o retry só pode usar os ~5.5 s restantes
    # (total ≈ 9.5 s). Com o prazo cheio no retry seriam 4 + 9.5 = 13.5 s.
    r = asyncio.run(asyncio.wait_for(P.execute_probe("https://self-signed.test/", timeout=0.5), timeout=20))
    elapsed = time.monotonic() - t0
    assert calls == [True, False]
    assert r.error_code == "timeout" and "Timeout rígido" in r.error
    assert elapsed < 11.5, f"retry dobrou o prazo total ({elapsed:.1f}s)"
