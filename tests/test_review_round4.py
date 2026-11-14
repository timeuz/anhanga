"""Lote 5 (4ª revisão). Cada teste falhava antes da sua correção."""

import asyncio
import time

import pytest

from anhanga.engine import probe as P
from anhanga.engine import revocation as R
from anhanga.engine import security as S
from anhanga.engine import webhooks as W
from anhanga.engine.models import RevocationInspection, classify_error_message
from anhanga.metrics import exporter as E


# ---- 1. `_ssl.c` só conta como marcador de TLS no formato real "(_ssl.c:NNNN)" ----------------------------------------
def test_hostname_containing_ssl_c_is_not_a_tls_error():
    msg = "Erro HTTP/Conexão: [Errno -2] Name or service not known: my_ssl.cdn.example"
    assert classify_error_message(msg) != "tls_error"


def test_real_ssl_c_suffix_is_still_a_tls_error():
    assert classify_error_message("Erro HTTP/Conexão: [SSL] unknown error (_ssl.c:2406)") == "tls_error"
    assert classify_error_message("EOF occurred in violation of protocol (_ssl.c:2406)") == "tls_error"


# ---- 2. exceção CSRF aceita prefixos __Host-/__Secure- e '_' inicial --------------------------------------------------------
@pytest.mark.parametrize("name", ["__Host-csrf-token", "__Secure-XSRF-TOKEN", "_csrf_token", "__Host-X-CSRF-TOKEN"])
def test_prefixed_double_submit_names_are_exempt(name):
    assert not S._is_sensitive_cookie(name)


@pytest.mark.parametrize("name", ["_csrf", "__Host-session", "csrf_session", "__Secure-auth_token"])
def test_prefixes_do_not_open_the_exemption_for_secrets(name):
    assert S._is_sensitive_cookie(name)


# ---- 3. mensagem de timeout cita sempre o prazo total ---------------------------------------------------------------------
def test_first_pass_timeout_message_reports_the_overall_deadline(monkeypatch):
    async def hang(**kw):
        await asyncio.sleep(30)

    monkeypatch.setattr(P, "_run_probe_session", hang)
    monkeypatch.setattr(P, "_normalize_and_validate_scheme", lambda u: (u, None))
    orig = asyncio.wait_for

    async def fast_wait_for(aw, timeout):  # não esperar 9,5 s de verdade
        return await orig(aw, timeout=0.05)

    monkeypatch.setattr(P.asyncio, "wait_for", fast_wait_for)
    r = asyncio.run(P.execute_probe("https://hang.test/", timeout=0.5))
    assert r.error_code == "timeout"
    assert "(9.5s)" in r.error and "(0.5s)" not in r.error, r.error


# ---- 4. recuperação nunca mostra "Alvo OFFLINE" ao lado de RECUPERADO ---------------------------------------------------------
def test_recovery_payload_does_not_get_an_offline_line(mk):
    res = mk("https://t.example", up=False, status=500, error="HTTP 500")
    out = W._collect_violations(res, ["Latência: resolvido"], "recovery")
    assert out == ["Latência: resolvido"]


# ---- 5. fila de revogação com teto e espera limitada -----------------------------------------------------------------------
def test_revocation_queue_has_a_cap_and_fails_fast(monkeypatch):
    R.clear_caches()
    monkeypatch.setattr(R, "MAX_QUEUED_CHECKS", 3)

    async def slow(*a, **k):
        await asyncio.sleep(0.3)
        return RevocationInspection(status="good", method="crl")

    monkeypatch.setattr(R, "_check_uncached", slow)

    async def scenario():
        ders = [[b"\x30\x03\x02\x01" + bytes([i])] for i in range(8)]
        t0 = time.monotonic()
        out = await asyncio.gather(*(R.check_revocation(d, deadline=2.0) for d in ders))
        return out, time.monotonic() - t0, len(R._inflight)

    out, elapsed, left = asyncio.run(scenario())
    full = [o for o in out if "fila de verificação cheia" in (o.detail or "")]
    assert len(full) == 5, [o.detail for o in out]
    assert all(o.status == "unavailable" for o in full)
    R.clear_caches()


def test_revocation_slot_wait_is_bounded_and_not_cached(monkeypatch):
    R.clear_caches()
    monkeypatch.setattr(R, "MAX_CONCURRENT_CHECKS", 1)
    monkeypatch.setattr(R, "QUEUE_WAIT_SECONDS", 0.2)
    calls = []

    async def slow(chain, **k):
        calls.append(chain[0])
        await asyncio.sleep(0.6)
        return RevocationInspection(status="good", method="crl")

    monkeypatch.setattr(R, "_check_uncached", slow)
    a, b = [b"\x30\x03\x02\x01A"], [b"\x30\x03\x02\x01B"]

    async def scenario():
        ra, rb = await asyncio.gather(R.check_revocation(a, deadline=2.0), R.check_revocation(b, deadline=2.0))
        return ra, rb, await R.check_revocation(b, deadline=2.0)  # B desistiu da fila: não pode estar em cache

    ra, rb, again = asyncio.run(scenario())
    assert ra.status == "good"
    assert rb.status == "unavailable" and "saturada" in rb.detail, "a espera pela vaga não tem limite"
    assert again.status == "good" and len(calls) == 2, "B deveria ter desistido na 1ª rodada e rodado só na 2ª"
    R.clear_caches()


# ---- 6. single-flight não entrega a cadeia do certificado antigo a quem já tem o novo -------------------------------------------
def test_extras_joiner_with_a_renewed_leaf_does_not_receive_the_old_chain(monkeypatch):
    S.clear_extras_cache()

    async def fake(ip, port, host, timeout=4.0):
        await asyncio.sleep(0.2)
        return [b"OLD-LEAF", b"CA"], True

    monkeypatch.setattr(S, "_fetch_tls_extras_uncached", fake)

    async def scenario():
        first = asyncio.ensure_future(S.fetch_tls_extras("203.0.113.1", 443, "r.test", timeout=2.0, expected_leaf=b"OLD-LEAF"))
        await asyncio.sleep(0.05)
        joined = await S.fetch_tls_extras("203.0.113.1", 443, "r.test", timeout=2.0, expected_leaf=b"NEW-LEAF")
        return await first, joined

    first, joined = asyncio.run(scenario())
    assert first == ([b"OLD-LEAF", b"CA"], True)
    assert joined == ([], None), "o joiner recebeu a cadeia do certificado antigo"
    S.clear_extras_cache()


# ---- 7. asserção não avaliada vira métrica e log (não só linha na UI) --------------------------------------------------------------
def test_not_evaluated_assertion_increments_a_counter(mk):
    res = mk("https://na.example", up=True, status=200)
    res.assertions.not_evaluated = ["fail_if_body_not_matches_regexp: avaliador de regex indisponível (x)"]
    before = E.PROBE_ASSERTIONS_NOT_EVALUATED_TOTAL.labels(target="https://na.example")._value.get()
    E.record_probe_metrics(res)
    after = E.PROBE_ASSERTIONS_NOT_EVALUATED_TOTAL.labels(target="https://na.example")._value.get()
    assert after == before + 1


def test_not_evaluated_assertion_logs_a_warning(monkeypatch, caplog):
    async def unavailable(pattern, body):
        return "unavailable", "fork falhou"

    monkeypatch.setattr(P, "_regex_search", unavailable)
    import logging

    with caplog.at_level(logging.WARNING, logger="anhanga.probe"):
        asyncio.run(P._evaluate_content_assertions("body", 4, "https://x/", fail_if_body_not_matches_regexp="a"))
    assert any("não avaliada" in r.message for r in caplog.records)


# ---- 8. TimeoutError() sem texto é truthy: a mensagem não pode terminar vazia ("(19.0s): ") ------------------------------
def test_timeout_message_never_ends_with_an_empty_reason(monkeypatch):
    async def hang(**kw):
        await asyncio.sleep(30)

    monkeypatch.setattr(P, "_run_probe_session", hang)
    monkeypatch.setattr(P, "_normalize_and_validate_scheme", lambda u: (u, None))
    orig = asyncio.wait_for

    async def fast_wait_for(aw, timeout):
        return await orig(aw, timeout=0.05)

    monkeypatch.setattr(P.asyncio, "wait_for", fast_wait_for)
    r = asyncio.run(P.execute_probe("https://hang.test/", timeout=0.5))
    assert not r.error.rstrip().endswith(":"), repr(r.error)
    assert "limite de tempo esgotado" in r.error
