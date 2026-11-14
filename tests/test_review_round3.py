"""Lote 4 (3ª revisão): concorrência/prazo, cookies e contratos. Cada teste falhava antes da sua correção."""

import asyncio
import hashlib
import os
import subprocess
import sys
import time

import pytest

from anhanga.engine import probe as P
from anhanga.engine import revocation as R
from anhanga.engine import security as S
from anhanga.engine import tlsenum
from anhanga.engine import webhooks as W
from anhanga.engine.models import RevocationInspection, classify_error_message


# ---- 1. regex de cookie inválida não desliga a exceção CSRF -----------------------------------------------------
def test_invalid_operator_regex_keeps_csrf_exemption():
    code = ("import anhanga.engine.security as s;"
            "print(s._is_sensitive_cookie('csrftoken'), s._is_sensitive_cookie('XSRF-TOKEN'), s._is_sensitive_cookie('sessionid'))")
    out = subprocess.run([sys.executable, "-c", code], env={**os.environ, "ANHANGA_SENSITIVE_COOKIE_REGEX": "([unclosed"},
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr[-300:]
    assert out.stdout.strip() == "False False True", out.stdout


def test_valid_operator_regex_is_taken_literally_even_for_csrf_names():
    out = subprocess.run([sys.executable, "-c", "import anhanga.engine.security as s; print(s._is_sensitive_cookie('csrftoken'))"],
                         env={**os.environ, "ANHANGA_SENSITIVE_COOKIE_REGEX": "csrf"}, capture_output=True, text=True, timeout=60)
    assert out.stdout.strip() == "True"


# ---- 6. exceção CSRF só para nomes de token de double-submit -------------------------------------------------------
@pytest.mark.parametrize("name", ["csrftoken", "XSRF-TOKEN", "X-CSRF-TOKEN", "csrf_token", "xsrf-token"])
def test_double_submit_token_names_are_exempt(name):
    assert not S._is_sensitive_cookie(name)


@pytest.mark.parametrize("name", ["_csrf", "csrf_session", "auth_xsrf_sid", "session_csrf", "sessionid", "jwt"])
def test_session_like_cookies_with_csrf_in_the_name_stay_sensitive(name):
    assert S._is_sensitive_cookie(name)


# ---- 2. semáforo: espera dentro do prazo, degrada, single-flight --------------------------------------------------
def test_extras_queue_wait_counts_toward_the_deadline_and_degrades(monkeypatch):
    S.clear_extras_cache()
    running = {"now": 0, "max": 0}

    async def slow(ip, port, host, timeout=4.0):
        running["now"] += 1
        running["max"] = max(running["max"], running["now"])
        await asyncio.sleep(1.0)
        running["now"] -= 1
        return [b"C" + host.encode()], None

    monkeypatch.setattr(S, "_fetch_tls_extras_uncached", slow)

    async def scenario():
        t0 = time.monotonic()
        out = await asyncio.gather(*(S.fetch_tls_extras("203.0.113.1", 443, f"h{i}.test", timeout=0.6) for i in range(24)))
        return out, time.monotonic() - t0

    async def scenario_and_drain():
        out, elapsed = await scenario()
        await asyncio.sleep(0.5)
        return out, elapsed, dict(S._extras_inflight)

    out, elapsed, leftover = asyncio.run(scenario_and_drain())
    assert elapsed < 1.8, f"a fila prendeu a sondagem por {elapsed:.1f}s (prazo pedido: 0.6s)"
    assert not leftover, "tarefas destacadas continuaram na fila (e rodariam depois) em vez de degradar"
    assert running["max"] <= S.EXTRAS_MAX_CONCURRENCY
    degraded = sum(1 for chain, _ in out if chain == [])
    assert 0 < degraded < 24, "quem não achou vaga deve degradar para ([], None), sem derrubar nem travar os outros"
    S.clear_extras_cache()


def test_extras_single_flight_per_host(monkeypatch):
    S.clear_extras_cache()
    calls = []

    async def fake(ip, port, host, timeout=4.0):
        calls.append(host)
        await asyncio.sleep(0.2)
        return [b"CERT"], True

    monkeypatch.setattr(S, "_fetch_tls_extras_uncached", fake)

    async def scenario():
        return await asyncio.gather(*(S.fetch_tls_extras("203.0.113.1", 443, "same.test", timeout=2.0) for _ in range(20)))

    out = asyncio.run(scenario())
    assert len(calls) == 1 and all(r == ([b"CERT"], True) for r in out)
    S.clear_extras_cache()


# ---- 4. cache fail-closed: leaf desconhecido = miss --------------------------------------------------------------
def test_extras_cache_is_a_miss_when_the_current_leaf_is_unknown(monkeypatch):
    S.clear_extras_cache()
    calls = []

    async def fake(ip, port, host, timeout=4.0):
        calls.append(1)
        return [b"LEAF"], None

    monkeypatch.setattr(S, "_fetch_tls_extras_uncached", fake)

    async def scenario():
        await S.fetch_tls_extras("203.0.113.1", 443, "a.test", expected_leaf=None)
        await S.fetch_tls_extras("203.0.113.1", 443, "a.test", expected_leaf=None)  # getpeercert falhou: não confiar
        await S.fetch_tls_extras("203.0.113.1", 443, "a.test", expected_leaf=b"LEAF")  # conhecido e igual: hit
        await S.fetch_tls_extras("203.0.113.1", 443, "a.test", expected_leaf=b"LEAF")

    asyncio.run(scenario())
    # 2 buscas com leaf desconhecido (nunca confiar no cache); as duas com leaf conhecido e igual são hits.
    # Fail-open (bug) daria 1: a 2ª chamada com leaf desconhecido serviria o cache.
    assert len(calls) == 2
    S.clear_extras_cache()


# ---- 3. revogação em segundo plano: limite, cancelamento, loop herdado ---------------------------------------------
def test_revocation_background_concurrency_is_bounded(monkeypatch):
    R.clear_caches()
    running = {"now": 0, "max": 0}

    async def slow(*a, **k):
        running["now"] += 1
        running["max"] = max(running["max"], running["now"])
        await asyncio.sleep(0.15)
        running["now"] -= 1
        return RevocationInspection(status="good", method="crl")

    monkeypatch.setattr(R, "_check_uncached", slow)

    async def scenario():
        ders = [[b"\x30\x03\x02\x01" + bytes([i])] for i in range(16)]
        return await asyncio.gather(*(R.check_revocation(d, deadline=5.0) for d in ders))

    out = asyncio.run(scenario())
    assert all(r.status == "good" for r in out)
    assert running["max"] <= R.MAX_CONCURRENT_CHECKS, running
    R.clear_caches()


def test_revocation_cancel_background_stops_pending_work(monkeypatch):
    R.clear_caches()
    started = []

    async def forever(*a, **k):
        started.append(1)
        await asyncio.sleep(60)

    monkeypatch.setattr(R, "_check_uncached", forever)

    async def scenario():
        r = await R.check_revocation([b"\x30\x03\x02\x01\x01"], deadline=0.1)  # estoura o orçamento; segue no fundo
        tasks = list(R._inflight.values())
        R.cancel_background()
        await asyncio.sleep(0.1)
        # lido AQUI: `asyncio.run` cancela tudo que sobrar ao encerrar e mascararia um cancel_background quebrado
        return r, tasks, [t.cancelled() for t in tasks]

    r, tasks, cancelled = asyncio.run(scenario())
    assert r.status == "unavailable" and started and tasks and all(cancelled), cancelled
    assert not R._inflight
    R.clear_caches()


def test_revocation_ignores_inflight_future_from_another_event_loop(monkeypatch):
    R.clear_caches()
    der = [b"\x30\x03\x02\x01\x07"]
    other = asyncio.new_event_loop()
    stale = other.create_future()
    other.close()
    R._inflight[hashlib.sha256(der[0]).hexdigest()] = stale

    async def ok(*a, **k):
        return RevocationInspection(status="good", method="ocsp")

    monkeypatch.setattr(R, "_check_uncached", ok)
    assert asyncio.run(R.check_revocation(der, deadline=2.0)).status == "good"
    R.clear_caches()


def test_tls_enumeration_ignores_inflight_future_from_another_event_loop(monkeypatch):
    tlsenum.clear_cache()
    other = asyncio.new_event_loop()
    stale = other.create_future()
    other.close()
    tlsenum._inflight[("loop.test", 443)] = stale
    from anhanga.engine.models import TLSEnumeration

    async def fake(ip, port, host, timeout=3.0, use_cache=True):
        return TLSEnumeration(protocols=[])

    monkeypatch.setattr(tlsenum, "enumerate_tls", fake)
    assert asyncio.run(tlsenum.enumerate_tls_bounded("203.0.113.3", 443, "loop.test", budget=2.0)) is not None
    tlsenum.clear_cache()


# ---- 7. classificação: erros reais de TLS do Python -----------------------------------------------------------------
@pytest.mark.parametrize("msg", [
    "Erro HTTP/Conexão: EOF occurred in violation of protocol (_ssl.c:2406)",
    "Erro HTTP/Conexão: [Errno 104] Connection reset by peer (_ssl.c:2406)",
    "Erro HTTP/Conexão: tlsv13 alert certificate required",
    "Erro HTTP/Conexão: sslv3 alert handshake failure",
    "Erro HTTP/Conexão: tlsv1.2 alert protocol version",
])
def test_real_python_tls_errors_are_tls_error(msg):
    assert classify_error_message(msg) == "tls_error"


@pytest.mark.parametrize("msg", [
    "Erro HTTP/Conexão: connection refused (alert.example:443)",
    "Erro HTTP/Conexão: [Errno 111] Connection refused to tlsv13-alert.example",
])
def test_alert_in_a_hostname_is_not_tls_error(msg):
    assert classify_error_message(msg) == "connect_error"


# ---- 5. avaliador de regex indisponível: não reprova nem alerta ----------------------------------------------------
def test_regex_evaluator_outage_does_not_fail_the_target(monkeypatch):
    monkeypatch.setattr(P, "_regex_worker_argv", lambda: [sys.executable, "-I", "/nonexistent/worker.py"])
    res = asyncio.run(P._evaluate_content_assertions(
        "body", 4, "https://x/", fail_if_body_not_matches_regexp="a", fail_if_body_matches_regexp="b", min_payload_bytes=1))
    assert res.passed and not res.failures
    assert len(res.not_evaluated) == 2
    # as demais asserções continuam valendo
    res2 = asyncio.run(P._evaluate_content_assertions(
        "body", 4, "https://x/", fail_if_body_not_matches_regexp="a", min_payload_bytes=100))
    assert not res2.passed and any("abaixo do mínimo" in f for f in res2.failures) and len(res2.not_evaluated) == 1


# ---- 8. retry: prazo restante, mensagem fiel, sem piso que estoura o total -----------------------------------------
class _Clock:
    """Relógio controlável para `probe.time.monotonic` (o resto do módulo `time` fica intacto)."""

    def __init__(self):
        self.offset = 0.0

    def __getattr__(self, name):
        return getattr(time, name)

    def monotonic(self):
        return time.monotonic() + self.offset


def _retry_scenario(monkeypatch, spent):
    import ssl

    clock = _Clock()
    monkeypatch.setattr(P, "time", clock)
    calls = []

    async def fake_session(**kw):
        calls.append(kw["verify_ssl"])
        if kw["verify_ssl"]:
            clock.offset += spent  # o 1º passe consumiu `spent` s do prazo total antes de falhar
            raise ssl.SSLCertVerificationError("certificate verify failed: self-signed certificate")
        await asyncio.sleep(30)

    monkeypatch.setattr(P, "_run_probe_session", fake_session)
    monkeypatch.setattr(P, "_normalize_and_validate_scheme", lambda u: (u, None))
    r = asyncio.run(asyncio.wait_for(P.execute_probe("https://self-signed.test/", timeout=0.5), timeout=10))  # total = 9.5 s
    return r, calls


def test_retry_is_skipped_when_less_than_a_second_of_budget_remains(monkeypatch):
    r, calls = _retry_scenario(monkeypatch, spent=8.8)  # sobra 0.7 s
    assert calls == [True], "o retry foi forçado com um piso de 1 s, estourando o prazo total"
    assert r.error_code == "timeout" and "prazo total esgotado" in r.error


def test_retry_timeout_message_reports_the_total_budget_not_the_request_timeout(monkeypatch):
    r, calls = _retry_scenario(monkeypatch, spent=8.3)  # sobram ~1.2 s do total de 9.5 s
    assert calls == [True, False] and r.error_code == "timeout"
    assert "(9.5s)" in r.error and "(0.5s)" not in r.error, r.error


# ---- 9. OFFLINE sempre tem motivo, em qualquer evento ------------------------------------------------------------------
@pytest.mark.parametrize("event", ["reminder", "alert", None])
def test_offline_reason_is_added_when_messages_are_generic(mk, event):
    res = mk("https://t.example", up=False, status=None, error="connection refused")
    out = W._collect_violations(res, ["⏱ Reenvio: entrega original falhou"], event)
    assert any("Alvo OFFLINE: connection refused" in m for m in out)


def test_reminder_does_not_add_tls_lines_or_duplicate_offline(mk):
    res = mk("https://t.example", up=False, status=None, error="boom", tls_valid=False, tls_days=-3)
    out = W._collect_violations(res, ["Alvo offline (2 ciclos)"], "reminder")
    assert out == ["Alvo offline (2 ciclos)"]
