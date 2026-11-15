"""4ª revisão da main, lote F. Cada teste falhava antes da sua correção."""

import asyncio
import shutil
import sqlite3
import ssl
import subprocess
import time
from pathlib import Path

import httpx
import pytest

from anhanga import cli
from anhanga import storage as storage_mod
from anhanga.engine import probe as P
from anhanga.engine import webhooks as W
from anhanga.engine.alerting import AlertManager, AlertPolicy
from anhanga.engine.config import SLORules
from anhanga.engine.models import RevocationInspection, TLSInspection
from anhanga.engine.security import audit_http_security
from anhanga.storage import Store


# ---------- helpers: servidor HTTP/HTTPS local ----------
async def _serve(ssl_ctx=None):
    async def handle(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ssl_ctx)
    return server, server.sockets[0].getsockname()[1]


@pytest.fixture(scope="module")
def tls_ctx(tmp_path_factory):
    if shutil.which("openssl") is None:
        pytest.skip("openssl indisponível")
    d = tmp_path_factory.mktemp("f")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(d / "k.pem"), "-out", str(d / "c.pem"),
         "-days", "2", "-subj", "/CN=localhost"], check=True, capture_output=True,
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(d / "c.pem"), str(d / "k.pem"))
    return ctx


# ---- 1. falha definitiva (URL/tamanho) não se perde quando o regex estoura o prazo ------------------------------------------------------
def test_definitive_assertion_failure_survives_a_regex_stage_that_overruns(monkeypatch):
    real_eval = P._evaluate_content_assertions

    async def slow_regex(*a, **k):
        if k.get("fail_if_body_not_matches_regexp") or k.get("fail_if_body_matches_regexp"):
            await asyncio.sleep(30)
        return await real_eval(*a, **k)

    monkeypatch.setattr(P, "_evaluate_content_assertions", slow_regex)
    monkeypatch.setattr(P, "_overall_timeout", lambda timeout, samples: 3.0)

    async def scenario():
        server, port = await _serve()
        try:
            return await P.execute_probe(
                f"http://127.0.0.1:{port}/", timeout=1, samples=1, allow_private=True,
                fail_if_body_matches_regexp="ok", assert_final_url="https://outro.example/", max_payload_bytes=1,
            )
        finally:
            server.close()

    r = asyncio.run(scenario())
    assert r.status_code == 200
    assert not r.assertions.passed and not r.is_up, "a falha definitiva de URL/tamanho foi descartada junto com o regex"
    assert any("URL final" in f for f in r.assertions.failures) and any("acima do máximo" in f for f in r.assertions.failures)
    assert any("regex" in n for n in r.assertions.not_evaluated)


# ---- 2 e 5. etapa TLS pulada: legado "não verificado" (sem bônus) e as etapas que terminaram são mantidas -----------------------------------
def test_skipped_tls_stage_marks_legacy_as_unverified_and_keeps_finished_stages(monkeypatch, tls_ctx):
    async def slow(*a, **k):
        await asyncio.sleep(30)

    async def quick_port80(*a, **k):
        return "301 Redireciona para HTTPS (Correto)"

    monkeypatch.setattr(P, "fetch_tls_extras", slow)  # estoura o prazo
    monkeypatch.setattr(P, "enumerate_tls_bounded", slow)
    monkeypatch.setattr(P, "check_tls10_11_accepted_async", slow)
    monkeypatch.setattr(P, "_check_port_80", quick_port80)  # já tinha terminado
    monkeypatch.setattr(P, "_overall_timeout", lambda timeout, samples: 3.0)

    async def scenario():
        server, port = await _serve(tls_ctx)
        try:
            return await P.execute_probe(f"https://localhost:{port}/", timeout=1, samples=1, allow_private=True)
        finally:
            server.close()

    r = asyncio.run(scenario())
    assert r.status_code == 200 and r.tls is not None, r.error
    assert r.tls.legacy_check_incomplete is True and r.tls.enumeration is None
    assert r.http_port_80_status == "301 Redireciona para HTTPS (Correto)", "a porta 80, já pronta, foi descartada junto"
    assert any("TLS 1.0/1.1 legado" in n for n in r.timings.timing_notes)


def _tls(**kw):
    base = dict(valid=True, protocol="TLSv1.3", days_remaining=200, alert_expiring=False)
    base.update(kw)
    return TLSInspection(**base)


def test_unverified_legacy_tls_does_not_earn_the_modern_tls_bonus():
    verified = audit_http_security(httpx.Headers({}), True, _tls())
    unverified = audit_http_security(httpx.Headers({}), True, _tls(legacy_check_incomplete=True))
    assert verified.transport_score - unverified.transport_score == 10, (verified.transport_score, unverified.transport_score)


def test_bounded_keeps_the_stages_that_finished_when_another_overruns():
    skipped = []

    async def fast():
        return "ok"

    async def slow():
        await asyncio.sleep(30)

    async def scenario():
        dl = time.monotonic() + 0.3
        return await asyncio.gather(
            P._bounded(lambda: fast(), dl, "padrão-a", skipped, "a"),
            P._bounded(lambda: slow(), dl, "padrão-b", skipped, "b"),
            P._bounded(lambda: fast(), dl, "padrão-c", skipped, "c"),
        )

    assert asyncio.run(scenario()) == ["ok", "padrão-b", "ok"] and skipped == ["b"]


# ---- 3. limites do Slack (3000 por bloco) e do Telegram (4096 por mensagem) -----------------------------------------------------------------
def _many(n=120, size=400):
    return [f"Content Assertion: padrão <b>&{i}</b> " + "x" * size for i in range(n)]


def test_slack_violations_block_fits_the_3000_char_limit(mk):
    payload = W.build_slack_payload(mk("https://t.example", up=False, status=None, error="x"), _many())
    texts = []
    for blk in payload.get("blocks", []) + [b for a in payload.get("attachments", []) for b in a.get("blocks", [])]:
        if blk.get("type") == "section" and isinstance(blk.get("text"), dict):
            texts.append(blk["text"]["text"])
    assert texts and all(len(t) <= 3000 for t in texts), [len(t) for t in texts]
    assert any("omitidas" in t for t in texts)


def test_telegram_message_fits_4096_even_after_html_escaping(mk):
    payload = W.build_telegram_payload(mk("https://t.example", up=False, status=None, error="x"), _many(), "1")
    assert len(payload["text"]) <= 4096, len(payload["text"])
    assert "omitidas" in payload["text"]


def test_few_short_violations_are_not_changed(mk):
    payload = W.build_telegram_payload(mk("https://t.example"), ["curta 1", "curta 2"], "1")
    assert "curta 1" in payload["text"] and "curta 2" in payload["text"] and "omitidas" not in payload["text"]


# ---- 4. recuperação de tls_expiring: silenciada só quando a CAUSA é expiração/revogação ----------------------------------------------------
class _Clock:
    t = 1_000_000.0

    def __call__(self):
        return self.t


def _recovery_texts(mk, after):
    clock = _Clock()
    mgr = AlertManager(AlertPolicy(failure_threshold=1, recovery_threshold=1, cooldown_seconds=0, notify_recovery=True), clock)
    expiring = mk()
    expiring.tls.days_remaining = 5
    expiring.tls.alert_expiring = True
    mgr.evaluate(expiring, SLORules())
    clock.t += 60
    return [m for e in mgr.evaluate(after, SLORules()) for m in e.messages]


def test_renewal_with_another_tls_defect_still_announces_the_expiry_as_resolved(mk):
    renewed_but_broken = mk(tls_valid=False, tls_days=90)  # renovou, mas hostname divergente (degraded)
    renewed_but_broken.tls.validation_error = "Hostname mismatch"
    texts = _recovery_texts(mk, renewed_but_broken)
    assert any("expirando" in m.lower() and "resolvido" in m for m in texts), texts


def test_expired_certificate_is_not_announced_as_resolved(mk):
    expired = mk(tls_valid=False, tls_days=-2)
    expired.tls.days_remaining = -2
    assert not any("resolvido" in m for m in _recovery_texts(mk, expired))


def test_revoked_certificate_is_not_announced_as_resolved(mk):
    revoked = mk(tls_valid=False, tls_days=60)
    revoked.tls.revocation = RevocationInspection(status="revoked", method="ocsp")
    assert not any("expirando" in m.lower() and "resolvido" in m for m in _recovery_texts(mk, revoked))


# ---- 6. IDN: IDNA 2008 do httpx (faß.de não vira fass.de) e userinfo intacto ---------------------------------------------------------------
@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://faß.de/x", "https://xn--fa-hia.de/x"),
        ("https://münchen@münchen.de/", "https://münchen@xn--mnchen-3ya.de/"),
        ("https://münchen.de:8443/p?q=1", "https://xn--mnchen-3ya.de:8443/p?q=1"),
        ("https://ascii.example/", "https://ascii.example/"),
    ],
)
def test_idn_normalization_uses_idna2008_and_only_touches_the_host(url, expected):
    assert P._normalize_and_validate_scheme(url) == (expected, None)


def test_ss_is_not_equivalent_to_sharp_s():
    assert P._normalize_and_validate_scheme("https://faß.de")[0] != P._normalize_and_validate_scheme("https://fass.de")[0]


# ---- 7. vacuum em blocos: não esvazia tudo de uma vez segurando o lock ---------------------------------------------------------------------
def test_prune_vacuums_in_bounded_chunks(tmp_path, mk, monkeypatch):
    monkeypatch.setattr(storage_mod, "VACUUM_CHUNK_PAGES", 4)
    monkeypatch.setattr(storage_mod, "VACUUM_MAX_CHUNKS", 2)
    store = Store(str(tmp_path / "v.db"), retention_days=1)
    old = time.time() - 5 * 86400
    for i in range(2000):
        store.record_probe(mk(f"https://t{i % 5}.example"))
    store._conn.execute("UPDATE probe_history SET ts = ?", (old,))
    store._conn.commit()
    store._conn.execute("DELETE FROM probe_history")
    store._conn.commit()
    free_before = store._conn.execute("PRAGMA freelist_count").fetchone()[0]
    assert free_before > 20
    store.prune(time.time())
    free_after = store._conn.execute("PRAGMA freelist_count").fetchone()[0]
    store.close()
    assert 0 < free_after < free_before, (free_before, free_after)
    assert free_before - free_after <= 8 + 2, "liberou mais páginas do que 2 blocos de 4 (vacuum sem limite)"


# ---- 8. TimeoutError próprio da etapa não é rotulado como falta de prazo ---------------------------------------------------------------------
def test_stage_own_timeout_is_not_reported_as_the_probe_deadline():
    skipped = []

    async def stage_timeout():
        raise TimeoutError("socket")

    got = asyncio.run(P._bounded(lambda: stage_timeout(), time.monotonic() + 30, "padrão", skipped, "revogação"))
    assert got == "padrão" and skipped == ["revogação (timeout da própria etapa)"], skipped


def test_real_deadline_is_still_reported_plainly():
    skipped = []

    async def slow():
        await asyncio.sleep(30)

    asyncio.run(P._bounded(lambda: slow(), time.monotonic() + 0.2, "padrão", skipped, "revogação"))
    assert skipped == ["revogação"]


# ---- 9. backup: banco inválido/travado dá erro claro (sem traceback) e não deixa o .tmp --------------------------------------------------------------
def test_backup_of_a_non_sqlite_file_is_a_clean_error(tmp_path, capsys):
    bad = tmp_path / "lixo.db"
    bad.write_bytes(b"isto nao e um banco sqlite" * 100)
    dest = tmp_path / "out.db"
    assert cli.main(["backup", str(dest), "--db", str(bad)]) == 2
    assert "Erro no backup" in capsys.readouterr().err
    assert not dest.exists() and not (tmp_path / "out.db.tmp").exists()


# ---- 10. exit code 3 só pelo error_code ---------------------------------------------------------------------------------------------------------
def test_execution_error_needs_both_a_message_and_a_structured_code():
    assert cli._is_execution_or_ssrf_error(None, "dns_error") is False
    assert cli._is_execution_or_ssrf_error("Erro de DNS: x", None) is False
    assert cli._is_execution_or_ssrf_error("Erro de DNS: x", "dns_error") is True
