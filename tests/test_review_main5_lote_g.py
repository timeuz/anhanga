"""Revisão do diff do lote F, lote G. Cada teste falhava antes da sua correção."""

import asyncio
import html
import re
import shutil
import sqlite3
import ssl
import subprocess
import time

import pytest

from anhanga import main as app_main
from anhanga.engine import probe as P
from anhanga.engine import webhooks as W
from anhanga.engine.alerting import AlertManager, AlertPolicy
from anhanga.engine.config import SLORules
from anhanga.engine.models import TLSEnumeration, TLSProtocolResult
from anhanga.storage import Store

HTML = (app_main.BASE_DIR / "web" / "templates" / "index.html").read_text(encoding="utf-8")


# ---- 1. Telegram: o limite é medido no texto ESCAPADO (aspas, < e & expandem 4-6x) ---------------------------------------------------------
def _nasty(n=40, size=300):
    return [f"Content Assertion: padrão '\"<{i}>\"&&' " + "'\"<>&" * (size // 5) for i in range(n)]


def test_telegram_message_fits_4096_with_worst_case_html_escaping(mk):
    payload = W.build_telegram_payload(mk("https://t.example", up=False, status=None, error="x"), _nasty(), "1")
    assert len(payload["text"]) <= 4096, len(payload["text"])
    assert "omitidas" in payload["text"]


def test_telegram_never_cuts_an_html_entity_in_half(mk):
    text = W.build_telegram_payload(mk("https://t.example", up=False, status=None, error="x"), _nasty(), "1")["text"]
    assert not re.search(r"&(?:#x?[0-9a-fA-F]*|[a-z]+)(?![0-9a-zA-Z;#])", text), "entidade HTML partida: o Telegram recusa a mensagem"


# ---- 2. a 1ª violação SEMPRE entra, mesmo com cabeçalho enorme ------------------------------------------------------------------------------
def test_first_violation_is_never_dropped_even_with_a_huge_header(mk):
    url = "https://example.com/" + "a" * 5000  # só o cabeçalho já passaria de 4096
    payload = W.build_telegram_payload(mk(url, up=False, status=None, error="x"), ["Alvo OFFLINE: motivo importante " + "z" * 400, "outra"], "1")
    assert len(payload["text"]) <= 4096
    assert "Alvo OFFLINE: motivo importante" in payload["text"], "alerta entregue sem o motivo"


def test_fit_violations_keeps_the_first_even_with_a_tiny_limit():
    out = W._fit_violations(["x" * 500, "y" * 500, "z" * 500], 100)
    assert out and out[0].startswith("x") and any("omitidas" in o for o in out[1:])


def test_fit_violations_measures_the_rendered_text():
    render = lambda v: "• " + html.escape(v)  # noqa: E731
    items = ["'" * 300] * 30  # cada ' vira &#x27; (6x)
    out = W._fit_violations(items, 2000, per_item=300, render=render)
    assert sum(len(o) + 1 for o in out) <= 2000, sum(len(o) + 1 for o in out)


def test_short_violations_are_untouched_by_fitting():
    assert W._fit_violations(["a", "b"], 3000, render=lambda v: "• " + v) == ["• a", "• b"]


# ---- 3. "resolvido" só quando o certificado NÃO continua prestes a expirar -----------------------------------------------------------------
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


def test_same_expiring_certificate_failing_for_another_reason_is_not_resolved(mk):
    after = mk(tls_valid=False, tls_days=5)  # ainda com 5 dias, agora também com cadeia/hostname inválidos
    after.tls.days_remaining = 5
    after.tls.alert_expiring = True
    texts = _recovery_texts(mk, after)
    assert not any("expirando" in m.lower() and "resolvido" in m for m in texts), texts


def test_actual_renewal_is_still_resolved_even_if_it_has_another_defect(mk):
    after = mk(tls_valid=False, tls_days=90)
    after.tls.validation_error = "Hostname mismatch"
    after.tls.alert_expiring = False
    assert any("resolvido" in m for m in _recovery_texts(mk, after))


# ---- 4. legado "não verificado" também com enumeração parcial e sem IP/host ---------------------------------------------------------------------
async def _serve(ssl_ctx):
    async def handle(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
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
    d = tmp_path_factory.mktemp("g")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(d / "k.pem"), "-out", str(d / "c.pem"),
                    "-days", "2", "-subj", "/CN=localhost"], check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(d / "c.pem"), str(d / "k.pem"))
    return ctx


def _enum(status_v1, status_v11):
    mk_p = lambda n, st: TLSProtocolResult(protocol=n, status=st, ciphers=["X"] if st == "accepted" else [])  # noqa: E731
    return TLSEnumeration(
        protocols=[mk_p("TLSv1", status_v1), mk_p("TLSv1.1", status_v11), mk_p("TLSv1.2", "accepted"), mk_p("TLSv1.3", "accepted")],
        tested_at=1.0,
    )


def _probe_with_enum(monkeypatch, tls_ctx, enum):
    async def fake_enum(*a, **k):
        return enum

    async def fast(*a, **k):
        return [], None

    monkeypatch.setattr(P, "enumerate_tls_bounded", fake_enum)
    monkeypatch.setattr(P, "fetch_tls_extras", fast)

    async def scenario():
        server, port = await _serve(tls_ctx)
        try:
            return await P.execute_probe(f"https://localhost:{port}/", timeout=2, samples=1, allow_private=True)
        finally:
            server.close()

    return asyncio.run(scenario())


@pytest.mark.parametrize("v1, v11", [("unknown", "rejected"), ("rejected", "unknown"), ("unknown", "unknown")])
def test_partial_enumeration_with_unknown_legacy_versions_is_unverified(monkeypatch, tls_ctx, v1, v11):
    r = _probe_with_enum(monkeypatch, tls_ctx, _enum(v1, v11))
    assert r.tls is not None and r.tls.legacy_check_incomplete is True, (r.error, v1, v11)


def test_complete_enumeration_that_rejects_legacy_is_verified(monkeypatch, tls_ctx):
    r = _probe_with_enum(monkeypatch, tls_ctx, _enum("rejected", "rejected"))
    assert r.tls is not None and r.tls.legacy_check_incomplete is False and not r.tls.tls10_11_accepted


def test_accepted_legacy_is_a_finding_not_an_unverified_state(monkeypatch, tls_ctx):
    r = _probe_with_enum(monkeypatch, tls_ctx, _enum("accepted", "unknown"))
    assert r.tls.tls10_11_accepted is True and r.tls.legacy_check_incomplete is False


# ---- 5. a UI mostra "não verificado" em vez de "Bloqueado (Seguro)" -----------------------------------------------------------------------------
def test_ui_has_an_unverified_state_for_legacy_tls_in_both_languages():
    assert HTML.count("tlsLegacyUnverified:") == 2
    assert "legacy_check_incomplete" in HTML
    assert "legacyKey(tls)" in HTML and "t(legacyKey(result.tls))" in HTML
    assert "t('tlsLegacyBlocked')" not in HTML, "o selo seguro fixo no template voltou"


def test_ui_orders_accepted_before_unverified_before_blocked():
    m = re.search(r"legacyKey\(tls\) \{(.*?)\n                \},", HTML, re.S)
    assert m, "função legacyKey não encontrada"
    body = m.group(1)
    assert body.index("tlsLegacyAccepted") < body.index("tlsLegacyUnverified") < body.index("tlsLegacyBlocked")


# ---- 6. vacuum só em banco com auto_vacuum=INCREMENTAL ---------------------------------------------------------------------------------------------
class _SpyConn:
    def __init__(self, conn):
        self._c, self.sql = conn, []

    def execute(self, sql, *a):
        self.sql.append(sql)
        return self._c.execute(sql, *a)

    def __getattr__(self, name):
        return getattr(self._c, name)


def test_prune_skips_vacuum_on_a_legacy_database_without_incremental_auto_vacuum(tmp_path, mk):
    store = Store(str(tmp_path / "legacy.db"), retention_days=1)
    store._conn.execute("PRAGMA auto_vacuum = 0")
    store._conn.execute("VACUUM")
    assert store._conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 0
    spy = _SpyConn(store._conn)
    store._conn = spy
    store.prune(time.time())
    store._conn = spy._c
    store.close()
    assert not any("incremental_vacuum" in q for q in spy.sql), spy.sql
    assert not any("freelist_count" in q for q in spy.sql), "20 PRAGMAs inúteis por poda em banco legado"


def test_prune_still_vacuums_an_incremental_database(tmp_path, mk):
    store = Store(str(tmp_path / "new.db"), retention_days=1)
    assert store._conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 2
    for i in range(1500):
        store.record_probe(mk(f"https://t{i % 5}.example"))
    store._conn.execute("UPDATE probe_history SET ts = ?", (time.time() - 5 * 86400,))
    store._conn.commit()
    store.prune(time.time())
    assert store._conn.execute("PRAGMA freelist_count").fetchone()[0] < 5
    store.close()
