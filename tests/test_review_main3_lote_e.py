"""3ª revisão da main, lote E. Cada teste falhava antes da sua correção."""

import asyncio
import io
import sqlite3
import time
from pathlib import Path

import httpx
import pytest
from rich.console import Console

from anhanga import cli
from anhanga.engine import probe as P
from anhanga.engine import webhooks as W
from anhanga.engine.alerting import AlertManager, AlertPolicy
from anhanga.engine.config import SLORules
from anhanga.engine.models import ProbeResult
from anhanga.engine.security import parse_tls_certificate
from anhanga.storage import Store, backup_database


# ---- 1. "expirando" que vira "expirado" não gera recuperação verde -------------------------------------------------------------------
class _Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


def _expiring(mk):
    res = mk()
    res.tls.days_remaining = 5
    res.tls.alert_expiring = True
    return res


def _expired(mk):
    res = mk(tls_valid=False, tls_days=-3)
    res.tls.days_remaining = -3
    return res


def test_expiring_that_becomes_expired_is_not_announced_as_resolved(mk):
    clock = _Clock()
    mgr = AlertManager(AlertPolicy(failure_threshold=1, recovery_threshold=1, cooldown_seconds=0, notify_recovery=True), clock)
    rules = SLORules()
    events = mgr.evaluate(_expiring(mk), rules)
    assert any("expira" in m for e in events for m in e.messages)
    clock.t += 60
    events = mgr.evaluate(_expired(mk), rules)
    texts = [m for e in events for m in e.messages]
    assert not any("expirando" in m.lower() and "resolvido" in m for m in texts), f"recuperação falsa: {texts}"
    assert any("inválido" in m.lower() for m in texts), "o problema escalou e precisava ser alertado"


def test_renewal_is_still_announced_as_resolved(mk):
    clock = _Clock()
    mgr = AlertManager(AlertPolicy(failure_threshold=1, recovery_threshold=1, cooldown_seconds=0, notify_recovery=True), clock)
    rules = SLORules()
    mgr.evaluate(_expiring(mk), rules)
    clock.t += 60
    events = mgr.evaluate(mk(tls_days=90), rules)  # renovado e saudável
    assert any("resolvido" in m for e in events for m in e.messages)


# ---- 2. cabeçalho do Slack respeita 150 caracteres ----------------------------------------------------------------------------------------
def test_slack_header_text_never_exceeds_150_chars(mk):
    long_url = "https://example.com/" + "a" * 400 + "?q=" + "b" * 200
    payload = W.build_slack_payload(mk(long_url), ["Alvo OFFLINE: x"])
    header = next(b for b in _all_blocks(payload) if b["type"] == "header")
    assert len(header["text"]["text"]) <= 150, len(header["text"]["text"])
    assert header["text"]["text"].endswith("…")


def test_short_urls_are_not_truncated_in_the_slack_header(mk):
    payload = W.build_slack_payload(mk("https://t.example"), [])
    header = next(b for b in _all_blocks(payload) if b["type"] == "header")
    assert header["text"]["text"].endswith("https://t.example")


def _all_blocks(payload):
    blocks = list(payload.get("blocks", []))
    for att in payload.get("attachments", []):
        blocks += att.get("blocks", [])
    return blocks


# ---- 3. orçamento combinado das etapas pós-HTTP: resposta válida nunca é descartada ------------------------------------------------------
def test_bounded_returns_default_and_records_the_skipped_stage_when_out_of_time():
    skipped = []

    async def slow():
        await asyncio.sleep(30)
        return "real"

    async def scenario():
        t0 = time.monotonic()
        got = await P._bounded(lambda: slow(), time.monotonic() + 0.2, "padrão", skipped, "etapa X")
        return got, time.monotonic() - t0

    got, elapsed = asyncio.run(scenario())
    assert got == "padrão" and skipped == ["etapa X"] and elapsed < 2.0


def test_bounded_skips_without_even_starting_when_the_deadline_has_passed():
    skipped, started = [], []

    async def stage():
        started.append(1)
        return "real"

    got = asyncio.run(P._bounded(lambda: stage(), time.monotonic() - 1.0, "padrão", skipped, "etapa Y"))
    assert got == "padrão" and skipped == ["etapa Y"] and not started


def test_bounded_without_a_deadline_runs_normally():
    async def stage():
        return "real"

    assert asyncio.run(P._bounded(lambda: stage(), None, "padrão", [], "z")) == "real"


async def _ok_server():
    async def handle(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


def test_slow_post_http_stages_degrade_to_a_partial_result_instead_of_a_false_timeout(monkeypatch):
    async def slow_cors(*a, **k):
        await asyncio.sleep(30)

    monkeypatch.setattr(P, "audit_cors_active", slow_cors)
    monkeypatch.setattr(P, "_overall_timeout", lambda timeout, samples: 3.0)  # sobra ~2 s depois da reserva

    async def scenario():
        server, port = await _ok_server()
        try:
            t0 = time.monotonic()
            r = await P.execute_probe(f"http://127.0.0.1:{port}/", timeout=1, samples=1, allow_private=True)
            return r, time.monotonic() - t0
        finally:
            server.close()

    r, elapsed = asyncio.run(scenario())
    assert r.is_up and r.status_code == 200 and r.error is None, f"resposta 200 descartada: {r.error}"
    assert r.security.cors_audit.tested is False
    assert any("CORS" in n and "prazo" in n for n in r.timings.timing_notes), r.timings.timing_notes
    assert elapsed < 4.0


def test_regex_assertion_skipped_for_lack_of_time_is_not_evaluated_not_failed(monkeypatch):
    real_eval = P._evaluate_content_assertions

    async def slow_eval(*a, **k):
        if k.get("fail_if_body_not_matches_regexp") or k.get("fail_if_body_matches_regexp"):
            await asyncio.sleep(30)  # só o regex (subprocesso) é lento
        return await real_eval(*a, **k)

    monkeypatch.setattr(P, "_evaluate_content_assertions", slow_eval)
    monkeypatch.setattr(P, "_overall_timeout", lambda timeout, samples: 3.0)

    async def scenario():
        server, port = await _ok_server()
        try:
            return await P.execute_probe(
                f"http://127.0.0.1:{port}/", timeout=1, samples=1, allow_private=True, fail_if_body_not_matches_regexp="ok"
            )
        finally:
            server.close()

    r = asyncio.run(scenario())
    assert r.is_up and r.assertions.passed and r.assertions.not_evaluated, (r.error, r.assertions)


# ---- 4. dados do alvo nunca são markup do Rich ---------------------------------------------------------------------------------------------
def _render(mk, **kw):
    res = mk(**{k: v for k, v in kw.items() if k in ("url", "up", "status", "error")})
    return res


def test_check_report_does_not_swallow_or_crash_on_bracket_text(mk):
    res = mk("https://t.example/[/x]?q=[a-z]+", up=False, status=None, error="falha em [/boom] e [a-z]+")
    out = cli.render_rich_report(res, ["Content Assertion: padrão ^[a-z]+$ não casou", "erro [/x] estranho"], 1, {})
    assert "[a-z]+" in out and "[/x]" in out and "^[a-z]+$" in out, "texto entre colchetes foi engolido como estilo"


def test_check_report_survives_a_closing_tag_in_a_violation(mk):
    res = mk()
    cli.render_rich_report(res, ["violação com [/x] solto"], 1, {})  # antes: MarkupError


# ---- 5. exit code 3 só pelo error_code estruturado ---------------------------------------------------------------------------------------------
def test_assertion_text_that_mentions_dns_is_not_an_execution_error():
    msg = "Falha em Content Assertion: Corpo contém o padrão proibido: 'Erro de DNS'"
    assert cli._is_execution_or_ssrf_error(msg, "assertion_failed") is False


@pytest.mark.parametrize("code", ["ssrf_blocked", "dns_error", "invalid_url"])
def test_structured_codes_still_mean_execution_error(code):
    assert cli._is_execution_or_ssrf_error("qualquer", code) is True


def test_gate_exit_code_for_a_forbidden_pattern_mentioning_dns_is_1(mk):
    res = mk()
    res.is_up = False
    res.error = "Falha em Content Assertion: Corpo contém o padrão proibido: 'Erro de DNS'"
    res.error_code = "assertion_failed"
    res.assertions.passed = False
    res.assertions.failures = ["Corpo contém o padrão proibido: 'Erro de DNS'"]
    _, code, _ = cli.evaluate_probe_gates(res, None, None, None, True)
    assert code == 1


# ---- 6. hostnames internacionalizados (IDN) -------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("host", ["münchen.de", "exemplo.com.br", "açaí.com.br", "日本語.jp"])
def test_idn_hostnames_are_valid(host):
    assert P._validate_hostname_syntax(host) is None


@pytest.mark.parametrize("host", ["mün chen.de", "a..b.com", "ü" * 70 + ".com"])
def test_invalid_idn_hostnames_are_still_rejected(host):
    assert P._validate_hostname_syntax(host) is not None


def test_idn_target_is_normalized_to_punycode_and_accepted_in_config():
    from anhanga.engine import config as C

    url, err = P._normalize_and_validate_scheme("https://münchen.de/pfad")
    assert err is None and url == "https://xn--mnchen-3ya.de/pfad"
    cfg = C.parse_config({"targets": ["https://münchen.de", "açaí.com.br"]})
    assert len(cfg.targets) == 2 and not cfg.errors, cfg.errors


# ---- 7. incremental_vacuum precisa ser consumido ------------------------------------------------------------------------------------------------
def test_prune_actually_shrinks_the_database_file(tmp_path, mk):
    db = tmp_path / "v.db"
    store = Store(str(db), retention_days=1)
    old = time.time() - 5 * 86400
    for i in range(3000):
        r = mk(f"https://t{i % 7}.example")
        store.record_probe(r)
        store._conn.execute("UPDATE probe_history SET ts = ?", (old,))
    store._conn.commit()
    before = db.stat().st_size
    store.prune(time.time())
    store._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
    free = store._conn.execute("PRAGMA freelist_count").fetchone()[0]
    store.close()
    assert free < 5, f"{free} páginas livres continuam no arquivo (incremental_vacuum não foi consumido)"
    assert db.stat().st_size < before


# ---- 8. porta 80: IPv6 literal e 303 --------------------------------------------------------------------------------------------------------------
def test_port80_check_brackets_an_ipv6_literal_and_treats_303_as_redirect(monkeypatch):
    seen = {}

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url):
            seen["url"] = url
            return httpx.Response(303, headers={"location": "https://x.example/"})

    monkeypatch.setattr(P.httpx, "AsyncClient", FakeClient)

    async def fake_open(*a, **k):
        class W:
            def close(self):
                pass

            async def wait_closed(self):
                pass

        return None, W()

    monkeypatch.setattr(P.asyncio, "open_connection", fake_open)
    monkeypatch.setattr(P, "is_ssrf_safe", lambda ip, allow: True)
    out = asyncio.run(P._check_port_80("2606:4700::1111", allow_private=True, timeout=1.0, ip="2606:4700::1111"))
    assert seen["url"] == "http://[2606:4700::1111]/", seen
    assert "Redireciona para HTTPS" in out and "303" in out, out


# ---- 9. max_payload_bytes com resposta truncada: não avaliado, nunca aprovado em silêncio ---------------------------------------------------------
def test_max_payload_assertion_is_not_evaluated_when_the_read_was_truncated():
    res = asyncio.run(
        P._evaluate_content_assertions(
            body_text="x", payload_bytes=2_097_152, final_url="https://t/", max_payload_bytes=3_000_000, payload_truncated=True
        )
    )
    assert res.passed and any("max_payload_bytes" in n and "truncada" in n for n in res.not_evaluated), res


def test_max_payload_still_fails_when_even_the_truncated_size_exceeds_it():
    res = asyncio.run(
        P._evaluate_content_assertions(
            body_text="x", payload_bytes=2_097_152, final_url="https://t/", max_payload_bytes=1_000_000, payload_truncated=True
        )
    )
    assert not res.passed and not res.not_evaluated


def test_max_payload_is_evaluated_normally_without_truncation():
    res = asyncio.run(
        P._evaluate_content_assertions(body_text="x", payload_bytes=10, final_url="https://t/", max_payload_bytes=100, payload_truncated=False)
    )
    assert res.passed and not res.not_evaluated


# ---- 10. backup: ~ e caracteres especiais no caminho ------------------------------------------------------------------------------------------------
def test_backup_expands_the_home_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    src = tmp_path / "anhanga.db"
    c = sqlite3.connect(src)
    c.execute("CREATE TABLE t (v INTEGER)")
    c.execute("INSERT INTO t VALUES (1)")
    c.commit()
    c.close()
    out = backup_database("~/anhanga.db", "~/copia.db")
    assert out == tmp_path / "copia.db" and out.exists()


@pytest.mark.parametrize("name", ["com?interrogacao.db", "com#hash.db", "com%25pct.db", "com espaco.db"])
def test_backup_handles_special_characters_in_the_source_path(tmp_path, name):
    src = tmp_path / name
    c = sqlite3.connect(src)
    c.execute("CREATE TABLE t (v INTEGER)")
    c.commit()
    c.close()
    out = backup_database(str(src), str(tmp_path / "destino.db"))
    assert out.exists()
