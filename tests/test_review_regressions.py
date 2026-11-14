"""Regressões dos achados da revisão do PR #5. Cada teste falhava antes da correção correspondente."""

import asyncio
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import anhanga.main as app_main
from anhanga.engine import probe as P
from anhanga.engine import revocation as R
from anhanga.engine import tlsenum
from anhanga.engine.config import load_config, parse_config
from anhanga.engine.models import RevocationInspection
from anhanga.engine.security import RATE_LIMITER


# ---- 1. booleanos estritos (bool("false") era True e desligava o Anti-SSRF) -----------------------------
@pytest.mark.parametrize("raw,expected", [("false", False), ("False", False), ("no", False), ("0", False), ("off", False),
                                          ("true", True), ("yes", True), ("1", True), (True, True), (False, False)])
def test_allow_private_accepts_only_real_booleans(raw, expected):
    cfg = parse_config({"allow_private": raw, "targets": ["example.com"]})
    assert cfg.allow_private is expected and cfg.targets[0].allow_private is expected and not cfg.errors


@pytest.mark.parametrize("raw", ["maybe", "", "talvez", [], {}, 2])
def test_invalid_boolean_is_an_error_and_fails_safe(raw):
    cfg = parse_config({"allow_private": raw, "targets": [{"url": "example.com", "allow_private": raw}],
                        "webhooks": [{"url": "https://hooks.example/x", "allow_private": raw}]})
    assert cfg.allow_private is False and cfg.targets[0].allow_private is False and cfg.webhooks[0].allow_private is False
    assert sum("booleano inválido" in e for e in cfg.errors) == 3


def test_env_interpolated_boolean_string(monkeypatch, tmp_path):
    monkeypatch.setenv("AP", "false")
    monkeypatch.delenv("UNSET_VAR", raising=False)
    f = tmp_path / "t.yaml"
    f.write_text("allow_private: ${AP}\nalerting: {notify_recovery: 'no'}\nstorage: {enabled: off}\ntargets: [example.com]\n")
    cfg = load_config(f)
    assert cfg.allow_private is False and cfg.policy.notify_recovery is False and cfg.storage.enabled is False
    f.write_text("allow_private: ${UNSET_VAR}\ntargets: [example.com]\n")  # variável não definida => ""
    cfg = load_config(f)
    assert cfg.allow_private is False and any("allow_private" in e for e in cfg.errors)


# ---- 7. duplicata pela URL normalizada ---------------------------------------------------------------------
def test_duplicate_targets_deduplicated_by_normalized_url():
    cfg = parse_config({"targets": ["example.com", "https://example.com", {"url": "HTTPS://example.com"}]})
    assert len(cfg.targets) == 1
    assert sum("duplicado" in w for w in cfg.warnings) == 2


# ---- 3. recarga com YAML quebrado ----------------------------------------------------------------------------
def test_unreadable_config_is_marked_load_failed(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("targets: [unclosed\n  - : :\n")
    assert load_config(bad).load_failed
    bad.write_text("- just\n- a list\n")
    assert load_config(bad).load_failed
    assert load_config(tmp_path / "missing.yaml").load_failed
    ok = tmp_path / "ok.yaml"
    ok.write_text("targets: []\n")
    assert not load_config(ok).load_failed
    assert not load_config(None).load_failed


def test_hot_reload_keeps_previous_config_on_broken_yaml(tmp_path, monkeypatch, mk):
    cfgfile = tmp_path / "targets.yaml"
    cfgfile.write_text("interval_seconds: 5\nstorage: {enabled: false}\ntargets: [https://keep.example]\n")
    monkeypatch.setenv("ANHANGA_CONFIG", str(cfgfile))
    monkeypatch.setattr(app_main, "_config_path", lambda: cfgfile)
    app_main.STATE_CACHE.clear()
    app_main._CONFIG = None

    async def fake_probe(url, **kw):
        return mk(url)

    monkeypatch.setattr(app_main, "_monitored_probe", fake_probe)
    real_sleep = asyncio.sleep

    async def fast_sleep(d, *a, **k):
        await real_sleep(0.05)

    monkeypatch.setattr(app_main.asyncio, "sleep", fast_sleep)

    async def scenario():
        task = asyncio.create_task(app_main.background_guardian_loop())
        for _ in range(100):
            await real_sleep(0.05)
            if "https://keep.example" in app_main.STATE_CACHE:
                break
        assert "https://keep.example" in app_main.STATE_CACHE
        cfgfile.write_text("targets: [unclosed\n  - : :\n")  # meio salvo
        import os
        os.utime(cfgfile, (time.time() + 5, time.time() + 5))
        for _ in range(10):  # vários ciclos
            await real_sleep(0.1)
        still = "https://keep.example" in app_main.STATE_CACHE
        cur = app_main._CONFIG
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return still, cur

    still, cur = asyncio.run(scenario())
    assert still, "alvo foi apagado por uma recarga inválida"
    assert [t.url for t in cur.targets] == ["https://keep.example"]


# ---- 4. orçamento de tempo ------------------------------------------------------------------------------------
def test_revocation_budget_does_not_cancel_the_work(monkeypatch):
    """Estourar o orçamento da sondagem não cancela a checagem: ela termina em segundo plano e o ciclo
    seguinte lê o cache (antes, o CRL baixado pela metade era descartado e refeito a cada 5 min)."""
    R.clear_caches()
    calls = []

    async def slow_but_finite(*a, **k):
        calls.append(1)
        await asyncio.sleep(0.5)
        return RevocationInspection(status="good", method="crl")

    monkeypatch.setattr(R, "_check_uncached", slow_but_finite)
    der = [b"\x30\x03\x02\x01\x01"]

    async def scenario():
        t0 = time.monotonic()
        first = await R.check_revocation(der, deadline=0.1)
        waited = time.monotonic() - t0
        await asyncio.sleep(0.7)
        second = await R.check_revocation(der, deadline=0.1)
        return first, waited, second

    first, waited, second = asyncio.run(scenario())
    assert waited < 0.4 and first.status == "unavailable" and "em andamento" in first.detail
    assert second.status == "good" and len(calls) == 1
    R.clear_caches()


def test_tls_enumeration_never_blocks_past_budget_and_fills_cache_later(monkeypatch):
    tlsenum.clear_cache()
    from anhanga.engine.models import TLSEnumeration

    async def slow_enum(ip, port, host, timeout=3.0, use_cache=True):
        await asyncio.sleep(0.6)
        out = TLSEnumeration(protocols=[])
        tlsenum._cache[(host.lower(), port)] = (time.monotonic(), out)
        return out

    monkeypatch.setattr(tlsenum, "enumerate_tls", slow_enum)

    async def scenario():
        t0 = time.monotonic()
        first = await tlsenum.enumerate_tls_bounded("203.0.113.9", 443, "a.test", budget=0.1)
        waited = time.monotonic() - t0
        await asyncio.sleep(0.8)  # a enumeração terminou em segundo plano
        second = await tlsenum.enumerate_tls_bounded("203.0.113.9", 443, "a.test", budget=0.1)
        return first, waited, second

    first, waited, second = asyncio.run(scenario())
    assert first is None and waited < 0.4
    assert second is not None, "o ciclo seguinte deveria achar o resultado em cache"
    tlsenum.clear_cache()


# ---- 5. diagnóstico por tipo de exceção + sem amplificação -------------------------------------------------
def test_tls_error_detected_by_type_not_by_text():
    import ssl
    import httpx

    assert P._is_tls_handshake_error(ssl.SSLError("x"))
    try:
        try:
            raise ssl.SSLError("boom")
        except ssl.SSLError as inner:
            raise httpx.ConnectError("wrapped") from inner
    except httpx.ConnectError as wrapped:
        assert P._is_tls_handshake_error(wrapped)
    # hostname com "ssl"/"tls" no nome NÃO é erro de TLS
    assert not P._is_tls_handshake_error(httpx.ConnectError("[Errno -2] ssl.example.com: Name or service not known"))
    assert not P._is_tls_handshake_error(OSError("tls-proxy refused"))


def test_enumeration_throttled_per_ip_port_even_if_hostname_varies(monkeypatch):
    tlsenum.clear_cache()
    runs = []

    async def fake(ip, port, host, timeout=3.0, use_cache=True):
        runs.append(host)
        return None

    monkeypatch.setattr(tlsenum, "enumerate_tls", fake)

    async def scenario():
        await tlsenum.enumerate_tls_bounded("203.0.113.7", 443, "a.test", budget=1)
        return [await tlsenum.enumerate_tls_bounded("203.0.113.7", 443, f"v{i}.test", budget=1) for i in range(20)]

    asyncio.run(scenario())
    assert runs == ["a.test"], "variar o hostname no mesmo ip:porta não pode multiplicar enumerações"
    tlsenum.clear_cache()


# ---- 6. GET / não vaza o estado -------------------------------------------------------------------------------
def test_dashboard_html_does_not_leak_cached_state_without_auth(monkeypatch, mk):
    monkeypatch.setenv("ANHANGA_API_KEY", "s3cret")
    RATE_LIMITER.reset()
    app_main.STATE_CACHE.clear()
    app_main.STATE_CACHE["https://secret-internal.example"] = mk("https://secret-internal.example")
    c = TestClient(app_main.app)
    assert "secret-internal.example" not in c.get("/").text
    authed = c.get("/", headers={"Authorization": "Bearer s3cret"})
    assert "secret-internal.example" in authed.text
    app_main.STATE_CACHE.clear()


# ---- 8. desligamento não perde alerta em voo ----------------------------------------------------------------
def test_cancelled_delivery_is_saved_to_outbox(tmp_path, monkeypatch, mk):
    from anhanga.engine.alerting import AlertEvent
    from anhanga.engine.config import WebhookSpec
    from anhanga.storage import Store

    store = Store(str(tmp_path / "t.db"))
    monkeypatch.setattr(app_main, "_STORE", store)

    async def hang(*a, **k):
        await asyncio.sleep(60)

    monkeypatch.setattr(app_main, "_send_to_webhook", hang)
    ev = AlertEvent(kind="alert", target="https://t.example", messages=["down"])
    wh = WebhookSpec(url="https://hooks.example/x", provider="auto", chat_id=None, allow_private=False)

    async def scenario():
        task = asyncio.create_task(app_main._deliver_event(ev, mk("https://t.example", up=False, status=None), [wh]))
        await asyncio.sleep(0.2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())
    assert store.outbox_size() == 1
    store.close()


# ---- 9. falha de modo comum só para a vigilância contínua -----------------------------------------------------
def test_common_mode_failure_ignores_adhoc_scans():
    P._GLOBAL_PROBE_HISTORY.clear()
    for h in ("a.test", "b.test", "c.test", "d.test"):  # scans avulsos ruins (API/CLI)
        assert P._check_common_mode_failure(h, 900.0, True) is None
    assert not P._GLOBAL_PROBE_HISTORY, "scan avulso não pode alimentar a heurística"
    token = P.MONITORED_PROBE.set(True)
    try:
        for h in ("a.test", "b.test"):
            assert P._check_common_mode_failure(h, 900.0, True) is None
        assert P._check_common_mode_failure("c.test", 900.0, True) is not None
    finally:
        P.MONITORED_PROBE.reset(token)
        P._GLOBAL_PROBE_HISTORY.clear()
