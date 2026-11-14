import json
import os
import sqlite3
import stat
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

import anhanga.main as app_main
from anhanga.engine.alerting import AlertManager
from anhanga.engine.config import AlertPolicy, SLORules, parse_config
from anhanga.storage import OUTBOX_BACKOFF_SECONDS, OUTBOX_MAX_AGE_SECONDS, SCHEMA_VERSION, Store, webhook_key

NO_RULES = SLORules()
T = "https://t.example"


@pytest.fixture
def store():
    s = Store(":memory:", retention_days=7)
    yield s
    s.close()


def at(mk, ts: float, **kw):
    r = mk(**kw)
    r.timestamp = datetime.fromtimestamp(ts, timezone.utc)
    return r


# ---------------------------------------------------------------- histórico
def test_record_and_recent_totals_chronological_and_skip_no_response(store, mk):
    for i, ms in enumerate([100, 200, 300]):
        store.record_probe(at(mk, 1000 + i, total_ms=ms))
    store.record_probe(at(mk, 1010, up=False, status=None, error="x"))  # sem medição: não entra no sparkline
    assert store.recent_totals(T, 30) == [100.0, 200.0, 300.0]
    assert store.recent_totals(T, 2) == [200.0, 300.0]


def test_uptime_and_availability_and_coverage(store, mk):
    now = 1_000_000.0
    for i in range(8):
        store.record_probe(at(mk, now - 3600 + i, ))  # 8 up
    store.record_probe(at(mk, now - 100, tls_valid=False, tls_days=-1))  # degraded: HTTP ok, TLS ruim
    store.record_probe(at(mk, now - 90, up=False, status=None, error="x"))  # down
    u = store.uptime(T, now=now)["24h"]
    assert u["checks"] == 10
    assert u["uptime_pct"] == 80.0 and u["availability_pct"] == 90.0
    assert u["covered_seconds"] < 7200  # dados cobrem ~1h, não as 24h
    assert store.uptime("https://nobody.example", now=now)["24h"]["uptime_pct"] is None


def test_history_buckets_and_counts(store, mk):
    base = 10_000.0
    for i in range(60):
        store.record_probe(at(mk, base + i * 10, total_ms=100 + i, up=(i % 10 != 0), status=200 if i % 10 else None,
                              error=None if i % 10 else "x"))
    pts = store.history(T, base, base + 600, max_points=10)
    assert 9 <= len(pts) <= 11
    assert sum(p["checks"] for p in pts) == 60
    assert sum(p["down"] for p in pts) == 6 and sum(p["up"] for p in pts) == 54


def test_prune_respects_retention(store, mk):
    now = 5_000_000.0
    store.record_probe(at(mk, now - 8 * 86400))  # fora (7d)
    store.record_probe(at(mk, now - 3600))
    assert store.prune(now=now) == 1
    assert store.uptime(T, now=now)["7d"]["checks"] == 1


# ---------------------------------------------------------------- estado dos alertas / reinício
def test_restart_does_not_repeat_active_alert_and_cooldown_survives(store, mk):
    t = [1000.0]
    policy = AlertPolicy(failure_threshold=1, cooldown_seconds=600)
    m1 = AlertManager(policy, clock=lambda: t[0])
    down = lambda: mk(up=False, status=None, error="x")  # noqa: E731
    assert m1.evaluate(down(), NO_RULES)[0].kind == "alert"
    store.save_alert_state(T, m1.snapshot(T))

    # "reinício": novo manager, estado restaurado do banco
    m2 = AlertManager(policy, clock=lambda: t[0])
    m2.restore(store.load_alert_state())
    t[0] += 30
    assert m2.evaluate(down(), NO_RULES) == []  # sem alerta duplicado
    t[0] += 600
    assert [e.kind for e in m2.evaluate(down(), NO_RULES)] == ["reminder"]  # cooldown respeitado entre reinícios
    # e a recuperação ainda é entregue após o reinício
    assert [e.kind for e in m2.evaluate(mk(), NO_RULES)] == ["recovery"]


def test_without_persistence_restart_would_duplicate_alert(mk):
    """Controle: prova que o teste acima mede algo (sem restore, o alerta repetiria)."""
    policy = AlertPolicy(failure_threshold=1)
    m = AlertManager(policy, clock=lambda: 1000.0)
    assert m.evaluate(mk(up=False, status=None, error="x"), NO_RULES)[0].kind == "alert"
    m2 = AlertManager(policy, clock=lambda: 1030.0)
    assert m2.evaluate(mk(up=False, status=None, error="x"), NO_RULES)[0].kind == "alert"


def test_incident_starts_at_first_failure_not_at_notification(store, mk):
    t = [1000.0]
    m = AlertManager(AlertPolicy(failure_threshold=3), clock=lambda: t[0])
    down = lambda: mk(up=False, status=None, error="x")  # noqa: E731
    m.evaluate_full(down(), NO_RULES)
    t[0] += 30
    m.evaluate_full(down(), NO_RULES)
    t[0] += 30
    ev = m.evaluate_full(down(), NO_RULES)
    (problem, msg, started), = ev.opened
    assert problem == "down" and started == 1000.0
    store.open_incident(T, problem, started, msg)
    store.open_incident(T, problem, started + 5, msg)  # idempotente: um incidente aberto por problema
    t[0] += 60
    closed = m.evaluate_full(mk(), NO_RULES).closed
    assert closed == ["down"]
    store.close_incident(T, "down", t[0])
    (inc,) = store.incidents(T)
    assert inc["open"] is False and inc["duration_seconds"] == 120.0


def test_incident_closes_even_when_recovery_notification_disabled(mk):
    m = AlertManager(AlertPolicy(failure_threshold=1, notify_recovery=False), clock=lambda: 1.0)
    m.evaluate_full(mk(up=False, status=None, error="x"), NO_RULES)
    ev = m.evaluate_full(mk(), NO_RULES)
    assert ev.events == [] and ev.closed == ["down"]


def test_forget_targets_clears_state_and_closes_incidents(store, mk):
    store.save_alert_state(T, [{"problem": "down", "streak": 2, "clear_streak": 0, "active": True,
                                "last_notified": 1.0, "first_seen": 1.0}])
    store.open_incident(T, "down", 1.0, "x")
    store.forget_targets([T], now=50.0)
    assert store.load_alert_state() == [] and store.incidents(T)[0]["open"] is False


# ---------------------------------------------------------------- outbox
def test_outbox_backoff_schedule_and_drop(store):
    store.enqueue("k", T, "alert", ["m"], "{}", now=0.0)
    assert store.due(now=OUTBOX_BACKOFF_SECONDS[0] - 1) == []
    (row,) = store.due(now=OUTBOX_BACKOFF_SECONDS[0])
    assert row["messages"] == ["m"] and row["webhook_key"] == "k"
    now = float(OUTBOX_BACKOFF_SECONDS[0])
    for expected in OUTBOX_BACKOFF_SECONDS[1:]:
        assert store.reschedule(row["id"], now=now) is False
        assert store.due(now=now + expected - 1) == []
        assert len(store.due(now=now + expected)) == 1
        now += expected
    assert store.reschedule(row["id"], now=now) is True  # tentativas esgotadas -> descartado
    assert store.outbox_size() == 0


def test_outbox_drops_stale_alerts_and_mark_done(store):
    store.enqueue("k", T, "alert", ["m"], "{}", now=0.0)
    (row,) = store.due(now=100)
    assert store.reschedule(row["id"], now=OUTBOX_MAX_AGE_SECONDS + 10) is True  # velho demais
    store.enqueue("k", T, "alert", ["m"], "{}", now=0.0)
    (row,) = store.due(now=100)
    store.mark_done(row["id"])
    assert store.outbox_size() == 0


def test_webhook_secret_url_is_not_stored(store):
    secret = "https://hooks.slack.com/services/T000/B000/SECRETTOKEN"
    store.enqueue(webhook_key(secret), T, "alert", ["m"], "{}")
    dump = "\n".join(store._conn.iterdump())  # noqa: SLF001
    assert "SECRETTOKEN" not in dump and webhook_key(secret) in dump


# ---------------------------------------------------------------- arquivo
def test_file_db_permissions_wal_and_reopen(tmp_path, mk):
    path = str(tmp_path / "sub" / "a.db")
    s = Store(path)
    s.record_probe(mk())
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert s._conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"  # noqa: SLF001
    s.close()
    s2 = Store(path)
    assert s2.recent_totals(T) == [120.0]
    s2.close()


def test_refuses_database_from_newer_schema(tmp_path):
    path = str(tmp_path / "new.db")
    Store(path).close()
    conn = sqlite3.connect(path)
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    conn.close()
    with pytest.raises(RuntimeError, match="mais nova"):
        Store(path)


def test_sql_injection_attempt_in_target_is_inert(store, mk):
    store.record_probe(mk())
    evil = "x' OR '1'='1"
    assert store.recent_totals(evil) == [] and store.history(evil, 0, 10**10) == []
    assert store.uptime(evil)["24h"]["checks"] == 0


# ---------------------------------------------------------------- config
def test_storage_config(monkeypatch):
    monkeypatch.delenv("ANHANGA_DB_PATH", raising=False)
    cfg = parse_config({"storage": {"path": "/data/a.db", "retention_days": 30}})
    assert (cfg.storage.path, cfg.storage.retention_days, cfg.storage.enabled) == ("/data/a.db", 30, True)
    monkeypatch.setenv("ANHANGA_DB_PATH", "/env/b.db")
    assert parse_config({"storage": {"path": "/data/a.db"}}).storage.path == "/env/b.db"
    assert parse_config({"storage": {"enabled": False}}).storage.enabled is False
    bad = parse_config({"storage": {"retention_days": 99999, "bogus": 1}})
    assert bad.storage.retention_days == 3650 and len(bad.warnings) >= 2
    assert parse_config({"storage": "x"}).errors


# ---------------------------------------------------------------- API
@pytest.fixture
def api(store, monkeypatch):
    for var in ("ANHANGA_API_KEY",):
        monkeypatch.delenv(var, raising=False)
    app_main._STORE = store
    app_main.STATE_CACHE.clear()
    yield TestClient(app_main.app, client=("127.0.0.1", 50000))
    app_main._STORE = None


def test_api_503_without_store(monkeypatch):
    app_main._STORE = None
    c = TestClient(app_main.app, client=("127.0.0.1", 50000))
    for path in ("/api/v1/history?target=x", "/api/v1/uptime", "/api/v1/incidents"):
        assert c.get(path).status_code == 503


def test_api_history_uptime_incidents(api, store, mk):
    import time

    now = time.time()
    for i in range(5):
        store.record_probe(at(mk, now - 60 + i))
    store.open_incident(T, "down", now - 30, "Alvo OFFLINE: x")
    app_main.STATE_CACHE[T] = mk()
    h = api.get("/api/v1/history", params={"target": T, "hours": 1, "max_points": 10}).json()
    assert sum(p["checks"] for p in h["points"]) == 5
    u = api.get("/api/v1/uptime").json()["targets"][T]["24h"]
    assert u["checks"] == 5 and u["uptime_pct"] == 100.0
    inc = api.get("/api/v1/incidents", params={"open_only": "true"}).json()["incidents"]
    assert len(inc) == 1 and inc[0]["open"] is True and inc[0]["problem"] == "down"
    assert api.get("/api/v1/history", params={"target": T, "hours": 0}).status_code == 422


def test_persist_batch_writes_probe_incident_and_state(store, mk):
    m = AlertManager(AlertPolicy(failure_threshold=1), clock=lambda: 100.0)
    res = mk(up=False, status=None, error="x")
    ev = m.evaluate_full(res, NO_RULES)
    app_main._persist_batch(store, [(res, ev, m.snapshot(T))], now=100.0)
    assert store.incidents(T, open_only=True)[0]["problem"] == "down"
    assert store.load_alert_state()[0]["active"] is True
    assert store.uptime(T, now=101.0)["24h"]["checks"] == 1
    ev2 = m.evaluate_full(mk(), NO_RULES)
    app_main._persist_batch(store, [(mk(), ev2, m.snapshot(T))], now=130.0)
    assert store.incidents(T)[0]["open"] is False and store.load_alert_state() == []
