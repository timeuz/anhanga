"""Lote I: alvos fixos adicionados/removidos pela UI (SQLite), sempre com anti-SSRF e atrás da chave de API."""
import asyncio

import pytest
from fastapi.testclient import TestClient

import anhanga.main as app_main
from anhanga.engine import config as C
from anhanga.engine.security import RATE_LIMITER
from anhanga.storage import Store


@pytest.fixture(autouse=True)
def env(monkeypatch, tmp_path, mk):
    for var in ("ANHANGA_API_KEY", "ANHANGA_ALLOW_PRIVATE", "ANHANGA_RATE_LIMIT_PER_MIN"):
        monkeypatch.delenv(var, raising=False)
    RATE_LIMITER.reset()
    app_main.STATE_CACHE.clear()
    app_main.HISTORY_CACHE.clear()
    app_main._MANAGED.clear()
    store = Store(str(tmp_path / "t.db"))
    monkeypatch.setattr(app_main, "_STORE", store)
    app_main._CONFIG = C.parse_config({"targets": ["https://yaml.example"], "min_grade": "B"})
    probed = []

    async def fake_probe(url, **kw):
        probed.append((url, kw))
        return mk(url)

    monkeypatch.setattr(app_main, "_monitored_probe", fake_probe)
    monkeypatch.setattr(app_main, "MAX_MANAGED_TARGETS", 3)
    yield store, probed
    app_main._CONFIG = None
    app_main._MANAGED.clear()
    RATE_LIMITER.reset()
    store.close()


def client():
    return TestClient(app_main.app, base_url="http://localhost", client=("127.0.0.1", 50000))


def test_add_persists_probes_immediately_and_never_with_allow_private(env):
    store, probed = env
    r = client().post("/api/v1/targets/managed", json={"url": "novo.example"})
    assert r.status_code == 201 and r.json()["url"] == "https://novo.example"
    assert store.list_managed_targets() == [("https://novo.example", 1)]
    assert "https://novo.example" in app_main.STATE_CACHE
    assert probed[0][1]["allow_private"] is False
    assert [t.url for t in app_main._all_targets(app_main._current_config())] == ["https://yaml.example", "https://novo.example"]
    assert client().get("/api/v1/targets/managed").json()["targets"] == [{"url": "https://novo.example", "samples": 1}]


def test_managed_targets_inherit_the_top_level_slo_rules():
    client().post("/api/v1/targets/managed", json={"url": "novo.example"})
    spec = app_main._all_targets(app_main._current_config())[-1]
    assert spec.rules == app_main._current_config().default_rules and spec.rules.min_grade == "B"


def test_forbidden_target_is_rejected_and_never_stored(env, monkeypatch):
    store, _ = env
    from anhanga.engine.probe import execute_probe

    async def real_probe(url, **kw):  # probe real: o loopback é bloqueado na resolução, antes de qualquer conexão
        return await execute_probe(url, timeout=2.0, **kw)

    monkeypatch.setattr(app_main, "_monitored_probe", real_probe)
    r = client().post("/api/v1/targets/managed", json={"url": "http://127.0.0.1:9/"})
    assert r.status_code == 403
    assert store.list_managed_targets() == [] and not app_main._MANAGED


def test_invalid_url_is_400(env):
    store, _ = env
    assert client().post("/api/v1/targets/managed", json={"url": "ftp://x.example"}).status_code == 400
    assert client().post("/api/v1/targets/managed", json={"url": "   "}).status_code == 400
    assert store.list_managed_targets() == []


def test_duplicates_are_409_even_with_different_case_and_scheme_default(env):
    assert client().post("/api/v1/targets/managed", json={"url": "https://YAML.example"}).status_code == 409
    assert client().post("/api/v1/targets/managed", json={"url": "a.example"}).status_code == 201
    assert client().post("/api/v1/targets/managed", json={"url": "https://A.example"}).status_code == 409


def test_limit_is_enforced_by_the_store_and_reported(env):
    store, _ = env
    for h in ("a", "b", "c"):
        assert client().post("/api/v1/targets/managed", json={"url": f"{h}.example"}).status_code == 201
    r = client().post("/api/v1/targets/managed", json={"url": "d.example"})
    assert r.status_code == 409 and "Limite" in r.json()["detail"]
    assert len(store.list_managed_targets()) == 3


def test_store_limit_is_atomic_in_the_insert_itself(env):
    store, _ = env
    assert [store.add_managed_target(f"https://{i}.x", 1, 2) for i in range(3)] == ["added", "added", "limit"]
    assert store.add_managed_target("https://0.x", 1, 2) == "exists"


def test_remove_clears_store_state_and_history(env):
    store, _ = env
    client().post("/api/v1/targets/managed", json={"url": "a.example"})
    app_main.HISTORY_CACHE["https://a.example"] = [1.0]
    r = client().delete("/api/v1/targets/managed", params={"url": "https://A.example"})
    assert r.status_code == 200
    assert store.list_managed_targets() == [] and not app_main._MANAGED
    assert "https://a.example" not in app_main.STATE_CACHE and "https://a.example" not in app_main.HISTORY_CACHE
    assert client().delete("/api/v1/targets/managed", params={"url": "a.example"}).status_code == 404


def test_yaml_targets_cannot_be_removed_through_the_api(env):
    r = client().delete("/api/v1/targets/managed", params={"url": "https://yaml.example"})
    assert r.status_code == 409 and "targets.yaml" in r.json()["detail"]


def test_write_endpoints_require_the_api_key(monkeypatch):
    monkeypatch.setenv("ANHANGA_API_KEY", "s3cret")
    c = TestClient(app_main.app)  # não-loopback
    assert c.post("/api/v1/targets/managed", json={"url": "a.example"}).status_code == 401
    assert c.delete("/api/v1/targets/managed", params={"url": "a.example"}).status_code == 401
    assert c.get("/api/v1/targets/managed").status_code == 401
    ok = c.post("/api/v1/targets/managed", json={"url": "a.example"}, headers={"Authorization": "Bearer s3cret"})
    assert ok.status_code == 201


def test_loopback_post_with_cross_site_form_content_type_is_rejected():
    # CSRF: <form> de outro site só consegue text/plain ou form-urlencoded; o corpo precisa ser JSON.
    r = client().post("/api/v1/targets/managed", content='{"url":"a.example"}', headers={"Content-Type": "text/plain"})
    assert r.status_code == 422


def test_all_targets_yaml_wins_over_managed_duplicate(env):
    app_main._MANAGED.append(C.TargetSpec(url="https://YAML.example"))
    assert len(app_main._all_targets(app_main._current_config())) == 1


def test_refresh_managed_reads_the_store_and_keeps_old_value_on_read_error(env, monkeypatch):
    store, _ = env
    store.add_managed_target("https://z.example", 2, 5)
    cfg = app_main._current_config()
    asyncio.run(app_main._refresh_managed(cfg))
    assert [(t.url, t.samples) for t in app_main._MANAGED] == [("https://z.example", 2)]
    assert app_main._MANAGED[0].rules.min_grade == "B" and not app_main._MANAGED[0].allow_private  # herda o slo/min_grade de topo

    async def boom(fn, *a, **k):
        return None

    monkeypatch.setattr(app_main, "_store_call", boom)
    asyncio.run(app_main._refresh_managed(cfg))
    assert len(app_main._MANAGED) == 1


def test_store_opens_with_no_yaml_targets_when_the_database_already_exists(tmp_path, monkeypatch):
    db = tmp_path / "x.db"
    Store(str(db)).close()
    monkeypatch.setattr(app_main, "_STORE", None)
    cfg = C.parse_config({"storage": {"path": str(db)}})
    cfg.targets.clear()
    asyncio.run(app_main._open_store(cfg, app_main.AlertManager(cfg.policy)))
    assert app_main._STORE is not None
    app_main._STORE.close()
    monkeypatch.setattr(app_main, "_STORE", None)
    cfg2 = C.parse_config({"storage": {"path": str(tmp_path / "nao-existe.db")}})
    asyncio.run(app_main._open_store(cfg2, app_main.AlertManager(cfg2.policy)))
    assert app_main._STORE is None  # sem alvos e sem banco: continua sem criar arquivo


def test_migration_from_schema_1_adds_the_table(tmp_path):
    p = str(tmp_path / "old.db")
    s = Store(p)
    s._conn.execute("DROP TABLE managed_targets")
    s._conn.execute("PRAGMA user_version = 1")
    s.close()
    s2 = Store(p)
    assert s2.add_managed_target("https://a.x", 1, 5) == "added"
    s2.close()


def test_ui_wires_the_managed_endpoints_and_confirms_before_removing():
    from pathlib import Path

    html = (Path(app_main.BASE_DIR) / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    assert "/api/v1/targets/managed" in html and "method: 'DELETE'" in html and "method: 'POST'" in html
    assert "window.confirm" not in html and "pendingRemove" in html
    assert "isManaged(item)" in html


def test_ui_shows_the_structured_error_message_not_raw_json():
    from pathlib import Path

    html = (Path(app_main.BASE_DIR) / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    assert "(d && d.message) || JSON.stringify(d)" in html
