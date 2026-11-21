import pytest
from fastapi.testclient import TestClient

import anhanga.main as app_main
from anhanga.engine.config import MonitorConfig, WebhookSpec
from anhanga.engine.models import ProbeResult
from anhanga.engine.security import RATE_LIMITER, SlidingWindowRateLimiter


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for var in ("ANHANGA_API_KEY", "ANHANGA_ALLOW_PRIVATE", "ANHANGA_RATE_LIMIT_PER_MIN", "ANHANGA_TRUSTED_PROXIES"):
        monkeypatch.delenv(var, raising=False)
    RATE_LIMITER.reset()
    app_main.STATE_CACHE.clear()
    yield
    RATE_LIMITER.reset()
    app_main._CONFIG = None


def local_client():
    return TestClient(app_main.app, base_url="http://localhost", client=("127.0.0.1", 50000))


def test_fail_closed_without_key_rejects_non_loopback():
    assert TestClient(app_main.app).get("/metrics").status_code == 401  # client "testclient" não é loopback


def test_loopback_direct_allowed_but_proxy_headers_are_not():
    c = local_client()
    assert c.get("/metrics").status_code == 200
    assert c.get("/metrics", headers={"X-Forwarded-For": "8.8.8.8"}).status_code == 401


def test_api_key_bearer_and_x_api_key(monkeypatch):
    monkeypatch.setenv("ANHANGA_API_KEY", "s3cret")
    c = TestClient(app_main.app)
    assert c.get("/metrics").status_code == 401
    assert c.get("/metrics", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert c.get("/metrics", headers={"Authorization": "Bearer s3cret"}).status_code == 200
    assert c.get("/api/v1/targets", headers={"X-API-Key": "s3cret"}).status_code == 200
    assert c.get("/healthz").status_code == 200  # liveness segue aberto


def test_allow_private_query_param_cannot_bypass_ssrf():
    r = local_client().get("/api/v1/scan", params={"url": "http://127.0.0.1:9/", "allow_private": "true"})
    assert r.status_code == 403 and r.json()["detail"]["error_code"] == "ssrf_blocked"


def test_structured_errors_and_status_codes():
    c = local_client()
    assert c.get("/api/v1/scan", params={"url": "bad_host!.com"}).json()["detail"]["error_code"] == "invalid_url"
    assert c.get("/api/v1/scan", params={"url": "bad_host!.com"}).status_code == 400
    assert c.get("/api/v1/scan", params={"url": "file:///etc/passwd"}).status_code == 403
    assert c.get("/api/v1/scan", params={"url": "  "}).status_code == 400


def test_status_mapping_for_network_failures_vs_findings(monkeypatch, mk):
    async def fake_probe(url, **kw):
        return {
            "dns": ProbeResult(target_url=url, error="Erro de DNS: o domínio 'x' não existe (NXDOMAIN)"),
            "timeout": ProbeResult(target_url=url, error="Timeout rígido excedido (5s)"),
            "tls": mk(url, tls_valid=False, tls_days=-3),
            "5xx": mk(url, up=False, status=503),
        }[url.split("//")[1]]

    monkeypatch.setattr(app_main, "execute_probe", fake_probe)
    c = local_client()
    assert c.get("/api/v1/scan", params={"url": "https://dns"}).status_code == 502
    assert c.get("/api/v1/scan", params={"url": "https://timeout"}).status_code == 504
    r = c.get("/api/v1/scan", params={"url": "https://tls"})  # achado, não falha de execução
    assert r.status_code == 200 and r.json()["health"] == "degraded"
    assert c.get("/api/v1/scan", params={"url": "https://5xx"}).status_code == 200


def test_samples_cost_rate_limit(monkeypatch):
    monkeypatch.setenv("ANHANGA_RATE_LIMIT_PER_MIN", "5")
    c = local_client()
    p = {"url": "bad_host!.com", "samples": 5}
    assert c.get("/api/v1/scan", params=p).status_code == 400  # consumiu 5
    assert c.get("/api/v1/scan", params=p).status_code == 429


def test_xff_ignored_by_default_for_rate_limit_identity():
    assert RATE_LIMITER.extract_client_ip("1.2.3.4", "9.9.9.9") == "1.2.3.4"


def test_trusted_proxy_xff_honored_only_when_configured(monkeypatch):
    monkeypatch.setenv("ANHANGA_TRUSTED_PROXIES", "10.0.0.0/8")
    rl = SlidingWindowRateLimiter()
    assert rl.extract_client_ip("10.1.1.1", "203.0.113.9") == "203.0.113.9"
    assert rl.extract_client_ip("198.51.100.7", "203.0.113.9") == "198.51.100.7"


def test_webhook_allowlist_blocks_unlisted_destination():
    app_main._CONFIG = MonitorConfig(webhooks=[WebhookSpec(url="https://hooks.example/ok")])
    r = local_client().post(
        "/api/v1/webhooks/notify", json={"webhook_url": "http://169.254.169.254/", "url": "https://x.example"}
    )
    assert r.status_code == 403 and "allowlist" in r.json()["detail"]


def test_adhoc_probe_and_scan_do_not_create_state_or_series(monkeypatch, mk):
    async def fake_probe(url, **kw):
        return mk(url)

    monkeypatch.setattr(app_main, "execute_probe", fake_probe)
    c = local_client()
    assert c.get("/probe", params={"target": "https://adhoc-unique.example"}).status_code == 200
    assert c.get("/api/v1/scan", params={"url": "https://adhoc-unique2.example"}).status_code == 200
    assert app_main.STATE_CACHE == {}
    assert "adhoc-unique" not in c.get("/metrics").text
    body = c.get("/probe", params={"target": "https://adhoc-unique.example"}).text
    assert "probe_success 1.0" in body


def test_dashboard_renders_version_and_local_assets():
    html = local_client().get("/").text
    assert "cdn.tailwindcss.com" not in html and "cdn.jsdelivr.net" not in html
    assert f"v{app_main.__version__}" in html
    assert local_client().get("/static/alpine.min.js").status_code == 200
    assert local_client().get("/static/app.css").status_code == 200
