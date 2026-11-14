"""Revisão da main, lote B. Cada teste falhava antes da sua correção."""

import asyncio
import os
from pathlib import Path

import httpx
import pytest
import yaml

from anhanga import main as app_main
from anhanga.engine import config as C
from anhanga.engine import webhooks as W
from anhanga.engine.security import audit_cors_active
from anhanga.metrics import exporter as E


# ---- 6. ANHANGA_CONFIG explícito e inexistente é erro, nunca fallback para outro targets.yaml -------------------------------------
def test_missing_explicit_config_does_not_fall_back_to_cwd_targets_yaml(tmp_path, monkeypatch):
    (tmp_path / "targets.yaml").write_text("targets: [https://unrelated.example]\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ANHANGA_CONFIG", str(tmp_path / "typo.yaml"))
    path = C.find_config_path()
    assert path == tmp_path / "typo.yaml", f"caiu em {path}"
    cfg = C.load_config(path)
    assert cfg.load_failed and cfg.targets == [] and any("Falha ao ler" in e for e in cfg.errors)


def test_without_explicit_config_cwd_targets_yaml_is_still_found(tmp_path, monkeypatch):
    (tmp_path / "targets.yaml").write_text("targets: [https://ok.example]\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ANHANGA_CONFIG", raising=False)
    assert C.find_config_path() == Path("targets.yaml")


def test_existing_explicit_config_is_used(tmp_path, monkeypatch):
    f = tmp_path / "custom.yaml"
    f.write_text("targets: [https://ok.example]\n")
    monkeypatch.setenv("ANHANGA_CONFIG", str(f))
    assert C.find_config_path() == f


def test_mtime_of_a_missing_config_is_none_not_a_crash(tmp_path):
    assert app_main._mtime(tmp_path / "nao-existe.yaml") is None
    assert app_main._mtime(None) is None
    f = tmp_path / "c.yaml"
    f.write_text("x: 1\n")
    assert isinstance(app_main._mtime(f), float)


# ---- 7. a sonda CORS lê só os cabeçalhos, nunca o corpo ------------------------------------------------------------------------------
class _CountingBody(httpx.AsyncByteStream):
    def __init__(self):
        self.read = 0

    async def __aiter__(self):
        for _ in range(1000):
            self.read += 1
            yield b"x" * 65536


def test_cors_probe_does_not_download_the_response_body():
    body = _CountingBody()

    def handler(request):
        return httpx.Response(200, headers={"access-control-allow-origin": "https://evil.anhanga.test"}, stream=body)

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await audit_cors_active(client, "https://t.example/")

    r = asyncio.run(scenario())
    assert r.tested and r.reflects_origin, r
    assert body.read == 0, f"o corpo foi baixado ({body.read} blocos de 64 KiB)"


def test_cors_probe_still_reports_wildcard_with_credentials():
    def handler(request):
        return httpx.Response(200, headers={"access-control-allow-origin": "*", "access-control-allow-credentials": "true"}, content=b"x")

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await audit_cors_active(client, "https://t.example/")

    r = asyncio.run(scenario())
    assert r.wildcard and r.allow_credentials and r.vulnerable


# ---- 8. .inf/.nan do YAML nunca derrubam o parser --------------------------------------------------------------------------------------
@pytest.mark.parametrize("value", [".inf", "-.inf", ".nan"])
def test_non_finite_numbers_in_yaml_never_raise(value):
    raw = yaml.safe_load(
        f"interval_seconds: {value}\nsamples: {value}\nslo: {{max_ttfb: {value}, max_total: {value}}}\n"
        f"alerting: {{failure_threshold: {value}, recovery_threshold: {value}, cooldown_seconds: {value}}}\n"
        "targets: [https://a.example]\n"
    )
    cfg = C.parse_config(raw)  # antes: OverflowError / ValueError
    assert cfg.interval_seconds == 60 and cfg.targets, cfg.errors
    assert cfg.policy.cooldown_seconds == 3600.0
    assert any("interval_seconds" in e for e in cfg.errors)


@pytest.mark.parametrize("value", [float("nan"), float("inf")])
def test_parse_duration_rejects_non_finite(value):
    with pytest.raises(ValueError):
        C.parse_duration_ms(value)


def test_nan_slo_does_not_silently_disable_the_threshold():
    cfg = C.parse_config(yaml.safe_load("slo: {max_ttfb: .nan}\ntargets: [https://a.example]\n"))
    assert any("max_ttfb" in e or "slo" in e.lower() for e in cfg.errors), cfg.errors


# ---- 9. provedor do webhook pelo HOSTNAME -------------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://alerts.myteams.example/hook", "slack"),
        ("https://telegram-relay.internal/x", "slack"),
        ("https://evil.example/?u=api.telegram.org", "slack"),
        ("https://notoffice.com/x", "slack"),
        ("https://hooks.slack.com/services/T/B/x", "slack"),
        ("https://api.telegram.org/bot1:AA/sendMessage", "telegram"),
        ("https://contoso.webhook.office.com/webhookb2/x", "teams"),
        ("https://outlook.office.com/webhook/x", "teams"),
        ("https://prod-12.westus.logic.azure.com/workflows/x", "teams"),
        ("https://API.TELEGRAM.ORG./bot1/x", "telegram"),
    ],
)
def test_webhook_provider_is_detected_by_hostname(url, expected):
    assert W.detect_webhook_provider(url) == expected


def test_explicit_provider_still_wins():
    assert W.detect_webhook_provider("https://hooks.example/x", "teams") == "teams"


def test_telegram_chat_id_rule_follows_the_same_detection():
    relay = C.parse_config({"targets": ["https://a.example"], "webhooks": [{"url": "https://telegram-relay.internal/x"}]})
    assert len(relay.webhooks) == 1 and not relay.errors  # relay slack-compatível: não exige chat_id
    tg = C.parse_config({"targets": ["https://a.example"], "webhooks": [{"url": "https://api.telegram.org/bot1:A/sendMessage"}]})
    assert not tg.webhooks and any("telegram_chat_id" in e.lower() or "Telegram" in e for e in tg.errors)


# ---- 10. métrica de expiração não fica velha quando o certificado deixa de ser observado ---------------------------------------------
def _series(target):
    text = E.render_prometheus_metrics()[0].decode()
    return [ln for ln in text.splitlines() if f'target="{target}"' in ln and ln.startswith("probe_ssl_earliest_cert_expiry")]


def test_cert_expiry_series_is_removed_when_tls_is_no_longer_observed(mk):
    t = "https://stale-expiry.example"
    E.record_probe_metrics(mk(t))
    assert _series(t), "pré-condição: a série deveria existir com TLS válido"
    http_only = mk(t)
    http_only.tls = None  # último salto http / TLS não inspecionado, mas com resposta (status_code definido)
    E.record_probe_metrics(http_only)
    assert not _series(t), "série de expiração obsoleta continua exportada"
