"""2ª revisão da main, lote C. Cada teste falhava antes da sua correção."""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from anhanga import main as app_main
from anhanga.engine import config as C
from anhanga.engine import probe as P
from anhanga.engine.config import MonitorConfig, WebhookSpec
from anhanga.engine.security import parse_tls_certificate
from anhanga.metrics import exporter as E

BAD = ["https://[bad", "http://[::1", "https://[", "[bad]]/x"]


# ---- 1. URL malformada (colchete IPv6) nunca levanta: um typo no targets.yaml não pode desligar o monitor ------------------------------
@pytest.mark.parametrize("bad", BAD)
def test_malformed_target_url_is_a_config_error_not_an_exception(bad):
    cfg = C.parse_config({"targets": [bad, "https://ok.example"]})  # antes: ValueError: Invalid IPv6 URL
    assert [t.url for t in cfg.targets] == ["https://ok.example"]
    assert any("URL inválida" in e for e in cfg.errors)


@pytest.mark.parametrize("bad", BAD)
def test_malformed_webhook_url_is_a_config_error(bad):
    cfg = C.parse_config({"targets": ["https://ok.example"], "webhooks": [bad]})
    assert not cfg.webhooks and cfg.errors


def test_load_config_never_raises_even_on_an_unexpected_parser_error(tmp_path, monkeypatch):
    f = tmp_path / "t.yaml"
    f.write_text("targets: [https://a.example]\n")
    monkeypatch.setattr(C, "parse_config", lambda raw: (_ for _ in ()).throw(RuntimeError("boom")))
    cfg = C.load_config(f)
    assert cfg.load_failed and any("RuntimeError" in e for e in cfg.errors)


@pytest.mark.parametrize("bad", BAD)
def test_probe_of_a_malformed_url_returns_an_invalid_url_result(bad):
    r = asyncio.run(P.execute_probe(bad, timeout=2))
    assert r.error and "URL inválida" in r.error and r.error_code == "invalid_url"


def test_scan_endpoint_answers_400_for_a_malformed_url():
    c = TestClient(app_main.app, base_url="http://localhost", client=("127.0.0.1", 50000))
    r = c.get("/api/v1/scan", params={"url": "https://[bad"})
    assert r.status_code == 400, r.text


def test_metrics_for_a_malformed_target_do_not_raise(mk):
    res = mk("https://[bad", up=False, status=None, error="URL inválida")
    E.record_probe_metrics(res)  # _resolve_instance_label fazia urlparse sem proteção


# ---- 2. exceção no pós-processamento de um alvo não aborta o ciclo dos outros -----------------------------------------------------
def test_one_target_failing_postprocessing_does_not_blind_the_others(mk, monkeypatch):
    app_main.STATE_CACHE.clear()
    cfg = C.parse_config({"interval_seconds": 5, "targets": ["https://a.example", "https://b.example", "https://c.example"]})
    seen = []

    async def fake_probe(url, **kw):
        return mk(url)

    real_update = app_main._update_state_and_history

    def update(res, is_continuous=False):
        if res.target_url == "https://b.example":
            raise RuntimeError("resultado inesperado")
        seen.append(res.target_url)
        return real_update(res, is_continuous=is_continuous)

    monkeypatch.setattr(app_main, "_monitored_probe", fake_probe)
    monkeypatch.setattr(app_main, "_update_state_and_history", update)
    monkeypatch.setattr(app_main, "_config_path", lambda: None)
    monkeypatch.setattr(app_main, "load_config", lambda p: cfg)
    persisted = []

    async def fake_store_call(fn, *a, **k):
        persisted.append(a)

    monkeypatch.setattr(app_main, "_store_call", fake_store_call)
    monkeypatch.setattr(app_main, "_STORE", object())

    async def _open(cfg_, manager):
        return None

    monkeypatch.setattr(app_main, "_open_store", _open)

    async def scenario():
        task = asyncio.create_task(app_main.background_guardian_loop())
        await asyncio.sleep(0.6)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(scenario())
    assert "https://a.example" in seen and "https://c.example" in seen, f"ciclo abortado: {seen}"
    assert persisted, "o lote dos alvos saudáveis nunca foi persistido"


# ---- 3. expiração relativa à vida do certificado (vida curta não fica "expirando" para sempre) ------------------------------------------
class _Cert:
    def __init__(self, total_days, remaining_days):
        now = datetime.now(timezone.utc)
        fmt = "%b %d %H:%M:%S %Y GMT"
        self._cert = {
            "notBefore": (now + timedelta(days=remaining_days - total_days)).strftime(fmt),
            "notAfter": (now + timedelta(days=remaining_days)).strftime(fmt),
            "subject": ((("commonName", "x.example"),),),
            "issuer": ((("organizationName", "Acme CA"),),),
            "subjectAltName": (("DNS", "x.example"),),
        }

    def getpeercert(self, binary_form=False):
        return b"" if binary_form else self._cert

    def cipher(self):
        return ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)

    def version(self):
        return "TLSv1.3"


@pytest.mark.parametrize(
    "total, remaining, expected",
    [
        (6, 4.5, False),    # vida curta saudável: 4,5 de 6 dias restantes
        (6, 0.5, True),     # perto do fim da vida curta
        (47, 20, False),    # 47 dias, 20 restantes: saudável
        (47, 12, False),    # 47 dias, 12 restantes: ainda acima de 20% (9,4 d)
        (47, 8, True),
        (90, 30, False),
        (90, 16, False),    # 90 dias: o limiar continua sendo 15 dias
        (90, 14, True),
        (365, 16, False),
        (365, 14, True),
    ],
)
def test_expiring_threshold_follows_the_certificate_lifetime(total, remaining, expected):
    tls = parse_tls_certificate(_Cert(total, remaining), verified=True)
    assert tls.alert_expiring is expected, f"vida {total} d, restam {remaining} d"


def test_a_healthy_short_lived_certificate_does_not_open_a_tls_expiring_problem(mk):
    from anhanga.engine.alerting import detect_problems
    from anhanga.engine.config import SLORules

    res = mk()
    res.tls = parse_tls_certificate(_Cert(6, 4.0), verified=True)
    assert "tls_expiring" not in detect_problems(res, SLORules())


# ---- 4. /notify usa provider e chat_id do targets.yaml, nunca os do corpo ---------------------------------------------------------------
@pytest.fixture
def notify(monkeypatch, mk):
    spec_teams = WebhookSpec(url="https://hooks.proxy.example/teams", provider="teams", chat_id=None, allow_private=False)
    spec_tg = WebhookSpec(url="https://relay.example/tg", provider="telegram", chat_id="-100CONFIGURADO", allow_private=False)
    spec_auto = WebhookSpec(url="https://relay.example/auto", provider="auto", chat_id=None, allow_private=False)
    monkeypatch.setattr(app_main, "_CONFIG", MonitorConfig(webhooks=[spec_teams, spec_tg, spec_auto]))
    app_main.STATE_CACHE["https://t.example"] = mk("https://t.example")
    sent = []

    async def fake_send(**kw):
        sent.append(kw)
        return {"ok": True}

    monkeypatch.setattr(app_main, "send_webhook_alert", fake_send)
    client = TestClient(app_main.app, base_url="http://localhost", client=("127.0.0.1", 50000))
    return client, sent


def _post(client, hook, **extra):
    return client.post("/api/v1/webhooks/notify", json={"webhook_url": hook, "url": "https://t.example", **extra})


def test_notify_uses_the_configured_provider(notify):
    client, sent = notify
    assert _post(client, "https://hooks.proxy.example/teams").status_code == 200
    assert sent[0]["provider"] == "teams", "um webhook 'provider: teams' caía no payload Slack (provider=auto do corpo)"


def test_notify_uses_the_configured_telegram_chat_id(notify):
    client, sent = notify
    assert _post(client, "https://relay.example/tg").status_code == 200
    assert sent[0]["chat_id"] == "-100CONFIGURADO" and sent[0]["provider"] == "telegram"


def test_notify_rejects_a_request_chat_id_that_differs_from_the_configured_one(notify):
    client, sent = notify
    r = _post(client, "https://relay.example/tg", chat_id="-100DO-ATACANTE")
    assert r.status_code == 400 and not sent, "quem tem a chave escolheu o chat de destino do bot"


def test_notify_rejects_a_conflicting_provider(notify):
    client, sent = notify
    assert _post(client, "https://hooks.proxy.example/teams", provider="slack").status_code == 400 and not sent


def test_notify_accepts_matching_values_and_lets_auto_webhooks_pick_the_format(notify):
    client, sent = notify
    assert _post(client, "https://relay.example/tg", chat_id="-100CONFIGURADO", provider="telegram").status_code == 200
    assert _post(client, "https://relay.example/auto", provider="teams").status_code == 200
    assert sent[-1]["provider"] == "teams"
