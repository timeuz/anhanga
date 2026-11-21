"""idioma dos textos do backend: pt-BR por padrão, en-US sob demanda."""

import asyncio
import re

import httpx
import pytest

from anhanga.engine.models import classify_error_message
from anhanga.engine.probe import execute_probe
from anhanga.engine.security import audit_http_security
from anhanga.i18n import LStr, get_lang, reset_lang, set_lang, tr, tx

# acento ou palavra funcional do português: não pode sobrar em texto inglês
_PT = re.compile(r"[áéíóúãõçâêô]|\b(não|para|com|sem|erro|falha|ausente|servidor|alvo|deve|está)\b", re.I)


@pytest.fixture()
def english():
    token = set_lang("en-US")
    yield
    reset_lang(token)


def test_default_language_is_portuguese_and_switches_per_context(monkeypatch):
    monkeypatch.delenv("ANHANGA_LANG", raising=False)
    assert get_lang() == "pt-BR"
    assert tr("a", "b") == "a"
    token = set_lang("en-US,en;q=0.9")
    try:
        assert tr("a", "b") == "b"
    finally:
        reset_lang(token)
    assert tr("a", "b") == "a"


def test_env_var_sets_the_process_default(monkeypatch):
    monkeypatch.setenv("ANHANGA_LANG", "en")
    assert tr("a", "b") == "b"
    token = set_lang("pt-BR")  # o pedido pode pedir pt mesmo com o padrão em inglês
    try:
        assert tr("a", "b") == "a"
    finally:
        reset_lang(token)


def test_lstr_is_a_plain_str_with_an_english_twin(monkeypatch):
    monkeypatch.delenv("ANHANGA_LANG", raising=False)
    text = LStr("oi", "hi")
    assert text == "oi" and isinstance(text, str)
    assert tx(text) == "oi"
    assert tx(None) is None
    token = set_lang("en-US")
    try:
        assert tx(text) == "hi"
    finally:
        reset_lang(token)


@pytest.mark.parametrize(
    "pt,en,code",
    [
        ("Bloqueado pelo Guardião Anti-SSRF: IP privado (1.2.3.4).", "Blocked by the Anti-SSRF guard: private IP (1.2.3.4).", "ssrf_blocked"),
        ("URL inválida: vazia.", "Invalid URL: empty.", "invalid_url"),
        ("Erro de DNS: tempo esgotado", "DNS error: timed out", "dns_error"),
        ("Timeout rígido excedido (5s)", "Hard timeout exceeded (5s)", "timeout"),
        ("Falha em Content Assertion: x", "Content assertion failed: x", "assertion_failed"),
        ("Limite máximo de redirecionamentos (10) excedido.", "Maximum number of redirects (10) exceeded.", "redirect_loop"),
        ("Erro HTTP/Conexão: boom", "HTTP/Connection error: boom", "connect_error"),
    ],
)
def test_error_code_is_the_same_in_both_languages(pt, en, code):
    assert classify_error_message(pt) == code
    assert classify_error_message(en) == code


def test_probe_errors_come_back_in_english_with_the_same_error_code(english):
    result = asyncio.run(execute_probe("ftp://example.com"))
    assert result.error_code == "ssrf_blocked"
    assert result.error.startswith("Blocked by the Anti-SSRF guard")
    assert not _PT.search(result.error)

    bad = asyncio.run(execute_probe("http://exa mple.com"))
    assert bad.error_code == "invalid_url"
    assert bad.error.startswith("Invalid URL")


def test_security_findings_have_no_portuguese_left_in_english(english):
    headers = httpx.Headers(
        {
            "Server": "nginx/1.18.0",
            "X-Powered-By": "PHP/7.4",
            "Set-Cookie": "sessionid=abc; Path=/",
            "Content-Security-Policy-Report-Only": "default-src *",
        }
    )
    audit = audit_http_security(headers, is_https=True, tls=None)
    assert audit.missing_findings
    for finding in audit.missing_findings:
        for text in (finding.header, finding.description, finding.remediation, finding.safe_default or ""):
            assert not _PT.search(text), f"{finding.id}: {text}"
        for step in finding.progressive_steps or []:
            assert not _PT.search(" ".join(step.values())), finding.id
    for cookie in audit.cookies_audited:
        assert not any(_PT.search(i) for i in cookie.issues)


def test_security_findings_stay_in_portuguese_by_default(monkeypatch):
    monkeypatch.delenv("ANHANGA_LANG", raising=False)
    audit = audit_http_security(httpx.Headers({}), is_https=True, tls=None)
    assert any("Força o navegador" in f.description for f in audit.missing_findings)


def test_api_follows_accept_language_for_errors():
    from fastapi.testclient import TestClient

    import anhanga.main as app_main

    client = TestClient(app_main.app, base_url="http://localhost", client=("127.0.0.1", 50000))
    pt = client.get("/api/v1/scan", params={"url": "ftp://x.com"})
    en = client.get("/api/v1/scan", params={"url": "ftp://x.com"}, headers={"Accept-Language": "en-US"})
    via_param = client.get("/api/v1/scan", params={"url": "ftp://x.com", "lang": "en-US"})
    assert pt.status_code == en.status_code == via_param.status_code == 403
    assert pt.json()["detail"]["error_code"] == en.json()["detail"]["error_code"] == "ssrf_blocked"
    assert pt.json()["detail"]["message"].startswith("Bloqueado")
    assert en.json()["detail"]["message"].startswith("Blocked")
    assert via_param.json()["detail"]["message"].startswith("Blocked")


def test_alert_messages_and_webhook_dedup_work_in_english(english):
    from anhanga.engine.alerting import PROBLEM_LABELS, detect_problems
    from anhanga.engine.config import SLORules
    from anhanga.engine.models import ProbeResult
    from anhanga.engine.webhooks import build_slack_payload

    result = ProbeResult(target_url="https://x.test", error="boom")
    problems = detect_problems(result, SLORules())
    assert problems["down"].startswith("Target OFFLINE")
    assert tx(PROBLEM_LABELS["down"]) == "Target offline"
    text = str(build_slack_payload(result, violations=list(problems.values())))
    assert text.count("Target OFFLINE") >= 1 and "Alvo OFFLINE" not in text
