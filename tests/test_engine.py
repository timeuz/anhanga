import socket
from datetime import datetime, timezone

import httpx
import pytest

from anhanga.cli import evaluate_probe_gates, main as cli_main
from anhanga.engine import probe as P
from anhanga.engine import webhooks as W
from anhanga.engine.models import ProbeResult, classify_error_message
from anhanga.engine.security import _audit_cookies, audit_http_security, parse_tls_certificate
from anhanga.metrics import exporter as E


# ---------- modelo / health / erros ----------
def test_health_states(mk):
    assert mk().health == "up"
    assert mk(tls_valid=False, tls_days=-2).health == "degraded"
    assert mk(up=False, status=503).health == "down"
    assert mk(up=False, status=None, error="x").health == "down"
    assert mk("http://plain.example").health == "up"  # sem TLS não há o que invalidar


@pytest.mark.parametrize(
    "msg,code",
    [
        ("Bloqueado pelo Guardião Anti-SSRF: x", "ssrf_blocked"),
        ("URL inválida: x", "invalid_url"),
        ("Erro de DNS: x", "dns_error"),
        ("Timeout rígido excedido", "timeout"),
        ("Falha em Content Assertion: x", "assertion_failed"),
        ("Erro HTTP/Conexão: [SSL: HANDSHAKE_FAILURE]", "tls_error"),
        ("Erro HTTP/Conexão: All connection attempts failed", "connect_error"),
    ],
)
def test_error_classification(msg, code):
    assert classify_error_message(msg) == code


# ---------- probe: helpers ----------
def test_hostname_validation():
    ok = ["example.com", "a-b.example.org", "localhost", "127.0.0.1", "[::1]", "intranet"]
    bad = ["bad_host!.com", "-x.com", "a..b", "x" * 300 + ".com", "sp ace.com"]
    assert all(P._validate_hostname_syntax(h) is None for h in ok)
    assert all(P._validate_hostname_syntax(h) for h in bad)


def test_dns_error_messages_are_consistent():
    nx = P._format_dns_error(socket.gaierror(socket.EAI_NONAME, "x"), "foo.invalid")
    again = P._format_dns_error(socket.gaierror(socket.EAI_AGAIN, "x"), "foo.invalid")
    assert nx.startswith("Erro de DNS:") and "NXDOMAIN" in nx
    assert again.startswith("Erro de DNS:") and "temporária" in again
    assert P._format_dns_error(TimeoutError(), "h").startswith("Erro de DNS: tempo esgotado")


def test_regex_isolation_kills_catastrophic_pattern():
    assert P._regex_search_isolated("a+", "caaat") == ("ok", True)
    assert P._regex_search_isolated("zzz", "caaat") == ("ok", False)
    assert P._regex_search_isolated("(", "x")[0] == "invalid"
    assert P._regex_search_isolated("a" * 600, "x")[0] == "invalid"
    assert P._regex_search_isolated("(a+)+$", "a" * 40 + "!")[0] == "timeout"  # ~2 s


# ---------- TLS ----------
class FakeSSL:
    def __init__(self, not_after="Apr 12 23:59:59 2015 GMT", not_before="Apr  9 00:00:00 2015 GMT"):
        self._cert = {
            "notBefore": not_before,
            "notAfter": not_after,
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


def test_expired_cert_has_negative_days_and_reason():
    tls = parse_tls_certificate(FakeSSL(), verified=False)
    assert tls.valid is False and tls.days_remaining < -1000
    assert tls.validation_error == "certificado expirado"
    assert tls.relative_validity_percent_remaining == 0.0 and tls.alert_expiring


def test_verification_reason_is_propagated():
    tls = parse_tls_certificate(FakeSSL(), verified=False, validation_error="Hostname mismatch")
    assert tls.validation_error == "Hostname mismatch"


def test_ocsp_unknown_is_never_reported_as_absent():
    assert parse_tls_certificate(FakeSSL(), ocsp_stapled=None).ocsp_stapling is None
    assert parse_tls_certificate(FakeSSL(), ocsp_stapled=True).ocsp_stapling is True
    assert parse_tls_certificate(FakeSSL(), ocsp_stapled=False).ocsp_stapling is False


def test_chain_from_openssl_fallback_absent_means_empty_not_invented():
    tls = parse_tls_certificate(FakeSSL())
    assert tls.cert_chain == [] and tls.chain_source is None


# ---------- heurísticas de segurança ----------
def _audit(headers):
    return audit_http_security(httpx.Headers(headers), True, None)


def test_server_header_leak_only_with_version():
    assert _audit({"Server": "cloudflare"}).leaked_tech == []
    assert _audit({"Server": "github.com"}).leaked_tech == []
    assert _audit({"Server": "nginx/1.18.0"}).leaked_tech == ["Server: nginx/1.18.0"]
    assert _audit({"X-Powered-By": "Express"}).leaked_tech == ["X-Powered-By: Express"]


def test_httponly_only_required_for_session_cookies():
    h = httpx.Headers(
        [("set-cookie", "_ga=1; Secure; SameSite=Lax"), ("set-cookie", "sessionid=abc; Secure; SameSite=Lax")]
    )
    ga, sess = _audit_cookies(h, True)
    assert ga.issues == [] and not ga.sensitive
    assert sess.sensitive and any("HttpOnly" in i for i in sess.issues)


# ---------- gates do CLI ----------
def test_gate_fails_on_invalid_cert_unless_opted_out(mk):
    bad = mk(tls_valid=False, tls_days=-1)
    assert evaluate_probe_gates(bad)[1] == 1
    assert evaluate_probe_gates(bad, require_valid_cert=False)[1] == 0
    assert evaluate_probe_gates(mk())[1] == 0


def test_cli_argument_errors_exit_3_before_any_network():
    assert cli_main(["check", "https://x.example", "--min-grade", "Z"]) == 3
    assert cli_main(["check", "https://x.example", "--max-ttfb", "abc"]) == 3
    assert cli_main(["check"]) == 3


# ---------- webhooks ----------
def test_webhook_event_labels_and_violations(mk):
    assert "RECUPERADO" in W.build_slack_payload(mk(), ["ok"], event="recovery")["text"]
    assert "LEMBRETE" in W.build_slack_payload(mk(up=False, status=None), ["x"], event="reminder")["text"]
    assert "RECUPERADO" in W.build_telegram_payload(mk(), ["ok"], chat_id="1", event="recovery")["text"]
    teams = W.build_teams_payload(mk(), ["ok"], event="recovery")
    assert teams["themeColor"] == "10B981" and "RECUPERADO" in teams["sections"][0]["activitySubtitle"]
    v = W._collect_violations(mk(tls_valid=False, tls_days=-10))
    assert any("inválido" in x for x in v) and any("expirado há 10" in x for x in v)


# ---------- exporter ----------
def _series(target):
    text = E.render_prometheus_metrics()[0].decode()
    return [ln for ln in text.splitlines() if f'target="{target}"' in ln and not ln.startswith("#")]


def test_offline_target_exports_no_fake_zero_series(mk):
    t = "https://exporter-offline.example"
    E.record_probe_metrics(mk(t))  # primeiro online: cria séries
    assert any(l.startswith("probe_duration_seconds") for l in _series(t))
    E.record_probe_metrics(mk(t, up=False, status=None, error="x"))
    names = {l.split("{")[0] for l in _series(t)}
    assert "probe_success" in names and "anhanga_probe_up" in names
    assert "probe_duration_seconds" not in names and "anhanga_probe_security_score" not in names


def test_degraded_target_probe_success_zero_and_negative_days(mk):
    t = "https://exporter-degraded.example"
    E.record_probe_metrics(mk(t, tls_valid=False, tls_days=-30))
    lines = _series(t)
    assert any(l.startswith("probe_success") and l.endswith(" 0.0") for l in lines)
    assert any(l.startswith("anhanga_probe_up") and l.endswith(" 1.0") for l in lines)
    assert any(l.startswith("anhanga_probe_tls_valid") and l.endswith(" 0.0") for l in lines)
    assert any("tls_cert_expiry_days" in l and l.endswith(" -30.0") for l in lines)


def test_security_score_grade_label_has_no_stale_series(mk):
    t = "https://exporter-grade.example"
    E.record_probe_metrics(mk(t, grade="A"))
    E.record_probe_metrics(mk(t, grade="F"))
    grades = [l for l in _series(t) if l.startswith("anhanga_probe_security_score")]
    assert len(grades) == 1 and 'grade="F"' in grades[0]


def test_offline_alert_payload_has_no_fake_zero_metrics(mk):
    r = mk(up=False, status=None, error="conexão recusada")
    for payload in (
        W.build_slack_payload(r, ["x"])["text"],
        str(W.build_teams_payload(r, ["x"])),
        W.build_telegram_payload(r, ["x"], chat_id="1")["text"],
    ):
        assert "N/D" in payload and "0.00" not in payload and "(0/100)" not in payload


def test_regex_isolation_independent_of_how_parent_was_launched():
    """Regressão: com multiprocessing/spawn quebrava quando o pai rodava via `python -` / `-c`."""
    import subprocess
    import sys

    code = "from anhanga.engine.probe import _regex_search_isolated as r; print(r('a+', 'caat'))"
    out = subprocess.run([sys.executable, "-"], input=code, capture_output=True, text=True, timeout=30)
    assert out.stdout.strip() == "('ok', True)", out.stderr


def test_forget_target_removes_every_series_including_counters_and_histograms(mk):
    t, other = "https://forget-me.example", "https://keep-me.example"
    E.record_probe_metrics(mk(t))
    E.record_probe_metrics(mk(other))
    assert any("anhanga_probe_executions_total" in l for l in _series(t))
    assert any("duration_seconds_histogram_bucket" in l for l in _series(t))
    E.forget_target(t)
    assert _series(t) == []
    assert _series(other)  # não afeta os demais
