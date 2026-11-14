import httpx
import pytest

from anhanga.engine.csp import analyze_csp
from anhanga.engine.security import audit_http_security

STRICT = "default-src 'none'; script-src 'self' 'nonce-abc123' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'"


def ids(csp, ro=None):
    return {i.id for i in analyze_csp(csp, ro).issues}


def test_absent_and_strong():
    assert analyze_csp(None, None).strength == "none" and not analyze_csp("", "").present
    a = analyze_csp(STRICT, None)
    assert a.strength == "strong" and a.issues == [] and a.uses_nonce_or_hash and a.strict_dynamic and a.enforced


@pytest.mark.parametrize(
    "policy,expected_id,severity",
    [
        ("default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'", "csp-unsafe-inline", "high"),
        ("script-src 'self' *; object-src 'none'; base-uri 'self'", "csp-wildcard", "high"),
        ("script-src 'self' http:; object-src 'none'; base-uri 'self'", "csp-http-scheme", "high"),
        ("script-src 'self' data:; object-src 'none'; base-uri 'self'", "csp-data-scheme", "high"),
        ("img-src 'self'; object-src 'none'; base-uri 'self'", "csp-no-script-src", "high"),
        ("script-src 'self' 'unsafe-eval'; object-src 'none'; base-uri 'self'", "csp-unsafe-eval", "medium"),
        ("script-src 'self' https:; object-src 'none'; base-uri 'self'", "csp-https-scheme", "medium"),
        ("script-src 'self' https://cdnjs.cloudflare.com; object-src 'none'; base-uri 'self'", "csp-bypass-host", "medium"),
        ("script-src 'self' https://x.googleapis.com; object-src 'none'; base-uri 'self'", "csp-bypass-host", "medium"),
        ("script-src 'self'; base-uri 'self'", "csp-object-src", "medium"),
        ("script-src 'self'; object-src 'self'; base-uri 'self'", "csp-object-src", "medium"),
        ("script-src 'self'; object-src 'none'", "csp-base-uri", "low"),
    ],
)
def test_each_weakness_is_detected(policy, expected_id, severity):
    got = {i.id: i.severity for i in analyze_csp(policy, None).issues}
    assert got.get(expected_id) == severity, got


def test_strength_levels():
    assert analyze_csp("script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'", None).strength == "weak"
    assert analyze_csp("script-src 'self' 'unsafe-eval'; object-src 'none'; base-uri 'self'", None).strength == "moderate"
    assert analyze_csp("script-src 'self'; object-src 'none'; base-uri 'self'", None).strength == "strong"


def test_unsafe_inline_is_neutralized_by_nonce_or_hash():
    assert "csp-unsafe-inline" not in ids("script-src 'unsafe-inline' 'nonce-xyz'; object-src 'none'; base-uri 'none'")
    assert "csp-unsafe-inline" not in ids("script-src 'unsafe-inline' 'sha256-abc='; object-src 'none'; base-uri 'none'")
    assert "csp-unsafe-inline" in ids("script-src 'unsafe-inline'; object-src 'none'; base-uri 'none'")


def test_default_src_is_the_fallback_for_scripts_and_objects():
    assert "csp-unsafe-inline" in ids("default-src 'self' 'unsafe-inline'; base-uri 'self'")
    assert "csp-object-src" in ids("default-src 'self'; base-uri 'self'")  # default-src 'self' não restringe plugins
    assert "csp-object-src" not in ids("default-src 'none'; script-src 'self'; base-uri 'self'")


def test_strict_dynamic_makes_host_lists_and_https_irrelevant():
    assert "csp-bypass-host" not in ids("script-src 'nonce-a' 'strict-dynamic' https://cdnjs.cloudflare.com; object-src 'none'; base-uri 'none'")
    assert "csp-https-scheme" not in ids("script-src 'nonce-a' 'strict-dynamic' https:; object-src 'none'; base-uri 'none'")


def test_script_src_none_has_no_script_issues():
    assert ids("script-src 'none'; object-src 'none'; base-uri 'none'") == set()


def test_first_occurrence_of_a_directive_wins():
    assert "csp-unsafe-inline" not in ids("script-src 'self'; script-src 'unsafe-inline'; object-src 'none'; base-uri 'self'")


def test_report_only_is_not_enforcement():
    a = analyze_csp(None, STRICT)
    assert a.present and not a.enforced and a.strength == "report-only"
    assert a.issues[0].id == "csp-report-only"


def test_multiple_policies_are_conjunctive():
    """Uma fraqueza só vale se TODAS as políticas a tiverem: outra política bloquearia."""
    weak = "script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'"
    tight = "script-src 'self'; object-src 'none'; base-uri 'self'"
    assert "csp-unsafe-inline" not in ids(f"{weak}, {tight}")
    assert "csp-unsafe-inline" in ids(f"{weak}, {weak}")
    assert analyze_csp(f"{weak}, {tight}", None).policies == 2


# ---------- integração com a pontuação ----------
def _audit(headers):
    return audit_http_security(httpx.Headers(headers), True, None)


def test_report_only_no_longer_earns_csp_points():
    only_ro = _audit({"Content-Security-Policy-Report-Only": STRICT})
    none = _audit({})
    enforced = _audit({"Content-Security-Policy": STRICT})
    assert only_ro.headers_score == none.headers_score  # antes: ganhava a nota cheia
    assert enforced.headers_score == none.headers_score + 15
    ro_finding = next(f for f in only_ro.missing_findings if f.id == "SEC-CSP")
    assert "Report-Only" in ro_finding.description
    assert only_ro.csp_analysis.strength == "report-only"


def test_score_is_proportional_to_csp_quality():
    strong = _audit({"Content-Security-Policy": STRICT})
    moderate = _audit({"Content-Security-Policy": "script-src 'self' 'unsafe-eval'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"})
    weak = _audit({"Content-Security-Policy": "default-src * 'unsafe-inline'; frame-ancestors 'self'"})
    assert strong.headers_score > moderate.headers_score > weak.headers_score
    assert not any(f.id == "SEC-CSP-WEAK" for f in strong.missing_findings)
    wf = next(f for f in weak.missing_findings if f.id == "SEC-CSP-WEAK")
    assert wf.severity == "high" and "unsafe-inline" in wf.description and wf.snippets
    assert weak.csp_analysis.strength == "weak"


def test_weak_csp_cannot_reach_top_grade():
    # um site "perfeito" exceto por uma CSP com unsafe-inline não pode manter A+
    perfect = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=(), microphone=()",
    }
    a = _audit({**perfect, "Content-Security-Policy": STRICT})
    b = _audit({**perfect, "Content-Security-Policy": "default-src 'self' 'unsafe-inline'; frame-ancestors 'self'"})
    assert a.score > b.score
