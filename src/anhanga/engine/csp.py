"""Análise de qualidade da Content-Security-Policy (puro, sem I/O).

Uma CSP só protege se não for trivialmente contornável. Avalia as regras que mais importam na prática
(baseadas na orientação "strict CSP" do Google e no CSP Evaluator):

  high   script-src/default-src ausente, 'unsafe-inline' sem nonce/hash, '*', 'http:', 'data:'
  medium 'unsafe-eval', 'https:' genérico, object-src não 'none', host conhecido por bypass (JSONP/CDN),
         política apenas em Report-Only
  low    base-uri ausente

Várias políticas (cabeçalhos repetidos ou separados por vírgula) são conjuntivas: uma fraqueza só some se
OUTRA política restringe a mesma coisa. Política sem `script-src`/`default-src` não restringe scripts.
"""

from __future__ import annotations

import re

from anhanga.engine.models import CSPAnalysis, CSPIssue

# hosts que servem JSONP ou bibliotecas com gadgets de execução: liberar eles no script-src derruba a proteção.
BYPASS_HOSTS = (
    "ajax.googleapis.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com", "www.google.com",
    "accounts.google.com", "raw.githubusercontent.com", "*.googleapis.com", "*.cloudfront.net",
    "*.amazonaws.com", "*.herokuapp.com", "*.firebaseapp.com", "*.appspot.com",
)
_NONCE_OR_HASH = re.compile(r"^'(nonce-[^']+|sha(256|384|512)-[^']+)'$", re.I)


def _parse(policy: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in policy.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        directives.setdefault(name, tokens[1:])  # primeira ocorrência vale (como nos navegadores)
    return directives


def _host_of(token: str) -> str:
    t = re.sub(r"^[a-z][a-z0-9+.-]*://", "", token.lower())
    return t.split("/", 1)[0].split(":", 1)[0]


def _analyze_policy(policy: str) -> tuple[list[CSPIssue], bool, bool]:
    d = _parse(policy)
    issues: list[CSPIssue] = []

    script_name = "script-src" if "script-src" in d else ("default-src" if "default-src" in d else None)
    sources = [t for t in d.get(script_name or "", [])]
    low = [t.lower() for t in sources]
    has_nonce_hash = any(_NONCE_OR_HASH.match(t) for t in sources)
    strict_dynamic = "'strict-dynamic'" in low

    def add(id_: str, sev: str, directive: str, msg: str) -> None:
        issues.append(CSPIssue(id=id_, severity=sev, directive=directive, message=msg))  # type: ignore[arg-type]

    if script_name is None:
        add("csp-no-script-src", "high", "script-src",
            "Sem script-src nem default-src: scripts de qualquer origem podem executar.")
    elif "'none'" not in low:
        if "'unsafe-inline'" in low and not has_nonce_hash:
            add("csp-unsafe-inline", "high", script_name,
                "'unsafe-inline' sem nonce/hash permite scripts inline: anula a proteção contra XSS.")
        if "'unsafe-eval'" in low:
            add("csp-unsafe-eval", "medium", script_name, "'unsafe-eval' permite eval()/new Function() (vetor de XSS).")
        if "*" in low:
            add("csp-wildcard", "high", script_name, "O curinga '*' permite carregar scripts de qualquer host.")
        if "http:" in low:
            add("csp-http-scheme", "high", script_name, "'http:' permite scripts em texto claro (interceptáveis).")
        if "data:" in low:
            add("csp-data-scheme", "high", script_name, "'data:' em script-src permite executar scripts embutidos em URL.")
        if "https:" in low and not strict_dynamic:
            add("csp-https-scheme", "medium", script_name,
                "'https:' genérico permite scripts de qualquer host HTTPS; liste hosts explícitos.")
        if not strict_dynamic:
            for token in sources:
                host = _host_of(token)
                if host in BYPASS_HOSTS or any(
                    b.startswith("*.") and host.endswith(b[1:]) and host != b[2:] for b in BYPASS_HOSTS
                ):
                    add("csp-bypass-host", "medium", script_name,
                        f"'{token}' hospeda JSONP/bibliotecas que permitem contornar a CSP.")
                    break

    obj = d.get("object-src", d.get("default-src"))
    if obj is None or [t.lower() for t in obj] != ["'none'"]:
        add("csp-object-src", "medium", "object-src",
            "object-src deveria ser 'none' (plugins/<object> são um vetor clássico de bypass).")
    if "base-uri" not in d:
        add("csp-base-uri", "low", "base-uri", "Sem base-uri: uma tag <base> injetada pode redirecionar URLs relativas.")
    return issues, has_nonce_hash, strict_dynamic


def _split_policies(value: str | None) -> list[str]:
    # cabeçalhos repetidos chegam unidos por ", " (httpx); políticas distintas são conjuntivas
    return [p.strip() for p in (value or "").split(",") if p.strip()]


_SCRIPT_IDS = frozenset({
    "csp-no-script-src", "csp-unsafe-inline", "csp-unsafe-eval", "csp-wildcard", "csp-http-scheme",
    "csp-data-scheme", "csp-https-scheme", "csp-bypass-host",
})


def _combine_policies(per_policy: list[list[CSPIssue]]) -> list[CSPIssue]:
    """Políticas conjuntivas: um recurso só é permitido se TODAS permitirem.

    - object-src / base-uri: a fraqueza some se QUALQUER política os restringe (interseção por id).
    - scripts: uma política SEM script-src/default-src não restringe nada (não neutraliza a fraqueza de outra),
      então só as que definem scripts contam; a fraqueza vale se todas essas a tiverem. Se nenhuma define
      scripts, vale o `csp-no-script-src`."""
    defining = [iss for iss in per_policy if not any(i.id == "csp-no-script-src" for i in iss)]
    if defining:
        script_ids = set.intersection(*[{i.id for i in iss} & _SCRIPT_IDS for iss in defining])
        script_issues = [i for i in defining[0] if i.id in script_ids]
    else:
        script_issues = [i for i in per_policy[0] if i.id == "csp-no-script-src"]
    other_ids = set.intersection(*[{i.id for i in iss} - _SCRIPT_IDS for iss in per_policy])
    return script_issues + [i for i in per_policy[0] if i.id in other_ids]


def analyze_csp(enforced: str | None, report_only: str | None) -> CSPAnalysis:
    enforced_policies = _split_policies(enforced)
    ro_policies = _split_policies(report_only)
    if not enforced_policies and not ro_policies:
        return CSPAnalysis(present=False, strength="none")

    policies = enforced_policies or ro_policies
    per_policy = [_analyze_policy(p) for p in policies]
    issues = _combine_policies([iss for iss, _, _ in per_policy])
    nonce_hash = any(n for _, n, _ in per_policy)
    strict_dynamic = any(sd for _, _, sd in per_policy)

    if not enforced_policies:
        issues.insert(0, CSPIssue(
            id="csp-report-only", severity="medium", directive="Content-Security-Policy-Report-Only",
            message="A política está apenas em modo Report-Only: reporta violações, mas não bloqueia nada.",
        ))
        strength = "report-only"
    elif any(i.severity == "high" for i in issues):
        strength = "weak"
    elif any(i.severity == "medium" for i in issues):
        strength = "moderate"
    else:
        strength = "strong"
    return CSPAnalysis(
        present=True, enforced=bool(enforced_policies), strength=strength, issues=issues,
        uses_nonce_or_hash=nonce_hash, strict_dynamic=strict_dynamic, policies=len(policies),
    )
