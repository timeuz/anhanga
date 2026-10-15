import ipaddress
from datetime import datetime, timezone
import httpx
from anhanga.engine.models import SecurityAudit, SecurityFinding, TLSInspection

SECURITY_HEADERS_DETAILS = {
    "Strict-Transport-Security": {
        "weight": 25,
        "desc": "Força o navegador a usar HTTPS estritamente, prevenindo ataques de Downgrade SSL.",
        "fix": 'add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;'
    },
    "Content-Security-Policy": {
        "weight": 25,
        "desc": "Controla quais fontes de scripts e imagens podem ser executadas, mitigando XSS.",
        "fix": "add_header Content-Security-Policy \"default-src 'self'\" always;"
    },
    "X-Content-Type-Options": {
        "weight": 15,
        "desc": "Previne que o browser faça MIME-sniffing e execute arquivos com tipos incorretos.",
        "fix": 'add_header X-Content-Type-Options "nosniff" always;'
    },
    "X-Frame-Options": {
        "weight": 15,
        "desc": "Protege a aplicação contra ataques de Clickjacking (embebimento em iframes maliciosos).",
        "fix": 'add_header X-Frame-Options "SAMEORIGIN" always;'
    },
    "Referrer-Policy": {
        "weight": 10,
        "desc": "Controla quanta informação de URL é passada no header Referer para terceiros.",
        "fix": 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;'
    },
    "Permissions-Policy": {
        "weight": 10,
        "desc": "Restringe o acesso a APIs sensíveis do navegador (câmera, geolocalização, microfone).",
        "fix": 'add_header Permissions-Policy "geolocation=(), microphone=()" always;'
    },
}

LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

def is_ssrf_safe(ip_str: str, allow_private: bool = False) -> bool:
    if allow_private:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)
    except ValueError:
        return False

def parse_tls_certificate(ssl_obj) -> TLSInspection:
    if not ssl_obj:
        return TLSInspection(valid=False)

    cert = ssl_obj.getpeercert()
    cipher_info = ssl_obj.cipher()
    protocol = ssl_obj.version()

    issuer_dict = dict(x[0] for x in cert.get("issuer", []))
    subject_dict = dict(x[0] for x in cert.get("subject", []))

    not_after_str = cert.get("notAfter")
    expires_at = None
    days_remaining = None
    if not_after_str:
        expires_at = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        delta = expires_at - datetime.now(timezone.utc)
        days_remaining = max(0, delta.days)

    return TLSInspection(
        valid=True,
        protocol=protocol,
        cipher=cipher_info[0] if cipher_info else None,
        issuer=issuer_dict.get("organizationName") or issuer_dict.get("commonName"),
        subject=subject_dict.get("commonName"),
        expires_at=expires_at,
        days_remaining=days_remaining,
        alert_expiring=(days_remaining is not None and days_remaining < 15),
    )

def audit_http_security(headers: httpx.Headers, is_https: bool, tls: TLSInspection | None) -> SecurityAudit:
    score = 0
    present = {}
    missing_findings = []
    leaks = []

    if not is_https or (tls and not tls.valid):
        all_findings = [
            SecurityFinding(header=h, weight=info["weight"], description=info["desc"], remediation=info["fix"])
            for h, info in SECURITY_HEADERS_DETAILS.items()
        ]
        return SecurityAudit(grade="F", score=0, missing_findings=all_findings)

    for header, info in SECURITY_HEADERS_DETAILS.items():
        if header in headers:
            present[header] = headers[header]
            score += info["weight"]
        else:
            missing_findings.append(
                SecurityFinding(
                    header=header,
                    weight=info["weight"],
                    description=info["desc"],
                    remediation=info["fix"],
                )
            )

    for leak_h in LEAK_HEADERS:
        if leak_h in headers:
            leaks.append(f"{leak_h}: {headers[leak_h]}")
            score = max(0, score - 5)

    if tls and tls.protocol in ("TLSv1", "TLSv1.1"):
        score = min(score, 40)

    if score >= 95 and not leaks:
        grade = "A+"
    elif score >= 80:
        grade = "A"
    elif score >= 65:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 30:
        grade = "D"
    else:
        grade = "F"

    return SecurityAudit(
        grade=grade,
        score=score,
        present_headers=present,
        missing_findings=missing_findings,
        leaked_tech=leaks,
    )