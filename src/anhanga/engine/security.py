import asyncio
import hashlib
import ipaddress
import os
import re
import socket
import ssl
import tempfile
import warnings
from datetime import datetime, timezone
from typing import Any

import httpx

from anhanga.engine.models import (
    CookieAuditItem,
    SecurityAudit,
    SecurityFinding,
    TLSInspection,
)

SECURITY_HEADERS_DETAILS: dict[str, dict[str, Any]] = {
    "Strict-Transport-Security": {
        "id": "SEC-HSTS",
        "severity": "high",
        "weight": 25,
        "desc": "Força o navegador a usar HTTPS estritamente, prevenindo ataques de Downgrade SSL e MITM.",
        "fix": 'add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;',
    },
    "Content-Security-Policy": {
        "id": "SEC-CSP",
        "severity": "high",
        "weight": 25,
        "desc": "Controla quais fontes de scripts e imagens podem ser executadas, mitigando XSS e Clickjacking.",
        "fix": "add_header Content-Security-Policy \"default-src 'self'; frame-ancestors 'self'\" always;",
    },
    "X-Content-Type-Options": {
        "id": "SEC-XCTO",
        "severity": "medium",
        "weight": 15,
        "desc": "Previne que o browser faça MIME-sniffing e execute arquivos com tipos incorretos.",
        "fix": 'add_header X-Content-Type-Options "nosniff" always;',
    },
    "X-Frame-Options": {
        "id": "SEC-XFO",
        "severity": "medium",
        "weight": 15,
        "desc": "Protege a aplicação contra ataques de Clickjacking (embebimento em iframes maliciosos).",
        "fix": 'add_header X-Frame-Options "SAMEORIGIN" always;',
    },
    "Referrer-Policy": {
        "id": "SEC-REFPOL",
        "severity": "low",
        "weight": 10,
        "desc": "Controla quanta informação de URL é passada no header Referer para terceiros.",
        "fix": 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
    },
    "Permissions-Policy": {
        "id": "SEC-PERMPOL",
        "severity": "low",
        "weight": 10,
        "desc": "Restringe o acesso a APIs sensíveis do navegador (câmera, geolocalização, microfone).",
        "fix": 'add_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;',
    },
}

LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]


def is_ssrf_safe(ip_str: str, allow_private: bool = False) -> bool:
    if allow_private:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
        if getattr(ip, "ipv4_mapped", None) is not None:
            ip = ip.ipv4_mapped
        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return False


def _decode_der_cert(der_bytes: bytes) -> dict[str, Any]:
    """Decodifica certificado DER usando o parser interno da stdlib (_ssl._test_decode_cert)."""
    if not der_bytes or not hasattr(ssl, "DER_cert_to_PEM_cert"):
        return {}
    tmp_path = None
    try:
        pem_data = ssl.DER_cert_to_PEM_cert(der_bytes)
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False, encoding="utf-8") as tmp:
            tmp.write(pem_data)
            tmp_path = tmp.name
        return ssl._ssl._test_decode_cert(tmp_path) or {}  # type: ignore[attr-defined]
    except Exception:
        return {}
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _extract_dn_dict(dn_tuples: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    if not dn_tuples:
        return result
    for rdn in dn_tuples:
        for item in rdn:
            if isinstance(item, tuple) and len(item) == 2:
                result[str(item[0])] = str(item[1])
    return result


def _parse_asn1_time(time_str: str | None) -> datetime | None:
    if not time_str:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ"):
        try:
            return datetime.strptime(time_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def check_tls10_11_accepted(host: str, port: int, timeout: float = 1.0) -> bool:
    """Checagem síncrona rápida se o servidor aceita TLS 1.0 ou TLS 1.1."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            except ssl.SSLError:
                pass
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    ver = ssock.version()
                    return ver in ("TLSv1", "TLSv1.1")
    except Exception:
        return False


async def check_tls10_11_accepted_async(
    ip: str, server_hostname: str, port: int, timeout: float = 0.8
) -> bool:
    """Checagem assíncrona não-bloqueante para detectar se o servidor aceita TLS 1.0/1.1."""
    writer = None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            except ssl.SSLError:
                pass
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx, server_hostname=server_hostname),
                timeout=timeout,
            )
            ssl_obj = writer.get_extra_info("ssl_object")
            ver = ssl_obj.version() if ssl_obj else None
            return ver in ("TLSv1", "TLSv1.1")
    except Exception:
        return False
    finally:
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


def parse_tls_certificate(
    ssl_obj: Any,
    verified: bool = True,
    tls10_11_accepted: bool = False,
) -> TLSInspection:
    if not ssl_obj:
        return TLSInspection(valid=False)

    try:
        cert: dict[str, Any] = ssl_obj.getpeercert() or {}
    except Exception:
        cert = {}

    der_cert: bytes | None = None
    try:
        der_cert = ssl_obj.getpeercert(binary_form=True)
    except Exception:
        der_cert = None

    if not cert and der_cert:
        cert = _decode_der_cert(der_cert)

    cipher_info = None
    try:
        cipher_info = ssl_obj.cipher()
    except Exception:
        cipher_info = None

    protocol = None
    try:
        protocol = ssl_obj.version()
    except Exception:
        protocol = None

    deprecated_protocol = protocol in ("TLSv1", "TLSv1.1", "SSLv3")
    legacy_accepted = bool(tls10_11_accepted or deprecated_protocol)

    cipher_name = cipher_info[0] if cipher_info and len(cipher_info) > 0 else None
    cipher_bits = cipher_info[2] if cipher_info and len(cipher_info) > 2 else None

    issuer_dict = _extract_dn_dict(cert.get("issuer", []))
    subject_dict = _extract_dn_dict(cert.get("subject", []))

    issuer = issuer_dict.get("organizationName") or issuer_dict.get("commonName")
    subject = subject_dict.get("commonName") or subject_dict.get("organizationName")

    serial_number = cert.get("serialNumber")
    fingerprint_sha256 = (
        hashlib.sha256(der_cert).hexdigest().upper() if der_cert else None
    )

    not_before = _parse_asn1_time(cert.get("notBefore"))
    expires_at = _parse_asn1_time(cert.get("notAfter"))
    days_remaining: int | None = None
    is_time_valid = True
    if expires_at is not None:
        now = datetime.now(timezone.utc)
        delta = expires_at - now
        if delta.total_seconds() < 0:
            is_time_valid = False
            days_remaining = 0
        else:
            days_remaining = max(0, delta.days)
    if not_before is not None and not_before > datetime.now(timezone.utc):
        is_time_valid = False

    # Extração de SANs (Subject Alternative Names)
    sans: list[str] = []
    for san_type, san_val in cert.get("subjectAltName", []):
        if san_type in ("DNS", "IP Address") and san_val not in sans:
            sans.append(san_val)

    # Extração da cadeia de certificação (Certificate Chain)
    cert_chain: list[str] = []
    inner_ssl = getattr(ssl_obj, "_sslobj", ssl_obj)
    raw_chain: list[bytes] = []
    for chain_getter in ("get_verified_chain", "get_unverified_chain"):
        getter = getattr(inner_ssl, chain_getter, None)
        if callable(getter):
            try:
                raw_chain = getter() or []
                if raw_chain:
                    break
            except Exception:
                pass

    last_issuer: str | None = None
    for der_item in raw_chain:
        if isinstance(der_item, bytes):
            decoded = _decode_der_cert(der_item)
            sub_d = _extract_dn_dict(decoded.get("subject", []))
            iss_d = _extract_dn_dict(decoded.get("issuer", []))
            node_name = sub_d.get("commonName") or sub_d.get("organizationName")
            if node_name and (not cert_chain or cert_chain[-1] != node_name):
                cert_chain.append(node_name)
            last_issuer = iss_d.get("commonName") or iss_d.get("organizationName")

    if last_issuer and (not cert_chain or cert_chain[-1] != last_issuer):
        cert_chain.append(last_issuer)

    if not cert_chain:
        for node in (subject, issuer):
            if node and (not cert_chain or cert_chain[-1] != node):
                cert_chain.append(node)

    # Detecção de OCSP Stapling
    ocsp_resp = getattr(ssl_obj, "ocsp_response", None) or getattr(
        inner_ssl, "ocsp_response", None
    )
    if ocsp_resp:
        ocsp_stapling = True
        ocsp_status = "Ativo (Stapled)"
    elif cert.get("OCSP"):
        ocsp_stapling = False
        ocsp_status = "Suportado pelo CA (Sem Stapling)"
    else:
        ocsp_stapling = False
        ocsp_status = "Não detectado"

    valid = bool(verified and is_time_valid and (cert or der_cert))

    return TLSInspection(
        valid=valid,
        protocol=protocol,
        deprecated_protocol=deprecated_protocol,
        tls10_11_accepted=legacy_accepted,
        cipher=cipher_name,
        cipher_bits=cipher_bits,
        issuer=issuer,
        subject=subject,
        serial_number=serial_number,
        fingerprint_sha256=fingerprint_sha256,
        not_before=not_before,
        expires_at=expires_at,
        days_remaining=days_remaining,
        alert_expiring=(days_remaining is not None and days_remaining < 15),
        sans=sans,
        cert_chain=cert_chain,
        ocsp_stapling=ocsp_stapling,
        ocsp_status=ocsp_status,
    )


def _audit_cookies(headers: httpx.Headers, is_https: bool) -> list[CookieAuditItem]:
    cookies_audited: list[CookieAuditItem] = []
    raw_cookies = headers.get_list("set-cookie")
    for raw in raw_cookies:
        parts = [p.strip() for p in raw.split(";") if p.strip()]
        if not parts:
            continue
        name_val = parts[0]
        cookie_name = name_val.split("=", 1)[0].strip() or "unknown"
        secure = False
        httponly = False
        samesite: str | None = None
        for attr in parts[1:]:
            lower = attr.lower()
            if lower == "secure":
                secure = True
            elif lower == "httponly":
                httponly = True
            elif lower.startswith("samesite="):
                samesite = attr.split("=", 1)[1].strip()

        issues: list[str] = []
        if is_https and not secure:
            issues.append("Ausência da flag Secure")
        if not httponly:
            issues.append("Ausência da flag HttpOnly")
        if not samesite:
            issues.append("Ausência de SameSite (Lax/Strict)")

        cookies_audited.append(
            CookieAuditItem(
                name=cookie_name,
                secure=secure,
                httponly=httponly,
                samesite=samesite,
                issues=issues,
            )
        )
    return cookies_audited


def audit_http_security(
    headers: httpx.Headers, is_https: bool, tls: TLSInspection | None
) -> SecurityAudit:
    score = 0
    present: dict[str, str] = {}
    missing_findings: list[SecurityFinding] = []
    leaks: list[str] = []

    cookies_audited = _audit_cookies(headers, is_https)
    cors_val = headers.get("access-control-allow-origin", "").strip()
    cors_wildcard = cors_val == "*"

    if not is_https or (tls and not tls.valid):
        all_findings = [
            SecurityFinding(
                id=info["id"],
                header=h,
                category="header",
                severity=info["severity"],
                weight=info["weight"],
                description=info["desc"],
                remediation=info["fix"],
            )
            for h, info in SECURITY_HEADERS_DETAILS.items()
        ]
        return SecurityAudit(
            grade="F",
            score=0,
            missing_findings=all_findings,
            cookies_audited=cookies_audited,
            cors_wildcard=cors_wildcard,
        )

    hsts_max_age: int | None = None
    hsts_include_subdomains = False
    hsts_preload_opt_in = False
    csp_frame_ancestors = False
    permissions_camera_restricted = False

    for header, info in SECURITY_HEADERS_DETAILS.items():
        if header in headers:
            val = headers[header]
            present[header] = val
            score += info["weight"]

            if header == "Strict-Transport-Security":
                m = re.search(r"max-age\s*=\s*(\d+)", val, re.IGNORECASE)
                if m:
                    hsts_max_age = int(m.group(1))
                hsts_include_subdomains = "includesubdomains" in val.lower()
                hsts_preload_opt_in = "preload" in val.lower()
            elif header == "Content-Security-Policy":
                csp_frame_ancestors = "frame-ancestors" in val.lower()
            elif header == "Permissions-Policy":
                permissions_camera_restricted = "camera=()" in val.lower().replace(" ", "")
        else:
            missing_findings.append(
                SecurityFinding(
                    id=info["id"],
                    header=header,
                    category="header",
                    severity=info["severity"],
                    weight=info["weight"],
                    description=info["desc"],
                    remediation=info["fix"],
                )
            )

    for leak_h in LEAK_HEADERS:
        if leak_h in headers:
            leaks.append(f"{leak_h}: {headers[leak_h]}")
            score = max(0, score - 5)

    if tls and (tls.protocol in ("TLSv1", "TLSv1.1", "SSLv3") or tls.deprecated_protocol):
        score = min(score, 40)

    if score >= 95 and not leaks:
        grade: Any = "A+"
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
        cookies_audited=cookies_audited,
        cors_wildcard=cors_wildcard,
        hsts_max_age=hsts_max_age,
        hsts_include_subdomains=hsts_include_subdomains,
        hsts_preload_opt_in=hsts_preload_opt_in,
        csp_frame_ancestors=csp_frame_ancestors,
        permissions_camera_restricted=permissions_camera_restricted,
    )