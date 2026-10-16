import asyncio
from collections import deque
import hashlib
import ipaddress
import os
import re
import socket
import ssl
import tempfile
import time
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

FORBIDDEN_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    # Loopback
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    # RFC 1918 (Redes Privadas IPv4)
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # Link-Local & Cloud Metadata (AWS/GCP/Azure/OpenStack 169.254.169.254)
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    # CGNAT / Shared Address Space (RFC 6598 - Alibaba Cloud / Tailscale / ISP)
    ipaddress.ip_network("100.64.0.0/10"),
    # IPv6 Unique Local Addresses - ULA (RFC 4193)
    ipaddress.ip_network("fc00::/7"),
    # Redes especiais, IETF protocol assignments, benchmarking (RFC 2544), documentação e multicast
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("2001:db8::/32"),
    ipaddress.ip_network("ff00::/8"),
)

HSTS_PROGRESSIVE_STEPS: list[dict[str, str]] = [
    {
        "stage": "Etapa 1 (5 min - Teste seguro)",
        "value": "max-age=300",
        "description": "Valide inicialmente por 5 minutos se nenhum subdomínio ou sistema legado quebra com HTTPS forçado.",
    },
    {
        "stage": "Etapa 2 (1 semana - Validação)",
        "value": "max-age=604800; includeSubDomains",
        "description": "Amplie para 7 dias cobrindo subdomínios após validar certificados TLS em toda a malha.",
    },
    {
        "stage": "Etapa 3 (1 mês+ - Produção)",
        "value": "max-age=2592000; includeSubDomains",
        "description": "Estágio recomendado de produção (30 dias ou mais). Concede nota máxima sem risco de bloqueio irreversível.",
    },
    {
        "stage": "Opt-in Opcional (Preload List)",
        "value": "max-age=31536000; includeSubDomains; preload",
        "description": "Opcional (Opt-in): submissão à HSTS Preload List dos navegadores. Requer compromisso permanente de HTTPS em todos os subdomínios.",
    },
]


def _build_header_snippets(header_name: str, header_value: str) -> dict[str, str]:
    escaped_val = header_value.replace('"', '\\"')
    k8s_snippet = f'more_set_headers "{header_name}: {header_value}";'
    return {
        "nginx": f'add_header {header_name} "{escaped_val}" always;',
        "apache": f'Header always set {header_name} "{escaped_val}"',
        "caddy": f'header {header_name} "{escaped_val}"',
        "traefik": (
            f"http:\n"
            f"  middlewares:\n"
            f"    sec-headers:\n"
            f"      headers:\n"
            f"        customResponseHeaders:\n"
            f'          {header_name}: "{escaped_val}"'
        ),
        "kubernetes": (
            f"metadata:\n"
            f"  annotations:\n"
            f"    nginx.ingress.kubernetes.io/configuration-snippet: |\n"
            f"      {k8s_snippet}"
        ),
    }


def _build_cookie_snippets() -> dict[str, str]:
    return {
        "nginx": "proxy_cookie_flags ~ secure httponly samesite=lax;",
        "apache": 'Header always edit Set-Cookie ^(.*)$ "$1; HttpOnly; Secure; SameSite=Lax"',
        "caddy": 'header Set-Cookie "^(.*)$" "$1; Secure; HttpOnly; SameSite=Lax"',
        "traefik": (
            "http:\n"
            "  middlewares:\n"
            "    sec-cookies:\n"
            "      headers:\n"
            "        customResponseHeaders:\n"
            '          Set-Cookie: "Secure; HttpOnly; SameSite=Lax"'
        ),
        "kubernetes": (
            "metadata:\n"
            "  annotations:\n"
            '    nginx.ingress.kubernetes.io/session-cookie-secure: "true"\n'
            '    nginx.ingress.kubernetes.io/session-cookie-samesite: "Lax"'
        ),
    }


def _build_cors_snippets() -> dict[str, str]:
    origin = "https://app.seudominio.com"
    return {
        "nginx": f'add_header Access-Control-Allow-Origin "{origin}" always;',
        "apache": f'Header always set Access-Control-Allow-Origin "{origin}"',
        "caddy": f'header Access-Control-Allow-Origin "{origin}"',
        "traefik": (
            "http:\n"
            "  middlewares:\n"
            "    cors-strict:\n"
            "      headers:\n"
            "        accessControlAllowOriginList:\n"
            f'          - "{origin}"'
        ),
        "kubernetes": (
            "metadata:\n"
            "  annotations:\n"
            '    nginx.ingress.kubernetes.io/enable-cors: "true"\n'
            f'    nginx.ingress.kubernetes.io/cors-allow-origin: "{origin}"'
        ),
    }


def _build_leak_snippets(leak_header: str) -> dict[str, str]:
    nginx_cmd = (
        "server_tokens off;"
        if leak_header.lower() == "server"
        else f"proxy_hide_header {leak_header};"
    )
    return {
        "nginx": nginx_cmd,
        "apache": f"Header always unset {leak_header}\nServerTokens Prod\nServerSignature Off",
        "caddy": f"header -{leak_header}",
        "traefik": (
            "http:\n"
            "  middlewares:\n"
            "    hide-fingerprint:\n"
            "      headers:\n"
            "        customResponseHeaders:\n"
            f'          {leak_header}: ""'
        ),
        "kubernetes": (
            "metadata:\n"
            "  annotations:\n"
            "    nginx.ingress.kubernetes.io/configuration-snippet: |\n"
            f"      more_clear_headers '{leak_header}';"
        ),
    }


SECURITY_HEADERS_DETAILS: dict[str, dict[str, Any]] = {
    "Strict-Transport-Security": {
        "id": "SEC-HSTS",
        "severity": "high",
        "weight": 25,
        "value": "max-age=2592000; includeSubDomains",
        "desc": (
            "Força o navegador a usar HTTPS estritamente, prevenindo ataques de Downgrade SSL e MITM. "
            "Recomenda-se adoção progressiva (5 min -> 1 semana -> 1 mês); a diretiva 'preload' é opcional (opt-in)."
        ),
        "fix": 'add_header Strict-Transport-Security "max-age=2592000; includeSubDomains" always;',
    },
    "Content-Security-Policy": {
        "id": "SEC-CSP",
        "severity": "high",
        "weight": 25,
        "value": "default-src 'self'; frame-ancestors 'self'",
        "desc": "Controla quais fontes de scripts e objetos podem ser executadas, mitigando XSS e Clickjacking.",
        "fix": "add_header Content-Security-Policy \"default-src 'self'; frame-ancestors 'self'\" always;",
    },
    "X-Content-Type-Options": {
        "id": "SEC-XCTO",
        "severity": "medium",
        "weight": 15,
        "value": "nosniff",
        "desc": "Previne que o browser faça MIME-sniffing e execute arquivos com tipos incorretos.",
        "fix": 'add_header X-Content-Type-Options "nosniff" always;',
    },
    "X-Frame-Options": {
        "id": "SEC-XFO",
        "severity": "medium",
        "weight": 15,
        "value": "SAMEORIGIN",
        "desc": "Protege a aplicação contra ataques de Clickjacking (também atendido por CSP frame-ancestors).",
        "fix": 'add_header X-Frame-Options "SAMEORIGIN" always;',
    },
    "Referrer-Policy": {
        "id": "SEC-REFPOL",
        "severity": "low",
        "weight": 10,
        "value": "strict-origin-when-cross-origin",
        "desc": "Controla quanta informação de URL é passada no header Referer para terceiros.",
        "fix": 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
    },
    "Permissions-Policy": {
        "id": "SEC-PERMPOL",
        "severity": "low",
        "weight": 10,
        "value": "camera=(), geolocation=(), microphone=()",
        "desc": "Restringe o acesso a APIs sensíveis do navegador (especialmente camera=(), geolocalização e microfone).",
        "fix": 'add_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;',
    },
}

LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]


class SlidingWindowRateLimiter:
    """Rate limiter em memória por IP de cliente usando janela deslizante."""

    def __init__(
        self, max_requests: int | None = None, window_seconds: float = 60.0
    ) -> None:
        self._explicit_max = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = {}

    @property
    def max_requests(self) -> int:
        if self._explicit_max is not None:
            return self._explicit_max
        try:
            return max(1, int(os.getenv("ANHANGA_RATE_LIMIT_PER_MIN", "30")))
        except ValueError:
            return 30

    @max_requests.setter
    def max_requests(self, value: int | None) -> None:
        self._explicit_max = value

    def check(self, client_ip: str) -> tuple[bool, int]:
        """Retorna (allowed, retry_after_seconds)."""
        now = time.monotonic()
        cutoff = now - self.window_seconds
        key = (client_ip or "unknown").strip()
        q = self._hits.setdefault(key, deque())
        while q and q[0] <= cutoff:
            q.popleft()

        limit = self.max_requests
        if len(q) >= limit:
            retry_after = max(1, int(self.window_seconds - (now - q[0])) + 1)
            return False, retry_after

        q.append(now)
        return True, 0

    def is_allowed(self, client_ip: str) -> bool:
        allowed, _ = self.check(client_ip)
        return allowed

    def reset(self) -> None:
        self._hits.clear()


RATE_LIMITER = SlidingWindowRateLimiter()


def _is_single_ip_forbidden(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    for net in FORBIDDEN_NETWORKS:
        if ip.version == net.version and ip in net:
            return True
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or not ip.is_global
    )


def is_ssrf_safe(ip_str: str, allow_private: bool = False) -> bool:
    """
    Valida rigorosamente se um endereço IP é seguro contra SSRF:
    - Limpa colchetes e rejeita/remove zona IPv6 (%eth0)
    - Desencapsula IPv4-mapped IPv6 (::ffff:127.0.0.1), 6to4 (2002::/16) e Teredo (2001::/32)
    - Bloqueia Loopback, RFC 1918, Link-Local (169.254/16, fe80::/10), CGNAT (100.64/10) e IPv6 ULA (fc00::/7)
    """
    if allow_private:
        return True
    if not ip_str or not isinstance(ip_str, str):
        return False

    cleaned = ip_str.strip()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1].strip()
    if "%" in cleaned:
        cleaned = cleaned.split("%", 1)[0].strip()
    if not cleaned:
        return False

    try:
        ip = ipaddress.ip_address(cleaned)
    except ValueError:
        return False

    candidates: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = [ip]
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            candidates.append(ip.ipv4_mapped)
        if ip.sixtofour is not None:
            candidates.append(ip.sixtofour)
        if ip.teredo is not None:
            candidates.extend(ip.teredo)

    for candidate in candidates:
        if _is_single_ip_forbidden(candidate):
            return False

    return True


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
        else:
            ss_lower = samesite.lower()
            if ss_lower == "none" and not secure:
                issues.append("SameSite=None exige a flag Secure")
            elif ss_lower not in ("strict", "lax", "none"):
                issues.append(f"SameSite inválido ({samesite})")

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
    cors_credentials = (
        headers.get("access-control-allow-credentials", "").strip().lower() == "true"
    )

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
                snippets=_build_header_snippets(h, info["value"]),
                progressive_steps=(
                    list(HSTS_PROGRESSIVE_STEPS)
                    if h == "Strict-Transport-Security"
                    else []
                ),
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

    # Pré-avalia CSP para saber se frame-ancestors já protege contra Clickjacking
    if "Content-Security-Policy" in headers:
        csp_raw = headers["Content-Security-Policy"]
        csp_frame_ancestors = bool(
            re.search(r"\bframe-ancestors\b", csp_raw, re.IGNORECASE)
        )

    for header, info in SECURITY_HEADERS_DETAILS.items():
        default_snippets = _build_header_snippets(header, info["value"])

        if header == "Strict-Transport-Security":
            if header in headers:
                val = headers[header]
                present[header] = val
                m = re.search(r"max-age\s*=\s*(\d+)", val, re.IGNORECASE)
                if m:
                    hsts_max_age = int(m.group(1))
                hsts_include_subdomains = "includesubdomains" in val.lower()
                hsts_preload_opt_in = "preload" in val.lower()

                if hsts_max_age is not None and hsts_max_age >= 2592000:
                    # Etapa 3 atingida (>= 30 dias): nota integral de HSTS sem exigir preload!
                    score += 25
                elif hsts_max_age is not None and hsts_max_age >= 604800:
                    # Etapa 2 (1 semana a < 1 mês): 15 pts + recomendação de avançar para Etapa 3
                    score += 15
                    missing_findings.append(
                        SecurityFinding(
                            id=info["id"],
                            header=header,
                            category="header",
                            severity="low",
                            weight=10,
                            description=(
                                f"HSTS ativo em estágio intermediário (max-age={hsts_max_age}s). "
                                "Avance para a Etapa 3 (max-age=2592000; includeSubDomains - 1 mês+) para proteção integral. "
                                "A diretiva 'preload' é opcional (opt-in)."
                            ),
                            remediation=info["fix"],
                            snippets=default_snippets,
                            progressive_steps=list(HSTS_PROGRESSIVE_STEPS),
                        )
                    )
                elif hsts_max_age is not None and hsts_max_age >= 300:
                    # Etapa 1 (5 min a < 1 semana): 10 pts + recomendação de avançar para Etapa 2/3
                    score += 10
                    missing_findings.append(
                        SecurityFinding(
                            id=info["id"],
                            header=header,
                            category="header",
                            severity="medium",
                            weight=15,
                            description=(
                                f"HSTS em fase inicial de teste (max-age={hsts_max_age}s). "
                                "Evolua gradualmente para a Etapa 2 (1 semana: max-age=604800; includeSubDomains) "
                                "e Etapa 3 (1 mês: max-age=2592000; includeSubDomains). 'preload' é opt-in."
                            ),
                            remediation='add_header Strict-Transport-Security "max-age=604800; includeSubDomains" always;',
                            snippets=_build_header_snippets(
                                header, "max-age=604800; includeSubDomains"
                            ),
                            progressive_steps=list(HSTS_PROGRESSIVE_STEPS),
                        )
                    )
                else:
                    # max-age ausente ou < 300s
                    missing_findings.append(
                        SecurityFinding(
                            id=info["id"],
                            header=header,
                            category="header",
                            severity="high",
                            weight=25,
                            description=(
                                "HSTS configurado com max-age insuficiente (< 300s). "
                                "Siga o runbook progressivo: 300s (teste) -> 604800s (1 semana) -> 2592000s (1 mês). "
                                "A diretiva 'preload' é estritamente opt-in."
                            ),
                            remediation=info["fix"],
                            snippets=default_snippets,
                            progressive_steps=list(HSTS_PROGRESSIVE_STEPS),
                        )
                    )
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
                        snippets=default_snippets,
                        progressive_steps=list(HSTS_PROGRESSIVE_STEPS),
                    )
                )
            continue

        if header == "X-Frame-Options":
            if header in headers:
                present[header] = headers[header]
                score += info["weight"]
            elif csp_frame_ancestors:
                # Equivalência moderna: CSP frame-ancestors substitui X-Frame-Options com segurança superior
                present["X-Frame-Options (via CSP frame-ancestors)"] = (
                    "Ativo via Content-Security-Policy"
                )
                score += info["weight"]
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
                        snippets=default_snippets,
                    )
                )
            continue

        if header == "Permissions-Policy":
            if header in headers:
                val = headers[header]
                present[header] = val
                permissions_camera_restricted = bool(
                    re.search(r"camera\s*=\s*\(\s*\)", val, re.IGNORECASE)
                )
                if permissions_camera_restricted:
                    score += info["weight"]
                else:
                    score += 5
                    missing_findings.append(
                        SecurityFinding(
                            id=info["id"],
                            header=header,
                            category="header",
                            severity="low",
                            weight=5,
                            description=(
                                "Permissions-Policy está presente, mas não restringe explicitamente "
                                "o acesso à câmera via diretiva 'camera=()'."
                            ),
                            remediation=info["fix"],
                            snippets=default_snippets,
                        )
                    )
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
                        snippets=default_snippets,
                    )
                )
            continue

        # Demais headers padrão (Content-Security-Policy, X-Content-Type-Options, Referrer-Policy)
        if header in headers:
            val = headers[header]
            present[header] = val
            score += info["weight"]
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
                    snippets=default_snippets,
                )
            )

    # Auditoria de Cookies inseguros
    insecure_cookies = [c for c in cookies_audited if c.issues]
    if insecure_cookies:
        score = max(0, score - 5)
        cookie_details = "; ".join(
            f"{c.name} ({', '.join(c.issues)})" for c in insecure_cookies
        )
        missing_findings.append(
            SecurityFinding(
                id="SEC-COOKIES",
                header="Set-Cookie (Flags Inseguras)",
                category="cookie",
                severity="medium",
                weight=5,
                description=f"Cookies detectados sem blindagem completa: {cookie_details}.",
                remediation="Configure as flags Secure, HttpOnly e SameSite=Lax (ou Strict) na emissão de cookies.",
                snippets=_build_cookie_snippets(),
            )
        )

    # Auditoria de CORS com Wildcard (*)
    if cors_wildcard:
        cors_weight = 10 if cors_credentials else 5
        cors_severity: Any = "high" if cors_credentials else "medium"
        score = max(0, score - cors_weight)
        cors_desc = (
            "Cabeçalho 'Access-Control-Allow-Origin: *' expõe respostas para qualquer domínio externo."
        )
        if cors_credentials:
            cors_desc += " Crítico: combinado com Access-Control-Allow-Credentials: true."
        missing_findings.append(
            SecurityFinding(
                id="SEC-CORS",
                header="Access-Control-Allow-Origin (Wildcard)",
                category="cors",
                severity=cors_severity,
                weight=cors_weight,
                description=cors_desc,
                remediation='Restrinja Access-Control-Allow-Origin para origens explícitas confiáveis (ex: "https://app.seudominio.com").',
                snippets=_build_cors_snippets(),
            )
        )

    # Auditoria de Vazamento de Stack/Versão (Server, X-Powered-By, etc.)
    for leak_h in LEAK_HEADERS:
        if leak_h in headers:
            leak_val = headers[leak_h]
            leaks.append(f"{leak_h}: {leak_val}")
            score = max(0, score - 5)
            missing_findings.append(
                SecurityFinding(
                    id=f"SEC-LEAK-{leak_h.upper()}",
                    header=f"Vazamento: {leak_h}",
                    category="leak",
                    severity="low",
                    weight=5,
                    description=(
                        f"O cabeçalho '{leak_h}: {leak_val}' expõe tecnologia/versão da borda ou backend, "
                        "facilitando reconhecimento automatizado de vulnerabilidades (fingerprinting)."
                    ),
                    remediation=f"Oculte ou remova o cabeçalho {leak_h} na borda.",
                    snippets=_build_leak_snippets(leak_h),
                )
            )

    if tls and (
        tls.protocol in ("TLSv1", "TLSv1.1", "SSLv3")
        or tls.deprecated_protocol
        or tls.tls10_11_accepted
    ):
        score = min(score, 40)

    score = max(0, min(100, score))

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