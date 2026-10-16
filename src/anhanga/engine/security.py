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
    CORSInspection,
    CookieAuditItem,
    SecurityAudit,
    SecurityFinding,
    TLSInspection,
    X509ChainLink,
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
            f"# Padrão Moderno: Kubernetes Gateway API (HTTPRoute)\n"
            f"apiVersion: gateway.networking.k8s.io/v1\n"
            f"kind: HTTPRoute\n"
            f"metadata:\n"
            f"  name: sec-headers\n"
            f"spec:\n"
            f"  rules:\n"
            f"    - filters:\n"
            f"        - type: ResponseHeaderModifier\n"
            f"          responseHeaderModifier:\n"
            f"            add:\n"
            f"              - name: {header_name}\n"
            f'                value: "{escaped_val}"\n'
            f"# Observação: ingress-nginx foi descontinuado upstream em março/2026.\n"
            f"# Caso use legado ingress-nginx:\n"
            f"# metadata:\n"
            f"#   annotations:\n"
            f"#     nginx.ingress.kubernetes.io/configuration-snippet: |\n"
            f"#       {k8s_snippet}"
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
            "# Kubernetes Gateway API com Traefik ou Envoy Plugin\n"
            "apiVersion: gateway.networking.k8s.io/v1\n"
            "kind: HTTPRoute\n"
            "metadata:\n"
            "  name: sec-cookies\n"
            "spec:\n"
            "  rules:\n"
            "    - filters:\n"
            "        - type: ResponseHeaderModifier\n"
            "          responseHeaderModifier:\n"
            "            add:\n"
            "              - name: Set-Cookie\n"
            '                value: "Secure; HttpOnly; SameSite=Lax"\n'
            "# Legado ingress-nginx:\n"
            "# metadata:\n"
            "#   annotations:\n"
            '#     nginx.ingress.kubernetes.io/session-cookie-secure: "true"\n'
            '#     nginx.ingress.kubernetes.io/session-cookie-samesite: "Lax"'
        ),
    }


def _build_cors_snippets() -> dict[str, str]:
    origin = "https://app.seudominio.com"
    return {
        "nginx": f'add_header Access-Control-Allow-Origin "{origin}" always;\nadd_header Vary "Origin" always;',
        "apache": f'Header always set Access-Control-Allow-Origin "{origin}"\nHeader always set Vary "Origin"',
        "caddy": f'header Access-Control-Allow-Origin "{origin}"\nheader Vary "Origin"',
        "traefik": (
            "http:\n"
            "  middlewares:\n"
            "    cors-strict:\n"
            "      headers:\n"
            "        accessControlAllowOriginList:\n"
            f'          - "{origin}"\n'
            "        addVaryHeader: true"
        ),
        "kubernetes": (
            "# Kubernetes Gateway API / Traefik Middleware\n"
            "apiVersion: traefik.io/v1alpha1\n"
            "kind: Middleware\n"
            "metadata:\n"
            "  name: cors-strict\n"
            "spec:\n"
            "  headers:\n"
            "    accessControlAllowOriginList:\n"
            f'      - "{origin}"\n'
            "    addVaryHeader: true\n"
            "# Legado ingress-nginx:\n"
            "# metadata:\n"
            "#   annotations:\n"
            '#     nginx.ingress.kubernetes.io/enable-cors: "true"\n'
            f'#     nginx.ingress.kubernetes.io/cors-allow-origin: "{origin}"'
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
            "# Kubernetes Gateway API (HTTPRoute) remoção de cabeçalho\n"
            "apiVersion: gateway.networking.k8s.io/v1\n"
            "kind: HTTPRoute\n"
            "metadata:\n"
            "  name: hide-fingerprint\n"
            "spec:\n"
            "  rules:\n"
            "    - filters:\n"
            "        - type: ResponseHeaderModifier\n"
            "          responseHeaderModifier:\n"
            "            remove:\n"
            f"              - {leak_header}\n"
            "# Legado ingress-nginx:\n"
            "# metadata:\n"
            "#   annotations:\n"
            "#     nginx.ingress.kubernetes.io/configuration-snippet: |\n"
            f"#       more_clear_headers '{leak_header}';"
        ),
    }


SECURITY_HEADERS_DETAILS: dict[str, dict[str, Any]] = {
    "Strict-Transport-Security": {
        "id": "SEC-HSTS",
        "severity": "high",
        "weight": 15,
        "value": "max-age=300",
        "safe_default": "max-age=300 (Etapa 1: Teste seguro de 5 min)",
        "desc": (
            "Força o navegador a usar HTTPS estritamente, prevenindo ataques de Downgrade SSL e MITM. "
            "Recomenda-se iniciar na Etapa 1 (max-age=300) antes de fixar em produção (max-age=2592000). "
            "A diretiva 'preload' é opcional (opt-in)."
        ),
        "fix": 'add_header Strict-Transport-Security "max-age=300" always;',
    },
    "Content-Security-Policy": {
        "id": "SEC-CSP",
        "severity": "high",
        "weight": 15,
        "value": "default-src 'self'; frame-ancestors 'self'; report-to /csp-violation-report-endpoint",
        "safe_default": "Modo Report-Only (não quebra a aplicação em produção)",
        "desc": (
            "Controla fontes de scripts, estilos e conexões externas, mitigando XSS e Clickjacking (via frame-ancestors). "
            "Recomenda-se implantar primeiro como 'Content-Security-Policy-Report-Only' para validar relatórios antes do bloqueio definitivo."
        ),
        "fix": 'add_header Content-Security-Policy-Report-Only "default-src \'self\'; frame-ancestors \'self\'; report-to /csp-violation-report-endpoint" always;',
    },
    "X-Content-Type-Options": {
        "id": "SEC-XCTO",
        "severity": "medium",
        "weight": 5,
        "value": "nosniff",
        "safe_default": "nosniff",
        "desc": "Previne que o navegador realize MIME-sniffing e execute arquivos com tipos incorretos.",
        "fix": 'add_header X-Content-Type-Options "nosniff" always;',
    },
    "X-Frame-Options": {
        "id": "SEC-XFO",
        "severity": "medium",
        "weight": 5,
        "value": "SAMEORIGIN",
        "safe_default": "SAMEORIGIN (ou CSP frame-ancestors)",
        "desc": "Protege a aplicação contra ataques de Clickjacking (atendido nativamente por CSP frame-ancestors).",
        "fix": 'add_header X-Frame-Options "SAMEORIGIN" always;',
    },
    "Referrer-Policy": {
        "id": "SEC-REFPOL",
        "severity": "low",
        "weight": 5,
        "value": "strict-origin-when-cross-origin",
        "safe_default": "strict-origin-when-cross-origin",
        "desc": "Controla quanta informação de URL é repassada no cabeçalho Referer para domínios terceiros.",
        "fix": 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
    },
    "Permissions-Policy": {
        "id": "SEC-PERMPOL",
        "severity": "low",
        "weight": 5,
        "value": "camera=(), geolocation=(), microphone=()",
        "safe_default": "camera=(), geolocation=(), microphone=()",
        "desc": "Restringe o acesso da página a APIs sensíveis do dispositivo (câmera, geolocalização e microfone).",
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

        for k, existing_q in list(self._hits.items()):
            while existing_q and existing_q[0] <= cutoff:
                existing_q.popleft()
            if not existing_q:
                del self._hits[k]

        q = self._hits.get(key)
        if q is None:
            q = deque()
            self._hits[key] = q

        limit = self.max_requests
        if len(q) >= limit:
            if not q:
                self._hits.pop(key, None)
                return False, 1
            retry_after = max(1, int(self.window_seconds - (now - q[0])) + 1)
            return False, retry_after

        q.append(now)
        return True, 0

    def is_allowed(self, client_ip: str) -> bool:
        allowed, _ = self.check(client_ip)
        return allowed

    def get_trusted_proxies(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        raw = os.getenv("ANHANGA_TRUSTED_PROXIES", "127.0.0.1,::1")
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for item in raw.split(","):
            cleaned = item.strip()
            if not cleaned:
                continue
            try:
                if "/" in cleaned:
                    networks.append(ipaddress.ip_network(cleaned, strict=False))
                else:
                    ip = ipaddress.ip_address(cleaned)
                    networks.append(ipaddress.ip_network(f"{ip}/{32 if ip.version == 4 else 128}"))
            except ValueError:
                pass
        return networks

    def extract_client_ip(
        self,
        remote_addr: str,
        x_forwarded_for: str | None = None,
    ) -> str:
        """
        Extrai com segurança o IP do cliente real:
        - Se remote_addr não for de um proxy confiável, ignora XFF e retorna remote_addr (evita spoofing).
        - Se remote_addr for confiável e XFF existir, extrai o primeiro IP não-confiável a partir da direita.
        """
        clean_remote = (remote_addr or "127.0.0.1").strip()
        if clean_remote.startswith("[") and clean_remote.endswith("]"):
            clean_remote = clean_remote[1:-1].strip()
        if "%" in clean_remote:
            clean_remote = clean_remote.split("%", 1)[0].strip()

        try:
            remote_ip = ipaddress.ip_address(clean_remote)
        except ValueError:
            return clean_remote

        trusted = self.get_trusted_proxies()
        is_trusted = any(remote_ip in net for net in trusted)
        if not is_trusted or not x_forwarded_for:
            return clean_remote

        ips = [p.strip() for p in x_forwarded_for.split(",") if p.strip()]
        for ip_cand in reversed(ips):
            cand_clean = ip_cand.strip("[]")
            if "%" in cand_clean:
                cand_clean = cand_clean.split("%", 1)[0].strip()
            try:
                parsed_cand = ipaddress.ip_address(cand_clean)
                if not any(parsed_cand in net for net in trusted):
                    return str(parsed_cand)
            except ValueError:
                continue
        return ips[0] if ips else clean_remote

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
    total_validity_days: int | None = None
    relative_validity_percent_remaining: float | None = None
    alert_relative_expiring = False

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

    if expires_at is not None and not_before is not None:
        total_validity_days = max(1, (expires_at - not_before).days)
        if days_remaining is not None:
            relative_validity_percent_remaining = round(
                (days_remaining / total_validity_days) * 100.0, 1
            )
            # Alerta se restar menos de 15% do ciclo total de vida do certificado
            alert_relative_expiring = bool(relative_validity_percent_remaining < 15.0)

    # Extração de SANs (Subject Alternative Names)
    sans: list[str] = []
    for san_type, san_val in cert.get("subjectAltName", []):
        if san_type in ("DNS", "IP Address") and san_val not in sans:
            sans.append(san_val)

    # Extração da cadeia de certificação (Certificate Chain)
    cert_chain: list[str] = []
    cert_chain_details: list[X509ChainLink] = []
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
            link_cn = sub_d.get("commonName")
            link_org = sub_d.get("organizationName")
            link_iss = iss_d.get("commonName") or iss_d.get("organizationName")
            link_nb = _parse_asn1_time(decoded.get("notBefore"))
            link_na = _parse_asn1_time(decoded.get("notAfter"))
            link_days: int | None = None
            if link_na is not None:
                d_delta = link_na - datetime.now(timezone.utc)
                link_days = max(0, d_delta.days) if d_delta.total_seconds() >= 0 else 0
            link_sn = decoded.get("serialNumber")
            link_fp = hashlib.sha256(der_item).hexdigest().upper()
            cert_chain_details.append(
                X509ChainLink(
                    common_name=link_cn,
                    organization=link_org,
                    issuer=link_iss,
                    not_before=link_nb,
                    expires_at=link_na,
                    days_remaining=link_days,
                    serial_number=str(link_sn) if link_sn else None,
                    fingerprint_sha256=link_fp,
                )
            )

            node_name = link_cn or link_org
            if node_name and (not cert_chain or cert_chain[-1] != node_name):
                cert_chain.append(node_name)
            last_issuer = link_iss

    if last_issuer and (not cert_chain or cert_chain[-1] != last_issuer):
        cert_chain.append(last_issuer)

    if not cert_chain:
        for node in (subject, issuer):
            if node and (not cert_chain or cert_chain[-1] != node):
                cert_chain.append(node)

    # Detecção de OCSP Stapling e checagem da extensão AIA no certificado
    ocsp_resp = getattr(ssl_obj, "ocsp_response", None) or getattr(
        inner_ssl, "ocsp_response", None
    )
    cert_ocsp = cert.get("OCSP")
    if ocsp_resp:
        ocsp_stapling = True
        ocsp_status = "Ativo (Stapled)"
    elif cert_ocsp:
        ocsp_stapling = False
        ocsp_status = "Suportado pelo CA (Sem Stapling)"
    else:
        # Let's Encrypt encerrou OCSP e removeu as URLs OCSP dos certificados em 2025/2026
        ocsp_stapling = False
        ocsp_status = "N/A (sem OCSP no certificado)"

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
        total_validity_days=total_validity_days,
        relative_validity_percent_remaining=relative_validity_percent_remaining,
        alert_expiring=(days_remaining is not None and days_remaining < 15),
        alert_relative_expiring=alert_relative_expiring,
        sans=sans,
        cert_chain=cert_chain,
        cert_chain_details=cert_chain_details,
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


async def audit_cors_active(
    client: httpx.AsyncClient,
    target_url: str,
    timeout: float = 2.0,
) -> CORSInspection:
    """
    Sonda ativamente a política CORS enviando Origin hostil (https://evil.anhanga.test).
    Verifica se a aplicação reflete o Origin hostil, se usa wildcard (*),
    e se expõe credenciais sensíveis (Access-Control-Allow-Credentials: true).
    """
    test_origin = "https://evil.anhanga.test"
    try:
        resp = await client.get(
            target_url,
            headers={"Origin": test_origin},
            timeout=timeout,
        )
        allow_origin = resp.headers.get("access-control-allow-origin", "").strip()
        allow_creds = (
            resp.headers.get("access-control-allow-credentials", "").strip().lower() == "true"
        )
        if not allow_origin:
            return CORSInspection(
                tested=True,
                status="Restrito / Seguro (Sem CORS público)",
                reflects_origin=False,
                wildcard=False,
                allow_credentials=allow_creds,
                vulnerable=False,
                details="A aplicação não reflete origens arbitrárias nem expõe cabeçalhos de CORS público.",
            )
        if allow_origin == "*":
            return CORSInspection(
                tested=True,
                status="Wildcard (*) detectado",
                reflects_origin=False,
                wildcard=True,
                allow_credentials=allow_creds,
                vulnerable=allow_creds,
                details="Permite acesso de qualquer origem (*). "
                + ("CRÍTICO: combinado com Allow-Credentials: true!" if allow_creds else "Inadequado para dados sensíveis."),
            )
        if allow_origin in (test_origin, "null"):
            return CORSInspection(
                tested=True,
                status="Vulnerável: reflete origem arbitrária",
                reflects_origin=True,
                wildcard=False,
                allow_credentials=allow_creds,
                vulnerable=True,
                details=f"O servidor refletiu a origem hostil '{allow_origin}'"
                + (" com credenciais habilitadas!" if allow_creds else "."),
            )
        return CORSInspection(
            tested=True,
            status=f"Restrito para {allow_origin}",
            reflects_origin=False,
            wildcard=False,
            allow_credentials=allow_creds,
            vulnerable=False,
            details=f"O servidor restringe o acesso explicitamente à origem configurada: {allow_origin}.",
        )
    except Exception as exc:
        return CORSInspection(
            tested=False,
            status="Não testado (Falha na requisição)",
            details=str(exc),
        )


def audit_http_security(
    headers: httpx.Headers,
    is_https: bool,
    tls: TLSInspection | None,
    cors_audit: CORSInspection | None = None,
) -> SecurityAudit:
    present: dict[str, str] = {}
    missing_findings: list[SecurityFinding] = []
    leaks: list[str] = []

    cookies_audited = _audit_cookies(headers, is_https)

    # Avaliação de CORS
    cors_val = headers.get("access-control-allow-origin", "").strip()
    cors_wildcard = cors_val == "*" or bool(cors_audit and cors_audit.wildcard)
    cors_credentials = (
        headers.get("access-control-allow-credentials", "").strip().lower() == "true"
        or bool(cors_audit and cors_audit.allow_credentials)
    )
    cors_vulnerable = bool(cors_audit and cors_audit.vulnerable) or (cors_wildcard and cors_credentials)

    # Identifica subdomínios do certificado que seriam afetados por HSTS includeSubDomains
    hsts_affected_sans: list[str] = []
    if tls and tls.sans:
        for s in tls.sans:
            if s.startswith("*.") or "." in s:
                if s not in hsts_affected_sans:
                    hsts_affected_sans.append(s)

    # 1. Dimensão: Transporte & TLS (até 40 pontos)
    transport_score = 0
    if is_https and tls and tls.valid:
        transport_score += 20  # Base HTTPS com certificado válido
        is_modern_tls = (
            tls.protocol in ("TLSv1.2", "TLSv1.3")
            and not tls.deprecated_protocol
            and not tls.tls10_11_accepted
        )
        if is_modern_tls:
            transport_score += 10
        is_cert_healthy = (not tls.alert_expiring) and (not getattr(tls, "alert_relative_expiring", False))
        if is_cert_healthy:
            transport_score += 10
        else:
            transport_score += 5

    # 2. Dimensão: Cabeçalhos de Proteção (até 40 pontos)
    headers_score = 0
    hsts_max_age: int | None = None
    hsts_include_subdomains = False
    hsts_preload_opt_in = False

    # 2.1 HSTS (até 15 pontos)
    hsts_info = SECURITY_HEADERS_DETAILS["Strict-Transport-Security"]
    hsts_default_snippets = _build_header_snippets("Strict-Transport-Security", hsts_info["value"])
    if "Strict-Transport-Security" in headers:
        val = headers["Strict-Transport-Security"]
        present["Strict-Transport-Security"] = val
        m = re.search(r"max-age\s*=\s*(\d+)", val, re.IGNORECASE)
        if m:
            hsts_max_age = int(m.group(1))
        hsts_include_subdomains = "includesubdomains" in val.lower()
        hsts_preload_opt_in = "preload" in val.lower()

        if hsts_max_age is not None and hsts_max_age >= 2592000:
            headers_score += 15  # Produção (30 dias+)
        elif hsts_max_age is not None and hsts_max_age >= 604800:
            headers_score += 10  # 1 semana
            missing_findings.append(
                SecurityFinding(
                    id=hsts_info["id"],
                    header="Strict-Transport-Security",
                    category="header",
                    severity="low",
                    weight=5,
                    safe_default="max-age=2592000; includeSubDomains",
                    description=(
                        f"HSTS ativo em estágio intermediário (max-age={hsts_max_age}s). "
                        "Avance para a Etapa 3 (max-age=2592000; includeSubDomains) para proteção integral."
                    ),
                    remediation='add_header Strict-Transport-Security "max-age=2592000; includeSubDomains" always;',
                    snippets=_build_header_snippets("Strict-Transport-Security", "max-age=2592000; includeSubDomains"),
                    progressive_steps=list(HSTS_PROGRESSIVE_STEPS),
                )
            )
        elif hsts_max_age is not None and hsts_max_age >= 300:
            headers_score += 5   # Teste inicial (5 min)
            missing_findings.append(
                SecurityFinding(
                    id=hsts_info["id"],
                    header="Strict-Transport-Security",
                    category="header",
                    severity="medium",
                    weight=10,
                    safe_default="max-age=604800; includeSubDomains",
                    description=(
                        f"HSTS em fase de teste (max-age={hsts_max_age}s). "
                        "Após validar subdomínios, avance para a Etapa 2 (max-age=604800; includeSubDomains)."
                    ),
                    remediation='add_header Strict-Transport-Security "max-age=604800; includeSubDomains" always;',
                    snippets=_build_header_snippets("Strict-Transport-Security", "max-age=604800; includeSubDomains"),
                    progressive_steps=list(HSTS_PROGRESSIVE_STEPS),
                )
            )
        else:
            sans_alert = f" Atenção: afetará os subdomínios do certificado: {', '.join(hsts_affected_sans[:4])}." if hsts_affected_sans else ""
            missing_findings.append(
                SecurityFinding(
                    id=hsts_info["id"],
                    header="Strict-Transport-Security",
                    category="header",
                    severity="high",
                    weight=15,
                    safe_default=hsts_info.get("safe_default", "max-age=300"),
                    description=f"HSTS configurado com max-age insuficiente (< 300s).{sans_alert}",
                    remediation=hsts_info["fix"],
                    snippets=hsts_default_snippets,
                    progressive_steps=list(HSTS_PROGRESSIVE_STEPS),
                )
            )
    else:
        sans_alert = f" Atenção: ativar includeSubDomains cobrirá os seguintes subdomínios identificados no certificado: {', '.join(hsts_affected_sans[:4])}." if hsts_affected_sans else ""
        missing_findings.append(
            SecurityFinding(
                id=hsts_info["id"],
                header="Strict-Transport-Security",
                category="header",
                severity="high",
                weight=15,
                safe_default=hsts_info.get("safe_default", "max-age=300"),
                description=hsts_info["desc"] + sans_alert,
                remediation=hsts_info["fix"],
                snippets=hsts_default_snippets,
                progressive_steps=list(HSTS_PROGRESSIVE_STEPS),
            )
        )

    # 2.2 Content-Security-Policy & Clickjacking (até 15 pontos)
    csp_info = SECURITY_HEADERS_DETAILS["Content-Security-Policy"]
    csp_default_snippets = _build_header_snippets("Content-Security-Policy-Report-Only", csp_info["value"])
    csp_raw = headers.get("Content-Security-Policy") or headers.get("Content-Security-Policy-Report-Only", "")
    has_csp = bool(csp_raw)
    csp_frame_ancestors = bool(re.search(r"\bframe-ancestors\b", csp_raw, re.IGNORECASE)) if has_csp else False
    has_xfo = "X-Frame-Options" in headers

    if has_csp:
        present["Content-Security-Policy"] = csp_raw
        if csp_frame_ancestors:
            headers_score += 15
            present["X-Frame-Options (via CSP frame-ancestors)"] = "Ativo via Content-Security-Policy frame-ancestors"
        elif has_xfo:
            headers_score += 15
            present["X-Frame-Options"] = headers["X-Frame-Options"]
        else:
            headers_score += 10
            xfo_info = SECURITY_HEADERS_DETAILS["X-Frame-Options"]
            missing_findings.append(
                SecurityFinding(
                    id=xfo_info["id"],
                    header="X-Frame-Options",
                    category="header",
                    severity="medium",
                    weight=5,
                    safe_default="frame-ancestors 'self'",
                    description="CSP ativo, mas sem a diretiva 'frame-ancestors' e sem cabeçalho X-Frame-Options para proteção contra Clickjacking.",
                    remediation=xfo_info["fix"],
                    snippets=_build_header_snippets("X-Frame-Options", xfo_info["value"]),
                )
            )
    else:
        if has_xfo:
            headers_score += 5
            present["X-Frame-Options"] = headers["X-Frame-Options"]
            missing_findings.append(
                SecurityFinding(
                    id=csp_info["id"],
                    header="Content-Security-Policy",
                    category="header",
                    severity="high",
                    weight=10,
                    safe_default=csp_info.get("safe_default"),
                    description=csp_info["desc"],
                    remediation=csp_info["fix"],
                    snippets=csp_default_snippets,
                )
            )
        else:
            missing_findings.append(
                SecurityFinding(
                    id=csp_info["id"],
                    header="Content-Security-Policy",
                    category="header",
                    severity="high",
                    weight=15,
                    safe_default=csp_info.get("safe_default"),
                    description=csp_info["desc"],
                    remediation=csp_info["fix"],
                    snippets=csp_default_snippets,
                )
            )

    # 2.3 X-Content-Type-Options (5 pontos)
    xcto_info = SECURITY_HEADERS_DETAILS["X-Content-Type-Options"]
    if "X-Content-Type-Options" in headers:
        present["X-Content-Type-Options"] = headers["X-Content-Type-Options"]
        headers_score += 5
    else:
        missing_findings.append(
            SecurityFinding(
                id=xcto_info["id"],
                header="X-Content-Type-Options",
                category="header",
                severity="medium",
                weight=5,
                safe_default="nosniff",
                description=xcto_info["desc"],
                remediation=xcto_info["fix"],
                snippets=_build_header_snippets("X-Content-Type-Options", xcto_info["value"]),
            )
        )

    # 2.4 Permissions-Policy (5 pontos)
    perm_info = SECURITY_HEADERS_DETAILS["Permissions-Policy"]
    permissions_camera_restricted = False
    if "Permissions-Policy" in headers:
        pval = headers["Permissions-Policy"]
        present["Permissions-Policy"] = pval
        permissions_camera_restricted = bool(re.search(r"camera\s*=\s*\(\s*\)", pval, re.IGNORECASE))
        if permissions_camera_restricted:
            headers_score += 5
        else:
            headers_score += 3
            missing_findings.append(
                SecurityFinding(
                    id=perm_info["id"],
                    header="Permissions-Policy",
                    category="header",
                    severity="low",
                    weight=2,
                    safe_default="camera=(), geolocation=(), microphone=()",
                    description="Permissions-Policy está presente, mas não restringe explicitamente o acesso à câmera via 'camera=()'.",
                    remediation=perm_info["fix"],
                    snippets=_build_header_snippets("Permissions-Policy", perm_info["value"]),
                )
            )
    else:
        missing_findings.append(
            SecurityFinding(
                id=perm_info["id"],
                header="Permissions-Policy",
                category="header",
                severity="low",
                weight=5,
                safe_default=perm_info.get("safe_default"),
                description=perm_info["desc"],
                remediation=perm_info["fix"],
                snippets=_build_header_snippets("Permissions-Policy", perm_info["value"]),
            )
        )

    # Referrer-Policy informativo
    if "Referrer-Policy" in headers:
        present["Referrer-Policy"] = headers["Referrer-Policy"]

    # 3. Dimensão: Higiene de Aplicação (até 20 pontos)
    hygiene_score = 20

    # 3.1 Vazamentos de Servidor / Versão (até 10 pontos)
    for leak_h in LEAK_HEADERS:
        if leak_h in headers:
            leak_val = headers[leak_h]
            leaks.append(f"{leak_h}: {leak_val}")
            missing_findings.append(
                SecurityFinding(
                    id=f"SEC-LEAK-{leak_h.upper()}",
                    header=f"Vazamento: {leak_h}",
                    category="leak",
                    severity="low",
                    weight=5,
                    safe_default=f"Remover cabeçalho {leak_h}",
                    description=(
                        f"O cabeçalho '{leak_h}: {leak_val}' expõe tecnologia/versão da borda ou backend, "
                        "facilitando reconhecimento de vulnerabilidades específicas."
                    ),
                    remediation=f"Oculte ou remova o cabeçalho {leak_h} na borda.",
                    snippets=_build_leak_snippets(leak_h),
                )
            )
    if leaks:
        hygiene_score -= 10

    # 3.2 Cookies (até 5 pontos)
    insecure_cookies = [c for c in cookies_audited if c.issues]
    if insecure_cookies:
        hygiene_score -= 5
        cookie_details = "; ".join(f"{c.name} ({', '.join(c.issues)})" for c in insecure_cookies)
        missing_findings.append(
            SecurityFinding(
                id="SEC-COOKIES",
                header="Set-Cookie (Flags Inseguras)",
                category="cookie",
                severity="medium",
                weight=5,
                safe_default="Secure; HttpOnly; SameSite=Lax",
                description=f"Cookies detectados sem blindagem completa: {cookie_details}.",
                remediation="Configure as flags Secure, HttpOnly e SameSite=Lax na emissão de cookies.",
                snippets=_build_cookie_snippets(),
            )
        )

    # 3.3 CORS (até 5 pontos)
    if cors_vulnerable or cors_wildcard:
        hygiene_score -= 5
        cors_desc = (
            cors_audit.details if cors_audit and cors_audit.details else
            "Cabeçalho 'Access-Control-Allow-Origin: *' expõe respostas da aplicação indiscriminadamente."
        )
        missing_findings.append(
            SecurityFinding(
                id="SEC-CORS",
                header="Access-Control-Allow-Origin (Inseguro)",
                category="cors",
                severity="high" if cors_credentials else "medium",
                weight=5,
                safe_default='add_header Access-Control-Allow-Origin "https://app.seudominio.com" always;',
                description=cors_desc,
                remediation='Restrinja Access-Control-Allow-Origin para origens explícitas e confiáveis.',
                snippets=_build_cors_snippets(),
            )
        )

    # Garante limites e soma total
    transport_score = max(0, min(40, transport_score))
    headers_score = max(0, min(40, headers_score))
    hygiene_score = max(0, min(20, hygiene_score))

    if tls and (
        tls.protocol in ("TLSv1", "TLSv1.1", "SSLv3")
        or tls.deprecated_protocol
        or tls.tls10_11_accepted
    ):
        transport_score = min(transport_score, 10)

    total_score = max(0, min(100, transport_score + headers_score + hygiene_score))

    if total_score >= 95 and not leaks and transport_score >= 35:
        grade: Any = "A+"
    elif total_score >= 80:
        grade = "A"
    elif total_score >= 65:
        grade = "B"
    elif total_score >= 50:
        grade = "C"
    elif total_score >= 30:
        grade = "D"
    else:
        grade = "F"

    return SecurityAudit(
        grade=grade,
        score=total_score,
        ruleset="v3",
        transport_score=transport_score,
        headers_score=headers_score,
        hygiene_score=hygiene_score,
        present_headers=present,
        missing_findings=missing_findings,
        leaked_tech=leaks,
        cookies_audited=cookies_audited,
        cors_wildcard=cors_wildcard,
        cors_audit=cors_audit or CORSInspection(),
        hsts_max_age=hsts_max_age,
        hsts_include_subdomains=hsts_include_subdomains,
        hsts_preload_opt_in=hsts_preload_opt_in,
        hsts_affected_sans=hsts_affected_sans,
        csp_frame_ancestors=csp_frame_ancestors,
        permissions_camera_restricted=permissions_camera_restricted,
    )