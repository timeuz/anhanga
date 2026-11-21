import asyncio
import contextlib
import shutil
from collections import deque
import functools
import hashlib
import ipaddress
import logging
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

from anhanga.engine.csp import analyze_csp
from anhanga.i18n import LStr, tr, tx
from anhanga.engine.models import (
    CSPAnalysis,
    CORSInspection,
    CookieAuditItem,
    SecurityAudit,
    SecurityFinding,
    TLSInspection,
    X509ChainLink,
)

FORBIDDEN_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    # loopback
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    # redes privadas IPv4 (RFC 1918)
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # link-local e metadados de nuvem (AWS, GCP, Azure e OpenStack usam 169.254.169.254)
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    # CGNAT / espaço compartilhado (RFC 6598), usado por Alibaba Cloud, Tailscale e provedores
    ipaddress.ip_network("100.64.0.0/10"),
    # IPv6 ULA (RFC 4193)
    ipaddress.ip_network("fc00::/7"),
    # faixas especiais: atribuições da IETF, benchmarking (RFC 2544), documentação e multicast
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
        "stage": LStr("Etapa 1 (5 min - Teste seguro)", "Stage 1 (5 min - safe test)"),
        "value": "max-age=300",
        "description": LStr(
            "Valide inicialmente por 5 minutos se nenhum subdomínio ou sistema legado quebra com HTTPS forçado.",
            "First check for 5 minutes that no subdomain or legacy system breaks under forced HTTPS.",
        ),
    },
    {
        "stage": LStr("Etapa 2 (1 semana - Validação)", "Stage 2 (1 week - validation)"),
        "value": "max-age=604800; includeSubDomains",
        "description": LStr(
            "Amplie para 7 dias cobrindo subdomínios após validar certificados TLS em toda a malha.",
            "Extend to 7 days covering subdomains once TLS certificates are validated everywhere.",
        ),
    },
    {
        "stage": LStr("Etapa 3 (1 mês+ - Produção)", "Stage 3 (1 month+ - production)"),
        "value": "max-age=2592000; includeSubDomains",
        "description": LStr(
            "Estágio recomendado de produção (30 dias ou mais). Concede nota máxima sem risco de bloqueio irreversível.",
            "Recommended production stage (30 days or more). Earns the top grade without risking an irreversible lockout.",
        ),
    },
    {
        "stage": LStr("Opt-in Opcional (Preload List)", "Optional opt-in (Preload List)"),
        "value": "max-age=31536000; includeSubDomains; preload",
        "description": LStr(
            "Opcional (Opt-in): submissão à HSTS Preload List dos navegadores. Requer compromisso permanente de HTTPS em todos os subdomínios.",
            "Optional (opt-in): submission to the browsers' HSTS Preload List. Requires a permanent HTTPS commitment on every subdomain.",
        ),
    },
]


def _hsts_steps() -> list[dict[str, str]]:
    return [{k: tx(v) for k, v in step.items()} for step in HSTS_PROGRESSIVE_STEPS]


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
            f"# {tr('Padrão Moderno: Kubernetes Gateway API (HTTPRoute)', 'Modern standard: Kubernetes Gateway API (HTTPRoute)')}\n"
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
            f"# {tr('Observação: ingress-nginx foi descontinuado upstream em março/2026.', 'Note: ingress-nginx was discontinued upstream in March 2026.')}\n"
            f"# {tr('Caso use legado ingress-nginx:', 'If you still use legacy ingress-nginx:')}\n"
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
            f"# {tr('Kubernetes Gateway API com Traefik ou Envoy Plugin', 'Kubernetes Gateway API with Traefik or Envoy Plugin')}\n"
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
            f"# {tr('Legado ingress-nginx:', 'Legacy ingress-nginx:')}\n"
            "# metadata:\n"
            "#   annotations:\n"
            '#     nginx.ingress.kubernetes.io/session-cookie-secure: "true"\n'
            '#     nginx.ingress.kubernetes.io/session-cookie-samesite: "Lax"'
        ),
    }


def _build_cors_snippets() -> dict[str, str]:
    origin = "https://app.example.com"
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
            f"# {tr('Legado ingress-nginx:', 'Legacy ingress-nginx:')}\n"
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
            f"# {tr('Kubernetes Gateway API (HTTPRoute) remoção de cabeçalho', 'Kubernetes Gateway API (HTTPRoute) header removal')}\n"
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
            f"# {tr('Legado ingress-nginx:', 'Legacy ingress-nginx:')}\n"
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
        "safe_default": LStr("max-age=300 (Etapa 1: Teste seguro de 5 min)", "max-age=300 (Stage 1: safe 5-minute test)"),
        "desc": LStr(
            "Força o navegador a usar HTTPS estritamente, prevenindo ataques de Downgrade SSL e MITM. "
            "Recomenda-se iniciar na Etapa 1 (max-age=300) antes de fixar em produção (max-age=2592000). "
            "A diretiva 'preload' é opcional (opt-in).",
            "Forces the browser to use HTTPS strictly, preventing SSL downgrade and MITM attacks. "
            "Start at Stage 1 (max-age=300) before settling on production (max-age=2592000). "
            "The 'preload' directive is optional (opt-in).",
        ),
        "fix": 'add_header Strict-Transport-Security "max-age=300" always;',
    },
    "Content-Security-Policy": {
        "id": "SEC-CSP",
        "severity": "high",
        "weight": 15,
        "value": "default-src 'self'; frame-ancestors 'self'; report-to /csp-violation-report-endpoint",
        "safe_default": LStr("Modo Report-Only (não quebra a aplicação em produção)", "Report-Only mode (does not break the application in production)"),
        "desc": LStr(
            "Controla fontes de scripts, estilos e conexões externas, mitigando XSS e Clickjacking (via frame-ancestors). "
            "Recomenda-se implantar primeiro como 'Content-Security-Policy-Report-Only' para validar relatórios antes do bloqueio definitivo.",
            "Controls the sources of scripts, styles and external connections, mitigating XSS and clickjacking (via frame-ancestors). "
            "Deploy it first as 'Content-Security-Policy-Report-Only' to validate the reports before enforcing it.",
        ),
        "fix": 'add_header Content-Security-Policy-Report-Only "default-src \'self\'; frame-ancestors \'self\'; report-to /csp-violation-report-endpoint" always;',
    },
    "X-Content-Type-Options": {
        "id": "SEC-XCTO",
        "severity": "medium",
        "weight": 5,
        "value": "nosniff",
        "safe_default": "nosniff",
        "desc": LStr(
            "Previne que o navegador realize MIME-sniffing e execute arquivos com tipos incorretos.",
            "Stops the browser from MIME-sniffing and running files served with the wrong type.",
        ),
        "fix": 'add_header X-Content-Type-Options "nosniff" always;',
    },
    "X-Frame-Options": {
        "id": "SEC-XFO",
        "severity": "medium",
        "weight": 5,
        "value": "SAMEORIGIN",
        "safe_default": LStr("SAMEORIGIN (ou CSP frame-ancestors)", "SAMEORIGIN (or CSP frame-ancestors)"),
        "desc": LStr(
            "Protege a aplicação contra ataques de Clickjacking (atendido nativamente por CSP frame-ancestors).",
            "Protects the application against clickjacking (natively covered by CSP frame-ancestors).",
        ),
        "fix": 'add_header X-Frame-Options "SAMEORIGIN" always;',
    },
    "Referrer-Policy": {
        "id": "SEC-REFPOL",
        "severity": "low",
        "weight": 5,
        "value": "strict-origin-when-cross-origin",
        "safe_default": "strict-origin-when-cross-origin",
        "desc": LStr(
            "Controla quanta informação de URL é repassada no cabeçalho Referer para domínios terceiros.",
            "Controls how much URL information is passed to third-party domains in the Referer header.",
        ),
        "fix": 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
    },
    "Permissions-Policy": {
        "id": "SEC-PERMPOL",
        "severity": "low",
        "weight": 5,
        "value": "camera=(), geolocation=(), microphone=()",
        "safe_default": "camera=(), geolocation=(), microphone=()",
        "desc": LStr(
            "Restringe o acesso da página a APIs sensíveis do dispositivo (câmera, geolocalização e microfone).",
            "Restricts the page's access to sensitive device APIs (camera, geolocation and microphone).",
        ),
        "fix": 'add_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;',
    },
}

LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]
_VERSION_IN_HEADER_RE = re.compile(r"\d+\.\d+|/\s*\d")


class SlidingWindowRateLimiter:
    """Rate limiter em memória por IP de cliente usando janela deslizante."""

    def __init__(
        self, max_requests: int | None = None, window_seconds: float = 60.0
    ) -> None:
        self._explicit_max = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = {}
        self._last_sweep = 0.0

    SWEEP_INTERVAL = 5.0  # varredura global de chaves ociosas: no máx. 1 vez a cada 5 s (não a cada chamada)

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

    def check(self, client_ip: str, cost: int = 1) -> tuple[bool, int]:
        """Retorna (allowed, retry_after_seconds). `cost` = nº de requisições equivalentes consumidas."""
        cost = max(1, int(cost))
        now = time.monotonic()
        cutoff = now - self.window_seconds
        key = (client_ip or "unknown").strip()

        if now - self._last_sweep >= self.SWEEP_INTERVAL:
            self._last_sweep = now
            for k, existing_q in list(self._hits.items()):
                while existing_q and existing_q[0] <= cutoff:
                    existing_q.popleft()
                if not existing_q:
                    del self._hits[k]

        q = self._hits.get(key)
        if q is None:
            q = deque()
            self._hits[key] = q
        while q and q[0] <= cutoff:  # a janela do próprio cliente é sempre exata
            q.popleft()

        limit = self.max_requests
        if len(q) + cost > limit:
            if not q:
                self._hits.pop(key, None)
                return False, 1
            retry_after = max(1, int(self.window_seconds - (now - q[0])) + 1)
            return False, retry_after

        q.extend([now] * cost)
        return True, 0

    def is_allowed(self, client_ip: str) -> bool:
        allowed, _ = self.check(client_ip)
        return allowed

    def get_trusted_proxies(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        raw = os.getenv("ANHANGA_TRUSTED_PROXIES", "")
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
        self._last_sweep = 0.0


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


_HOSTNAME_SAFE_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")
_PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)


EXTRAS_CACHE_TTL = 300.0
EXTRAS_MAX_CONCURRENCY = 8
_extras_cache: dict[tuple[str, int], tuple[float, list[bytes], bool | None]] = {}
_extras_sem: tuple[asyncio.AbstractEventLoop, asyncio.Semaphore] | None = None


def cancel_extras_background() -> None:
    """Desligamento: cancela as execuções destacadas de `openssl s_client` (que matam o filho ao cancelar)."""
    for task in list(_extras_inflight.values()):
        task.cancel()
    _extras_inflight.clear()


def clear_extras_cache() -> None:
    global _extras_sem
    _extras_cache.clear()
    _extras_inflight.clear()
    _extras_sem = None


def _get_extras_semaphore() -> asyncio.Semaphore:
    global _extras_sem
    loop = asyncio.get_running_loop()
    if _extras_sem is None or _extras_sem[0] is not loop:
        _extras_sem = (loop, asyncio.Semaphore(EXTRAS_MAX_CONCURRENCY))
    return _extras_sem[1]


_extras_inflight: dict[tuple[str, int], "asyncio.Future[tuple[list[bytes], bool | None]]"] = {}


async def fetch_tls_extras(
    ip: str, port: int, server_hostname: str, timeout: float = 4.0, expected_leaf: bytes | None = None
) -> tuple[list[bytes], bool | None]:
    """Cadeia + OCSP grampeado, com cache, limite de concorrência e prazo TOTAL de `timeout`.

    - Cache de 5 min por host:porta. Só vale se `expected_leaf` (certificado da conexão atual) for conhecido
      e igual ao da cadeia em cache: leaf desconhecido = miss (falhar aberto atribuiria a cadeia/revogação do
      certificado antigo ao novo após uma renovação).
    - No máx. 8 `openssl s_client` simultâneos; a espera pela vaga conta no prazo e, se estourar, a etapa
      degrada para ([], None) neste ciclo (não segura nem derruba a sondagem). Quem rodou já preencheu o cache.
    - Single-flight por host:porta: chamadas concorrentes dividem a mesma execução."""
    key = (server_hostname.lower(), port)
    hit = _extras_cache.get(key)
    if (
        hit
        and expected_leaf is not None
        and time.monotonic() - hit[0] < EXTRAS_CACHE_TTL
        and hit[1]
        and hit[1][0] == expected_leaf
    ):
        return hit[1], hit[2]
    loop = asyncio.get_running_loop()
    task = _extras_inflight.get(key)
    if task is not None and task.get_loop() is not loop:
        task = None  # herdado de outro event loop (testes/reinício): não aguardar
    if task is None:
        task = asyncio.ensure_future(_extras_task(key, ip, port, server_hostname, timeout))
        _extras_inflight[key] = task

        def _done(t: "asyncio.Future") -> None:
            if _extras_inflight.get(key) is t:
                _extras_inflight.pop(key, None)
            if not t.cancelled():
                t.exception()

        task.add_done_callback(_done)
    try:
        chain, stapled = await asyncio.wait_for(asyncio.shield(task), timeout=timeout + 0.5)
    except Exception:  # noqa: BLE001
        return [], None
    if expected_leaf is not None and chain and chain[0] != expected_leaf:
        # entrou numa execução iniciada antes de uma renovação: a cadeia é do certificado antigo.
        return [], None
    return chain, stapled


async def _extras_task(
    key: tuple[str, int], ip: str, port: int, server_hostname: str, timeout: float
) -> tuple[list[bytes], bool | None]:
    started = time.monotonic()
    sem = _get_extras_semaphore()
    try:
        await asyncio.wait_for(sem.acquire(), timeout=timeout * 0.5)
    except asyncio.TimeoutError:
        return [], None  # fila cheia: degrada neste ciclo
    try:
        remaining = max(0.5, timeout - (time.monotonic() - started))
        chain, stapled = await _fetch_tls_extras_uncached(ip, port, server_hostname, remaining)
    finally:
        sem.release()
    if chain:
        if len(_extras_cache) > 512:
            _extras_cache.pop(next(iter(_extras_cache)))
        _extras_cache[key] = (time.monotonic(), chain, stapled)
    return chain, stapled


async def _fetch_tls_extras_uncached(
    ip: str, port: int, server_hostname: str, timeout: float = 4.0
) -> tuple[list[bytes], bool | None]:
    """Obtém (cadeia DER enviada pelo servidor, OCSP grampeado?) via `openssl s_client`.

    O módulo `ssl` do Python não expõe a resposta OCSP grampeada (nem a cadeia antes do 3.13).
    Retorna ([], None) se o binário estiver ausente ou a consulta falhar: "não verificado" nunca
    é reportado como "ausente". `ip` já foi validado pela política Anti-SSRF pelo chamador.
    """
    openssl = shutil.which("openssl")
    if not openssl or not _HOSTNAME_SAFE_RE.match(server_hostname or ""):
        return [], None
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return [], None
    connect = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            openssl, "s_client", "-connect", connect, "-servername", server_hostname,
            "-status", "-showcerts",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(b""), timeout=timeout)
    except BaseException as exc:  # inclui CancelledError: o `openssl s_client` não pode ficar órfão
        if proc is not None and proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
        if isinstance(exc, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)):
            raise
        return [], None
    text = out.decode("utf-8", errors="replace")
    chain: list[bytes] = []
    for pem in _PEM_RE.findall(text):
        with contextlib.suppress(Exception):
            chain.append(ssl.PEM_cert_to_DER_cert(pem))
    stapled: bool | None = None
    if "OCSP Response Status: successful" in text:
        stapled = True
    elif "OCSP response: no response sent" in text:
        stapled = False
    if not chain and stapled is None:
        return [], None
    return chain, stapled


EXPIRING_DAYS = 15.0
EXPIRING_FRACTION = 0.20


def _cert_expiring(expires_at: datetime | None, total_validity_days: int | None) -> bool:
    """Alerta de expiração: menos de 15 dias OU de 20% da vida do certificado, o que for menor.

    Um limiar fixo de 15 dias deixaria certificados de vida curta (6 ou 47 dias) em "expirando" o tempo todo, com
    renovação automática saudável. Em certificados de 90 dias ou mais o limiar continua sendo 15 dias."""
    if expires_at is None:
        return False
    remaining_days = (expires_at - datetime.now(timezone.utc)).total_seconds() / 86400.0
    threshold = EXPIRING_DAYS
    if total_validity_days:
        threshold = min(EXPIRING_DAYS, EXPIRING_FRACTION * total_validity_days)
    return remaining_days < threshold


def parse_tls_certificate(
    ssl_obj: Any,
    verified: bool = True,
    tls10_11_accepted: bool = False,
    enumeration: Any = None,
    chain_der: list[bytes] | None = None,
    ocsp_stapled: bool | None = None,
    validation_error: str | None = None,
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
        # negativo = expirou há N dias (o floor mantém a ordem: -0.5d vira -1)
        days_remaining = delta.days
    if not_before is not None and not_before > datetime.now(timezone.utc):
        is_time_valid = False

    if expires_at is not None and not_before is not None:
        total_validity_days = max(1, (expires_at - not_before).days)
        if days_remaining is not None:
            relative_validity_percent_remaining = round(
                max(0.0, (days_remaining / total_validity_days) * 100.0), 1
            )
            # alerta se sobrar menos de 15% do tempo de vida total do certificado
            alert_relative_expiring = bool(relative_validity_percent_remaining < 15.0)

    # SANs (nomes alternativos do certificado)
    sans: list[str] = []
    for san_type, san_val in cert.get("subjectAltName", []):
        if san_type in ("DNS", "IP Address") and san_val not in sans:
            sans.append(san_val)

    # cadeia de certificação
    cert_chain: list[str] = []
    cert_chain_details: list[X509ChainLink] = []
    inner_ssl = getattr(ssl_obj, "_sslobj", ssl_obj)
    raw_chain: list[bytes] = []
    chain_source: str | None = None
    for chain_getter, source in (
        ("get_verified_chain", tr("verificada", "verified")),
        ("get_unverified_chain", tr("enviada pelo servidor", "sent by the server")),
    ):
        getter = getattr(inner_ssl, chain_getter, None)
        if callable(getter):
            try:
                raw_chain = [c for c in (getter() or []) if isinstance(c, bytes)]
                if raw_chain:
                    chain_source = source
                    break
            except Exception:
                pass
    if not raw_chain and chain_der:
        # no Python < 3.13 o ssl não expõe a cadeia: usa a que veio do `openssl s_client -showcerts`
        raw_chain = list(chain_der)
        chain_source = tr("enviada pelo servidor", "sent by the server")

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
                link_days = d_delta.days
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

    # OCSP: o módulo `ssl` NÃO expõe a resposta grampeada; `ocsp_stapled` vem do `openssl s_client -status`
    # (None = não verificado). nunca afirmar 'sem stapling' sem ter verificado.
    cert_ocsp = cert.get("OCSP")
    if ocsp_stapled is True:
        ocsp_stapling: bool | None = True
        ocsp_status = tr("Ativo (Stapled)", "Active (stapled)")
    elif ocsp_stapled is False:
        ocsp_stapling = False
        ocsp_status = (
            tr("Suportado pelo CA (Sem Stapling)", "Supported by the CA (no stapling)")
            if cert_ocsp
            else tr(
                "N/A (certificado sem OCSP; CAs modernas migraram para CRL)",
                "N/A (certificate without OCSP; modern CAs moved to CRL)",
            )
        )
    else:
        ocsp_stapling = None
        ocsp_status = tr("Não verificado (binário openssl indisponível)", "Not checked (openssl binary unavailable)")

    valid = bool(verified and is_time_valid and (cert or der_cert))

    if not valid and not validation_error:
        if not is_time_valid:
            validation_error = (
                tr("certificado expirado", "certificate expired") if expires_at and expires_at < datetime.now(timezone.utc)
                else tr("certificado ainda não válido", "certificate not yet valid")
            )
        elif not verified:
            validation_error = tr("cadeia/hostname não validados", "chain/hostname not validated")

    return TLSInspection(
        valid=valid,
        validation_error=None if valid else validation_error,
        chain_source=chain_source,
        protocol=protocol,
        deprecated_protocol=deprecated_protocol,
        tls10_11_accepted=legacy_accepted,
        enumeration=enumeration,
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
        alert_expiring=_cert_expiring(expires_at, total_validity_days),
        alert_relative_expiring=alert_relative_expiring,
        sans=sans,
        cert_chain=cert_chain,
        cert_chain_details=cert_chain_details,
        ocsp_stapling=ocsp_stapling,
        ocsp_status=ocsp_status,
    )


# csrf/xsrf ficam de fora de propósito: cookie de double-submit (csrftoken do Django, XSRF-TOKEN do Angular)
# precisa ser lido por JS, então exigir HttpOnly neles seria falso positivo e puniria o design certo. já o
# `_csrf` (segredo do csurf/Express) é o contrário do double-submit: deve ser HttpOnly, por isso entra.
_DEFAULT_SENSITIVE_COOKIE_PATTERN = (
    r"(sess|sid$|^sid|auth|token|jwt|login|passw|remember|sso|identity|account|^_csrf$)"
)


def _compile_sensitive_cookie_regex(custom: str | None) -> "tuple[re.Pattern[str], bool]":
    """(regex, é_do_operador). Regex do operador inválida não derruba a importação (e a app inteira): cai no
    padrão, e então `é_do_operador` é False, para que as exceções do padrão (CSRF) continuem valendo."""
    if custom:
        try:
            return re.compile(custom, re.I), True
        except re.error as exc:
            logging.getLogger("anhanga").error(
                f"ANHANGA_SENSITIVE_COOKIE_REGEX inválida ({exc}); usando o padrão."
            )
    return re.compile(_DEFAULT_SENSITIVE_COOKIE_PATTERN, re.I), False




@functools.lru_cache(maxsize=4)
def _sensitive_cookie_regex(custom: str | None) -> "tuple[re.Pattern[str], bool]":
    """Compilada sob demanda (não na importação): o `.env` só é lido pelo entrypoint do servidor, que pode rodar
    depois de este módulo ser importado (o CLI importa o motor antes de `serve`). Uma regex inválida loga uma vez."""
    return _compile_sensitive_cookie_regex(custom)


# só os NOMES de token de double-submit (csrftoken, XSRF-TOKEN, X-CSRF-TOKEN, csrf_token). não basta conter
# 'csrf': `auth_xsrf_sid` ou `csrf_session` são cookies de sessão de verdade.
_CSRF_TOKEN_COOKIE_RE = re.compile(r"^(?:__(?:host|secure)-)?_?(?:x-)?(?:csrf|xsrf)[-_]?token$", re.I)


def _is_sensitive_cookie(name: str) -> bool:
    """Cookie de sessão/autenticação. No padrão, tokens CSRF de double-submit ficam de fora mesmo casando com
    `token`: precisam ser legíveis por JS. Regex válida do operador vale como escrita."""
    regex, custom_active = _sensitive_cookie_regex(os.getenv("ANHANGA_SENSITIVE_COOKIE_REGEX"))
    if not regex.search(name):
        return False
    return custom_active or not _CSRF_TOKEN_COOKIE_RE.match(name)


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
            issues.append(tr("Ausência da flag Secure", "Missing Secure flag"))
        # HttpOnly só é exigido de cookie de sessão/autenticação. analytics e preferências (ex.: _octo, _ga)
        # precisam ser lidos por JS e não são falha.
        sensitive = _is_sensitive_cookie(cookie_name)
        if sensitive and not httponly:
            issues.append(tr("Ausência da flag HttpOnly (cookie de sessão/autenticação)", "Missing HttpOnly flag (session/authentication cookie)"))
        if not samesite:
            issues.append(tr("Ausência de SameSite (Lax/Strict)", "Missing SameSite (Lax/Strict)"))
        else:
            ss_lower = samesite.lower()
            if ss_lower == "none" and not secure:
                issues.append(tr("SameSite=None exige a flag Secure", "SameSite=None requires the Secure flag"))
            elif ss_lower not in ("strict", "lax", "none"):
                issues.append(tr(f"SameSite inválido ({samesite})", f"Invalid SameSite ({samesite})"))

        cookies_audited.append(
            CookieAuditItem(
                name=cookie_name,
                sensitive=sensitive,
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
        # stream: só os cabeçalhos interessam, e `client.get` baixaria o corpo inteiro (sem teto) a cada ciclo.
        async with client.stream(
            "GET",
            target_url,
            headers={"Origin": test_origin},
            timeout=timeout,
        ) as resp:
            allow_origin = resp.headers.get("access-control-allow-origin", "").strip()
            allow_creds = (
                resp.headers.get("access-control-allow-credentials", "").strip().lower() == "true"
            )
        if not allow_origin:
            return CORSInspection(
                tested=True,
                status=tr("Restrito / Seguro (Sem CORS público)", "Restricted / Safe (no public CORS)"),
                reflects_origin=False,
                wildcard=False,
                allow_credentials=allow_creds,
                vulnerable=False,
                details=tr(
                    "A aplicação não reflete origens arbitrárias nem expõe cabeçalhos de CORS público.",
                    "The application does not reflect arbitrary origins or expose public CORS headers.",
                ),
            )
        if allow_origin == "*":
            return CORSInspection(
                tested=True,
                status=tr("Wildcard (*) detectado", "Wildcard (*) detected"),
                reflects_origin=False,
                wildcard=True,
                allow_credentials=allow_creds,
                vulnerable=allow_creds,
                details=tr("Permite acesso de qualquer origem (*). ", "Allows access from any origin (*). ")
                + (
                    tr("CRÍTICO: combinado com Allow-Credentials: true!", "CRITICAL: combined with Allow-Credentials: true!")
                    if allow_creds
                    else tr("Inadequado para dados sensíveis.", "Not suitable for sensitive data.")
                ),
            )
        if allow_origin in (test_origin, "null"):
            return CORSInspection(
                tested=True,
                status=tr("Vulnerável: reflete origem arbitrária", "Vulnerable: reflects an arbitrary origin"),
                reflects_origin=True,
                wildcard=False,
                allow_credentials=allow_creds,
                vulnerable=True,
                details=tr(
                    f"O servidor refletiu a origem hostil '{allow_origin}'"
                    + (" com credenciais habilitadas!" if allow_creds else "."),
                    f"The server reflected the hostile origin '{allow_origin}'"
                    + (" with credentials enabled!" if allow_creds else "."),
                ),
            )
        return CORSInspection(
            tested=True,
            status=tr(f"Restrito para {allow_origin}", f"Restricted to {allow_origin}"),
            reflects_origin=False,
            wildcard=False,
            allow_credentials=allow_creds,
            vulnerable=False,
            details=tr(
                f"O servidor restringe o acesso explicitamente à origem configurada: {allow_origin}.",
                f"The server explicitly restricts access to the configured origin: {allow_origin}.",
            ),
        )
    except Exception as exc:
        return CORSInspection(
            tested=False,
            status=tr("Não testado (Falha na requisição)", "Not tested (request failed)"),
            details=str(exc),
        )


_CSP_QUALITY_FACTOR = {"strong": 1.0, "moderate": 0.8, "weak": 0.5}
_CSP_REPORT_ONLY_NOTE = LStr(
    " Atenção: há uma política em Report-Only, mas ela apenas reporta violações; promova-a para "
    "Content-Security-Policy para que passe a bloquear.",
    " Note: a Report-Only policy is present, but it only reports violations; promote it to "
    "Content-Security-Policy so it starts blocking.",
)


def _tls_enum_findings(tls: TLSInspection | None) -> tuple[list[SecurityFinding], int | None, int]:
    """Findings da enumeração de protocolos/cifras → (findings, teto do transporte, penalidade)."""
    enum = getattr(tls, "enumeration", None) if tls else None
    if enum is None:
        return [], None, 0
    out: list[SecurityFinding] = []
    cap: int | None = None
    penalty = 0
    legacy = [p.protocol for p in enum.protocols if p.protocol in ("TLSv1", "TLSv1.1") and p.status == "accepted"]
    weak = sorted({c for p in enum.protocols for c in p.weak_ciphers})
    nofs = sorted({c for p in enum.protocols for c in p.no_forward_secrecy})
    if legacy:
        out.append(SecurityFinding(
            id="SEC-TLS-LEGACY", header=tr("TLS (protocolos legados)", "TLS (legacy protocols)"), category="tls", severity="high", weight=15,
            description=tr(
                f"O servidor aceita {', '.join(legacy)}, protocolos obsoletos (RFC 8996) sujeitos a ataques como BEAST/POODLE-TLS.",
                f"The server accepts {', '.join(legacy)}, obsolete protocols (RFC 8996) exposed to attacks such as BEAST/POODLE-TLS.",
            ),
            remediation=tr("Desative TLS 1.0/1.1 e mantenha apenas TLS 1.2 e 1.3.", "Disable TLS 1.0/1.1 and keep only TLS 1.2 and 1.3."),
            snippets={
                "nginx": "ssl_protocols TLSv1.2 TLSv1.3;",
                "apache": "SSLProtocol -all +TLSv1.2 +TLSv1.3",
                "haproxy": "ssl-default-bind-options ssl-min-ver TLSv1.2",
            },
        ))
        cap = 10
    if weak:
        shown = ", ".join(weak[:8]) + (f" (+{len(weak) - 8})" if len(weak) > 8 else "")
        out.append(SecurityFinding(
            id="SEC-TLS-WEAK-CIPHER", header=tr("TLS (cifras fracas)", "TLS (weak ciphers)"), category="tls", severity="high", weight=15,
            description=tr(
                f"O servidor aceita {len(weak)} cifra(s) fraca(s) (NULL, anônimas, RC4/DES/3DES, EXPORT ou MD5): {shown}.",
                f"The server accepts {len(weak)} weak cipher(s) (NULL, anonymous, RC4/DES/3DES, EXPORT or MD5): {shown}.",
            ),
            remediation=tr(
                "Restrinja as cifras a suítes AEAD com forward secrecy (ECDHE + AES-GCM/ChaCha20).",
                "Restrict the ciphers to AEAD suites with forward secrecy (ECDHE + AES-GCM/ChaCha20).",
            ),
            snippets={
                "nginx": "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;\nssl_prefer_server_ciphers off;",
                "apache": "SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384",
            },
        ))
        cap = 10 if cap is None else min(cap, 10)
    if nofs and not weak:
        shown = ", ".join(nofs[:6]) + (f" (+{len(nofs) - 6})" if len(nofs) > 6 else "")
        out.append(SecurityFinding(
            id="SEC-TLS-NO-PFS", header=tr("TLS (forward secrecy)", "TLS (forward secrecy)"), category="tls", severity="low", weight=5,
            description=tr(
                f"O servidor aceita cifras sem forward secrecy (troca de chaves RSA estática): {shown}. Capturas de tráfego passadas ficam decifráveis se a chave privada vazar.",
                f"The server accepts ciphers without forward secrecy (static RSA key exchange): {shown}. Past traffic captures become decryptable if the private key leaks.",
            ),
            remediation=tr("Remova as suítes sem ECDHE/DHE.", "Remove the suites without ECDHE/DHE."),
            snippets={},
        ))
        penalty = 5
    return out, cap, penalty


_COOP_OK = {"same-origin", "same-origin-allow-popups"}
_COEP_OK = {"require-corp", "credentialless"}
_CORP_VALUES = {"same-origin", "same-site", "cross-origin"}


def _isolation_findings(headers: httpx.Headers) -> list[SecurityFinding]:
    """COOP/COEP/CORP. Sempre `info`/peso 0: são endurecimentos opcionais que podem quebrar embeds de
    terceiros, então não penalizam a nota. Valores inválidos viram `low` (o navegador os ignora)."""
    out: list[SecurityFinding] = []
    coop = headers.get("Cross-Origin-Opener-Policy", "").split(";")[0].strip().lower()
    coep = headers.get("Cross-Origin-Embedder-Policy", "").split(";")[0].strip().lower()
    corp = headers.get("Cross-Origin-Resource-Policy", "").strip().lower()

    def add(fid: str, header: str, sev: str, desc: str, fix: str, value: str) -> None:
        out.append(SecurityFinding(
            id=fid, header=header, category="header", severity=sev,  # type: ignore[arg-type]
            weight=0, description=desc, remediation=fix, safe_default=value,
            snippets=_build_header_snippets(header, value),
        ))

    if not coop or coop == "unsafe-none":
        add("SEC-COOP", "Cross-Origin-Opener-Policy", "info",
            tr("COOP ausente: janelas de outras origens que abrem seu site (ou que ele abre) mantêm referência umas às outras, "
               "o que expõe a ataques de canal lateral (XS-Leaks, Spectre) e é pré-requisito do isolamento de origem cruzada.",
               "COOP missing: windows from other origins that open your site (or that it opens) keep a reference to each other, "
               "which exposes it to side-channel attacks (XS-Leaks, Spectre) and is a prerequisite for cross-origin isolation."),
            tr("Use same-origin. Use same-origin-allow-popups se o site depende de popups de login/pagamento de terceiros.",
               "Use same-origin. Use same-origin-allow-popups if the site relies on third-party login/payment popups."),
            "same-origin")
    elif coop not in _COOP_OK:
        add("SEC-COOP", "Cross-Origin-Opener-Policy", "low",
            tr(f"COOP com valor inválido ({coop!r}): o navegador o ignora.", f"COOP has an invalid value ({coop!r}): the browser ignores it."),
            tr("Use same-origin.", "Use same-origin."), "same-origin")
    if not coep or coep == "unsafe-none":
        add("SEC-COEP", "Cross-Origin-Embedder-Policy", "info",
            tr("COEP ausente: sem COOP+COEP o site não fica 'cross-origin isolated' (necessário para SharedArrayBuffer e "
               "temporizadores de alta resolução). Ative apenas se todos os recursos de terceiros enviarem CORP/CORS, "
               "senão eles deixam de carregar.",
               "COEP missing: without COOP+COEP the site is not 'cross-origin isolated' (needed for SharedArrayBuffer and "
               "high-resolution timers). Enable it only if every third-party resource sends CORP/CORS, "
               "otherwise they stop loading."),
            tr("Teste primeiro com Cross-Origin-Embedder-Policy-Report-Only: require-corp.",
               "Try Cross-Origin-Embedder-Policy-Report-Only: require-corp first."),
            "require-corp")
    elif coep not in _COEP_OK:
        add("SEC-COEP", "Cross-Origin-Embedder-Policy", "low",
            tr(f"COEP com valor inválido ({coep!r}): o navegador o ignora.", f"COEP has an invalid value ({coep!r}): the browser ignores it."),
            "Use require-corp.", "require-corp")
    if corp and corp not in _CORP_VALUES:
        add("SEC-CORP", "Cross-Origin-Resource-Policy", "low",
            tr(f"CORP com valor inválido ({corp!r}): o navegador o ignora.", f"CORP has an invalid value ({corp!r}): the browser ignores it."),
            tr("Use same-origin, same-site ou cross-origin.", "Use same-origin, same-site or cross-origin."), "same-origin")
    return out


def _csp_points(base: int, analysis: CSPAnalysis) -> int:
    """Pontos da CSP aplicada, proporcionais à qualidade (CSP com 'unsafe-inline'/'*' vale metade)."""
    return round(base * _CSP_QUALITY_FACTOR.get(analysis.strength, 1.0))


def _csp_quality_finding(analysis: CSPAnalysis) -> SecurityFinding:
    worst = "high" if any(i.severity == "high" for i in analysis.issues) else "medium"
    details = "; ".join(f"[{i.severity}] {i.message}" for i in analysis.issues[:6])
    stricter = "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"
    return SecurityFinding(
        id="SEC-CSP-WEAK",
        header=tr("Content-Security-Policy (qualidade)", "Content-Security-Policy (quality)"),
        category="header",
        severity=worst,  # type: ignore[arg-type]
        weight=max(2, 15 - _csp_points(15, analysis)),
        safe_default=stricter,
        description=tr(
            f"A CSP existe, mas é {analysis.strength}: {details}. "
            "Substitua 'unsafe-inline' por nonces/hashes (com 'strict-dynamic'), liste hosts explícitos "
            "e defina object-src 'none' e base-uri.",
            f"A CSP exists, but it is {analysis.strength}: {details}. "
            "Replace 'unsafe-inline' with nonces/hashes (with 'strict-dynamic'), list explicit hosts "
            "and set object-src 'none' and base-uri.",
        ),
        remediation=tr(
            "Endureça a política (exemplo-base abaixo) validando antes em Report-Only.",
            "Tighten the policy (baseline example below), validating it in Report-Only first.",
        ),
        snippets=_build_header_snippets("Content-Security-Policy", stricter),
    )


def audit_http_security(
    headers: httpx.Headers,
    is_https: bool,
    tls: TLSInspection | None,
    cors_audit: CORSInspection | None = None,
    evaluated_url: str | None = None,
) -> SecurityAudit:
    present: dict[str, str] = {}
    missing_findings: list[SecurityFinding] = []
    leaks: list[str] = []

    cookies_audited = _audit_cookies(headers, is_https)

    # CORS
    cors_val = headers.get("access-control-allow-origin", "").strip()
    cors_wildcard = cors_val == "*" or bool(cors_audit and cors_audit.wildcard)
    cors_credentials = (
        headers.get("access-control-allow-credentials", "").strip().lower() == "true"
        or bool(cors_audit and cors_audit.allow_credentials)
    )
    cors_vulnerable = bool(cors_audit and cors_audit.vulnerable) or (cors_wildcard and cors_credentials)

    # acha os subdomínios do certificado que o HSTS includeSubDomains afetaria
    hsts_affected_sans: list[str] = []
    if tls and tls.sans:
        for s in tls.sans:
            if s.startswith("*.") or "." in s:
                if s not in hsts_affected_sans:
                    hsts_affected_sans.append(s)

    # dimensão 1: transporte e TLS (até 40 pontos)
    transport_score = 0
    if is_https and tls and tls.valid:
        transport_score += 20  # base: HTTPS com certificado válido
        is_modern_tls = (
            tls.protocol in ("TLSv1.2", "TLSv1.3")
            and not tls.deprecated_protocol
            and not tls.tls10_11_accepted
            and not tls.legacy_check_incomplete  # não verificado != seguro: sem bônus
        )
        if is_modern_tls:
            transport_score += 10
        is_cert_healthy = (not tls.alert_expiring) and (not getattr(tls, "alert_relative_expiring", False))
        if is_cert_healthy:
            transport_score += 10
        else:
            transport_score += 5

    # dimensão 2: cabeçalhos de proteção (até 40 pontos)
    headers_score = 0
    hsts_max_age: int | None = None
    hsts_include_subdomains = False
    hsts_preload_opt_in = False

    # HSTS (até 15 pontos)
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
            headers_score += 15  # produção (30 dias ou mais)
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
                    description=tr(
                        f"HSTS ativo em estágio intermediário (max-age={hsts_max_age}s). "
                        "Avance para a Etapa 3 (max-age=2592000; includeSubDomains) para proteção integral.",
                        f"HSTS active at an intermediate stage (max-age={hsts_max_age}s). "
                        "Move to Stage 3 (max-age=2592000; includeSubDomains) for full protection.",
                    ),
                    remediation='add_header Strict-Transport-Security "max-age=2592000; includeSubDomains" always;',
                    snippets=_build_header_snippets("Strict-Transport-Security", "max-age=2592000; includeSubDomains"),
                    progressive_steps=_hsts_steps(),
                )
            )
        elif hsts_max_age is not None and hsts_max_age >= 300:
            headers_score += 5  # teste inicial (5 min)
            missing_findings.append(
                SecurityFinding(
                    id=hsts_info["id"],
                    header="Strict-Transport-Security",
                    category="header",
                    severity="medium",
                    weight=10,
                    safe_default="max-age=604800; includeSubDomains",
                    description=tr(
                        f"HSTS em fase de teste (max-age={hsts_max_age}s). "
                        "Após validar subdomínios, avance para a Etapa 2 (max-age=604800; includeSubDomains).",
                        f"HSTS in testing phase (max-age={hsts_max_age}s). "
                        "Once subdomains are validated, move to Stage 2 (max-age=604800; includeSubDomains).",
                    ),
                    remediation='add_header Strict-Transport-Security "max-age=604800; includeSubDomains" always;',
                    snippets=_build_header_snippets("Strict-Transport-Security", "max-age=604800; includeSubDomains"),
                    progressive_steps=_hsts_steps(),
                )
            )
        else:
            sans_alert = (
                tr(
                    f" Atenção: afetará os subdomínios do certificado: {', '.join(hsts_affected_sans[:4])}.",
                    f" Note: this will affect the certificate's subdomains: {', '.join(hsts_affected_sans[:4])}.",
                )
                if hsts_affected_sans
                else ""
            )
            missing_findings.append(
                SecurityFinding(
                    id=hsts_info["id"],
                    header="Strict-Transport-Security",
                    category="header",
                    severity="high",
                    weight=15,
                    safe_default=tx(hsts_info.get("safe_default", "max-age=300")),
                    description=tr(
                        f"HSTS configurado com max-age insuficiente (< 300s).{sans_alert}",
                        f"HSTS configured with an insufficient max-age (< 300s).{sans_alert}",
                    ),
                    remediation=hsts_info["fix"],
                    snippets=hsts_default_snippets,
                    progressive_steps=_hsts_steps(),
                )
            )
    else:
        sans_alert = (
            tr(
                f" Atenção: ativar includeSubDomains cobrirá os seguintes subdomínios identificados no certificado: {', '.join(hsts_affected_sans[:4])}.",
                f" Note: enabling includeSubDomains will cover these subdomains found in the certificate: {', '.join(hsts_affected_sans[:4])}.",
            )
            if hsts_affected_sans
            else ""
        )
        missing_findings.append(
            SecurityFinding(
                id=hsts_info["id"],
                header="Strict-Transport-Security",
                category="header",
                severity="high",
                weight=15,
                safe_default=tx(hsts_info.get("safe_default", "max-age=300")),
                description=tx(hsts_info["desc"]) + sans_alert,
                remediation=hsts_info["fix"],
                snippets=hsts_default_snippets,
                progressive_steps=_hsts_steps(),
            )
        )

    # CSP e clickjacking (até 15 pontos)
    csp_info = SECURITY_HEADERS_DETAILS["Content-Security-Policy"]
    csp_default_snippets = _build_header_snippets("Content-Security-Policy-Report-Only", csp_info["value"])
    # Report-Only não bloqueia nada: só a política aplicada conta como proteção (e a qualidade dela pesa na nota).
    csp_raw = headers.get("Content-Security-Policy", "")
    csp_report_only = headers.get("Content-Security-Policy-Report-Only", "")
    csp_analysis = analyze_csp(csp_raw, csp_report_only)
    has_csp = csp_analysis.enforced
    if csp_report_only:
        present["Content-Security-Policy-Report-Only"] = csp_report_only
    csp_frame_ancestors = bool(re.search(r"\bframe-ancestors\b", csp_raw, re.IGNORECASE)) if has_csp else False
    has_xfo = "X-Frame-Options" in headers

    if has_csp:
        present["Content-Security-Policy"] = csp_raw
        if csp_frame_ancestors:
            headers_score += _csp_points(15, csp_analysis)
            present["X-Frame-Options (via CSP frame-ancestors)"] = tr("Ativo via Content-Security-Policy frame-ancestors", "Active via Content-Security-Policy frame-ancestors")
        elif has_xfo:
            headers_score += _csp_points(15, csp_analysis)
            present["X-Frame-Options"] = headers["X-Frame-Options"]
        else:
            headers_score += _csp_points(10, csp_analysis)
            xfo_info = SECURITY_HEADERS_DETAILS["X-Frame-Options"]
            missing_findings.append(
                SecurityFinding(
                    id=xfo_info["id"],
                    header="X-Frame-Options",
                    category="header",
                    severity="medium",
                    weight=5,
                    safe_default="frame-ancestors 'self'",
                    description=tr(
                        "CSP ativo, mas sem a diretiva 'frame-ancestors' e sem cabeçalho X-Frame-Options para proteção contra Clickjacking.",
                        "CSP is active, but there is no 'frame-ancestors' directive and no X-Frame-Options header to protect against clickjacking.",
                    ),
                    remediation=xfo_info["fix"],
                    snippets=_build_header_snippets("X-Frame-Options", xfo_info["value"]),
                )
            )
        if csp_analysis.strength != "strong":
            missing_findings.append(_csp_quality_finding(csp_analysis))
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
                    safe_default=tx(csp_info.get("safe_default")),
                    description=tx(csp_info["desc"]) + (tx(_CSP_REPORT_ONLY_NOTE) if csp_report_only else ""),
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
                    safe_default=tx(csp_info.get("safe_default")),
                    description=tx(csp_info["desc"]) + (tx(_CSP_REPORT_ONLY_NOTE) if csp_report_only else ""),
                    remediation=csp_info["fix"],
                    snippets=csp_default_snippets,
                )
            )

    # X-Content-Type-Options (5 pontos)
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
                description=tx(xcto_info["desc"]),
                remediation=xcto_info["fix"],
                snippets=_build_header_snippets("X-Content-Type-Options", xcto_info["value"]),
            )
        )

    # Permissions-Policy (5 pontos)
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
                    description=tr(
                        "Permissions-Policy está presente, mas não restringe explicitamente o acesso à câmera via 'camera=()'.",
                        "Permissions-Policy is present, but it does not explicitly restrict camera access via 'camera=()'.",
                    ),
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
                safe_default=tx(perm_info.get("safe_default")),
                description=tx(perm_info["desc"]),
                remediation=perm_info["fix"],
                snippets=_build_header_snippets("Permissions-Policy", perm_info["value"]),
            )
        )

    # Referrer-Policy, só informativo
    if "Referrer-Policy" in headers:
        present["Referrer-Policy"] = headers["Referrer-Policy"]

    # isolamento de origem cruzada (COOP/COEP/CORP): só informativo, não muda a nota.
    for iso_name in ("Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy", "Cross-Origin-Resource-Policy"):
        if iso_name in headers:
            present[iso_name] = headers[iso_name]
    if is_https:
        missing_findings.extend(_isolation_findings(headers))

    # dimensão 3: higiene da aplicação (até 20 pontos)
    hygiene_score = 20

    # vazamento de servidor/versão (até 10 pontos)
    for leak_h in LEAK_HEADERS:
        if leak_h in headers:
            leak_val = headers[leak_h]
            # `Server: cloudflare` ou `Server: github.com` não revelam versão, então não é vazamento que dê pra agir.
            # os outros (X-Powered-By, X-AspNet-Version, X-Generator) existem justamente pra divulgar tecnologia.
            if leak_h == "Server" and not _VERSION_IN_HEADER_RE.search(leak_val):
                continue
            leaks.append(f"{leak_h}: {leak_val}")
            missing_findings.append(
                SecurityFinding(
                    id=f"SEC-LEAK-{leak_h.upper()}",
                    header=tr(f"Vazamento: {leak_h}", f"Leak: {leak_h}"),
                    category="leak",
                    severity="low",
                    weight=5,
                    safe_default=tr(f"Remover cabeçalho {leak_h}", f"Remove the {leak_h} header"),
                    description=tr(
                        f"O cabeçalho '{leak_h}: {leak_val}' expõe tecnologia/versão da borda ou backend, "
                        "facilitando reconhecimento de vulnerabilidades específicas.",
                        f"The '{leak_h}: {leak_val}' header exposes edge or backend technology/version, "
                        "making it easier to find vulnerabilities specific to it.",
                    ),
                    remediation=tr(f"Oculte ou remova o cabeçalho {leak_h} na borda.", f"Hide or remove the {leak_h} header at the edge."),
                    snippets=_build_leak_snippets(leak_h),
                )
            )
    if leaks:
        hygiene_score -= min(10, 5 * len(leaks))  # coerente com o peso (5) declarado por finding

    # cookies (até 5 pontos)
    insecure_cookies = [c for c in cookies_audited if c.issues]
    if insecure_cookies:
        hygiene_score -= 5
        cookie_details = "; ".join(f"{c.name} ({', '.join(c.issues)})" for c in insecure_cookies)
        missing_findings.append(
            SecurityFinding(
                id="SEC-COOKIES",
                header=tr("Set-Cookie (Flags Inseguras)", "Set-Cookie (insecure flags)"),
                category="cookie",
                severity="medium",
                weight=5,
                safe_default="Secure; HttpOnly; SameSite=Lax",
                description=tr(
                    f"Cookies detectados sem blindagem completa: {cookie_details}.",
                    f"Cookies found without full hardening: {cookie_details}.",
                ),
                remediation=tr(
                    "Configure as flags Secure, HttpOnly e SameSite=Lax na emissão de cookies.",
                    "Set the Secure, HttpOnly and SameSite=Lax flags when issuing cookies.",
                ),
                snippets=_build_cookie_snippets(),
            )
        )

    # CORS (até 5 pontos)
    if cors_vulnerable or cors_wildcard:
        hygiene_score -= 5
        cors_desc = (
            cors_audit.details if cors_audit and cors_audit.details else
            tr(
                "Cabeçalho 'Access-Control-Allow-Origin: *' expõe respostas da aplicação indiscriminadamente.",
                "The 'Access-Control-Allow-Origin: *' header exposes the application's responses indiscriminately.",
            )
        )
        missing_findings.append(
            SecurityFinding(
                id="SEC-CORS",
                header=tr("Access-Control-Allow-Origin (Inseguro)", "Access-Control-Allow-Origin (insecure)"),
                category="cors",
                severity="high" if cors_credentials else "medium",
                weight=5,
                safe_default='add_header Access-Control-Allow-Origin "https://app.example.com" always;',
                description=cors_desc,
                remediation=tr(
                    "Restrinja Access-Control-Allow-Origin para origens explícitas e confiáveis.",
                    "Restrict Access-Control-Allow-Origin to explicit, trusted origins.",
                ),
                snippets=_build_cors_snippets(),
            )
        )

    # garante os limites e soma o total
    tls_findings, tls_cap, tls_penalty = _tls_enum_findings(tls)
    missing_findings.extend(tls_findings)
    transport_score -= tls_penalty
    transport_score = max(0, min(40, transport_score))
    headers_score = max(0, min(40, headers_score))
    hygiene_score = max(0, min(20, hygiene_score))

    if tls and (
        tls.protocol in ("TLSv1", "TLSv1.1", "SSLv3")
        or tls.deprecated_protocol
        or tls.tls10_11_accepted
    ):
        transport_score = min(transport_score, 10)
    if tls_cap is not None:
        transport_score = min(transport_score, tls_cap)

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
        evaluated_url=evaluated_url,
        csp_analysis=csp_analysis,
    )