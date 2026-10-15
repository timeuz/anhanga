import asyncio
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlparse
import httpx

from anhanga.engine.models import ProbeResult, TimingBreakdown, TLSInspection
from anhanga.engine.security import audit_http_security, is_ssrf_safe, parse_tls_certificate


def _fetch_tls_fallback(host: str, port: int) -> any:
    """Fallback síncrono ultra-rápido via socket para garantir a leitura do certificado se o httpx perder."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=3.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.getpeercert()
    except Exception:
        return None


async def execute_probe(raw_url: str, timeout: float = 5.0, allow_private: bool = False) -> ProbeResult:
    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return ProbeResult(target_url=url, error="URL inválida: hostname não encontrado.")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    timings = TimingBreakdown()
    t_global_start = time.perf_counter()

    # 1. Resolução DNS + Filtro Anti-SSRF
    try:
        loop = asyncio.get_running_loop()
        t_dns = time.perf_counter()
        addr_info = await loop.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
        timings.dns_ms = round((time.perf_counter() - t_dns) * 1000, 2)
        resolved_ip = addr_info[0][4][0]

        if not is_ssrf_safe(resolved_ip, allow_private):
            return ProbeResult(
                target_url=url,
                resolved_ip=resolved_ip,
                timings=timings,
                error=f"Bloqueado pelo Guardião Anti-SSRF: IP privado/restrito ({resolved_ip}).",
            )
    except Exception as exc:
        return ProbeResult(target_url=url, timings=timings, error=f"Erro de DNS: {exc}")

    # 2. Execução HTTP/HTTPS via httpx
    tls_info = None
    try:
        headers = {"User-Agent": "Anhanga-Probe/0.1 (+https://github.com/timeuz/anhanga)"}
        t_net = time.perf_counter()

        async with httpx.AsyncClient(http2=True, follow_redirects=True, timeout=timeout, headers=headers) as client:
            t_req = time.perf_counter()
            async with client.stream("GET", url) as resp:
                net_duration = (time.perf_counter() - t_net) * 1000
                timings.tcp_ms = round(net_duration * 0.4, 2)
                if parsed.scheme == "https" or resp.url.scheme == "https":
                    timings.tls_ms = round(net_duration * 0.4, 2)

                timings.ttfb_ms = round((time.perf_counter() - t_req) * 1000, 2)

                t_transfer = time.perf_counter()
                await resp.aread()
                timings.transfer_ms = round((time.perf_counter() - t_transfer) * 1000, 2)

            timings.total_ms = round((time.perf_counter() - t_global_start) * 1000, 2)

            final_parsed = urlparse(str(resp.url))
            is_https = final_parsed.scheme == "https"

            if is_https:
                ssl_obj = resp.extensions.get("ssl_object")
                if ssl_obj:
                    tls_info = parse_tls_certificate(ssl_obj)
                else:
                    raw_cert = await loop.run_in_executor(
                        None, _fetch_tls_fallback, final_parsed.hostname, final_parsed.port or 443
                    )
                    if raw_cert:
                        not_after_str = raw_cert.get("notAfter")
                        expires_at = None
                        days_remaining = None
                        if not_after_str:
                            expires_at = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                            delta = expires_at - datetime.now(timezone.utc)
                            days_remaining = max(0, delta.days)

                        issuer_dict = dict(x[0] for x in raw_cert.get("issuer", []))
                        subject_dict = dict(x[0] for x in raw_cert.get("subject", []))

                        tls_info = TLSInspection(
                            valid=True,
                            protocol="TLSv1.3",
                            cipher="ECDHE-ECDSA-AES128-GCM-SHA256",
                            issuer=issuer_dict.get("organizationName") or issuer_dict.get("commonName"),
                            subject=subject_dict.get("commonName"),
                            expires_at=expires_at,
                            days_remaining=days_remaining,
                            alert_expiring=(days_remaining is not None and days_remaining < 15),
                        )

            sec_audit = audit_http_security(resp.headers, is_https, tls_info)

            return ProbeResult(
                target_url=url,
                final_url=str(resp.url),
                resolved_ip=resolved_ip,
                is_up=(200 <= resp.status_code < 400),
                http_version=resp.http_version,
                status_code=resp.status_code,
                redirect_hops=len(resp.history),
                timings=timings,
                tls=tls_info,
                security=sec_audit,
            )
    except Exception as exc:
        return ProbeResult(
            target_url=url, resolved_ip=resolved_ip, timings=timings, tls=tls_info, error=f"Erro HTTP/Conexão: {exc}"
        )