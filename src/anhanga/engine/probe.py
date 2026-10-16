import asyncio
import math
import socket
import ssl
import statistics
import time
import typing
from urllib.parse import urlparse

import httpcore
import httpx
from httpcore._backends.auto import AutoBackend
from httpcore._backends.base import AsyncNetworkBackend, AsyncNetworkStream, SOCKET_OPTION

from anhanga.engine.models import (
    PhasePercentiles,
    ProbeResult,
    RedirectHop,
    SampleMeasurement,
    SamplingStats,
    TimingBreakdown,
    TLSInspection,
    build_timing_breakdown,
)
from anhanga.engine.security import (
    audit_http_security,
    check_tls10_11_accepted_async,
    is_ssrf_safe,
    parse_tls_certificate,
)


class SSRFBlockedError(Exception):
    """Exceção disparada quando um host resolve para IP privado ou restrito."""

    def __init__(self, ip: str, message: str) -> None:
        super().__init__(message)
        self.ip = ip


class InstrumentedAsyncNetworkStream(AsyncNetworkStream):
    """Wrapper sobre AsyncNetworkStream que mede com precisão o handshake TLS e captura o ssl_object."""

    def __init__(
        self, stream: AsyncNetworkStream, backend: "InstrumentedPinnedNetworkBackend"
    ) -> None:
        self._stream = stream
        self._backend = backend

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return await self._stream.read(max_bytes=max_bytes, timeout=timeout)

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        return await self._stream.write(buffer=buffer, timeout=timeout)

    async def aclose(self) -> None:
        await self._stream.aclose()

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> AsyncNetworkStream:
        t0 = time.perf_counter()
        tls_stream = await self._stream.start_tls(
            ssl_context=ssl_context,
            server_hostname=server_hostname,
            timeout=timeout,
        )
        t1 = time.perf_counter()
        self._backend.step_tls_ms = round((t1 - t0) * 1000, 2)
        self._backend.step_conn_ready_ts = t1
        ssl_obj = tls_stream.get_extra_info("ssl_object")
        if ssl_obj is not None:
            self._backend.last_ssl_object = ssl_obj
        return InstrumentedAsyncNetworkStream(tls_stream, self._backend)

    def get_extra_info(self, info: str) -> typing.Any:
        return self._stream.get_extra_info(info)


class InstrumentedPinnedNetworkBackend(AsyncNetworkBackend):
    """
    NetworkBackend customizado para httpcore que:
    1. Conecta diretamente ao IP já resolvido e validado (prevenindo DNS Rebinding / TOCTOU).
    2. Mede separadamente o handshake TCP (`step_tcp_ms`) e o handshake TLS (`step_tls_ms`).
    3. Registra o timestamp exato em que a conexão ficou pronta (`step_conn_ready_ts`)
       para que o cálculo de TTFB nunca inclua TCP ou TLS.
    """

    def __init__(self, allow_private: bool = False) -> None:
        self._inner = AutoBackend()
        self.allow_private = allow_private
        self.pinned_ips: dict[str, str] = {}
        self.step_tcp_ms: float = 0.0
        self.step_tls_ms: float = 0.0
        self.step_connected: bool = False
        self.step_conn_ready_ts: float | None = None
        self.last_ssl_object: typing.Any = None

    def reset_step(self) -> None:
        self.step_tcp_ms = 0.0
        self.step_tls_ms = 0.0
        self.step_connected = False
        self.step_conn_ready_ts = None

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: typing.Iterable[SOCKET_OPTION] | None = None,
    ) -> AsyncNetworkStream:
        target_ip = self.pinned_ips.get(host.lower(), host)
        if not is_ssrf_safe(target_ip, self.allow_private):
            raise SSRFBlockedError(
                target_ip,
                f"Bloqueado pelo Guardião Anti-SSRF: IP privado/restrito ({target_ip}).",
            )

        t0 = time.perf_counter()
        stream = await self._inner.connect_tcp(
            target_ip,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )
        t1 = time.perf_counter()
        self.step_tcp_ms = round((t1 - t0) * 1000, 2)
        self.step_connected = True
        self.step_conn_ready_ts = t1
        return InstrumentedAsyncNetworkStream(stream, self)

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: typing.Iterable[SOCKET_OPTION] | None = None,
    ) -> AsyncNetworkStream:
        stream = await self._inner.connect_unix_socket(
            path, timeout=timeout, socket_options=socket_options
        )
        return InstrumentedAsyncNetworkStream(stream, self)

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


async def resolve_and_validate_host(
    host: str, port: int, allow_private: bool = False
) -> tuple[str, float]:
    """
    Resolve o hostname via getaddrinfo (IPv4/IPv6), mede dns_ms real e valida
    TODOS os endereços retornados contra a política Anti-SSRF.
    """
    loop = asyncio.get_running_loop()
    t0 = time.perf_counter()
    addr_info = await loop.getaddrinfo(
        host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
    )
    dns_ms = round((time.perf_counter() - t0) * 1000, 2)

    if not addr_info:
        raise socket.gaierror(f"Nenhum registro DNS encontrado para {host}")

    resolved_ips: list[str] = []
    preferred_ipv4: str | None = None
    for family, _, _, _, sockaddr in addr_info:
        ip_str = str(sockaddr[0])
        if ip_str not in resolved_ips:
            resolved_ips.append(ip_str)
        if family == socket.AF_INET and preferred_ipv4 is None:
            preferred_ipv4 = ip_str

    for ip_str in resolved_ips:
        if not is_ssrf_safe(ip_str, allow_private):
            raise SSRFBlockedError(
                ip_str,
                f"Bloqueado pelo Guardião Anti-SSRF: IP privado/restrito ({ip_str}).",
            )

    chosen_ip = preferred_ipv4 or resolved_ips[0]
    return chosen_ip, dns_ms


def _percentile(sorted_vals: list[float], q: float) -> float:
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return round(sorted_vals[0], 2)
    pos = (len(sorted_vals) - 1) * (q / 100.0)
    lower = int(math.floor(pos))
    upper = int(math.ceil(pos))
    if lower == upper:
        return round(sorted_vals[lower], 2)
    weight = pos - lower
    return round(sorted_vals[lower] * (1.0 - weight) + sorted_vals[upper] * weight, 2)


def _compute_jitter(vals: list[float]) -> float:
    if len(vals) <= 1:
        return 0.0
    diffs = [abs(vals[i] - vals[i - 1]) for i in range(1, len(vals))]
    return round(statistics.mean(diffs), 2)


def _compute_phase_percentiles(vals: list[float]) -> PhasePercentiles:
    if not vals:
        return PhasePercentiles()
    s = sorted(vals)
    return PhasePercentiles(
        p50_ms=_percentile(s, 50.0),
        p95_ms=_percentile(s, 95.0),
        p99_ms=_percentile(s, 99.0),
        min_ms=round(s[0], 2),
        max_ms=round(s[-1], 2),
        mean_ms=round(statistics.mean(s), 2),
        jitter_ms=_compute_jitter(vals),
    )


def _build_sampling_stats(raw_samples: list[SampleMeasurement]) -> SamplingStats:
    if not raw_samples:
        return SamplingStats(samples_count=0)

    totals = [s.timings.total_ms for s in raw_samples]
    sorted_totals = sorted(totals)

    cold_total_ms = round(raw_samples[0].timings.total_ms, 2)
    warm_totals = [
        s.timings.total_ms
        for s in raw_samples[1:]
        if s.connection_reused
    ]
    if not warm_totals and len(raw_samples) > 1:
        warm_totals = [s.timings.total_ms for s in raw_samples[1:]]
    warm_avg_total_ms = (
        round(statistics.mean(warm_totals), 2) if warm_totals else None
    )

    phase_series: dict[str, list[float]] = {
        "dns": [s.timings.dns_ms for s in raw_samples],
        "tcp": [s.timings.tcp_ms for s in raw_samples],
        "tls": [s.timings.tls_ms for s in raw_samples],
        "ttfb": [s.timings.ttfb_ms for s in raw_samples],
        "transfer": [s.timings.transfer_ms for s in raw_samples],
        "total": totals,
    }
    phase_stats = {
        phase_name: _compute_phase_percentiles(series)
        for phase_name, series in phase_series.items()
    }

    return SamplingStats(
        samples_count=len(raw_samples),
        cold_total_ms=cold_total_ms,
        warm_avg_total_ms=warm_avg_total_ms,
        p50_ms=_percentile(sorted_totals, 50.0),
        p95_ms=_percentile(sorted_totals, 95.0),
        p99_ms=_percentile(sorted_totals, 99.0),
        min_ms=round(sorted_totals[0], 2),
        max_ms=round(sorted_totals[-1], 2),
        mean_ms=round(statistics.mean(totals), 2),
        stdev_ms=round(statistics.stdev(totals), 2) if len(totals) > 1 else 0.0,
        jitter_ms=_compute_jitter(totals),
        phase_stats=phase_stats,
        raw_samples=raw_samples,
    )


def _create_instrumented_transport(
    backend: InstrumentedPinnedNetworkBackend,
    verify: bool | ssl.SSLContext = True,
    http2: bool = True,
) -> httpx.AsyncHTTPTransport:
    transport = httpx.AsyncHTTPTransport(http2=http2, verify=verify)
    transport._pool._network_backend = backend  # type: ignore[attr-defined]
    return transport


async def _execute_single_http_step(
    client: httpx.AsyncClient,
    backend: InstrumentedPinnedNetworkBackend,
    url: str,
    dns_ms: float,
    max_body_bytes: int,
) -> tuple[httpx.Response, TimingBreakdown, bool, int, bool]:
    """
    Executa um único GET com streaming e mede de forma estritamente não-cumulativa:
    - tcp_ms e tls_ms via backend instrumentado
    - ttfb_ms desde o fim do handshake TCP/TLS (ou início do request se conexão reutilizada) até os headers
    - transfer_ms durante a leitura em streaming do body (limitado a max_body_bytes)
    """
    backend.reset_step()
    t_req_start = time.perf_counter()

    payload_bytes = 0
    payload_truncated = False

    async with client.stream("GET", url) as resp:
        t_headers_received = time.perf_counter()

        if backend.step_connected:
            connection_reused = False
            tcp_ms = backend.step_tcp_ms
            tls_ms = backend.step_tls_ms
            conn_ready_ts = backend.step_conn_ready_ts or t_req_start
            ttfb_ms = round(max(0.0, (t_headers_received - conn_ready_ts) * 1000), 2)
            step_dns_ms = dns_ms
        else:
            connection_reused = True
            step_dns_ms = 0.0
            tcp_ms = 0.0
            tls_ms = 0.0
            ttfb_ms = round(max(0.0, (t_headers_received - t_req_start) * 1000), 2)

        ssl_obj = resp.extensions.get("ssl_object")
        if ssl_obj is not None:
            backend.last_ssl_object = ssl_obj

        t_transfer_start = time.perf_counter()
        async for chunk in resp.aiter_bytes():
            payload_bytes += len(chunk)
            if payload_bytes > max_body_bytes:
                payload_bytes = max_body_bytes
                payload_truncated = True
                break
        transfer_ms = round(max(0.0, (time.perf_counter() - t_transfer_start) * 1000), 2)

    timings = build_timing_breakdown(
        dns_ms=step_dns_ms,
        tcp_ms=tcp_ms,
        tls_ms=tls_ms,
        ttfb_ms=ttfb_ms,
        transfer_ms=transfer_ms,
    )
    return resp, timings, connection_reused, payload_bytes, payload_truncated


async def _run_probe_session(
    initial_url: str,
    timeout: float,
    allow_private: bool,
    samples: int,
    max_body_bytes: int,
    verify_ssl: bool = True,
) -> ProbeResult:
    backend = InstrumentedPinnedNetworkBackend(allow_private=allow_private)
    transport = _create_instrumented_transport(backend, verify=verify_ssl, http2=True)
    headers = {"User-Agent": "Anhanga-Probe/0.1 (+https://github.com/timeuz/anhanga)"}

    redirect_chain: list[RedirectHop] = []
    origin_conn_timings: dict[tuple[str, str, int], tuple[float, float, float]] = {}

    current_url = initial_url
    max_redirects = 10
    resolved_ip: str | None = None
    last_dns_timings = TimingBreakdown()

    async with httpx.AsyncClient(
        transport=transport,
        follow_redirects=False,
        timeout=timeout,
        headers=headers,
    ) as client:
        # 1. Seguir cadeia de redirects manualmente (Amostra 1 / Fria)
        final_resp: httpx.Response | None = None
        final_timings: TimingBreakdown = TimingBreakdown()
        final_payload_bytes = 0
        final_payload_truncated = False

        for hop_num in range(1, max_redirects + 2):
            parsed = urlparse(current_url)
            host = parsed.hostname
            if not host:
                return ProbeResult(
                    target_url=initial_url,
                    error="URL inválida: hostname não encontrado.",
                )
            scheme = parsed.scheme.lower()
            port = parsed.port or (443 if scheme == "https" else 80)

            try:
                hop_ip, dns_ms = await resolve_and_validate_host(
                    host, port, allow_private=allow_private
                )
                resolved_ip = hop_ip
                backend.pinned_ips[host.lower()] = hop_ip
                last_dns_timings = build_timing_breakdown(dns_ms=dns_ms)
            except SSRFBlockedError as ssrf_err:
                return ProbeResult(
                    target_url=initial_url,
                    final_url=current_url,
                    resolved_ip=ssrf_err.ip,
                    redirect_hops=len(redirect_chain),
                    redirect_chain=redirect_chain,
                    timings=last_dns_timings,
                    error=str(ssrf_err),
                )
            except Exception as dns_exc:
                return ProbeResult(
                    target_url=initial_url,
                    final_url=current_url,
                    redirect_hops=len(redirect_chain),
                    redirect_chain=redirect_chain,
                    timings=last_dns_timings,
                    error=f"Erro de DNS: {dns_exc}",
                )

            resp, step_timings, conn_reused, p_bytes, p_trunc = (
                await _execute_single_http_step(
                    client=client,
                    backend=backend,
                    url=current_url,
                    dns_ms=dns_ms,
                    max_body_bytes=max_body_bytes,
                )
            )

            origin_key = (scheme, host.lower(), port)
            if not conn_reused:
                origin_conn_timings[origin_key] = (
                    step_timings.dns_ms,
                    step_timings.tcp_ms,
                    step_timings.tls_ms,
                )

            if (
                resp.status_code in (301, 302, 303, 307, 308)
                and "location" in resp.headers
            ):
                if hop_num > max_redirects:
                    return ProbeResult(
                        target_url=initial_url,
                        final_url=current_url,
                        resolved_ip=resolved_ip,
                        redirect_hops=len(redirect_chain),
                        redirect_chain=redirect_chain,
                        timings=step_timings,
                        error=f"Limite máximo de redirecionamentos ({max_redirects}) excedido.",
                    )

                raw_location = resp.headers["location"]
                next_url = str(resp.url.join(raw_location))
                redirect_chain.append(
                    RedirectHop(
                        hop=hop_num,
                        url=current_url,
                        target_url=next_url,
                        resolved_ip=hop_ip,
                        status_code=resp.status_code,
                        location=raw_location,
                        protocol=resp.http_version,
                        timings=step_timings,
                    )
                )
                current_url = next_url
                continue

            # Chegou na resposta final!
            # Se um redirect anterior para a mesma origem já havia aberto o socket desta amostra 1,
            # preservamos os tempos frios (DNS/TCP/TLS) da conexão inicial para a amostra 1.
            if conn_reused and origin_key in origin_conn_timings:
                o_dns, o_tcp, o_tls = origin_conn_timings[origin_key]
                step_timings = build_timing_breakdown(
                    dns_ms=o_dns,
                    tcp_ms=o_tcp,
                    tls_ms=o_tls,
                    ttfb_ms=step_timings.ttfb_ms,
                    transfer_ms=step_timings.transfer_ms,
                )

            final_resp = resp
            final_timings = step_timings
            final_payload_bytes = p_bytes
            final_payload_truncated = p_trunc
            break

        assert final_resp is not None

        raw_samples: list[SampleMeasurement] = [
            SampleMeasurement(
                sample_index=1,
                connection_reused=False,
                status_code=final_resp.status_code,
                timings=final_timings,
            )
        ]

        # 2. Amostras adicionais (2..samples) reutilizando a mesma conexão Keep-Alive
        for sample_idx in range(2, max(1, samples) + 1):
            s_resp, s_timings, s_reused, _, _ = await _execute_single_http_step(
                client=client,
                backend=backend,
                url=current_url,
                dns_ms=0.0,
                max_body_bytes=max_body_bytes,
            )
            raw_samples.append(
                SampleMeasurement(
                    sample_index=sample_idx,
                    connection_reused=s_reused,
                    status_code=s_resp.status_code,
                    timings=s_timings,
                )
            )

        sampling_stats = _build_sampling_stats(raw_samples)

        final_parsed = urlparse(str(final_resp.url))
        is_https = final_parsed.scheme.lower() == "https"
        tls_info: TLSInspection | None = None

        if is_https:
            ssl_obj = backend.last_ssl_object or final_resp.extensions.get("ssl_object")
            final_host = final_parsed.hostname or ""
            final_port = final_parsed.port or 443
            target_ip_for_tls = backend.pinned_ips.get(final_host.lower(), resolved_ip or final_host)

            legacy_tls_accepted = False
            if ssl_obj is not None and ssl_obj.version() in ("TLSv1", "TLSv1.1", "SSLv3"):
                legacy_tls_accepted = True
            elif target_ip_for_tls and final_host:
                legacy_tls_accepted = await check_tls10_11_accepted_async(
                    ip=target_ip_for_tls,
                    server_hostname=final_host,
                    port=final_port,
                    timeout=min(0.8, timeout * 0.25),
                )

            if ssl_obj is not None:
                tls_info = parse_tls_certificate(
                    ssl_obj,
                    verified=(verify_ssl or allow_private),
                    tls10_11_accepted=legacy_tls_accepted,
                )
            else:
                tls_info = TLSInspection(
                    valid=False,
                    tls10_11_accepted=legacy_tls_accepted,
                )

        sec_audit = audit_http_security(final_resp.headers, is_https, tls_info)

        return ProbeResult(
            target_url=initial_url,
            final_url=str(final_resp.url),
            resolved_ip=resolved_ip,
            is_up=(200 <= final_resp.status_code < 400),
            http_version=final_resp.http_version,
            status_code=final_resp.status_code,
            redirect_hops=len(redirect_chain),
            redirect_chain=redirect_chain,
            timings=final_timings,
            sampling=sampling_stats,
            tls=tls_info,
            security=sec_audit,
            payload_bytes=final_payload_bytes,
            payload_truncated=final_payload_truncated,
            history_ms=[s.timings.total_ms for s in raw_samples],
        )


async def execute_probe(
    raw_url: str,
    timeout: float = 5.0,
    allow_private: bool = False,
    samples: int = 1,
    max_body_bytes: int = 2_097_152,
) -> ProbeResult:
    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    parsed = urlparse(url)
    if not parsed.hostname:
        return ProbeResult(
            target_url=url, error="URL inválida: hostname não encontrado."
        )

    samples = max(1, min(int(samples), 50))

    try:
        return await _run_probe_session(
            initial_url=url,
            timeout=timeout,
            allow_private=allow_private,
            samples=samples,
            max_body_bytes=max_body_bytes,
            verify_ssl=True,
        )
    except SSRFBlockedError as ssrf_err:
        return ProbeResult(
            target_url=url,
            resolved_ip=ssrf_err.ip,
            error=str(ssrf_err),
        )
    except Exception as exc:
        # Se a falha foi causada por erro de verificação de certificado SSL (ex: self-signed ou expirado),
        # refazemos a sondagem capturando o certificado sem verificação de CA (marcando valid conforme política)
        exc_str = str(exc)
        is_ssl_verify_err = isinstance(exc, ssl.SSLCertVerificationError) or (
            "CERTIFICATE_VERIFY_FAILED" in exc_str
            or "SSLCertVerificationError" in exc_str
        )
        if is_ssl_verify_err:
            try:
                return await _run_probe_session(
                    initial_url=url,
                    timeout=timeout,
                    allow_private=allow_private,
                    samples=samples,
                    max_body_bytes=max_body_bytes,
                    verify_ssl=False,
                )
            except Exception as inner_exc:
                return ProbeResult(
                    target_url=url,
                    error=f"Erro HTTP/Conexão: {inner_exc}",
                )

        return ProbeResult(
            target_url=url,
            error=f"Erro HTTP/Conexão: {exc}",
        )