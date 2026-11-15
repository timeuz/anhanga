import asyncio
import contextvars
import contextlib
import ipaddress
import math
import json
import logging
import re
import socket
import ssl
import statistics
import subprocess
from pathlib import Path
import sys
import time
import typing
from urllib.parse import urlparse

import httpcore
import httpx
from httpcore._backends.auto import AutoBackend
from httpcore._backends.base import AsyncNetworkBackend, AsyncNetworkStream, SOCKET_OPTION

from collections import deque
import os

from anhanga import __version__
from anhanga.engine import revocation
from anhanga.engine.models import (
    ContentAssertionsResult,
    CORSInspection,
    PhasePercentiles,
    ProbeResult,
    RedirectHop,
    RevocationInspection,
    SampleMeasurement,
    SamplingStats,
    TimingBreakdown,
    TLSInspection,
    build_timing_breakdown,
)
from anhanga.engine.config import safe_urlparse
from anhanga.engine.tlsenum import enumerate_tls_bounded

logger = logging.getLogger("anhanga.probe")
from anhanga.engine.security import (
    audit_cors_active,
    audit_http_security,
    check_tls10_11_accepted_async,
    fetch_tls_extras,
    is_ssrf_safe,
    parse_tls_certificate,
)

ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})
DEFAULT_MAX_BODY_BYTES: int = 2_097_152  # 2 MiB
ABSOLUTE_MAX_BODY_BYTES: int = 5_242_880  # 5 MiB


class SSRFBlockedError(Exception):
    """Exceção disparada quando um host ou esquema viola a política Anti-SSRF."""

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
        if not self.allow_private:
            raise SSRFBlockedError(
                path,
                "Bloqueado pelo Guardião Anti-SSRF: conexões Unix Socket não são permitidas.",
            )
        stream = await self._inner.connect_unix_socket(
            path, timeout=timeout, socket_options=socket_options
        )
        return InstrumentedAsyncNetworkStream(stream, self)

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


_GLOBAL_PROBE_HISTORY: deque[tuple[float, str, float, bool]] = deque(maxlen=100)


def _detect_system_dns_resolver() -> str:
    resolv_conf = "/etc/resolv.conf"
    try:
        with open(resolv_conf, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
    except Exception:
        pass
    return "127.0.0.53 (systemd-resolved)"


# True só dentro das sondagens da vigilância contínua (definido pelo loop do servidor). Scans avulsos
# (API, /probe, CLI) não alimentam nem recebem o aviso: um terceiro varrendo 3 hosts ruins não pode
# acusar "resolvedor quebrado" nos alvos monitorados.
MONITORED_PROBE: contextvars.ContextVar[bool] = contextvars.ContextVar("anhanga_monitored_probe", default=False)


def _check_common_mode_failure(current_host: str, dns_ms: float, has_error: bool) -> str | None:
    if not MONITORED_PROBE.get():
        return None
    now = time.monotonic()
    _GLOBAL_PROBE_HISTORY.append((now, current_host.lower(), dns_ms, has_error))
    cutoff = now - 60.0
    recent = [item for item in _GLOBAL_PROBE_HISTORY if item[0] >= cutoff]
    degraded_domains = {
        host for _, host, d_ms, is_err in recent
        if (d_ms > 500.0 or is_err) and host
    }
    if len(degraded_domains) >= 3:
        return (
            f"Alerta de Falha em Modo Comum: múltiplos alvos distintos ({len(degraded_domains)}) apresentaram "
            "alta latência de DNS (>500ms) ou timeout simultaneamente nos últimos 60s. "
            "O gargalo pode estar no resolvedor ou na conectividade da sonda local."
        )
    return None


async def _check_port_80(
    host: str,
    allow_private: bool = False,
    timeout: float = 1.5,
    ip: str | None = None,
) -> str:
    """Verifica a porta 80 e se ela redireciona para HTTPS, distinguindo a causa de cada falha."""
    target_ip = ip or host
    if not is_ssrf_safe(target_ip, allow_private):
        return "Porta 80 não verificada (IP bloqueado pela política Anti-SSRF)"

    # 1. Conectividade TCP: distingue recusada (fechada) de timeout (filtrada) e reset.
    writer = None
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(target_ip, 80), timeout)
    except asyncio.TimeoutError:
        return "Porta 80 sem resposta (timeout; possível filtro de firewall/egress)"
    except ConnectionRefusedError:
        return "Porta 80 fechada (conexão recusada)"
    except ConnectionResetError:
        return "Porta 80 inacessível (conexão resetada)"
    except OSError as err:
        return f"Porta 80 inacessível ({err.strerror or type(err).__name__})"
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    # 2. Resposta HTTP, conectando ao IP já validado (sem nova resolução DNS).
    backend = InstrumentedPinnedNetworkBackend(allow_private=allow_private)
    backend.pinned_ips[host.lower()] = target_ip
    transport = _create_instrumented_transport(backend, verify=True, http2=False)
    try:
        async with httpx.AsyncClient(
            transport=transport,
            follow_redirects=False,
            timeout=timeout,
            headers={"User-Agent": f"Anhanga-Probe/{__version__} (+https://github.com/timeuz/anhanga)"},
        ) as c:
            url_host = f"[{host}]" if ":" in host and not host.startswith("[") else host  # IPv6 literal
            resp = await c.get(f"http://{url_host}/")
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("location", "").strip()
                if loc.lower().startswith("https://"):
                    return f"{resp.status_code} Redireciona para HTTPS (Correto)"
                return f"{resp.status_code} Redireciona para HTTP ({loc[:35]})"
            if 200 <= resp.status_code < 400:
                return f"{resp.status_code} Sem Redirecionamento HTTPS (Inseguro)"
            return f"HTTP {resp.status_code}"
    except httpx.TimeoutException:
        return "Porta 80 aberta, mas o HTTP não respondeu a tempo"
    except Exception as err:  # noqa: BLE001
        return f"Porta 80 aberta, mas a requisição HTTP falhou ({type(err).__name__})"


MAX_REGEX_LENGTH: int = 512
REGEX_TIMEOUT_SECONDS: float = 2.0


_REGEX_WORKER = Path(__file__).with_name("_regex_worker.py")


def _regex_worker_argv() -> list[str]:
    """`python -I <arquivo>`: o worker só usa `re`/`json`, então roda por CAMINHO. `-I` ignora PYTHONPATH
    e o cwd, então `-m anhanga...` só funcionava com o pacote instalado: em execução via `PYTHONPATH=src`
    toda asserção de regex virava "Regexp inválida"."""
    return [sys.executable, "-I", str(_REGEX_WORKER)]


def _regex_search_isolated(pattern: str, text: str) -> tuple[str, typing.Any]:
    """Executa re.search em subprocesso descartável com timeout rígido (anti-ReDoS).

    Subprocesso (e não multiprocessing/spawn, que reimporta o `__main__` do processo-pai e quebra conforme
    a forma de execução). Retorna ("ok", bool) | ("invalid", msg: padrão inválido) | ("timeout", None) |
    ("unavailable", msg: o avaliador em si falhou; isso NÃO é culpa do padrão do usuário).
    """
    if len(pattern) > MAX_REGEX_LENGTH:
        return "invalid", f"padrão excede {MAX_REGEX_LENGTH} caracteres"
    try:
        proc = subprocess.run(
            _regex_worker_argv(),
            input=json.dumps({"pattern": pattern, "text": text}).encode("utf-8"),
            capture_output=True,
            timeout=REGEX_TIMEOUT_SECONDS,
            check=False,
        )  # TimeoutExpired mata o filho antes de propagar
    except subprocess.TimeoutExpired:
        return "timeout", None
    except OSError as err:
        return "unavailable", f"não foi possível iniciar o avaliador de regex: {err}"
    if proc.returncode != 0:
        tail = proc.stderr.decode("utf-8", errors="replace").strip().splitlines()[-1:] or ["sem detalhe"]
        return "unavailable", f"o avaliador de regex encerrou com erro (código {proc.returncode}): {tail[0][:160]}"
    try:
        status, value = json.loads(proc.stdout.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return "unavailable", "resposta inválida do avaliador de regex"
    return status, value


async def _regex_search(pattern: str, text: str) -> tuple[str, typing.Any]:
    return await asyncio.get_running_loop().run_in_executor(
        None, _regex_search_isolated, pattern, text
    )


async def _evaluate_content_assertions(
    body_text: str,
    payload_bytes: int,
    final_url: str,
    fail_if_body_not_matches_regexp: str | None = None,
    fail_if_body_matches_regexp: str | None = None,
    min_payload_bytes: int | None = None,
    max_payload_bytes: int | None = None,
    assert_final_url: str | None = None,
    payload_truncated: bool = False,
) -> ContentAssertionsResult:
    failures: list[str] = []
    not_evaluated: list[str] = []

    for field, pattern, must_match in (
        ("fail_if_body_not_matches_regexp", fail_if_body_not_matches_regexp, True),
        ("fail_if_body_matches_regexp", fail_if_body_matches_regexp, False),
    ):
        if not pattern:
            continue
        status, value = await _regex_search(pattern, body_text)
        if status == "unavailable":
            # Falha do monitor, não do alvo: registra como "não avaliado" (visível) sem reprovar a asserção,
            # senão um problema de fork/arquivo derrubaria e alertaria TODOS os alvos com regex ao mesmo tempo.
            logger.warning(
                "asserção %s não avaliada: avaliador de regex indisponível (%s)", field, value
            )
            not_evaluated.append(
                f"{field}: avaliador de regex indisponível ({value}); o padrão não foi avaliado "
                "(falha do Anhangá, não do alvo)"
            )
        elif status == "invalid":
            failures.append(f"Regexp inválida em {field}: {value}")
        elif status == "timeout":
            failures.append(
                f"Regexp em {field} abortada após {REGEX_TIMEOUT_SECONDS:.0f}s (custo exponencial / ReDoS)"
            )
        elif must_match and not value:
            failures.append(f"Corpo não contém o padrão esperado: '{pattern}'")
        elif not must_match and value:
            failures.append(f"Corpo contém o padrão proibido: '{pattern}'")

    if min_payload_bytes is not None and payload_bytes < min_payload_bytes:
        failures.append(
            f"Payload recebido ({payload_bytes} bytes) abaixo do mínimo exigido ({min_payload_bytes} bytes)"
        )

    if max_payload_bytes is not None and payload_bytes > max_payload_bytes:
        failures.append(
            f"Payload recebido ({payload_bytes} bytes) acima do máximo permitido ({max_payload_bytes} bytes)"
        )
    elif max_payload_bytes is not None and payload_truncated:
        # A leitura parou no teto (max_body_bytes): o tamanho real é desconhecido e `payload_bytes` é só o teto.
        not_evaluated.append(
            f"max_payload_bytes: a resposta foi truncada em {payload_bytes} bytes (limite de leitura); o máximo de "
            f"{max_payload_bytes} bytes não pôde ser avaliado"
        )

    if assert_final_url and final_url != assert_final_url:
        failures.append(
            f"URL final obtida ('{final_url}') diverge da URL esperada ('{assert_final_url}')"
        )

    return ContentAssertionsResult(passed=(len(failures) == 0), failures=failures, not_evaluated=not_evaluated)


async def resolve_and_validate_host(
    host: str,
    port: int,
    allow_private: bool = False,
    dns_timeout: float = 3.0,
    resolve_override: dict[str, str] | None = None,
    return_all_ips: bool = False,
) -> tuple[str, float] | tuple[str, float, list[str]]:
    """
    Resolve o hostname via getaddrinfo (IPv4/IPv6) uma única vez com timeout próprio,
    mede dns_ms real e valida TODOS os endereços retornados contra a política Anti-SSRF.
    Suporta override (--resolve host:port:ip).
    """
    clean_host = host.strip()
    if clean_host.startswith("[") and clean_host.endswith("]"):
        clean_host = clean_host[1:-1].strip()

    if "%" in clean_host and not allow_private:
        raise SSRFBlockedError(
            clean_host,
            f"Bloqueado pelo Guardião Anti-SSRF: zona IPv6 não permitida ({clean_host}).",
        )

    # Suporte a override explícito de resolução (--resolve host:port:ip)
    if resolve_override:
        override_ip = (
            resolve_override.get(f"{clean_host.lower()}:{port}")
            or resolve_override.get(clean_host.lower())
        )
        if override_ip:
            if not is_ssrf_safe(override_ip, allow_private):
                raise SSRFBlockedError(
                    override_ip,
                    f"Bloqueado pelo Guardião Anti-SSRF: IP de override privado/restrito ({override_ip}).",
                )
            if return_all_ips:
                return override_ip, 0.0, [override_ip]
            return override_ip, 0.0

    # Se já for literal de IP, valida antes mesmo de invocar o resolvedor
    try:
        ipaddress.ip_address(clean_host.split("%", 1)[0])
        if not is_ssrf_safe(clean_host, allow_private):
            raise SSRFBlockedError(
                clean_host,
                f"Bloqueado pelo Guardião Anti-SSRF: IP privado/restrito ({clean_host}).",
            )
    except ValueError:
        pass

    loop = asyncio.get_running_loop()
    t0 = time.perf_counter()
    addr_info = await asyncio.wait_for(
        loop.getaddrinfo(
            clean_host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        ),
        timeout=max(0.5, dns_timeout),
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
    if return_all_ips:
        return chosen_ip, dns_ms, resolved_ips
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
    p50_total = _percentile(sorted_totals, 50.0)

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

    # DNS/TCP/TLS só existem em conexões novas: amostras reaproveitadas (0 ms) distorceriam a mediana.
    cold_samples = [s for s in raw_samples if not s.connection_reused] or raw_samples[:1]
    phase_series: dict[str, list[float]] = {
        "dns": [s.timings.dns_ms for s in cold_samples],
        "tcp": [s.timings.tcp_ms for s in cold_samples],
        "tls": [s.timings.tls_ms for s in cold_samples],
        "ttfb": [s.timings.ttfb_ms for s in raw_samples],
        "transfer": [s.timings.transfer_ms for s in raw_samples],
        "total": totals,
    }
    phase_stats = {
        phase_name: _compute_phase_percentiles(series)
        for phase_name, series in phase_series.items()
    }

    n_samples = len(raw_samples)
    p95_valid = n_samples >= 20
    p99_valid = n_samples >= 100
    if not p95_valid:
        sample_size_notice = (
            "Amostragem com n < 20: P95 e P99 requerem amostragem maior (n ≥ 20 para P95, n ≥ 100 para P99) para validade estatística."
        )
    elif not p99_valid:
        sample_size_notice = (
            "P99 requer n ≥ 100; um scan avulso é limitado a 20 amostras (para não sobrecarregar o alvo). "
            "Consulte o histórico do monitoramento para a cauda extrema."
        )
    else:
        sample_size_notice = None

    return SamplingStats(
        samples_count=n_samples,
        headline_total_ms=p50_total,
        headline_label="Latência Típica (Mediana P50)",
        cold_total_ms=cold_total_ms,
        warm_avg_total_ms=warm_avg_total_ms,
        p50_ms=p50_total,
        p95_ms=_percentile(sorted_totals, 95.0),
        p99_ms=_percentile(sorted_totals, 99.0),
        min_ms=round(sorted_totals[0], 2),
        max_ms=round(sorted_totals[-1], 2),
        mean_ms=round(statistics.mean(totals), 2),
        stdev_ms=round(statistics.stdev(totals), 2) if len(totals) > 1 else 0.0,
        jitter_ms=_compute_jitter(totals),
        p95_valid=p95_valid,
        p99_valid=p99_valid,
        sample_size_notice=sample_size_notice,
        phase_stats=phase_stats,
        phase_stats_note=(
            f"DNS/TCP/TLS calculados apenas sobre as {len(cold_samples)} amostra(s) com conexão nova; "
            "TTFB, transferência e total usam todas."
        ),
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
    reference_sample: str = "Amostra 1 (Conexão Fria)",
) -> tuple[httpx.Response, TimingBreakdown, bool, int, bool, bytes]:
    """
    Executa um único GET com streaming e mede de forma estritamente não-cumulativa:
    - tcp_ms e tls_ms via backend instrumentado
    - ttfb_ms desde o fim do handshake TCP/TLS (ou início do request se conexão reutilizada) até os headers
    - transfer_ms durante a leitura em streaming do body (limitado a max_body_bytes)
    - captura os bytes do payload para asserções de conteúdo
    """
    backend.reset_step()
    t_req_start = time.perf_counter()

    payload_bytes = 0
    payload_truncated = False
    body_chunks: list[bytes] = []

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
            body_chunks.append(chunk)
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
        reference_sample=reference_sample,
    )
    return resp, timings, connection_reused, payload_bytes, payload_truncated, b"".join(body_chunks)


STAGE_RESERVE_SECONDS = 1.0  # folga reservada para montar o resultado depois das etapas


def _overall_timeout(timeout: float, samples: int) -> float:
    """Prazo global da sondagem. A folga de +9 s cobre as etapas pós-HTTP, que também têm orçamento combinado
    (`_bounded`): se faltar prazo, elas degradam para resultado parcial em vez de cancelar tudo."""
    return min(60.0, max(timeout * min(samples, 5) + 9.0, timeout + 8.0))


async def _bounded(
    factory: typing.Callable[[], typing.Awaitable[typing.Any]],
    deadline: float | None,
    default: typing.Any,
    skipped: list[str],
    label: str,
) -> typing.Any:
    """Roda uma etapa pós-HTTP sem estourar o prazo da sondagem: sem prazo restante (ou ao estourá-lo) devolve
    `default` e registra a etapa em `skipped`. A resposta HTTP já obtida nunca é descartada por causa disso."""
    if deadline is None:
        return await factory()
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        skipped.append(label)
        return default
    try:
        return await asyncio.wait_for(factory(), timeout=remaining)
    except asyncio.TimeoutError:
        if time.monotonic() >= deadline - 0.05:
            skipped.append(label)  # o prazo da sondagem acabou de fato
        else:
            # Timeout PRÓPRIO da etapa (socket/OCSP...) que vazou: não é falta de prazo, e a etapa não concluiu.
            logger.warning("etapa '%s' levantou TimeoutError antes do prazo da sondagem", label)
            skipped.append(f"{label} (timeout da própria etapa)")
        return default


async def _run_probe_session(
    initial_url: str,
    timeout: float,
    allow_private: bool,
    samples: int,
    max_body_bytes: int,
    verify_ssl: bool = True,
    resolve_override: dict[str, str] | None = None,
    fail_if_body_not_matches_regexp: str | None = None,
    fail_if_body_matches_regexp: str | None = None,
    min_payload_bytes: int | None = None,
    max_payload_bytes: int | None = None,
    assert_final_url: str | None = None,
    tls_validation_error: str | None = None,
    stage_deadline: float | None = None,
) -> ProbeResult:
    skipped_stages: list[str] = []
    backend = InstrumentedPinnedNetworkBackend(allow_private=allow_private)
    transport = _create_instrumented_transport(backend, verify=verify_ssl, http2=True)
    headers = {"User-Agent": f"Anhanga-Probe/{__version__} (+https://github.com/timeuz/anhanga)"}

    redirect_chain: list[RedirectHop] = []
    origin_conn_timings: dict[tuple[str, str, int], tuple[float, float, float]] = {}

    current_url = initial_url
    max_redirects = 10
    resolved_ip: str | None = None
    all_resolved_ips: list[str] = []
    last_dns_timings = TimingBreakdown()

    step_timeout = httpx.Timeout(
        timeout=timeout,
        connect=min(timeout, 5.0),
        read=timeout,
        write=min(timeout, 5.0),
        pool=min(timeout, 5.0),
    )

    dns_resolver = _detect_system_dns_resolver()
    probe_origin = os.getenv("ANHANGA_PROBE_ORIGIN", "Sonda Local (Linux)")

    async with httpx.AsyncClient(
        transport=transport,
        follow_redirects=False,
        timeout=step_timeout,
        headers=headers,
    ) as client:
        # 1. Seguir cadeia de redirects manualmente (Amostra 1 / Fria)
        final_resp: httpx.Response | None = None
        final_timings: TimingBreakdown = TimingBreakdown()
        final_payload_bytes = 0
        final_payload_truncated = False
        final_body_bytes = b""

        for hop_num in range(1, max_redirects + 2):
            parsed = urlparse(current_url)
            scheme = parsed.scheme.lower()
            if scheme not in ALLOWED_SCHEMES:
                return ProbeResult(
                    target_url=initial_url,
                    final_url=current_url,
                    redirect_hops=len(redirect_chain),
                    redirect_chain=redirect_chain,
                    dns_resolver=dns_resolver,
                    probe_origin=probe_origin,
                    error=f"Bloqueado pelo Guardião Anti-SSRF: esquema '{scheme}' não permitido (apenas http/https).",
                )

            host = parsed.hostname
            if not host:
                return ProbeResult(
                    target_url=initial_url,
                    dns_resolver=dns_resolver,
                    probe_origin=probe_origin,
                    error="URL inválida: hostname não encontrado.",
                )
            port = parsed.port or (443 if scheme == "https" else 80)

            try:
                res_tuple = await resolve_and_validate_host(
                    host,
                    port,
                    allow_private=allow_private,
                    dns_timeout=min(timeout, 3.0),
                    resolve_override=resolve_override,
                    return_all_ips=True,
                )
                hop_ip, dns_ms, hop_all_ips = res_tuple  # type: ignore[misc]
                resolved_ip = hop_ip
                for ip_item in hop_all_ips:
                    if ip_item not in all_resolved_ips:
                        all_resolved_ips.append(ip_item)
                backend.pinned_ips[host.lower()] = hop_ip
                last_dns_timings = build_timing_breakdown(dns_ms=dns_ms)
            except SSRFBlockedError as ssrf_err:
                return ProbeResult(
                    target_url=initial_url,
                    final_url=current_url,
                    resolved_ip=ssrf_err.ip,
                    all_resolved_ips=all_resolved_ips,
                    dns_resolver=dns_resolver,
                    probe_origin=probe_origin,
                    redirect_hops=len(redirect_chain),
                    redirect_chain=redirect_chain,
                    timings=last_dns_timings,
                    error=str(ssrf_err),
                )
            except Exception as dns_exc:
                return ProbeResult(
                    target_url=initial_url,
                    final_url=current_url,
                    dns_resolver=dns_resolver,
                    probe_origin=probe_origin,
                    redirect_hops=len(redirect_chain),
                    redirect_chain=redirect_chain,
                    timings=last_dns_timings,
                    error=_format_dns_error(dns_exc, host),
                )

            resp, step_timings, conn_reused, p_bytes, p_trunc, p_body = (
                await _execute_single_http_step(
                    client=client,
                    backend=backend,
                    url=current_url,
                    dns_ms=dns_ms,
                    max_body_bytes=max_body_bytes,
                    reference_sample="Amostra 1 (Conexão Fria)",
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
                        all_resolved_ips=all_resolved_ips,
                        dns_resolver=dns_resolver,
                        probe_origin=probe_origin,
                        redirect_hops=len(redirect_chain),
                        redirect_chain=redirect_chain,
                        timings=step_timings,
                        error=f"Limite máximo de redirecionamentos ({max_redirects}) excedido.",
                    )

                raw_location = resp.headers["location"].strip()
                next_url = str(resp.url.join(raw_location))
                next_parsed = urlparse(next_url)
                next_scheme = next_parsed.scheme.lower()
                if next_scheme not in ALLOWED_SCHEMES:
                    return ProbeResult(
                        target_url=initial_url,
                        final_url=next_url,
                        resolved_ip=resolved_ip,
                        all_resolved_ips=all_resolved_ips,
                        dns_resolver=dns_resolver,
                        probe_origin=probe_origin,
                        redirect_hops=len(redirect_chain),
                        redirect_chain=redirect_chain,
                        timings=step_timings,
                        error=f"Bloqueado pelo Guardião Anti-SSRF: redirecionamento para esquema proibido ('{next_scheme}').",
                    )

                redirect_chain.append(
                    RedirectHop(
                        hop=hop_num,
                        url=current_url,
                        target_url=next_url,
                        resolved_ip=hop_ip,
                        status_code=resp.status_code,
                        location=raw_location,
                        protocol=resp.http_version,
                        insecure=(scheme == "http"),
                        timings=step_timings,
                    )
                )
                current_url = next_url
                continue

            # Chegou na resposta final!
            final_actual_total_ms = step_timings.total_ms
            inherited_setup = False
            if conn_reused and origin_key in origin_conn_timings:
                inherited_setup = True
                o_dns, o_tcp, o_tls = origin_conn_timings[origin_key]
                step_timings = build_timing_breakdown(
                    dns_ms=o_dns,
                    tcp_ms=o_tcp,
                    tls_ms=o_tls,
                    ttfb_ms=step_timings.ttfb_ms,
                    transfer_ms=step_timings.transfer_ms,
                    reference_sample="Amostra 1 (Conexão Fria)",
                )

            final_resp = resp
            final_timings = step_timings
            final_payload_bytes = p_bytes
            final_payload_truncated = p_trunc
            final_body_bytes = p_body
            break

        assert final_resp is not None

        end_to_end_ms = round(
            sum(h.timings.total_ms for h in redirect_chain) + final_actual_total_ms, 2
        )
        raw_samples: list[SampleMeasurement] = [
            SampleMeasurement(
                sample_index=1,
                connection_reused=False,
                status_code=final_resp.status_code,
                timings=final_timings,
            )
        ]

        # 2. Amostras adicionais (2..samples) reutilizando a mesma conexão Keep-Alive
        extra_sample_failure: str | None = None
        for sample_idx in range(2, max(1, samples) + 1):
            try:
                s_resp, s_timings, s_reused, _, _, _ = await _execute_single_http_step(
                    client=client,
                    backend=backend,
                    url=current_url,
                    dns_ms=0.0,
                    max_body_bytes=max_body_bytes,
                    reference_sample=f"Amostra {sample_idx} (Conexão Reaproveitada)",
                )
            except Exception as exc:  # noqa: BLE001
                # A 1ª amostra já provou que o alvo responde: uma conexão keep-alive fechada/resetada ou o timeout de
                # uma amostra quente não pode descartá-la nem marcar o alvo como OFFLINE. Encerra as amostras aqui.
                extra_sample_failure = f"Amostra {sample_idx} falhou ({type(exc).__name__}); amostras restantes interrompidas."
                logger.warning("amostra %d de %s falhou: %s", sample_idx, current_url, exc)
                break
            if s_reused:
                # Conexão reaproveitada: TCP=0, então o RTT vem da conexão fria (senão o TTFB inteiro viraria "servidor")
                s_timings.estimated_rtt_ms = final_timings.estimated_rtt_ms
                s_timings.server_processing_ms = max(
                    0.0, round(s_timings.ttfb_ms - final_timings.estimated_rtt_ms, 2)
                )
            raw_samples.append(
                SampleMeasurement(
                    sample_index=sample_idx,
                    connection_reused=s_reused,
                    status_code=s_resp.status_code,
                    timings=s_timings,
                )
            )

        if extra_sample_failure:
            final_timings.timing_notes.append(extra_sample_failure)

        # Tempo de processamento do servidor: só a partir de TTFB confiável.
        warm_ttfbs = sorted(s.timings.ttfb_ms for s in raw_samples[1:] if s.connection_reused)
        if warm_ttfbs:
            final_timings.server_processing_ms = max(
                0.0,
                round(_percentile(warm_ttfbs, 50.0) - final_timings.estimated_rtt_ms, 2),
            )
            final_timings.timing_notes.append(
                "Processamento do servidor estimado pela mediana do TTFB das amostras quentes menos o RTT."
            )
        elif final_resp.http_version in ("HTTP/2", "h2"):
            final_timings.server_processing_ms = None
            final_timings.timing_notes.append(
                "TTFB frio em HTTP/2 pode incluir ~1 RTT extra (o servidor aguarda o ACK de SETTINGS): "
                "use samples ≥ 2 para estimar o processamento do servidor."
            )
        if inherited_setup:
            final_timings.timing_notes.append(
                "DNS/TCP/TLS herdados da conexão aberta em hop anterior (reaproveitada); "
                f"tempo total incluindo redirects: {end_to_end_ms} ms."
            )

        sampling_stats = _build_sampling_stats(raw_samples)

        final_parsed = urlparse(str(final_resp.url))
        is_https = final_parsed.scheme.lower() == "https"
        tls_info: TLSInspection | None = None
        http_port_80_status: str | None = None

        if is_https:
            ssl_obj = backend.last_ssl_object or final_resp.extensions.get("ssl_object")
            final_host = final_parsed.hostname or ""
            final_port = final_parsed.port or 443
            target_ip_for_tls = backend.pinned_ips.get(final_host.lower(), resolved_ip or final_host)

            # Cadeia/OCSP via openssl (o módulo ssl não os expõe), porta 80 e enumeração de
            # protocolos/cifras (em cache por 6 h), em paralelo.
            # Cada etapa tem o SEU prazo: se a cadeia TLS estourar, a porta 80 e a enumeração que já terminaram são mantidas.
            (chain_der, ocsp_stapled), http_port_80_status, tls_enum = await asyncio.gather(
                _bounded(
                    lambda: fetch_tls_extras(
                        target_ip_for_tls, final_port, final_host, timeout=min(4.0, timeout),
                        expected_leaf=_peer_leaf_der(ssl_obj),
                    ),
                    stage_deadline, ([], None), skipped_stages, "cadeia TLS/OCSP grampeado",
                ),
                _bounded(
                    lambda: _check_port_80(
                        final_host,
                        allow_private=allow_private,
                        timeout=min(timeout, 2.0),
                        ip=target_ip_for_tls,
                    ),
                    stage_deadline, "Porta 80 não verificada (prazo da sondagem esgotado)", skipped_stages, "porta 80",
                ),
                _bounded(
                    lambda: enumerate_tls_bounded(
                        target_ip_for_tls, final_port, final_host, budget=min(3.0, timeout), timeout=min(3.0, timeout)
                    ),
                    stage_deadline, None, skipped_stages, "enumeração TLS",
                ),
            )

            legacy_unknown = False
            legacy_tls_accepted = bool(ssl_obj is not None and ssl_obj.version() in ("TLSv1", "TLSv1.1", "SSLv3"))
            if tls_enum is not None:
                legacy_tls_accepted = legacy_tls_accepted or any(
                    (tls_enum.get(v) is not None and tls_enum.get(v).status == "accepted")  # type: ignore[union-attr]
                    for v in ("TLSv1", "TLSv1.1")
                )
                if not legacy_tls_accepted:
                    # Enumeração concluída, mas com TLS 1.0/1.1 "unknown" (timeout, erro de rede) ou ausente: não há prova.
                    legacy_unknown = any(
                        tls_enum.get(v) is None or tls_enum.get(v).status == "unknown"  # type: ignore[union-attr]
                        for v in ("TLSv1", "TLSv1.1")
                    )
            elif not legacy_tls_accepted and target_ip_for_tls and final_host:
                legacy_probe = await _bounded(
                    lambda: check_tls10_11_accepted_async(
                        ip=target_ip_for_tls,
                        server_hostname=final_host,
                        port=final_port,
                        timeout=min(0.8, timeout * 0.25),
                    ),
                    stage_deadline, None, skipped_stages, "TLS 1.0/1.1 legado",
                )
                if legacy_probe is None:
                    legacy_unknown = True  # não houve verificação: "não aceito" seria uma afirmação sem prova
                else:
                    legacy_tls_accepted = bool(legacy_probe)

            if ssl_obj is not None:
                tls_info = parse_tls_certificate(
                    ssl_obj,
                    verified=verify_ssl,
                    tls10_11_accepted=legacy_tls_accepted,
                    chain_der=chain_der,
                    ocsp_stapled=ocsp_stapled,
                    validation_error=tls_validation_error,
                )
                tls_info.enumeration = tls_enum
                tls_info.legacy_check_incomplete = legacy_unknown and not tls_info.tls10_11_accepted
            else:
                tls_info = TLSInspection(
                    valid=False,
                    validation_error=tls_validation_error or "handshake TLS sem objeto SSL",
                    tls10_11_accepted=legacy_tls_accepted,
                    enumeration=tls_enum,
                )

            # Revogação (OCSP ativo, CRL de fallback): só faz sentido se o certificado ainda é válido.
            if tls_info.valid and revocation.enabled():
                rev_result = await _bounded(
                    lambda: revocation.check_revocation(
                        # OCSP/CRL/AIA vêm do certificado do alvo: nunca herdam o allow_private dele.
                        chain_der, allow_private=revocation.endpoints_allow_private(),
                        timeout=min(timeout, 5.0), deadline=min(timeout, 4.0),
                    ),
                    stage_deadline, None, skipped_stages, "revogação",
                )
                if rev_result is not None:
                    _apply_revocation(tls_info, rev_result)

        # Sonda ativa de CORS enviando Origin hostil
        cors_result = await _bounded(
            lambda: audit_cors_active(client=client, target_url=current_url, timeout=min(timeout, 2.0)),
            stage_deadline,
            CORSInspection(tested=False, status="Não testado (prazo da sondagem esgotado)"),
            skipped_stages,
            "CORS",
        )

        sec_audit = audit_http_security(
            final_resp.headers,
            is_https,
            tls_info,
            cors_audit=cors_result,
            evaluated_url=str(final_resp.url),
        )

        # Avaliação de Asserções de Conteúdo
        body_text = final_body_bytes.decode("utf-8", errors="replace")
        # URL final e tamanho do payload são instantâneos: calculados SEMPRE e primeiro, para que uma falha definitiva
        # nunca se perca se o regex (subprocesso lento) estourar o prazo.
        assertions_res = await _evaluate_content_assertions(
            body_text=body_text,
            payload_bytes=final_payload_bytes,
            payload_truncated=final_payload_truncated,
            final_url=str(final_resp.url),
            min_payload_bytes=min_payload_bytes,
            max_payload_bytes=max_payload_bytes,
            assert_final_url=assert_final_url,
        )
        if fail_if_body_not_matches_regexp or fail_if_body_matches_regexp:
            regex_res = await _bounded(
                lambda: _evaluate_content_assertions(
                    body_text=body_text,
                    payload_bytes=final_payload_bytes,
                    final_url=str(final_resp.url),
                    fail_if_body_not_matches_regexp=fail_if_body_not_matches_regexp,
                    fail_if_body_matches_regexp=fail_if_body_matches_regexp,
                ),
                stage_deadline,
                ContentAssertionsResult(
                    passed=True,
                    not_evaluated=["asserções de regex não avaliadas: prazo da sondagem esgotado antes da avaliação"],
                ),
                skipped_stages,
                "asserções de regex",
            )
            assertions_res = ContentAssertionsResult(
                passed=assertions_res.passed and regex_res.passed,
                failures=assertions_res.failures + regex_res.failures,
                not_evaluated=assertions_res.not_evaluated + regex_res.not_evaluated,
            )

        if skipped_stages:
            final_timings.timing_notes.append(
                "Resultado parcial: etapas não concluídas (prazo da sondagem ou timeout da própria etapa): "
                + ", ".join(skipped_stages) + "."
            )

        is_up = (200 <= final_resp.status_code < 400) and assertions_res.passed

        # Detecção de Falha em Modo Comum
        # Houve resposta HTTP: 5xx ou asserção reprovada são falhas da APLICAÇÃO, não do resolvedor/rede da sonda.
        # Só a latência de DNS conta aqui; as falhas reais de DNS/timeout/conexão entram em `_flag_connectivity_failure`.
        cmf_warning = _check_common_mode_failure(
            current_host=final_parsed.hostname or "",
            dns_ms=final_timings.dns_ms,
            has_error=False,
        )

        # Suporte a protocolos modernos e compressão
        http2_supported = final_resp.http_version in ("HTTP/2", "h2")
        http3_alt_svc = final_resp.headers.get("alt-svc")
        compression = final_resp.headers.get("content-encoding")

        err_msg: str | None = None
        if not assertions_res.passed:
            err_msg = f"Falha em Content Assertion: {'; '.join(assertions_res.failures)}"

        return ProbeResult(
            target_url=initial_url,
            final_url=str(final_resp.url),
            resolved_ip=resolved_ip,
            all_resolved_ips=all_resolved_ips,
            dns_resolver=dns_resolver,
            probe_origin=probe_origin,
            is_up=is_up,
            http_version=final_resp.http_version,
            status_code=final_resp.status_code,
            redirect_hops=len(redirect_chain),
            redirect_chain=redirect_chain,
            http_port_80_status=http_port_80_status,
            timings=final_timings,
            sampling=sampling_stats,
            tls=tls_info,
            security=sec_audit,
            assertions=assertions_res,
            common_mode_failure_warning=cmf_warning,
            payload_bytes=final_payload_bytes,
            payload_truncated=final_payload_truncated,
            http2_supported=http2_supported,
            http3_alt_svc=http3_alt_svc,
            compression=compression,
            history_ms=[s.timings.total_ms for s in raw_samples],
            end_to_end_ms=end_to_end_ms,
            error=err_msg,
        )


def _format_dns_error(exc: BaseException, host: str) -> str:
    """Mensagem de DNS consistente (mesmo formato e causa explícita) para qualquer falha de resolução."""
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return f"Erro de DNS: tempo esgotado ao resolver '{host}'"
    if isinstance(exc, socket.gaierror):
        code = exc.errno
        if code in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", None)):
            return f"Erro de DNS: o domínio '{host}' não existe ou não possui registros (NXDOMAIN)"
        if code == socket.EAI_AGAIN:
            return f"Erro de DNS: falha temporária do resolvedor ao consultar '{host}'"
        return f"Erro de DNS: não foi possível resolver '{host}' ({exc.strerror or exc})"
    return f"Erro de DNS: não foi possível resolver '{host}' ({exc})"


_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")


def _validate_hostname_syntax(host: str) -> str | None:
    """Valida a sintaxe do host (IP literal ou nome DNS). Retorna a mensagem de erro, se houver."""
    candidate = host.strip("[]").split("%", 1)[0]
    with contextlib.suppress(ValueError):
        ipaddress.ip_address(candidate)
        return None
    name = host.rstrip(".")
    if not name or len(name) > 253:
        return "URL inválida: hostname vazio ou longo demais."
    if not name.isascii():  # nome internacionalizado (münchen.de): valida a forma Punycode (IDNA 2008, a do httpx)
        try:
            name = httpx.URL(f"http://{name}/").raw_host.decode("ascii")
        except (httpx.InvalidURL, ValueError):
            return f"URL inválida: hostname '{host}' contém caracteres ou formato inválidos."
        if len(name) > 253:
            return "URL inválida: hostname vazio ou longo demais."
    if not all(_HOST_LABEL_RE.match(label) for label in name.split(".")):
        return f"URL inválida: hostname '{host}' contém caracteres ou formato inválidos."
    return None


def _peer_leaf_der(ssl_obj: typing.Any) -> bytes | None:
    try:
        return ssl_obj.getpeercert(binary_form=True) if ssl_obj is not None else None
    except Exception:  # noqa: BLE001
        return None


def _failure_result(url: str, exc: BaseException, timeout: float) -> ProbeResult | None:
    """Resultado de falha para SSRF/timeout (mesmo tratamento no 1º passe e no retry sem verificação)."""
    if isinstance(exc, SSRFBlockedError):
        return ProbeResult(target_url=url, resolved_ip=exc.ip, error=str(exc))
    if isinstance(exc, (asyncio.TimeoutError, httpx.TimeoutException)):
        return ProbeResult(
            target_url=url,
            error=f"Timeout rígido excedido ({timeout:.1f}s): {str(exc) or 'limite de tempo esgotado'}",
        )
    return None


def _is_tls_handshake_error(exc: BaseException) -> bool:
    """Por tipo (não por texto: um hostname 'ssl.exemplo.com' não é erro de TLS): há um ssl.SSLError na cadeia?"""
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        if isinstance(cur, ssl.SSLError):
            return True
        seen.add(id(cur))
        cur = cur.__cause__ or cur.__context__
    return False


async def _diagnose_tls_failure(
    url: str, exc_str: str, allow_private: bool, timeout: float,
    resolve_override: dict[str, str] | None,
) -> ProbeResult | None:
    """Handshake falhou: enumera protocolos/cifras para explicar *por quê* (ex.: só TLS 1.0, só cifras
    fracas) em vez de reduzir tudo a "offline". None se não for possível diagnosticar."""
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        return None
    port = parsed.port or 443
    try:
        ip = (await resolve_and_validate_host(
            parsed.hostname, port, allow_private=allow_private, dns_timeout=min(3.0, timeout),
            resolve_override=resolve_override,
        ))[0]
        # Roda fora do prazo global: o orçamento acompanha o `timeout` pedido (antes era 10 s fixos,
        # então `?timeout=1` num host com handshake ruim levava 15-20 s).
        enum = await enumerate_tls_bounded(
            ip, port, parsed.hostname, budget=min(10.0, max(1.0, 2 * timeout)), timeout=min(3.0, timeout)
        )
    except Exception:
        return None
    if enum is None:
        return None
    accepted = [p for p in enum.protocols if p.status == "accepted"]
    if accepted:
        detail = "; ".join(
            f"{p.protocol}" + (f" ({len(p.weak_ciphers)} cifra(s) fraca(s))" if p.weak_ciphers else "")
            for p in accepted
        )
        hint = f"servidor aceita apenas: {detail}"
    elif any(p.status == "unknown" for p in enum.protocols):
        hint = "não foi possível determinar os protocolos aceitos"
    else:
        hint = "nenhum protocolo TLS 1.0–1.3 testável é aceito (cifras/curvas incompatíveis com este cliente?)"
    return ProbeResult(
        target_url=url,
        resolved_ip=ip,
        error=f"Erro HTTP/Conexão: falha no handshake TLS ({hint}). Detalhe: {exc_str}",
        tls=TLSInspection(valid=False, validation_error="handshake TLS falhou", enumeration=enum,
                          tls10_11_accepted=any(p.protocol in ("TLSv1", "TLSv1.1") for p in accepted)),
    )


def _apply_revocation(tls: TLSInspection, rev: "RevocationInspection") -> None:
    """Anexa o resultado da revogação ao TLS; certificado REVOGADO deixa de ser válido (health -> degraded)."""
    tls.revocation = rev
    if rev.status == "revoked":
        when = f" em {rev.revoked_at:%Y-%m-%d}" if rev.revoked_at else ""
        tls.valid = False
        tls.validation_error = f"certificate revoked ({(rev.method or '').upper()}{when})"


def _idna_url(url: str) -> str:
    """Host internacionalizado -> Punycode (httpx, o resolvedor e o pinning de IP usam a forma ASCII)."""
    parsed = safe_urlparse(url)
    host = parsed.hostname if parsed else None
    if not host or host.isascii():
        return url
    try:
        ascii_host = httpx.URL(url).raw_host.decode("ascii")  # IDNA 2008 (UTS 46): `faß.de` NÃO vira `fass.de` (o codec idna do Python é 2003)
        port = parsed.port
    except (httpx.InvalidURL, ValueError):
        return url  # a validação de sintaxe do host recusa
    userinfo = parsed.netloc.rpartition("@")[0]  # só o host é trocado, nunca o userinfo
    netloc = (userinfo + "@" if userinfo else "") + (f"[{ascii_host}]" if ":" in ascii_host else ascii_host)
    if port:
        netloc += f":{port}"
    return parsed._replace(netloc=netloc).geturl()


def _normalize_and_validate_scheme(raw_url: str) -> tuple[str, str | None]:
    url, err = _normalize_scheme_only(raw_url)
    return (url, err) if err else (_idna_url(url), None)


def _normalize_scheme_only(raw_url: str) -> tuple[str, str | None]:
    """
    Normaliza a URL garantindo que esquemas proibidos (file://, gopher://, ftp://, etc.)
    sejam bloqueados imediatamente, antes de qualquer resolução ou auto-prefixo https://.
    """
    url = raw_url.strip()
    if not url:
        return url, "URL inválida: vazia."

    if "://" in url:
        scheme = url.split("://", 1)[0].strip().lower()
        if scheme not in ALLOWED_SCHEMES:
            return (
                url,
                f"Bloqueado pelo Guardião Anti-SSRF: esquema '{scheme}' não permitido (apenas http/https).",
            )
        return url, None

    # Detecta esquemas sem '://' como javascript:, data:, file:, mailto:, etc.
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):(.*)$", url)
    if m:
        candidate_scheme = m.group(1).lower()
        rest = m.group(2)
        if candidate_scheme not in ALLOWED_SCHEMES and not re.match(r"^\d+(/.*)?$", rest):
            return (
                url,
                f"Bloqueado pelo Guardião Anti-SSRF: esquema '{candidate_scheme}' não permitido (apenas http/https).",
            )

    return f"https://{url}", None


_CONNECTIVITY_ERROR_CODES = frozenset({"dns_error", "timeout", "connect_error"})


def _flag_connectivity_failure(result: ProbeResult) -> ProbeResult:
    """Falha de DNS/timeout/conexão (sem resposta do alvo) alimenta a heurística de falha em modo comum:
    é exatamente o que um resolvedor ou uma saída de rede quebrados produzem em vários alvos ao mesmo tempo."""
    if result.error_code in _CONNECTIVITY_ERROR_CODES and MONITORED_PROBE.get():
        parsed = safe_urlparse(result.final_url or result.target_url)
        host = (parsed.hostname if parsed else None) or ""
        if host:
            warning = _check_common_mode_failure(current_host=host, dns_ms=0.0, has_error=True)
            if warning and not result.common_mode_failure_warning:
                result.common_mode_failure_warning = warning
    return result


async def execute_probe(*args: typing.Any, **kwargs: typing.Any) -> ProbeResult:
    """Sondagem completa de uma URL (ver `_execute_probe_inner`); sinaliza falha em modo comum de conectividade."""
    return _flag_connectivity_failure(await _execute_probe_inner(*args, **kwargs))


async def _execute_probe_inner(
    raw_url: str,
    timeout: float = 5.0,
    allow_private: bool = False,
    samples: int = 1,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    resolve_override: dict[str, str] | None = None,
    fail_if_body_not_matches_regexp: str | None = None,
    fail_if_body_matches_regexp: str | None = None,
    min_payload_bytes: int | None = None,
    max_payload_bytes: int | None = None,
    assert_final_url: str | None = None,
) -> ProbeResult:
    url, scheme_err = _normalize_and_validate_scheme(raw_url)
    if scheme_err:
        return ProbeResult(target_url=raw_url.strip() or raw_url, error=scheme_err)

    parsed = safe_urlparse(url)
    if parsed is None:
        return ProbeResult(target_url=url, error="URL inválida: endereço malformado (ex.: colchete IPv6 sem fechar).")
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return ProbeResult(
            target_url=url,
            error=f"Bloqueado pelo Guardião Anti-SSRF: esquema '{parsed.scheme}' não permitido.",
        )
    if not parsed.hostname:
        return ProbeResult(
            target_url=url, error="URL inválida: hostname não encontrado."
        )
    try:
        _ = parsed.port
    except ValueError:
        return ProbeResult(target_url=url, error="URL inválida: porta fora do intervalo 1-65535.")
    host_err = _validate_hostname_syntax(parsed.hostname)
    if host_err:
        return ProbeResult(target_url=url, error=host_err)

    timeout = max(0.5, min(float(timeout), 30.0))
    samples = max(1, min(int(samples), 50))
    max_body_bytes = max(1, min(int(max_body_bytes), ABSOLUTE_MAX_BODY_BYTES))
    # Folga para o que roda após a sondagem HTTP. As etapas pós-HTTP têm orçamento combinado (`_bounded` até
    # `stage_deadline`): se faltar prazo elas são puladas (resultado parcial) e a resposta HTTP já obtida é mantida.
    overall_timeout = _overall_timeout(timeout, samples)

    started = time.monotonic()
    stage_deadline = started + overall_timeout - STAGE_RESERVE_SECONDS
    try:
        return await asyncio.wait_for(
            _run_probe_session(
                initial_url=url,
                timeout=timeout,
                allow_private=allow_private,
                samples=samples,
                max_body_bytes=max_body_bytes,
                verify_ssl=True,
                resolve_override=resolve_override,
                fail_if_body_not_matches_regexp=fail_if_body_not_matches_regexp,
                fail_if_body_matches_regexp=fail_if_body_matches_regexp,
                min_payload_bytes=min_payload_bytes,
                max_payload_bytes=max_payload_bytes,
                assert_final_url=assert_final_url,
                stage_deadline=stage_deadline,
            ),
            timeout=overall_timeout,
        )
    except SSRFBlockedError as ssrf_err:
        return ProbeResult(
            target_url=url,
            resolved_ip=ssrf_err.ip,
            error=str(ssrf_err),
        )
    except (asyncio.TimeoutError, httpx.TimeoutException) as timeout_err:
        return ProbeResult(
            target_url=url,
            error=f"Timeout rígido excedido ({overall_timeout:.1f}s): {str(timeout_err) or 'limite de tempo esgotado'}",
        )
    except Exception as exc:
        exc_str = str(exc)
        is_ssl_verify_err = isinstance(exc, ssl.SSLCertVerificationError) or (
            "CERTIFICATE_VERIFY_FAILED" in exc_str
            or "SSLCertVerificationError" in exc_str
        )
        if is_ssl_verify_err:
            reason_match = re.search(r"certificate verify failed:\s*([^(]+?)\s*(?:\(|$)", exc_str)
            verify_reason = (
                reason_match.group(1).strip() if reason_match else "falha na verificação do certificado"
            )
            # prazo RESTANTE do total (o retry não pode dobrar o tempo máximo da requisição). Sem folga
            # suficiente nem tenta, em vez de forçar um piso que estoura o prazo global.
            remaining = overall_timeout - (time.monotonic() - started)
            if remaining < 1.0:
                return ProbeResult(
                    target_url=url,
                    error=(
                        f"Timeout rígido excedido ({overall_timeout:.0f}s): prazo total esgotado antes de "
                        f"repetir sem verificação do certificado ({verify_reason})"
                    ),
                )
            try:
                return await asyncio.wait_for(
                    _run_probe_session(
                        initial_url=url,
                        timeout=timeout,
                        allow_private=allow_private,
                        samples=samples,
                        max_body_bytes=max_body_bytes,
                        verify_ssl=False,
                        tls_validation_error=verify_reason,
                        resolve_override=resolve_override,
                        fail_if_body_not_matches_regexp=fail_if_body_not_matches_regexp,
                        fail_if_body_matches_regexp=fail_if_body_matches_regexp,
                        min_payload_bytes=min_payload_bytes,
                        max_payload_bytes=max_payload_bytes,
                        assert_final_url=assert_final_url,
                        stage_deadline=stage_deadline,
                    ),
                    timeout=remaining,
                )
            except Exception as inner_exc:
                return _failure_result(url, inner_exc, overall_timeout) or ProbeResult(
                    target_url=url,
                    error=f"Erro HTTP/Conexão: {inner_exc}",
                )

        if _is_tls_handshake_error(exc):
            diagnosed = await _diagnose_tls_failure(
                url, exc_str, allow_private=allow_private, timeout=timeout,
                resolve_override=resolve_override,
            )
            if diagnosed is not None:
                return diagnosed

        return ProbeResult(
            target_url=url,
            error=f"Erro HTTP/Conexão: {exc}",
        )