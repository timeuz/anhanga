"""Enumeração ativa de protocolos TLS e cifras aceitas pelo servidor.

Cada versão (TLS 1.0–1.3) é testada com um handshake restrito a ela. Nas versões <= 1.2 as cifras
são descobertas por exclusão iterativa (aceita X → proíbe X → repete), com teto de handshakes.

Princípio: "o servidor recusou" e "não consegui testar" são resultados distintos. Só um alerta TLS
do servidor conta como recusa; falha local do cliente, timeout ou erro de rede viram `unknown`.
SSLv2/SSLv3 não são testáveis (o OpenSSL moderno os removeu) e são reportados como tal.
O `ip` já foi validado pela política Anti-SSRF pelo chamador (mesmo contrato de `fetch_tls_extras`).
"""

import asyncio
import os
import ssl
import time
import warnings
from typing import Literal

from anhanga.engine.models import TLSEnumeration, TLSProtocolResult

_VERSIONS: list[tuple[str, ssl.TLSVersion]] = [
    ("TLSv1", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]
MAX_CIPHER_HANDSHAKES = 24
CACHE_TTL = 6 * 3600
MAX_SCAN_SECONDS = 60.0  # teto de uma enumeração completa (rodando em segundo plano)
MIN_SCAN_INTERVAL = 120.0  # no máx. 1 enumeração nova por (ip, porta) a cada 2 min, qualquer que seja o hostname
_cache: dict[tuple[str, int], tuple[float, TLSEnumeration]] = {}
_inflight: dict[tuple[str, int], "asyncio.Future[TLSEnumeration | None]"] = {}
_last_scan: dict[tuple[str, int], float] = {}

# Razões do OpenSSL que indicam que *o servidor* respondeu recusando (e não falha do cliente).
_SERVER_REJECT_MARKERS = (
    "ALERT_PROTOCOL_VERSION", "ALERT_HANDSHAKE_FAILURE", "ALERT_INTERNAL_ERROR",
    "WRONG_VERSION_NUMBER", "UNSUPPORTED_PROTOCOL", "NO_PROTOCOLS_AVAILABLE_SERVER",
    "ALERT_INSUFFICIENT_SECURITY", "ALERT_ILLEGAL_PARAMETER", "NO_SHARED_CIPHER",
    "UNKNOWN_PROTOCOL", "ALERT_UNEXPECTED_MESSAGE", "ALERT_DECODE_ERROR",
)
_CLIENT_SIDE_MARKERS = ("NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE", "INVALID_SESSION_ID")

_WEAK_TOKENS = ("RC4", "NULL", "EXPORT", "EXP-", "MD5", "anon", "ADH", "AECDH", "DES-CBC", "DES-CBC3", "3DES", "SEED", "IDEA", "RC2")


def enabled() -> bool:
    return os.environ.get("ANHANGA_TLS_ENUM", "1").strip().lower() not in ("0", "false", "no", "off")


def classify_cipher(name: str) -> tuple[bool, bool]:
    """(fraca, sem forward secrecy). Fraca: RC4/3DES/DES/NULL/EXPORT/MD5/anônima/SEED/IDEA."""
    up = name.upper()
    weak = any(tok.upper() in up for tok in _WEAK_TOKENS)
    forward_secret = up.startswith(("ECDHE", "DHE", "EDH", "TLS_"))
    return weak, not forward_secret


def _context(version: ssl.TLSVersion, exclude: list[str]) -> ssl.SSLContext:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)  # TLSv1/1.1 são deprecated de propósito
        ctx.minimum_version = version
        ctx.maximum_version = version
    if version != ssl.TLSVersion.TLSv1_3:
        excl = "".join(f":!{c}" for c in exclude)
        # ALL:COMPLEMENTOFALL inclui RC4/3DES/EXPORT/anônimas; SECLEVEL=0 libera TLS 1.0/1.1 e SHA-1.
        ctx.set_ciphers(f"ALL:COMPLEMENTOFALL:@SECLEVEL=0{excl}")
    return ctx


async def _handshake(
    ip: str, port: int, hostname: str, version: ssl.TLSVersion, exclude: list[str], timeout: float
) -> tuple[Literal["accepted", "rejected", "unknown"], str | None, int | None]:
    """Resultado de um handshake restrito a `version`. Retorna (estado, cifra, bits)."""
    try:
        ctx = _context(version, exclude)
    except (ssl.SSLError, ValueError):
        return "unknown", None, None  # o cliente não suporta esta versão/cifras
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=hostname), timeout=timeout
        )
        obj = writer.get_extra_info("ssl_object")
        cipher = obj.cipher() if obj else None
        return "accepted", (cipher[0] if cipher else None), (cipher[2] if cipher else None)
    except ssl.SSLError as exc:
        text = f"{getattr(exc, 'reason', '')} {exc}".upper()
        if any(m in text for m in _CLIENT_SIDE_MARKERS) and "SERVER" not in text:
            return "unknown", None, None
        if any(m in text for m in _SERVER_REJECT_MARKERS) or "ALERT" in text:
            return "rejected", None, None
        return "unknown", None, None
    except (ConnectionResetError, EOFError, BrokenPipeError):
        return "rejected", None, None  # RST/EOF no ClientHello: comportamento comum de recusa
    except (asyncio.TimeoutError, OSError):
        return "unknown", None, None
    finally:
        if writer is not None:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass


async def _scan_version(
    ip: str, port: int, hostname: str, name: str, version: ssl.TLSVersion, timeout: float
) -> TLSProtocolResult:
    state, cipher, bits = await _handshake(ip, port, hostname, version, [], timeout)
    res = TLSProtocolResult(protocol=name, status=state)
    if state != "accepted" or cipher is None:
        return res
    ciphers = [cipher]
    complete = True
    if version != ssl.TLSVersion.TLSv1_3:
        excluded = [cipher]
        while True:
            if len(ciphers) >= MAX_CIPHER_HANDSHAKES:
                complete = False
                break
            st, c, _ = await _handshake(ip, port, hostname, version, excluded, timeout)
            if st != "accepted" or not c or c in excluded:
                if st == "unknown":
                    complete = False
                break
            ciphers.append(c)
            excluded.append(c)
    res.ciphers = ciphers
    res.ciphers_complete = complete
    res.weak_ciphers = [c for c in ciphers if classify_cipher(c)[0]]
    res.no_forward_secrecy = [c for c in ciphers if classify_cipher(c)[1] and not classify_cipher(c)[0]]
    return res


async def enumerate_tls(
    ip: str, port: int, hostname: str, timeout: float = 3.0, use_cache: bool = True
) -> TLSEnumeration | None:
    """Enumera protocolos/cifras. None se desligado (`ANHANGA_TLS_ENUM=0`). Resultado em cache por 6 h (por hostname:porta, já que CDNs rotacionam IPs)."""
    if not enabled():
        return None
    key = (hostname.lower(), port)
    now = time.monotonic()
    hit = _cache.get(key)
    if use_cache and hit and now - hit[0] < CACHE_TTL:
        return hit[1]
    results = await asyncio.gather(
        *(_scan_version(ip, port, hostname, n, v, timeout) for n, v in _VERSIONS)
    )
    protocols = list(results) + [
        TLSProtocolResult(protocol="SSLv3", status="untestable"),
        TLSProtocolResult(protocol="SSLv2", status="untestable"),
    ]
    out = TLSEnumeration(protocols=protocols, tested_at=time.time())
    # Só cacheia resultado conclusivo: com algum `unknown` nas versões testáveis, tenta de novo no ciclo seguinte.
    if all(p.status != "unknown" for p in results):
        if len(_cache) > 512:
            _cache.pop(next(iter(_cache)))
        _cache[key] = (now, out)
    return out


async def enumerate_tls_bounded(
    ip: str, port: int, hostname: str, budget: float = 3.0, timeout: float = 3.0
) -> TLSEnumeration | None:
    """Como `enumerate_tls`, mas nunca bloqueia a sondagem por mais de `budget` segundos.

    Se estourar, a enumeração continua em segundo plano (uma só por chave) e preenche o cache: o ciclo
    seguinte a encontra pronta. Sem isso, um alvo lento faria cada ciclo estourar o prazo e refazer
    o mesmo trabalho. Também limita a amplificação: no máx. 1 enumeração nova por (ip, porta) a cada
    `MIN_SCAN_INTERVAL`, mesmo que o chamador varie o hostname."""
    if not enabled():
        return None
    key = (hostname.lower(), port)
    hit = _cache.get(key)
    if hit and time.monotonic() - hit[0] < CACHE_TTL:
        return hit[1]
    task = _inflight.get(key)
    if task is None:
        now = time.monotonic()
        last = _last_scan.get((ip, port))
        if last is not None and now - last < MIN_SCAN_INTERVAL:
            return None
        if len(_last_scan) > 512:
            _last_scan.clear()
        _last_scan[(ip, port)] = now
        task = asyncio.ensure_future(
            asyncio.wait_for(enumerate_tls(ip, port, hostname, timeout=timeout), timeout=MAX_SCAN_SECONDS)
        )
        _inflight[key] = task

        def _done(t: "asyncio.Future") -> None:
            _inflight.pop(key, None)
            if not t.cancelled():
                t.exception()  # consome: evita "exception was never retrieved"

        task.add_done_callback(_done)
    try:
        return await asyncio.wait_for(asyncio.shield(task), timeout=budget)
    except Exception:  # noqa: BLE001  (inclui TimeoutError do orçamento e falhas da própria enumeração)
        return None


def clear_cache() -> None:
    _cache.clear()
    _inflight.clear()
    _last_scan.clear()
