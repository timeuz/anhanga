"""Checagem de revogação do certificado folha: OCSP ativo, com CRL de fallback.

Segurança: as URLs de OCSP/CRL/CA Issuers vêm do certificado inspecionado (ou seja, de terceiros).
Toda requisição passa pela mesma política Anti-SSRF das sondas (resolução única, validação de IP e
conexão fixada no IP), com redirects revalidados, limite de tamanho e timeout. Toda resposta tem a
assinatura verificada contra o emissor antes de ser considerada. Resultados são cacheados para não
martelar os respondedores a cada ciclo de monitoramento.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import re
import shutil
import ssl
import tempfile
import time
from collections import OrderedDict
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from anhanga.engine.models import RevocationInspection

MAX_OCSP_BYTES = 64 * 1024
MAX_CRL_BYTES = 3 * 1024 * 1024
MAX_ISSUER_BYTES = 64 * 1024
MAX_REDIRECTS = 3
CACHE_TTL = {"good": 1800.0, "revoked": 3600.0}
CACHE_TTL_DEFAULT = 300.0  # unknown / unavailable / error: tenta de novo logo
CRL_CACHE_MAX = 8
CRL_CACHE_MAX_AGE = 6 * 3600.0

_RESULT_CACHE: dict[str, tuple[float, RevocationInspection]] = {}
_CRL_CACHE: OrderedDict[str, tuple[float, dict[str, datetime | None]]] = OrderedDict()


def enabled() -> bool:
    return os.getenv("ANHANGA_REVOCATION_CHECK", "1").strip().lower() not in {"0", "false", "no", "off"}


BACKGROUND_DEADLINE = 25.0  # teto do trabalho que continua em segundo plano após o orçamento da sondagem
_inflight: dict[str, "asyncio.Future[RevocationInspection]"] = {}


def endpoints_allow_private() -> bool:
    """Se OCSP/CRL/AIA em IP privado são permitidos. Decisão do OPERADOR (variável de ambiente): essas URLs
    vêm do certificado do alvo (terceiro) e nunca herdam o `allow_private` do alvo, senão um certificado
    hostil faria o monitor requisitar 169.254.169.254, redes internas, etc. Útil só para PKI interna."""
    return os.getenv("ANHANGA_REVOCATION_ALLOW_PRIVATE", "0").strip().lower() in {"1", "true", "yes", "on"}


def clear_caches() -> None:
    _RESULT_CACHE.clear()
    _CRL_CACHE.clear()
    _inflight.clear()


def _parse_openssl_time(raw: str) -> datetime | None:
    """'Sep 15 21:01:24 2026 GMT' (dia pode vir com 2 espaços) -> datetime UTC."""
    try:
        return datetime.strptime(" ".join(raw.split()), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


async def _openssl(args: list[str], timeout: float = 8.0) -> tuple[int, str]:
    exe = shutil.which("openssl")
    if not exe:
        raise FileNotFoundError("binário openssl indisponível")
    proc = await asyncio.create_subprocess_exec(
        exe, *args,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except BaseException:  # TimeoutError e também CancelledError: não deixar `openssl` órfão
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        raise
    return proc.returncode or 0, out.decode("utf-8", errors="replace")


async def _fetch(
    url: str,
    *,
    allow_private: bool,
    max_bytes: int,
    timeout: float,
    method: str = "GET",
    body: bytes | None = None,
    content_type: str | None = None,
) -> bytes:
    """HTTP(S) com Anti-SSRF: resolve uma vez, valida o IP, conecta fixado no IP; redirects revalidados."""
    from anhanga.engine.probe import (  # import tardio: probe importa este módulo
        InstrumentedPinnedNetworkBackend,
        _create_instrumented_transport,
        resolve_and_validate_host,
    )

    current = url
    for _ in range(MAX_REDIRECTS + 1):
        parsed = urlparse(current)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            raise ValueError(f"URL de revogação inválida ou com esquema proibido: {current[:80]}")
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        ip, _dns = await resolve_and_validate_host(
            parsed.hostname, port, allow_private=allow_private, dns_timeout=min(timeout, 3.0)
        )
        backend = InstrumentedPinnedNetworkBackend(allow_private=allow_private)
        backend.pinned_ips[parsed.hostname.lower()] = ip
        transport = _create_instrumented_transport(backend, verify=True, http2=False)
        headers = {"User-Agent": "Anhanga-Revocation/1"}
        if content_type:
            headers["Content-Type"] = content_type
        async with httpx.AsyncClient(transport=transport, follow_redirects=False, timeout=timeout) as client:
            async with client.stream(method, current, content=body, headers=headers) as resp:
                if resp.status_code in (301, 302, 303, 307, 308) and "location" in resp.headers:
                    current = str(resp.url.join(resp.headers["location"]))
                    continue
                if resp.status_code != 200:
                    raise ValueError(f"HTTP {resp.status_code} de {parsed.hostname}")
                data = bytearray()
                async for chunk in resp.aiter_bytes():
                    data.extend(chunk)
                    if len(data) > max_bytes:
                        raise ValueError(f"resposta de {parsed.hostname} excede {max_bytes} bytes")
                return bytes(data)
    raise ValueError("redirecionamentos demais")


def _cert_fields(der: bytes) -> dict:
    from anhanga.engine.security import _decode_der_cert

    return _decode_der_cert(der) or {}


def _norm_serial(serial: str | None) -> str:
    return (serial or "").strip().upper().lstrip("0")


async def _ocsp_check(leaf_pem: str, issuer_pem: str, url: str, *, allow_private: bool, timeout: float,
                      now: datetime) -> RevocationInspection:
    with tempfile.TemporaryDirectory(prefix="anhanga-ocsp-") as tmp:
        files = {n: os.path.join(tmp, n) for n in ("leaf.pem", "iss.pem", "req.der", "resp.der")}
        for name, content in (("leaf.pem", leaf_pem), ("iss.pem", issuer_pem)):
            with open(files[name], "w", encoding="ascii") as fh:
                fh.write(content)
        rc, out = await _openssl(
            ["ocsp", "-issuer", files["iss.pem"], "-cert", files["leaf.pem"], "-reqout", files["req.der"], "-no_nonce"]
        )
        if rc != 0 or not os.path.exists(files["req.der"]):
            raise ValueError("não foi possível montar a requisição OCSP")
        with open(files["req.der"], "rb") as fh:
            request = fh.read()
        response = await _fetch(
            url, allow_private=allow_private, max_bytes=MAX_OCSP_BYTES, timeout=timeout, method="POST",
            body=request, content_type="application/ocsp-request",
        )
        with open(files["resp.der"], "wb") as fh:
            fh.write(response)
        rc, out = await _openssl(
            ["ocsp", "-respin", files["resp.der"], "-issuer", files["iss.pem"], "-cert", files["leaf.pem"]]
        )
    if "Response verify OK" not in out:
        raise ValueError("assinatura da resposta OCSP não verificada")
    m = re.search(r"leaf\.pem:\s*(good|revoked|unknown)", out)
    if not m:
        raise ValueError("resposta OCSP sem status do certificado")
    status = m.group(1)
    nxt = re.search(r"Next Update:\s*(.+)", out)
    next_update = _parse_openssl_time(nxt.group(1)) if nxt else None
    if next_update is not None and next_update < now:
        raise ValueError("resposta OCSP expirada (Next Update no passado)")
    revoked_at = None
    if status == "revoked":
        rt = re.search(r"Revocation Time:\s*(.+)", out)
        revoked_at = _parse_openssl_time(rt.group(1)) if rt else None
    return RevocationInspection(
        status=status, method="ocsp", revoked_at=revoked_at, responder=urlparse(url).hostname,
        next_update=next_update, detail=None if status != "unknown" else "o respondedor OCSP não conhece este serial",
    )


async def _crl_revoked_map(url: str, issuer_pem: str, *, allow_private: bool, timeout: float,
                           now: float) -> dict[str, datetime | None]:
    # A chave inclui o emissor: a assinatura foi verificada contra ELE; um hit só vale para o mesmo emissor.
    cache_key = f"{hashlib.sha256(issuer_pem.encode('ascii', 'ignore')).hexdigest()}|{url}"
    cached = _CRL_CACHE.get(cache_key)
    if cached and cached[0] > now:
        _CRL_CACHE.move_to_end(cache_key)
        return cached[1]
    data = await _fetch(url, allow_private=allow_private, max_bytes=MAX_CRL_BYTES, timeout=timeout)
    with tempfile.TemporaryDirectory(prefix="anhanga-crl-") as tmp:
        crl, iss = os.path.join(tmp, "crl.der"), os.path.join(tmp, "iss.pem")
        with open(crl, "wb") as fh:
            fh.write(data)
        with open(iss, "w", encoding="ascii") as fh:
            fh.write(issuer_pem)
        rc, out = await _openssl(["crl", "-inform", "DER", "-in", crl, "-CAfile", iss, "-noout", "-verify", "-nextupdate"], 10.0)
        if rc != 0 or "verify OK" not in out:
            raise ValueError("assinatura do CRL não verificada")
        nm = re.search(r"nextUpdate=(.+)", out)
        next_update = _parse_openssl_time(nm.group(1)) if nm else None
        if next_update is not None and next_update.timestamp() < now:
            raise ValueError("CRL expirado (nextUpdate no passado)")
        rc, text = await _openssl(["crl", "-inform", "DER", "-in", crl, "-noout", "-text"], 20.0)
        if rc != 0:
            raise ValueError("CRL ilegível")
    revoked: dict[str, datetime | None] = {}
    for m in re.finditer(r"Serial Number:\s*([0-9A-Fa-f]+)\s*\n\s*Revocation Date:\s*(.+)", text):
        revoked[_norm_serial(m.group(1))] = _parse_openssl_time(m.group(2))
    ttl_until = now + CRL_CACHE_MAX_AGE
    if next_update is not None:
        ttl_until = min(ttl_until, next_update.timestamp())
    _CRL_CACHE[cache_key] = (ttl_until, revoked)
    while len(_CRL_CACHE) > CRL_CACHE_MAX:
        _CRL_CACHE.popitem(last=False)
    return revoked


async def check_revocation(
    chain_der: list[bytes], *, allow_private: bool = False, timeout: float = 5.0, deadline: float = 6.0
) -> RevocationInspection:
    """Folha = chain_der[0]. Retorna sempre um RevocationInspection (nunca lança).

    `deadline` é o orçamento TOTAL (vários fetches em sequência): estourar vira um resultado "error" em cache
    (nova tentativa em 5 min), nunca derruba a sondagem nem repete o mesmo trabalho a cada ciclo."""
    if not chain_der:
        return RevocationInspection(status="unavailable", detail="cadeia do servidor indisponível")
    leaf_der = chain_der[0]
    key = hashlib.sha256(leaf_der).hexdigest()
    now_ts = time.time()
    cached = _RESULT_CACHE.get(key)
    if cached and cached[0] > now_ts:
        return cached[1]
    task = _inflight.get(key)
    if task is None:
        task = asyncio.ensure_future(_compute_and_cache(key, chain_der, allow_private, timeout))
        _inflight[key] = task

        def _done(t: "asyncio.Future") -> None:
            _inflight.pop(key, None)
            if not t.cancelled():
                t.exception()  # consome (evita "exception was never retrieved")

        task.add_done_callback(_done)
    try:
        return await asyncio.wait_for(asyncio.shield(task), timeout=deadline)
    except asyncio.TimeoutError:
        # O orçamento da sondagem acabou, mas o trabalho NÃO é cancelado: segue em segundo plano e o
        # próximo ciclo acha o resultado em cache. (Cancelar descartava o CRL baixado pela metade e
        # refazia o mesmo download a cada 5 min, então um CRL grande nunca produzia resultado.)
        return RevocationInspection(
            status="unavailable",
            detail=f"verificação em andamento (>{deadline:.0f}s); conclui em segundo plano",
        )
    except Exception as exc:  # noqa: BLE001
        return RevocationInspection(status="error", detail=f"falha na checagem: {exc}"[:300])


async def _compute_and_cache(
    key: str, chain_der: list[bytes], allow_private: bool, timeout: float
) -> RevocationInspection:
    try:
        result = await asyncio.wait_for(
            _check_uncached(chain_der, allow_private=allow_private, timeout=timeout), timeout=BACKGROUND_DEADLINE
        )
    except asyncio.TimeoutError:
        result = RevocationInspection(
            status="error", detail=f"tempo esgotado ({BACKGROUND_DEADLINE:.0f}s) ao consultar OCSP/CRL"
        )
    now_ts = time.time()
    ttl = CACHE_TTL.get(result.status, CACHE_TTL_DEFAULT)
    if result.next_update is not None:
        ttl = min(ttl, max(60.0, result.next_update.timestamp() - now_ts))
    _RESULT_CACHE[key] = (now_ts + ttl, result)
    if len(_RESULT_CACHE) > 256:
        for k in sorted(_RESULT_CACHE, key=lambda x: _RESULT_CACHE[x][0])[:64]:
            _RESULT_CACHE.pop(k, None)
    return result


async def _check_uncached(chain_der: list[bytes], *, allow_private: bool, timeout: float) -> RevocationInspection:
    if not shutil.which("openssl"):
        return RevocationInspection(status="unavailable", detail="binário openssl indisponível")
    leaf = _cert_fields(chain_der[0])
    leaf_issuer = leaf.get("issuer")
    ocsp_urls = [u for u in (leaf.get("OCSP") or ()) if u.lower().startswith(("http://", "https://"))]
    crl_urls = [u for u in (leaf.get("crlDistributionPoints") or ()) if u.lower().startswith(("http://", "https://"))]
    serial = _norm_serial(leaf.get("serialNumber"))

    issuer_der = next((c for c in chain_der[1:] if _cert_fields(c).get("subject") == leaf_issuer), None)
    if issuer_der is None:
        for ca_url in (leaf.get("caIssuers") or ())[:1]:  # emissor não enviado pelo servidor: busca via AIA
            with contextlib.suppress(Exception):
                fetched = await _fetch(ca_url, allow_private=allow_private, max_bytes=MAX_ISSUER_BYTES, timeout=timeout)
                if fetched.lstrip().startswith(b"-----BEGIN"):
                    fetched = ssl.PEM_cert_to_DER_cert(fetched.decode("ascii", "ignore"))
                if _cert_fields(fetched).get("subject") == leaf_issuer:
                    issuer_der = fetched
    if issuer_der is None:
        return RevocationInspection(status="unavailable", detail="certificado do emissor indisponível")
    if not ocsp_urls and not crl_urls:
        return RevocationInspection(
            status="unavailable",
            detail="certificado sem OCSP nem CRL (sem como checar revogação)",
        )

    leaf_pem = ssl.DER_cert_to_PEM_cert(chain_der[0])
    issuer_pem = ssl.DER_cert_to_PEM_cert(issuer_der)
    errors: list[str] = []
    ocsp_unknown: RevocationInspection | None = None
    now_dt = datetime.now(timezone.utc)

    for url in ocsp_urls[:2]:
        try:
            res = await _ocsp_check(leaf_pem, issuer_pem, url, allow_private=allow_private, timeout=timeout, now=now_dt)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"OCSP {urlparse(url).hostname}: {exc}")
            continue
        if res.status in ("good", "revoked"):
            return res
        ocsp_unknown = res  # "unknown": tenta o CRL antes de desistir

    for url in crl_urls[:2]:
        try:
            revoked = await _crl_revoked_map(url, issuer_pem, allow_private=allow_private, timeout=max(timeout, 8.0),
                                             now=time.time())
        except Exception as exc:  # noqa: BLE001
            errors.append(f"CRL {urlparse(url).hostname}: {exc}")
            continue
        if serial in revoked:
            return RevocationInspection(
                status="revoked", method="crl", revoked_at=revoked[serial], responder=urlparse(url).hostname
            )
        return RevocationInspection(status="good", method="crl", responder=urlparse(url).hostname)

    if ocsp_unknown is not None:
        return ocsp_unknown
    return RevocationInspection(status="error", detail="; ".join(errors)[:300] or "nenhum endpoint respondeu")
