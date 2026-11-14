"""Revogação contra uma PKI local real (openssl): CA, certificados bom/revogado/desconhecido, CRL e
respondedor OCSP. Sem internet."""

import functools
import http.server
import shutil
import socket
import ssl
import subprocess
import threading
import time
from pathlib import Path

import pytest

from anhanga.engine import revocation as R

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl indisponível")


def sh(*args, cwd, check=True):
    return subprocess.run(["openssl", *args], cwd=cwd, check=check, capture_output=True, text=True)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def pem_to_der(path: Path) -> bytes:
    return ssl.PEM_cert_to_DER_cert(path.read_text())


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki")
    http_port, ocsp_port = free_port(), free_port()
    (d / "newcerts").mkdir()
    (d / "index.txt").write_text("")
    (d / "serial").write_text("1000\n")
    (d / "crlnumber").write_text("01\n")
    (d / "ca.cnf").write_text(f"""
[ca]
default_ca = CA_default
[CA_default]
dir = {d}
database = {d}/index.txt
new_certs_dir = {d}/newcerts
certificate = {d}/ca.pem
private_key = {d}/ca.key
serial = {d}/serial
crlnumber = {d}/crlnumber
default_md = sha256
default_days = 30
default_crl_days = 7
policy = pol
unique_subject = no
[pol]
commonName = supplied
[v_both]
authorityInfoAccess = OCSP;URI:http://127.0.0.1:{ocsp_port}
crlDistributionPoints = URI:http://127.0.0.1:{http_port}/ca.crl.der
[v_ocsp]
authorityInfoAccess = OCSP;URI:http://127.0.0.1:{ocsp_port}
[v_crl]
crlDistributionPoints = URI:http://127.0.0.1:{http_port}/ca.crl.der
[v_none]
basicConstraints = CA:FALSE
""")
    sh("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-subj", "/CN=Anhanga Test CA", "-days", "30", cwd=d)

    def issue(name, ext):
        sh("req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.csr", "-subj", f"/CN={name}.test", cwd=d)
        sh("ca", "-batch", "-config", "ca.cnf", "-notext", "-in", f"{name}.csr", "-out", f"{name}.pem", "-extensions", ext, cwd=d)

    for name, ext in (("good", "v_both"), ("revoked", "v_both"), ("crlgood", "v_crl"), ("crlrevoked", "v_crl"),
                      ("ocspgood", "v_ocsp"), ("bare", "v_none")):
        issue(name, ext)
    # certificado assinado pela CA mas FORA do índice => o respondedor responde "unknown"
    sh("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "ghost.key", "-out", "ghost.csr", "-subj", "/CN=ghost.test", cwd=d)
    (d / "ghost.ext").write_text(f"authorityInfoAccess = OCSP;URI:http://127.0.0.1:{ocsp_port}\n")
    sh("x509", "-req", "-in", "ghost.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-set_serial", "0x9999", "-out", "ghost.pem",
       "-days", "30", "-extfile", "ghost.ext", cwd=d)
    for name in ("revoked", "crlrevoked"):
        sh("ca", "-config", "ca.cnf", "-revoke", f"{name}.pem", cwd=d)
    sh("ca", "-config", "ca.cnf", "-gencrl", "-out", "ca.crl.pem", cwd=d)
    sh("crl", "-in", "ca.crl.pem", "-outform", "DER", "-out", "ca.crl.der", cwd=d)

    # CRL assinado por OUTRA CA (rogue), servido como se fosse o da CA legítima
    (d / "rogue").mkdir()
    sh("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "rogue/ca.key", "-out", "rogue/ca.pem", "-subj", "/CN=Anhanga Test CA", "-days", "30", cwd=d)

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", http_port), functools.partial(Quiet, directory=str(d)))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    responder = subprocess.Popen(
        ["openssl", "ocsp", "-index", "index.txt", "-port", str(ocsp_port), "-rsigner", "ca.pem", "-rkey", "ca.key",
         "-CA", "ca.pem", "-ndays", "7"],
        cwd=d, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    # Espera com uma requisição OCSP REAL: o respondedor do openssl é single-thread e uma sondagem
    # vazia (connect+close) o derruba.
    import urllib.request

    sh("ocsp", "-issuer", "ca.pem", "-cert", "good.pem", "-reqout", "warm.der", "-no_nonce", cwd=d)
    warm = (d / "warm.der").read_bytes()
    for _ in range(50):
        try:
            urllib.request.urlopen(
                urllib.request.Request(f"http://127.0.0.1:{ocsp_port}/", data=warm,
                                       headers={"Content-Type": "application/ocsp-request"}), timeout=2).read()
            break
        except OSError:
            time.sleep(0.1)
    yield d
    responder.kill()
    httpd.shutdown()


@pytest.fixture(autouse=True)
def _fresh_cache():
    R.clear_caches()
    yield
    R.clear_caches()


def chain(pki, name):
    return [pem_to_der(pki / f"{name}.pem"), pem_to_der(pki / "ca.pem")]


def check(pki, name, **kw):
    import asyncio

    return asyncio.run(R.check_revocation(chain(pki, name), allow_private=kw.pop("allow_private", True), timeout=5.0))


def test_ocsp_good_and_revoked(pki):
    good = check(pki, "good")
    assert (good.status, good.method) == ("good", "ocsp") and good.next_update is not None
    bad = check(pki, "revoked")
    assert (bad.status, bad.method) == ("revoked", "ocsp") and bad.revoked_at is not None


def test_ocsp_unknown_serial_is_not_reported_as_good(pki):
    res = check(pki, "ghost")
    assert res.status == "unknown" and "não conhece" in (res.detail or "")


def test_crl_fallback_good_and_revoked(pki):
    assert (check(pki, "crlgood").status, check(pki, "crlgood").method) == ("good", "crl")
    rev = check(pki, "crlrevoked")
    assert (rev.status, rev.method) == ("revoked", "crl") and rev.revoked_at is not None


def test_cert_without_endpoints_is_unavailable_not_good(pki):
    res = check(pki, "bare")
    assert res.status == "unavailable" and "sem OCSP nem CRL" in res.detail


def test_missing_issuer_is_unavailable(pki):
    import asyncio

    res = asyncio.run(R.check_revocation([pem_to_der(pki / "good.pem")], allow_private=True))
    assert res.status == "unavailable" and "emissor" in res.detail


def test_empty_chain_unavailable():
    import asyncio

    assert asyncio.run(R.check_revocation([])).status == "unavailable"


def test_ssrf_policy_applies_to_certificate_supplied_urls(pki):
    """As URLs OCSP/CRL vêm do certificado (terceiro): sem allow_private nada pode ir a 127.0.0.1."""
    res = check(pki, "good", allow_private=False)
    assert res.status == "error" and "Anti-SSRF" in res.detail


def test_forged_crl_signature_is_rejected(pki, tmp_path):
    """CRL de uma CA diferente (mesmo nome) não pode inocentar nem condenar o certificado."""
    import asyncio

    rogue = pki / "rogue"
    (rogue / "index.txt").write_text("")
    (rogue / "crlnumber").write_text("01\n")
    (rogue / "ca.cnf").write_text(f"[ca]\ndefault_ca=c\n[c]\ndatabase={rogue}/index.txt\ncrlnumber={rogue}/crlnumber\n"
                                   f"certificate={rogue}/ca.pem\nprivate_key={rogue}/ca.key\ndefault_md=sha256\ndefault_crl_days=7\n")
    sh("ca", "-config", "ca.cnf", "-gencrl", "-out", "forged.pem", cwd=rogue)
    sh("crl", "-in", "forged.pem", "-outform", "DER", "-out", "forged.der", cwd=rogue)
    # servidor que entrega o CRL forjado no caminho do certificado crlgood
    port = free_port()
    forged_dir = tmp_path / "srv"
    forged_dir.mkdir()
    shutil.copy(rogue / "forged.der", forged_dir / "ca.crl.der")
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), functools.partial(Quiet, directory=str(forged_dir)))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        original = R._crl_revoked_map
        async def pointed(url, issuer_pem, **kw):
            return await original(f"http://127.0.0.1:{port}/ca.crl.der", issuer_pem, **kw)
        R._crl_revoked_map = pointed
        res = asyncio.run(R.check_revocation(chain(pki, "crlrevoked"), allow_private=True))
    finally:
        R._crl_revoked_map = original
        httpd.shutdown()
    assert res.status == "error" and "assinatura do CRL" in res.detail  # NÃO "good" nem "revoked"


def test_result_is_cached(pki, monkeypatch):
    import asyncio

    calls = []
    original = R._ocsp_check

    async def counting(*a, **kw):
        calls.append(1)
        return await original(*a, **kw)

    monkeypatch.setattr(R, "_ocsp_check", counting)
    chain_der = chain(pki, "good")
    for _ in range(3):
        assert asyncio.run(R.check_revocation(chain_der, allow_private=True)).status == "good"
    assert len(calls) == 1


def test_disabled_by_env(monkeypatch):
    monkeypatch.setenv("ANHANGA_REVOCATION_CHECK", "0")
    assert R.enabled() is False
    monkeypatch.setenv("ANHANGA_REVOCATION_CHECK", "1")
    assert R.enabled() is True


def test_tampered_ocsp_response_is_rejected(pki, monkeypatch):
    """Resposta OCSP com 1 byte adulterado não pode valer como 'good' (nem como 'revoked')."""
    import asyncio

    original = R._fetch

    async def tampering(url, **kw):
        data = bytearray(await original(url, **kw))
        data[300] ^= 0xFF  # dentro da assinatura RSA (o fim da resposta é o certificado embutido, ignorado)
        return bytes(data)

    monkeypatch.setattr(R, "_fetch", tampering)
    res = asyncio.run(R.check_revocation(chain(pki, "ocspgood"), allow_private=True))  # só OCSP, sem CRL de fallback
    assert res.status == "error" and "assinatura da resposta OCSP" in res.detail


def test_ssrf_blocks_even_when_resolution_layer_is_bypassed(pki, monkeypatch):
    """Defesa em profundidade: o backend fixado também recusa IP privado."""
    import asyncio

    from anhanga.engine import probe

    async def permissive_resolve(host, port, allow_private=False, **kw):
        return await orig(host, port, allow_private=True, **kw)

    orig = probe.resolve_and_validate_host
    monkeypatch.setattr(probe, "resolve_and_validate_host", permissive_resolve)
    res = asyncio.run(R.check_revocation(chain(pki, "ocspgood"), allow_private=False))
    assert res.status == "error" and "Anti-SSRF" in res.detail


def test_revoked_certificate_becomes_invalid_and_degrades_health(mk):
    from datetime import datetime, timezone

    from anhanga.engine.models import RevocationInspection
    from anhanga.engine.probe import _apply_revocation

    r = mk()  # TLS válido -> up
    assert r.health == "up"
    rev = RevocationInspection(status="revoked", method="crl",
                               revoked_at=datetime(2026, 9, 15, tzinfo=timezone.utc))
    _apply_revocation(r.tls, rev)
    assert r.tls.valid is False and r.tls.validation_error == "certificate revoked (CRL em 2026-09-15)"
    # health é derivado na construção: revalida o modelo como o probe faz
    from anhanga.engine.models import ProbeResult

    assert ProbeResult(**r.model_dump()).health == "degraded"


@pytest.mark.parametrize("status", ["good", "unknown", "unavailable", "error"])
def test_non_revoked_outcomes_never_invalidate_the_certificate(mk, status):
    from anhanga.engine.models import RevocationInspection
    from anhanga.engine.probe import _apply_revocation

    r = mk()
    _apply_revocation(r.tls, RevocationInspection(status=status))
    assert r.tls.valid is True and r.tls.revocation.status == status


# ---- 2. cache de CRL por emissor -------------------------------------------------------------------------------
def test_crl_cache_is_not_shared_across_issuers(pki):
    import asyncio
    ca = (pki / "ca.pem").read_text()
    rogue = (pki / "rogue" / "ca.pem").read_text()
    url = R._cert_fields(pem_to_der(pki / "crlgood.pem"))["crlDistributionPoints"][0]
    R.clear_caches()
    ok = asyncio.run(R._crl_revoked_map(url, ca, allow_private=True, timeout=5.0, now=time.time()))
    assert isinstance(ok, dict)
    # mesmo URL, outro emissor: precisa REVERIFICAR (e falhar), não devolver o mapa do cache
    with pytest.raises(ValueError, match="assinatura"):
        asyncio.run(R._crl_revoked_map(url, rogue, allow_private=True, timeout=5.0, now=time.time()))
