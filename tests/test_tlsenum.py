"""Enumeração de protocolos/cifras contra servidores `openssl s_server` locais configurados de
propósito de forma ruim. Sem internet."""

import asyncio
import shutil
import socket
import subprocess
import time

import pytest

from anhanga.engine import tlsenum
from anhanga.engine.models import TLSEnumeration, TLSInspection, TLSProtocolResult
from anhanga.engine.probe import execute_probe
from anhanga.engine.security import audit_http_security

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl indisponível")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def cert(tmp_path_factory):
    d = tmp_path_factory.mktemp("enum")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(d / "k.pem"),
         "-out", str(d / "c.pem"), "-days", "2", "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )
    return d


@pytest.fixture
def server(cert):
    procs = []

    def start(*args):
        port = free_port()
        p = subprocess.Popen(
            ["openssl", "s_server", "-accept", str(port), "-cert", str(cert / "c.pem"),
             "-key", str(cert / "k.pem"), "-www", *args],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        procs.append(p)
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                return port
            except OSError:
                time.sleep(0.1)
        pytest.skip("s_server não subiu")

    yield start
    for p in procs:
        p.kill()
        p.wait()


def scan(port):
    return asyncio.run(tlsenum.enumerate_tls("127.0.0.1", port, "localhost", use_cache=False))


def supports_tls1(server):
    try:
        port = server("-tls1", "-cipher", "ALL:@SECLEVEL=0")
    except pytest.skip.Exception:
        return False
    return scan(port).get("TLSv1").status == "accepted"


def test_classify_cipher():
    assert tlsenum.classify_cipher("ECDHE-RSA-AES128-GCM-SHA256") == (False, False)
    assert tlsenum.classify_cipher("AES256-GCM-SHA384") == (False, True)  # RSA estática: sem PFS
    assert tlsenum.classify_cipher("ADH-AES128-SHA")[0] is True
    assert tlsenum.classify_cipher("NULL-SHA")[0] is True
    assert tlsenum.classify_cipher("ECDHE-RSA-DES-CBC3-SHA")[0] is True
    assert tlsenum.classify_cipher("TLS_AES_256_GCM_SHA384") == (False, False)


def test_tls13_only(server):
    e = scan(server("-tls1_3"))
    assert e.get("TLSv1.3").status == "accepted"
    assert e.get("TLSv1.3").ciphers == ["TLS_AES_256_GCM_SHA384"]
    for v in ("TLSv1", "TLSv1.1", "TLSv1.2"):
        assert e.get(v).status == "rejected", v
    assert e.get("SSLv3").status == "untestable" and e.get("SSLv2").status == "untestable"


def test_tls12_lists_every_cipher_and_flags_missing_pfs(server):
    e = scan(server("-tls1_2", "-cipher", "AES128-SHA:AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256@SECLEVEL=0"))
    p = e.get("TLSv1.2")
    assert sorted(p.ciphers) == sorted(["AES128-SHA", "AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256"])
    assert sorted(p.no_forward_secrecy) == ["AES128-SHA", "AES256-GCM-SHA384"]
    assert p.weak_ciphers == [] and p.ciphers_complete


def test_legacy_protocol_and_weak_ciphers_detected(server):
    if not supports_tls1(server):
        pytest.skip("OpenSSL local sem TLS 1.0")
    e = scan(server("-tls1", "-cipher", "ALL:COMPLEMENTOFALL:@SECLEVEL=0"))
    p = e.get("TLSv1")
    assert p.status == "accepted"
    assert any(c.startswith(("ADH", "AECDH")) for c in p.weak_ciphers)
    assert any("NULL" in c for c in p.weak_ciphers)
    assert e.get("TLSv1.2").status == "rejected"


def test_closed_port_is_unknown_not_rejected():
    port = free_port()  # nada escutando
    e = scan(port)
    assert all(p.status == "unknown" for p in e.protocols if p.protocol.startswith("TLS"))


def test_inconclusive_result_is_not_cached():
    tlsenum.clear_cache()
    port = free_port()
    asyncio.run(tlsenum.enumerate_tls("127.0.0.1", port, "localhost"))
    assert not tlsenum._cache


def test_disabled_by_env(monkeypatch):
    monkeypatch.setenv("ANHANGA_TLS_ENUM", "0")
    assert asyncio.run(tlsenum.enumerate_tls("127.0.0.1", 1, "x")) is None


def _tls(enum):
    return TLSInspection(valid=True, protocol="TLSv1.3", enumeration=enum)


def test_findings_and_score_cap_for_legacy_and_weak():
    import httpx

    clean = audit_http_security(httpx.Headers({}), True, _tls(TLSEnumeration(protocols=[
        TLSProtocolResult(protocol="TLSv1.3", status="accepted", ciphers=["TLS_AES_256_GCM_SHA384"])])))
    assert not any(f.id.startswith("SEC-TLS") for f in clean.missing_findings)

    bad = TLSEnumeration(protocols=[
        TLSProtocolResult(protocol="TLSv1", status="accepted", ciphers=["ADH-AES128-SHA"], weak_ciphers=["ADH-AES128-SHA"]),
        TLSProtocolResult(protocol="TLSv1.3", status="accepted", ciphers=["TLS_AES_256_GCM_SHA384"]),
    ])
    a = audit_http_security(httpx.Headers({}), True, _tls(bad))
    ids = {f.id for f in a.missing_findings}
    assert {"SEC-TLS-LEGACY", "SEC-TLS-WEAK-CIPHER"} <= ids
    assert a.transport_score <= 10
    assert a.score < clean.score


def test_no_pfs_alone_is_low_and_penalizes_a_little():
    import httpx

    base = audit_http_security(httpx.Headers({}), True, _tls(None))
    e = TLSEnumeration(protocols=[TLSProtocolResult(
        protocol="TLSv1.2", status="accepted", ciphers=["AES128-SHA"], no_forward_secrecy=["AES128-SHA"])])
    a = audit_http_security(httpx.Headers({}), True, _tls(e))
    f = [x for x in a.missing_findings if x.id == "SEC-TLS-NO-PFS"]
    assert f and f[0].severity == "low"
    assert a.transport_score == base.transport_score - 5


def test_handshake_failure_is_diagnosed_not_just_offline(server):
    """Servidor só TLS 1.0: o cliente HTTP (>= TLS 1.2) falha; o resultado deve dizer por quê."""
    if not supports_tls1(server):
        pytest.skip("OpenSSL local sem TLS 1.0")
    port = server("-tls1", "-cipher", "ALL:COMPLEMENTOFALL:@SECLEVEL=0")
    r = asyncio.run(execute_probe(f"https://localhost:{port}/", timeout=3, allow_private=True))
    assert r.health == "down"
    assert "handshake TLS" in r.error and "TLSv1" in r.error
    assert r.tls is not None and r.tls.tls10_11_accepted
    assert r.tls.enumeration.get("TLSv1").weak_ciphers
