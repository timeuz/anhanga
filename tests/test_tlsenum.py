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


# ---- "handshake failure" é ambíguo: não prova que o servidor recusou a versão (achado da validação com testssl.sh) -------------------
import ssl


def _fail_with(monkeypatch, reason_text):
    async def boom(*a, **k):
        raise ssl.SSLError(1, f"[SSL: {reason_text}] alert (_ssl.c:1000)")

    monkeypatch.setattr(tlsenum.asyncio, "open_connection", boom)


def _hs(version, exclude=()):
    return asyncio.run(tlsenum._handshake("203.0.113.1", 443, "h.test", version, list(exclude), 1.0))[0]


@pytest.mark.parametrize("v", [ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_2])
def test_handshake_failure_is_unknown_when_local_openssl_lacks_rc4_or_3des(monkeypatch, v):
    # servidor só-RC4/3DES (rc4.badssl.com, 3des.badssl.com) responde assim; "rejected" seria afirmar algo que não foi provado
    monkeypatch.setattr(tlsenum, "local_ciphers_complete", lambda: False)
    _fail_with(monkeypatch, "SSLV3_ALERT_HANDSHAKE_FAILURE")
    assert _hs(v) == "unknown"


def test_handshake_failure_is_a_rejection_when_local_ciphers_are_complete(monkeypatch):
    monkeypatch.setattr(tlsenum, "local_ciphers_complete", lambda: True)
    _fail_with(monkeypatch, "SSLV3_ALERT_HANDSHAKE_FAILURE")
    assert _hs(ssl.TLSVersion.TLSv1) == "rejected"


@pytest.mark.parametrize("complete", [False, True])
def test_protocol_version_alert_is_always_a_rejection(monkeypatch, complete):
    monkeypatch.setattr(tlsenum, "local_ciphers_complete", lambda: complete)
    _fail_with(monkeypatch, "TLSV1_ALERT_PROTOCOL_VERSION")
    assert _hs(ssl.TLSVersion.TLSv1) == "rejected"


def test_tls13_handshake_failure_is_a_rejection_even_with_incomplete_ciphers(monkeypatch):
    monkeypatch.setattr(tlsenum, "local_ciphers_complete", lambda: False)  # TLS 1.3 não depende de RC4/3DES
    _fail_with(monkeypatch, "SSLV3_ALERT_HANDSHAKE_FAILURE")
    assert _hs(ssl.TLSVersion.TLSv1_3) == "rejected"


def test_cipher_exhaustion_still_ends_the_cipher_loop(monkeypatch):
    # na iteração por exclusão, "sem cifra em comum" é exatamente o fim esperado da lista (não vira "unknown")
    monkeypatch.setattr(tlsenum, "local_ciphers_complete", lambda: False)
    _fail_with(monkeypatch, "SSLV3_ALERT_HANDSHAKE_FAILURE")
    assert _hs(ssl.TLSVersion.TLSv1_2, exclude=["ECDHE-RSA-AES128-SHA"]) == "rejected"


def test_local_ciphers_complete_is_a_bool():
    assert isinstance(tlsenum.local_ciphers_complete(), bool)


class _StubCtx:
    def __init__(self, names, fail=False):
        self._names, self._fail = names, fail

    def set_ciphers(self, spec):
        if self._fail:
            raise ssl.SSLError("sem cifras")

    def get_ciphers(self):
        return [{"name": n} for n in self._names]


@pytest.mark.parametrize(
    "names, fail, expected",
    [
        (["ECDHE-RSA-AES128-GCM-SHA256", "RC4-SHA", "DES-CBC3-SHA"], False, True),
        (["ECDHE-RSA-AES128-GCM-SHA256", "DES-CBC3-SHA"], False, False),  # sem RC4
        (["ECDHE-RSA-AES128-GCM-SHA256", "RC4-SHA"], False, False),  # sem 3DES
        ([], True, False),  # OpenSSL recusa a lista
    ],
)
def test_local_ciphers_complete_needs_both_rc4_and_3des(monkeypatch, names, fail, expected):
    tlsenum.local_ciphers_complete.cache_clear()
    monkeypatch.setattr(tlsenum.ssl, "SSLContext", lambda *a, **k: _StubCtx(names, fail))
    try:
        assert tlsenum.local_ciphers_complete() is expected
    finally:
        monkeypatch.undo()
        tlsenum.local_ciphers_complete.cache_clear()


# ---- honestidade de cobertura (validação com testssl.sh: TLS 1.3 tem 3 suítes, RC4/3DES invisíveis ao OpenSSL local) ----------------
def test_tls13_cipher_list_is_never_claimed_complete(server):
    e = scan(server("-tls1_3"))
    assert e.get("TLSv1.3").ciphers_complete is False  # só a suíte negociada: as outras não são selecionáveis por exclusão


def test_tls12_list_by_exclusion_is_still_complete(server):
    e = scan(server("-tls1_2"))
    assert e.get("TLSv1.2").ciphers_complete is True


@pytest.mark.parametrize("local_complete", [True, False])
def test_enumeration_flags_untested_legacy_ciphers(server, monkeypatch, local_complete):
    monkeypatch.setattr(tlsenum, "local_ciphers_complete", lambda: local_complete)
    e = scan(server("-tls1_2"))
    assert e.legacy_ciphers_untested is (not local_complete)


def test_cli_text_warns_when_legacy_ciphers_were_not_testable():
    from anhanga.cli import _protocols_text

    enum = TLSEnumeration(
        protocols=[TLSProtocolResult(protocol="TLSv1.2", status="accepted", ciphers=["ECDHE-RSA-AES128-GCM-SHA256"])],
        legacy_ciphers_untested=True,
    )
    assert "RC4/3DES não testáveis" in _protocols_text(TLSInspection(enumeration=enum))
    enum.legacy_ciphers_untested = False
    assert "RC4/3DES" not in _protocols_text(TLSInspection(enumeration=enum))
