"""2ª revisão da main, lote D. Cada teste falhava antes da sua correção."""

import asyncio
import inspect
import os
import subprocess
import sys

import pytest

from anhanga import cli
from anhanga.engine import alerting
from anhanga.engine import probe as P
from anhanga.engine import tlsenum
from anhanga.engine.config import SLORules
from anhanga.engine.models import ProbeResult, TLSProtocolResult, TLSEnumeration


# ---- 5. enumeração inconclusiva (algum `unknown`) tem cache curto: não refaz o scan inteiro a cada ciclo -------------------------------------
def _enum_with(status):
    protos = [TLSProtocolResult(protocol=n, status=status) for n in ("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")]
    return protos


def test_inconclusive_enumeration_is_reused_for_a_while(monkeypatch):
    tlsenum.clear_cache()
    calls = []

    async def fake_scan(ip, port, host, name, version, timeout):
        calls.append(name)
        return TLSProtocolResult(protocol=name, status="unknown")  # alvo que descarta o ClientHello

    monkeypatch.setattr(tlsenum, "_scan_version", fake_scan)

    async def scenario():
        a = await tlsenum.enumerate_tls("203.0.113.9", 443, "slow.test")
        b = await tlsenum.enumerate_tls("203.0.113.9", 443, "slow.test")
        return a, b

    a, b = asyncio.run(scenario())
    assert a is b and len(calls) == 4, f"o scan inteiro foi refeito: {len(calls)} versões testadas em 2 chamadas"
    assert not tlsenum._cache, "resultado inconclusivo não pode ocupar o cache longo (6 h)"
    tlsenum.clear_cache()


def test_inconclusive_enumeration_expires_and_is_retried(monkeypatch):
    tlsenum.clear_cache()
    calls = []

    async def fake_scan(ip, port, host, name, version, timeout):
        calls.append(name)
        return TLSProtocolResult(protocol=name, status="unknown")

    monkeypatch.setattr(tlsenum, "_scan_version", fake_scan)
    now = [1000.0]
    monkeypatch.setattr(tlsenum.time, "monotonic", lambda: now[0])

    async def scenario():
        await tlsenum.enumerate_tls("203.0.113.9", 443, "slow.test")
        now[0] += tlsenum.INCONCLUSIVE_TTL + 1
        await tlsenum.enumerate_tls("203.0.113.9", 443, "slow.test")

    asyncio.run(scenario())
    assert len(calls) == 8, "depois do TTL curto o scan deveria ser repetido"
    tlsenum.clear_cache()


def test_bounded_enumeration_serves_the_cached_inconclusive_result(monkeypatch):
    tlsenum.clear_cache()
    out = TLSEnumeration(protocols=_enum_with("unknown"), tested_at=1.0)
    import time

    tlsenum._inconclusive[("cached.test", 443)] = (time.monotonic(), out)

    async def boom(*a, **k):
        raise AssertionError("não deveria iniciar um novo scan")

    monkeypatch.setattr(tlsenum, "enumerate_tls", boom)
    got = asyncio.run(tlsenum.enumerate_tls_bounded("203.0.113.9", 443, "cached.test", budget=1.0))
    assert got is out
    tlsenum.clear_cache()


# ---- 6. falha em modo comum: conectividade conta, 5xx de aplicação não -------------------------------------------------------------------------------
def _fresh_history(monkeypatch):
    P._GLOBAL_PROBE_HISTORY.clear()
    token = P.MONITORED_PROBE.set(True)
    return token


def test_real_dns_failures_on_three_hosts_raise_the_common_mode_warning(monkeypatch):
    token = _fresh_history(monkeypatch)
    try:
        async def inner(raw_url, *a, **k):
            return ProbeResult(target_url=raw_url, error="Erro de DNS: NXDOMAIN (domínio inexistente)")

        monkeypatch.setattr(P, "_execute_probe_inner", inner)

        async def scenario():
            return [await P.execute_probe(f"https://h{i}.example/") for i in range(3)]

        results = asyncio.run(scenario())
    finally:
        P.MONITORED_PROBE.reset(token)
        P._GLOBAL_PROBE_HISTORY.clear()
    assert results[0].error_code == "dns_error"
    assert results[2].common_mode_failure_warning, "queda real do resolvedor não gerou o aviso"
    assert not results[0].common_mode_failure_warning


def test_timeouts_also_count_as_connectivity_failures(monkeypatch):
    token = _fresh_history(monkeypatch)
    try:
        async def inner(raw_url, *a, **k):
            return ProbeResult(target_url=raw_url, error="Timeout rígido excedido (9.5s): limite de tempo esgotado")

        monkeypatch.setattr(P, "_execute_probe_inner", inner)
        results = asyncio.run(_gather(P.execute_probe, ["https://a.example/", "https://b.example/", "https://c.example/"]))
    finally:
        P.MONITORED_PROBE.reset(token)
        P._GLOBAL_PROBE_HISTORY.clear()
    assert results[2].common_mode_failure_warning


async def _gather(fn, urls):
    return [await fn(u) for u in urls]


def test_application_errors_do_not_trigger_the_resolver_warning(monkeypatch):
    """Três alvos respondendo 500 são um incidente de aplicação, não do resolvedor da sonda."""
    token = _fresh_history(monkeypatch)

    async def serve():
        async def handle(reader, writer):
            try:
                await reader.readuntil(b"\r\n\r\n")
                writer.write(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 2\r\nConnection: close\r\n\r\nno")
                await writer.drain()
            finally:
                writer.close()

        server = await asyncio.start_server(handle, "0.0.0.0", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            return [
                await P.execute_probe(f"http://{h}:{port}/", timeout=3, allow_private=True)
                for h in ("localhost", "127.0.0.1", "127.0.0.2")
            ]
        finally:
            server.close()

    try:
        results = asyncio.run(serve())
    finally:
        P.MONITORED_PROBE.reset(token)
        P._GLOBAL_PROBE_HISTORY.clear()
    assert all(r.status_code == 500 and not r.is_up for r in results), [r.error for r in results]
    assert not any(r.common_mode_failure_warning for r in results), "5xx de aplicação acusou o resolvedor"


def test_unmonitored_scans_never_raise_the_warning(monkeypatch):
    P._GLOBAL_PROBE_HISTORY.clear()

    async def inner(raw_url, *a, **k):
        return ProbeResult(target_url=raw_url, error="Erro de DNS: NXDOMAIN")

    monkeypatch.setattr(P, "_execute_probe_inner", inner)
    results = asyncio.run(_gather(P.execute_probe, [f"https://h{i}.example/" for i in range(4)]))
    assert not any(r.common_mode_failure_warning for r in results)


# ---- 7. .env só no servidor: `import anhanga` e o `check` não leem o .env do diretório ----------------------------------------------------------
def _py(code, env_file):
    env = {k: v for k, v in os.environ.items() if k not in ("ANHANGA_TLS_ENUM", "HTTP_PROXY")}
    env["ANHANGA_ENV_FILE"] = str(env_file)
    return subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=90)


def test_importing_the_package_or_the_cli_does_not_load_a_dotenv(tmp_path):
    f = tmp_path / ".env"
    f.write_text("ANHANGA_TLS_ENUM=0\nHTTP_PROXY=http://evil.example:3128\n")
    out = _py("import os, anhanga, anhanga.cli, anhanga.engine.probe; print(os.environ.get('ANHANGA_TLS_ENUM'), os.environ.get('HTTP_PROXY'))", f)
    assert out.returncode == 0, out.stderr[-300:]
    assert out.stdout.split() == ["None", "None"], f".env de outra aplicação vazou para o processo: {out.stdout!r}"


def test_the_server_entrypoint_does_load_the_dotenv(tmp_path):
    f = tmp_path / ".env"
    f.write_text("ANHANGA_DOCS=1\n")
    out = _py("import os, anhanga.main as m; print(os.environ.get('ANHANGA_DOCS'), m.app.docs_url)", f)
    assert out.stdout.split() == ["1", "/docs"], out.stdout + out.stderr[-200:]


# ---- 8. gates do CLI e do monitor usam a mesma métrica (mediana de TTFB, total "manchete") ----------------------------------------------------
def test_cli_ttfb_gate_uses_the_median_not_the_inflated_cold_sample(mk):
    res = mk(ttfb_ms=400.0, ttfb_p50=150.0, samples=10)  # frio inflado (HTTP/2), mediana saudável
    passed, code, violations = cli.evaluate_probe_gates(res, min_grade=None, max_ttfb_ms=300.0, max_total_ms=None, require_valid_cert=True)
    assert passed and code == 0, violations


def test_cli_ttfb_gate_still_fails_when_the_median_is_slow(mk):
    res = mk(ttfb_ms=100.0, ttfb_p50=500.0, samples=10)
    passed, code, _ = cli.evaluate_probe_gates(res, min_grade=None, max_ttfb_ms=300.0, max_total_ms=None, require_valid_cert=True)
    assert not passed and code == 1


def test_cli_total_gate_uses_the_headline_total(mk):
    res = mk(samples=5)
    res.timings.total_ms = 5000.0
    res.sampling.headline_total_ms = 900.0
    passed, _, v = cli.evaluate_probe_gates(res, min_grade=None, max_ttfb_ms=None, max_total_ms=1000.0, require_valid_cert=True)
    assert passed, v


@pytest.mark.parametrize("ttfb, p50, samples, limit", [(400, 150, 10, 300), (100, 500, 10, 300), (350, 350, 1, 300), (250, 250, 1, 300)])
def test_cli_and_monitor_agree_on_the_ttfb_slo(mk, ttfb, p50, samples, limit):
    res = mk(ttfb_ms=float(ttfb), ttfb_p50=float(p50), samples=samples)
    cli_fails = not cli.evaluate_probe_gates(res, None, float(limit), None, True)[0]
    monitor_fails = "slo_ttfb" in alerting.detect_problems(res, SLORules(max_ttfb_ms=float(limit)))
    assert cli_fails == monitor_fails


# ---- 9. regra SARIF pelo prefixo da violação / código de saída, não por substring --------------------------------------------------------------------
def _rule(violation, exit_code=1, mk_result=None):
    from tests.conftest import make_result

    sarif = cli.build_sarif_report(make_result(), [violation], exit_code)
    return sarif["runs"][0]["results"][0]["ruleId"]


@pytest.mark.parametrize(
    "violation, exit_code, expected",
    [
        ("Content Assertion: Corpo não contém o padrão esperado: 'total'", 1, "ANHANGA-ASSERTION"),
        ("Content Assertion: URL final 'https://cdns.exemplo.com/' difere", 1, "ANHANGA-ASSERTION"),
        ("Alvo OFFLINE: Erro HTTP/Conexão: connect to cdns.exemplo.com refused", 1, "ANHANGA-AVAILABILITY"),
        ("Alvo OFFLINE: HTTP 503", 1, "ANHANGA-AVAILABILITY"),
        ("Certificado TLS inválido: certificate has expired", 1, "ANHANGA-TLS-INVALID"),
        ("SLO de TTFB violado: 400.00ms excede o limite de 300.00ms.", 1, "ANHANGA-SLO-TTFB"),
        ("SLO de Latência Total violado: 900.00ms excede o limite de 500.00ms.", 1, "ANHANGA-SLO-TOTAL"),
        ("Nota de segurança insuficiente: obtido 'C' (score 55/100), mínimo exigido 'B'.", 2, "ANHANGA-GATE-SECURITY-GRADE"),
        ("Erro de DNS: NXDOMAIN para foo.exemplo", 3, "ANHANGA-SSRF-OR-DNS"),
        ("Bloqueado pelo Guardião Anti-SSRF: IP privado", 3, "ANHANGA-SSRF-OR-DNS"),
        ("Texto novo sem prefixo conhecido: total, dns, ttfb, assertion, offline", 1, "ANHANGA-GATE-1"),  # nada por substring
    ],
)
def test_sarif_rule_comes_from_the_violation_prefix(violation, exit_code, expected):
    assert _rule(violation, exit_code) == expected


# ---- 10. código morto removido: o parser nunca definiu --resolve nem flags de asserção --------------------------------------------------------------
def test_check_has_no_resolve_option_and_no_dead_getattr_code():
    assert cli.main(["check", "https://example.com", "--resolve", "example.com:1.2.3.4"]) == 3
    src = inspect.getsource(cli._run_check_async)
    assert "getattr(args" not in src and "resolve_override" not in src
