"""Revisão da main, lote A. Cada teste falhava antes da sua correção."""

import asyncio
import os
import subprocess
import sys

import pytest

from anhanga.engine import probe as P


# ---- 2. falha numa amostra quente não descarta a 1ª amostra boa nem derruba o alvo ----------------------------------------------
async def _flaky_server(fail_from: int):
    """HTTP/1.1 keep-alive: responde às primeiras `fail_from - 1` requisições e, na seguinte, derruba a conexão."""
    state = {"served": 0}

    async def handle(reader, writer):
        try:
            while True:
                data = await reader.readuntil(b"\r\n\r\n")
                if not data:
                    break
                state["served"] += 1
                if state["served"] >= fail_from:
                    writer.transport.abort()  # RST no meio da amostra
                    return
                body = b"ok"
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n" + body)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1], state


def test_failure_on_a_warm_sample_keeps_the_first_sample_and_the_target_up():
    async def scenario():
        server, port, state = await _flaky_server(fail_from=2)
        try:
            return await P.execute_probe(f"http://127.0.0.1:{port}/", timeout=3, samples=4, allow_private=True)
        finally:
            server.close()

    r = asyncio.run(scenario())
    assert r.is_up and r.status_code == 200, f"alvo marcado OFFLINE por falha numa amostra quente: {r.error}"
    assert r.error is None and r.error_code is None
    assert any("Amostra 2 falhou" in n for n in r.timings.timing_notes), r.timings.timing_notes
    assert r.sampling.samples_count == 1


def test_all_samples_succeed_without_failure_notes():
    async def scenario():
        server, port, _ = await _flaky_server(fail_from=10**6)
        try:
            return await P.execute_probe(f"http://127.0.0.1:{port}/", timeout=3, samples=3, allow_private=True)
        finally:
            server.close()

    r = asyncio.run(scenario())
    assert r.is_up and r.sampling.samples_count == 3
    assert not any("falhou" in n for n in r.timings.timing_notes)


def test_first_sample_failure_still_marks_the_target_down():
    async def scenario():
        server, port, _ = await _flaky_server(fail_from=1)  # falha já na 1ª requisição
        try:
            return await P.execute_probe(f"http://127.0.0.1:{port}/", timeout=3, samples=3, allow_private=True)
        finally:
            server.close()

    r = asyncio.run(scenario())
    assert not r.is_up and r.status_code is None


# ---- 3. só alerta de versão ou de cifra prova recusa; SNI/mTLS/erro interno deixam a versão como "unknown" ---------------------------
import ssl

from anhanga.engine import tlsenum


def _handshake(monkeypatch, reason, version, exclude=(), complete=True):
    async def boom(*a, **k):
        raise ssl.SSLError(1, f"[SSL: {reason}] alert (_ssl.c:1000)")

    monkeypatch.setattr(tlsenum.asyncio, "open_connection", boom)
    monkeypatch.setattr(tlsenum, "local_ciphers_complete", lambda: complete)
    return asyncio.run(tlsenum._handshake("203.0.113.1", 443, "h.test", version, list(exclude), 1.0))[0]


@pytest.mark.parametrize(
    "reason",
    [
        "TLSV13_ALERT_CERTIFICATE_REQUIRED", "SSLV3_ALERT_BAD_CERTIFICATE", "TLSV1_UNRECOGNIZED_NAME",
        "TLSV1_ALERT_INTERNAL_ERROR", "TLSV1_ALERT_ACCESS_DENIED", "SSLV3_ALERT_UNEXPECTED_MESSAGE",
    ],
)
@pytest.mark.parametrize("version", [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3])
def test_unrelated_alerts_do_not_prove_a_version_is_rejected(monkeypatch, reason, version):
    assert _handshake(monkeypatch, reason, version) == "unknown", f"{reason} virou recusa de {version.name}"


def test_unrelated_alert_during_cipher_iteration_is_unknown_not_end_of_list(monkeypatch):
    # antes: qualquer "ALERT" encerrava a lista como completa; um erro do servidor no meio a truncava sem avisar
    assert _handshake(monkeypatch, "TLSV1_ALERT_INTERNAL_ERROR", ssl.TLSVersion.TLSv1_2, exclude=["X"]) == "unknown"


@pytest.mark.parametrize("reason", ["TLSV1_ALERT_PROTOCOL_VERSION", "SSLV3_ALERT_HANDSHAKE_FAILURE", "NO_SHARED_CIPHER"])
def test_version_and_cipher_alerts_still_prove_rejection_with_full_coverage(monkeypatch, reason):
    assert _handshake(monkeypatch, reason, ssl.TLSVersion.TLSv1_2) == "rejected"


# ---- 4. .env é carregado ANTES das variáveis lidas na importação (cookies sensíveis) ---------------------------------------------------
def _run_py(code, env_file, extra_env=None):
    env = {k: v for k, v in os.environ.items() if k != "ANHANGA_SENSITIVE_COOKIE_REGEX"}
    env["ANHANGA_ENV_FILE"] = str(env_file)
    env.update(extra_env or {})
    return subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=90)


CODE = "import anhanga.engine.security as s; print(s._is_sensitive_cookie('zzz'), s._is_sensitive_cookie('sessionid'))"


def test_cookie_regex_from_dotenv_is_applied_by_the_server_entrypoint(tmp_path):
    f = tmp_path / ".env"
    f.write_text("ANHANGA_SENSITIVE_COOKIE_REGEX=^zzz$\n")
    out = _run_py("import anhanga.main\n" + CODE, f)  # o servidor carrega o .env; a regex é lida sob demanda
    assert out.returncode == 0, out.stderr[-300:]
    assert out.stdout.split() == ["True", "False"], f".env ignorado: {out.stdout!r}"


def test_cookie_regex_from_dotenv_applies_even_if_the_engine_was_imported_first(tmp_path):
    f = tmp_path / ".env"
    f.write_text("ANHANGA_SENSITIVE_COOKIE_REGEX=^zzz$\n")
    code = "import anhanga.cli\nfrom anhanga.envfile import load_dotenv\nload_dotenv()\n" + CODE
    out = _run_py(code, f)  # CLI importa probe -> security antes de `serve` carregar o .env
    assert out.stdout.split() == ["True", "False"], out.stdout + out.stderr[-200:]


def test_real_environment_still_wins_over_dotenv(tmp_path):
    f = tmp_path / ".env"
    f.write_text("ANHANGA_SENSITIVE_COOKIE_REGEX=^zzz$\n")
    out = _run_py("import anhanga.main\n" + CODE, f, {"ANHANGA_SENSITIVE_COOKIE_REGEX": "^sessionid$"})
    assert out.stdout.split() == ["False", "True"], out.stdout


# ---- 5. sem --workers: instância única (cada worker rodaria o loop de monitoramento e alertaria em duplicidade) ----------------------
def test_serve_has_no_workers_option(monkeypatch):
    import uvicorn

    from anhanga import cli

    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)  # sem isto, a versão antiga subiria um servidor de verdade

    assert cli.main(["serve", "--workers", "4"]) == 3
    assert cli.main(["serve", "-w", "4"]) == 3


def test_serve_always_runs_a_single_process_even_with_web_concurrency(monkeypatch):
    import argparse

    import uvicorn

    from anhanga import cli

    calls = []
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: calls.append(k))
    monkeypatch.setenv("WEB_CONCURRENCY", "4")  # o uvicorn lê isto quando workers=None
    assert cli._run_serve(argparse.Namespace(host="127.0.0.1", port=7890, reload=False)) == 0
    assert calls[0]["workers"] == 1
