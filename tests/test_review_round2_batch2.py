"""Lote 2 da 2ª revisão: worker de regex sem pacote instalado, `openssl s_client` órfão, diagnóstico dentro do prazo."""

import asyncio
import json
import shutil
import socket
import subprocess
import sys
import threading
import time

import pytest

from anhanga.engine import probe as P
from anhanga.engine import security as S


# ---- worker de regex não depende do pacote estar instalado -------------------------------------------------
def test_regex_worker_runs_without_the_package_importable():
    """`-I -S` (sem site-packages, PYTHONPATH nem cwd) = pacote não instalado. `-m anhanga...` falhava aqui."""
    argv = P._regex_worker_argv()
    out = subprocess.run([argv[0], "-I", "-S", *argv[2:]], input=json.dumps({"pattern": "a+", "text": "caaat"}).encode(),
                         capture_output=True, timeout=10, cwd="/")
    assert out.returncode == 0, out.stderr.decode()
    assert json.loads(out.stdout) == ["ok", True]


def test_regex_evaluator_failure_is_not_blamed_on_the_users_pattern(monkeypatch):
    monkeypatch.setattr(P, "_regex_worker_argv", lambda: [sys.executable, "-I", "/nonexistent/worker.py"])
    status, detail = P._regex_search_isolated("a+", "aaa")
    assert status == "unavailable" and "encerrou com erro" in detail
    res = asyncio.run(P._evaluate_content_assertions("aaa", 3, "https://x/", fail_if_body_not_matches_regexp="a+"))
    assert not res.passed
    msg = res.failures[0]
    assert "indisponível" in msg and "inválida" not in msg and "não do padrão" in msg


def test_real_invalid_pattern_still_reported_as_invalid():
    assert P._regex_search_isolated("(", "x")[0] == "invalid"
    assert P._regex_search_isolated("a+", "caaat") == ("ok", True)


# ---- `openssl s_client` não fica órfão no cancelamento ---------------------------------------------------------
@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl indisponível")
def test_fetch_tls_extras_kills_openssl_on_cancellation(monkeypatch):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    held = []

    def accept_and_stall():  # aceita a conexão e nunca responde ao ClientHello
        while True:
            try:
                held.append(srv.accept()[0])
            except OSError:
                return

    threading.Thread(target=accept_and_stall, daemon=True).start()
    spawned = []
    real = asyncio.create_subprocess_exec

    async def spy(*a, **k):
        proc = await real(*a, **k)
        spawned.append(proc)
        return proc

    monkeypatch.setattr(S.asyncio, "create_subprocess_exec", spy)

    async def scenario():
        task = asyncio.create_task(S.fetch_tls_extras("127.0.0.1", port, "localhost", timeout=60.0))
        await asyncio.sleep(0.6)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0.5)
        return spawned[0].returncode

    try:
        assert asyncio.run(scenario()) is not None, "openssl s_client continuou vivo após o cancelamento"
    finally:
        srv.close()


# ---- diagnóstico TLS acompanha o timeout pedido ----------------------------------------------------------------
@pytest.mark.parametrize("timeout,max_budget", [(1.0, 2.0), (5.0, 10.0), (30.0, 10.0)])
def test_tls_diagnosis_budget_follows_requested_timeout(monkeypatch, timeout, max_budget):
    seen = {}

    async def fake_resolve(*a, **k):
        return ("203.0.113.5", 1.0)

    async def fake_enum(ip, port, host, budget=3.0, timeout=3.0):
        seen["budget"] = budget
        return None

    monkeypatch.setattr(P, "resolve_and_validate_host", fake_resolve)
    monkeypatch.setattr(P, "enumerate_tls_bounded", fake_enum)
    asyncio.run(P._diagnose_tls_failure("https://x.test/", "boom", allow_private=False, timeout=timeout,
                                        resolve_override=None))
    assert seen["budget"] <= max_budget


def test_garbage_evaluator_output_is_unavailable_not_invalid(monkeypatch):
    monkeypatch.setattr(P, "_regex_worker_argv", lambda: [sys.executable, "-I", "-c", "print('not json')"])
    status, detail = P._regex_search_isolated("a+", "aaa")
    assert status == "unavailable" and "resposta inválida" in detail
