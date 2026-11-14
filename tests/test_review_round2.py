"""Regressões da 2ª revisão do PR #5 (lote 1): webhook não-2xx, SSRF via URLs do certificado, processos órfãos."""

import asyncio
import http.server
import os
import shutil
import socket
import subprocess
import threading
import time

import pytest

import anhanga.main as app_main
from anhanga.engine import probe as P
from anhanga.engine import revocation as R
from anhanga.engine.alerting import AlertEvent
from anhanga.engine.config import WebhookSpec
from anhanga.engine.models import RevocationInspection, TLSInspection
from anhanga.storage import Store


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def hook_server():
    """Webhook local cujo status é controlado pelo teste."""
    state = {"status": 200, "hits": 0}

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            state["hits"] += 1
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(state["status"])
            self.end_headers()

        def log_message(self, *a):
            pass

    port = free_port()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    state["url"] = f"http://127.0.0.1:{port}/hook"
    yield state
    httpd.shutdown()


def _wh(state):
    return WebhookSpec(url=state["url"], provider="slack", chat_id=None, allow_private=True)


# ---- 1. webhook respondendo não-2xx não pode contar como entregue ---------------------------------------------
@pytest.mark.parametrize("status", [500, 429, 404])
def test_non_2xx_webhook_response_is_a_failure_and_goes_to_outbox(hook_server, tmp_path, monkeypatch, mk, status):
    store = Store(str(tmp_path / "t.db"))
    monkeypatch.setattr(app_main, "_STORE", store)

    async def no_sleep(*a, **k):
        return None

    monkeypatch.setattr(app_main.asyncio, "sleep", no_sleep)  # pula o intervalo entre tentativas
    hook_server["status"] = status
    ev = AlertEvent(kind="alert", target="https://t.example", messages=["down"])
    asyncio.run(app_main._deliver_event(ev, mk("https://t.example", up=False, status=None), [_wh(hook_server)]))
    assert hook_server["hits"] == 2, "deveria tentar 2 vezes antes de ir para a outbox"
    assert store.outbox_size() == 1, "alerta com resposta não-2xx foi dado como entregue e perdido"
    store.close()


def test_2xx_webhook_is_delivered_without_outbox(hook_server, tmp_path, monkeypatch, mk):
    store = Store(str(tmp_path / "t.db"))
    monkeypatch.setattr(app_main, "_STORE", store)
    hook_server["status"] = 200
    ev = AlertEvent(kind="alert", target="https://t.example", messages=["down"])
    asyncio.run(app_main._deliver_event(ev, mk("https://t.example", up=False, status=None), [_wh(hook_server)]))
    assert hook_server["hits"] == 1 and store.outbox_size() == 0
    store.close()


def _make_due(store):
    with store._lock:
        store._conn.execute("UPDATE outbox SET next_attempt_ts = 0")


def test_outbox_keeps_item_when_resend_gets_5xx_and_clears_it_on_2xx(hook_server, tmp_path, monkeypatch, mk):
    from anhanga.engine.config import MonitorConfig
    from anhanga.storage import webhook_key

    store = Store(str(tmp_path / "t.db"))
    monkeypatch.setattr(app_main, "_STORE", store)
    wh = _wh(hook_server)
    store.enqueue(webhook_key(wh.url), "https://t.example", "alert", ["down"],
                  mk("https://t.example", up=False, status=None).model_dump_json())
    cfg = MonitorConfig(webhooks=[wh])

    hook_server["status"] = 503
    _make_due(store)
    asyncio.run(app_main._process_outbox(cfg))
    assert store.outbox_size() == 1, "reenvio com 503 foi marcado como concluído"

    hook_server["status"] = 200
    _make_due(store)
    asyncio.run(app_main._process_outbox(cfg))
    assert store.outbox_size() == 0
    store.close()


# ---- 3. URLs do certificado nunca herdam o allow_private do alvo --------------------------------------------
@pytest.fixture
def tls_server(tmp_path):
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(tmp_path / "k.pem"),
                    "-out", str(tmp_path / "c.pem"), "-days", "2", "-subj", "/CN=localhost"],
                   check=True, capture_output=True)
    port = free_port()
    p = subprocess.Popen(["openssl", "s_server", "-accept", str(port), "-cert", str(tmp_path / "c.pem"),
                          "-key", str(tmp_path / "k.pem"), "-www"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    yield port
    p.kill()
    p.wait()


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl indisponível")
@pytest.mark.parametrize("env,expected", [(None, False), ("1", True)])
def test_revocation_endpoints_ignore_target_allow_private(tls_server, monkeypatch, env, expected):
    seen = {}

    async def spy(chain_der, *, allow_private=False, **kw):
        seen["allow_private"] = allow_private
        return RevocationInspection(status="good", method="ocsp")

    monkeypatch.setattr(P.revocation, "check_revocation", spy)
    monkeypatch.setattr(P, "parse_tls_certificate", lambda *a, **k: TLSInspection(valid=True))
    if env:
        monkeypatch.setenv("ANHANGA_REVOCATION_ALLOW_PRIVATE", env)
    else:
        monkeypatch.delenv("ANHANGA_REVOCATION_ALLOW_PRIVATE", raising=False)
    # alvo configurado com allow_private=True (lab): o certificado dele NÃO pode herdar essa permissão
    asyncio.run(P.execute_probe(f"https://localhost:{tls_server}/", timeout=3, allow_private=True))
    assert seen.get("allow_private") is expected


# ---- 5 (parte). `openssl` não pode ficar órfão quando a tarefa é cancelada ----------------------------------
@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl indisponível")
def test_openssl_child_is_killed_on_cancellation(tmp_path, monkeypatch):
    spawned = []
    real = asyncio.create_subprocess_exec

    async def spy(*a, **k):
        proc = await real(*a, **k)
        spawned.append(proc)
        return proc

    monkeypatch.setattr(R.asyncio, "create_subprocess_exec", spy)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(tmp_path / "k.pem"),
                    "-out", str(tmp_path / "c.pem"), "-days", "2", "-subj", "/CN=x"], check=True, capture_output=True)

    async def scenario():
        # s_server fica rodando para sempre: só termina se for morto
        task = asyncio.create_task(R._openssl(
            ["s_server", "-accept", str(free_port()), "-cert", str(tmp_path / "c.pem"), "-key", str(tmp_path / "k.pem")],
            timeout=60.0))
        await asyncio.sleep(0.5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0.5)
        return spawned[0].returncode

    assert asyncio.run(scenario()) is not None, "o processo openssl continuou vivo após o cancelamento"
