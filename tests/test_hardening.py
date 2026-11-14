"""Hardening: Host loopback, /healthz mínimo, /docs opt-in, UI sem recursos externos, rate limiter, .env/keygen, backup."""

import argparse
import os
import stat
import sqlite3
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from anhanga import cli, envfile, main as app_main
from anhanga.engine.security import SlidingWindowRateLimiter
from anhanga.storage import backup_database


@pytest.fixture(autouse=True)
def _no_key(monkeypatch):
    monkeypatch.delenv("ANHANGA_API_KEY", raising=False)


def _client(host: str, ip: str = "127.0.0.1"):
    return TestClient(app_main.app, base_url=f"http://{host}", client=(ip, 50000))


# ---- Host loopback: proxy reverso local (aparece como 127.0.0.1) encaminha o Host público -----------------------------------
@pytest.mark.parametrize("host", ["localhost", "localhost:8000", "127.0.0.1:7890", "[::1]:8000"])
def test_loopback_host_header_is_accepted_without_key(host):
    assert _client(host).get("/metrics").status_code == 200


@pytest.mark.parametrize("host", ["anhanga.example.com", "monitor.corp:443", "10.0.0.5", "localhost.evil.com"])
def test_local_reverse_proxy_with_public_host_is_not_treated_as_loopback(host):
    # proxy em 127.0.0.1 SEM cabeçalhos de encaminhamento, mas com o Host público: antes passava como "loopback direto"
    assert _client(host).get("/metrics").status_code == 401
    assert _client(host).get("/api/v1/targets").status_code == 401


# ---- /healthz público não expõe nada além de "vivo" -------------------------------------------------------------------------------
def test_healthz_exposes_only_liveness():
    r = _client("anhanga.example.com", ip="203.0.113.9").get("/healthz")
    assert r.status_code == 200 and r.json() == {"status": "alive"}


# ---- /docs, /redoc e /openapi.json só com ANHANGA_DOCS=1 --------------------------------------------------------------------------
def test_docs_are_off_by_default():
    assert app_main.app.docs_url is None and app_main.app.redoc_url is None and app_main.app.openapi_url is None
    c = _client("localhost")
    assert c.get("/docs").status_code == 404
    assert c.get("/redoc").status_code == 404
    assert c.get("/openapi.json").status_code == 404


def test_docs_can_be_enabled_by_the_operator():
    code = "import anhanga.main as m; print(m.app.docs_url, m.app.openapi_url)"
    env = {**os.environ, "ANHANGA_DOCS": "1"}
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=60)
    assert out.stdout.strip() == "/docs /openapi.json", out.stderr[-300:]


# ---- UI: nenhum recurso externo, /metrics com chave ---------------------------------------------------------------------------------
def test_ui_loads_nothing_from_third_parties_and_hides_docs_link():
    html = _client("localhost").get("/").text
    assert "googleapis" not in html and "gstatic" not in html
    assert 'href="/docs"' not in html
    assert "openMetrics()" in html and 'href="/metrics"' not in html


# ---- rate limiter: sem varredura global a cada chamada --------------------------------------------------------------------------------
class _CountingDict(dict):
    sweeps = 0

    def items(self):
        type(self).sweeps += 1
        return super().items()


def _limiter():
    rl = SlidingWindowRateLimiter(max_requests=1000, window_seconds=60)
    _CountingDict.sweeps = 0
    rl._hits = _CountingDict()
    return rl


def test_rate_limiter_does_not_scan_every_key_on_every_call():
    rl = _limiter()
    for i in range(500):
        rl.check(f"10.0.{i // 250}.{i % 250}")
    assert _CountingDict.sweeps <= 2, f"varredura O(n) a cada chamada: {_CountingDict.sweeps} varreduras em 500 chamadas"


def test_rate_limiter_still_expires_idle_keys_and_windows(monkeypatch):
    import anhanga.engine.security as sec

    now = [1000.0]
    monkeypatch.setattr(sec.time, "monotonic", lambda: now[0])
    rl = SlidingWindowRateLimiter(max_requests=2, window_seconds=60)
    assert rl.check("a")[0] and rl.check("a")[0]
    assert rl.check("a")[0] is False  # limite
    now[0] += 61
    assert rl.check("a")[0] is True  # a janela do próprio cliente expira exatamente
    rl.check("b")
    now[0] += 61
    rl.check("c")  # dispara a varredura periódica
    assert "b" not in rl._hits, "chave ociosa nunca é removida"


def test_rate_limiter_client_window_is_exact_between_global_sweeps(monkeypatch):
    import anhanga.engine.security as sec

    now = [1000.0]
    monkeypatch.setattr(sec.time, "monotonic", lambda: now[0])
    rl = SlidingWindowRateLimiter(max_requests=2, window_seconds=2)  # janela menor que o intervalo da varredura (5 s)
    assert rl.check("a")[0] and rl.check("a")[0] and rl.check("a")[0] is False
    now[0] += 3  # janela do cliente expirou; a varredura global ainda não rodou de novo
    assert rl.check("a")[0] is True, "cliente bloqueado depois de a própria janela expirar"


# ---- .env e keygen ---------------------------------------------------------------------------------------------------------------------
def test_dotenv_parse_and_precedence(tmp_path, monkeypatch):
    f = tmp_path / ".env"
    f.write_text('# c\nA_ONE=1\nexport A_TWO="dois"\nA_THREE=\'tres\'\n\nsem_igual\nA_FOUR=ja_no_ambiente\n')
    monkeypatch.setenv("A_FOUR", "valor_do_ambiente")
    for k in ("A_ONE", "A_TWO", "A_THREE"):
        monkeypatch.delenv(k, raising=False)
    try:
        applied = envfile.load_dotenv(f)
        assert sorted(applied) == ["A_ONE", "A_THREE", "A_TWO"]
        assert (os.environ["A_ONE"], os.environ["A_TWO"], os.environ["A_THREE"]) == ("1", "dois", "tres")
        assert os.environ["A_FOUR"] == "valor_do_ambiente", "o .env sobrescreveu o ambiente"
    finally:
        for k in ("A_ONE", "A_TWO", "A_THREE"):
            os.environ.pop(k, None)  # load_dotenv escreve direto em os.environ (monkeypatch.delenv restauraria o valor)


def test_dotenv_missing_file_is_not_an_error(tmp_path):
    assert envfile.load_dotenv(tmp_path / "nao-existe") == []


def test_generate_key_creates_private_file_and_never_overwrites(tmp_path):
    f = tmp_path / ".env"
    f.write_text("OUTRA=1\n")
    path, key = envfile.generate_api_key(f)
    assert len(key) >= 43  # 32 bytes em base64 url-safe
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    text = f.read_text()
    assert "OUTRA=1" in text and f"ANHANGA_API_KEY={key}" in text
    with pytest.raises(FileExistsError):
        envfile.generate_api_key(f)
    assert f.read_text() == text, "sobrescreveu a chave sem --force"
    _, key2 = envfile.generate_api_key(f, force=True)
    assert key2 != key and text.count("ANHANGA_API_KEY") == 1
    assert f.read_text().count("ANHANGA_API_KEY") == 1 and "OUTRA=1" in f.read_text()


def test_keygen_cli_writes_file_and_second_run_fails(tmp_path, capsys):
    f = tmp_path / "k.env"
    assert cli.main(["keygen", "--env-file", str(f)]) == 0
    assert "ANHANGA_API_KEY=" in f.read_text()
    assert cli.main(["keygen", "--env-file", str(f)]) == 2
    assert cli.main(["keygen", "--env-file", str(f), "--force"]) == 0


# ---- serve fora do loopback exige chave -----------------------------------------------------------------------------------------------
def _serve_args(host):
    return argparse.Namespace(host=host, port=7890, reload=False, workers=1)


def _fake_uvicorn(monkeypatch):
    calls = []
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: calls.append(k))
    return calls


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.10", "monitor.corp"])
def test_serve_refuses_exposed_host_without_key(monkeypatch, host, capsys):
    monkeypatch.setenv("ANHANGA_ENV_FILE", os.devnull)
    calls = _fake_uvicorn(monkeypatch)
    assert cli._run_serve(_serve_args(host)) == 2
    assert calls == [] and "keygen" in capsys.readouterr().err


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_serve_on_loopback_needs_no_key(monkeypatch, host):
    calls = _fake_uvicorn(monkeypatch)
    assert cli._run_serve(_serve_args(host)) == 0 and len(calls) == 1


def test_serve_exposed_with_key_from_dotenv_is_allowed(monkeypatch, tmp_path):
    f = tmp_path / ".env"
    envfile.generate_api_key(f)
    monkeypatch.setenv("ANHANGA_ENV_FILE", str(f))
    calls = _fake_uvicorn(monkeypatch)
    try:
        assert cli._run_serve(_serve_args("0.0.0.0")) == 0 and len(calls) == 1
    finally:
        os.environ.pop("ANHANGA_API_KEY", None)


# ---- backup consistente ---------------------------------------------------------------------------------------------------------------------
def _make_db(path):
    c = sqlite3.connect(path)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("CREATE TABLE t (v INTEGER)")
    c.executemany("INSERT INTO t VALUES (?)", [(i,) for i in range(100)])
    c.commit()
    return c  # mantido ABERTO: o WAL ainda não foi consolidado no arquivo principal


def test_backup_is_consistent_while_the_source_is_open_in_wal_mode(tmp_path):
    src, dest = tmp_path / "a.db", tmp_path / "b.db"
    conn = _make_db(src)
    out = backup_database(str(src), str(dest))
    conn.close()
    assert out == dest and stat.S_IMODE(os.stat(dest).st_mode) == 0o600
    assert sqlite3.connect(dest).execute("SELECT count(*) FROM t").fetchone()[0] == 100
    assert not (tmp_path / "b.db.tmp").exists()


def test_backup_never_overwrites_or_clobbers_the_source(tmp_path):
    src, dest = tmp_path / "a.db", tmp_path / "b.db"
    _make_db(src).close()
    dest.write_text("importante")
    with pytest.raises(FileExistsError):
        backup_database(str(src), str(dest))
    assert dest.read_text() == "importante"
    with pytest.raises(ValueError):
        backup_database(str(src), str(src), force=True)
    backup_database(str(src), str(dest), force=True)
    assert sqlite3.connect(dest).execute("SELECT count(*) FROM t").fetchone()[0] == 100


def test_backup_of_missing_source_fails_cleanly(tmp_path):
    with pytest.raises(FileNotFoundError):
        backup_database(str(tmp_path / "nada.db"), str(tmp_path / "x.db"))
    assert not (tmp_path / "x.db").exists() and not (tmp_path / "x.db.tmp").exists()


def test_backup_cli(tmp_path):
    src, dest = tmp_path / "a.db", tmp_path / "b.db"
    _make_db(src).close()
    assert cli.main(["backup", str(dest), "--db", str(src)]) == 0 and dest.exists()
    assert cli.main(["backup", str(dest), "--db", str(src)]) == 2
