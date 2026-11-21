"""Persistência SQLite (stdlib) do Anhangá.

Guarda: histórico de sondagens (uptime, sparkline), estado dos alertas (sobrevive a reinício),
incidentes (abertura/fechamento) e a outbox de notificações que falharam (reenvio com backoff).

Segurança: o arquivo é criado com permissão 0600; a outbox guarda só um hash da URL do webhook
(a URL, que costuma conter token, continua apenas na configuração).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from anhanga.engine.models import ProbeResult

SCHEMA_VERSION = 2
OUTBOX_BACKOFF_SECONDS: tuple[int, ...] = (30, 120, 600, 1800, 3600)  # após a n-ésima falha
VACUUM_CHUNK_PAGES = 256  # ~1 MiB por bloco
VACUUM_MAX_CHUNKS = 20  # por poda
OUTBOX_MAX_AGE_SECONDS = 24 * 3600  # alerta velho demais deixa de ser útil

_MIGRATIONS: dict[int, str] = {
    1: """
    CREATE TABLE probe_history (
        id INTEGER PRIMARY KEY,
        target TEXT NOT NULL,
        ts REAL NOT NULL,
        health TEXT NOT NULL,
        status_code INTEGER,
        total_ms REAL,
        ttfb_ms REAL,
        grade TEXT,
        score INTEGER,
        tls_days INTEGER,
        error_code TEXT
    );
    CREATE INDEX idx_probe_history_target_ts ON probe_history (target, ts);
    CREATE INDEX idx_probe_history_ts ON probe_history (ts);

    CREATE TABLE alert_state (
        target TEXT NOT NULL,
        problem TEXT NOT NULL,
        streak INTEGER NOT NULL,
        clear_streak INTEGER NOT NULL,
        active INTEGER NOT NULL,
        last_notified REAL NOT NULL,
        first_seen REAL NOT NULL,
        PRIMARY KEY (target, problem)
    );

    CREATE TABLE incidents (
        id INTEGER PRIMARY KEY,
        target TEXT NOT NULL,
        problem TEXT NOT NULL,
        started_ts REAL NOT NULL,
        ended_ts REAL,
        message TEXT NOT NULL
    );
    CREATE INDEX idx_incidents_target ON incidents (target, started_ts);
    CREATE UNIQUE INDEX idx_incidents_open ON incidents (target, problem) WHERE ended_ts IS NULL;

    CREATE TABLE outbox (
        id INTEGER PRIMARY KEY,
        webhook_key TEXT NOT NULL,
        target TEXT NOT NULL,
        kind TEXT NOT NULL,
        messages TEXT NOT NULL,
        result_json TEXT NOT NULL,
        created_ts REAL NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt_ts REAL NOT NULL
    );
    CREATE INDEX idx_outbox_due ON outbox (next_attempt_ts);
    """,
    2: """
    CREATE TABLE managed_targets (
        url TEXT PRIMARY KEY,
        samples INTEGER NOT NULL DEFAULT 1,
        created_ts REAL NOT NULL
    );
    """,
}


def webhook_key(url: str) -> str:
    """Identificador estável do destino, sem guardar a URL (que costuma carregar o token)."""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]


def headline_ms(result: ProbeResult) -> float | None:
    """Latência representativa do ciclo (mediana quando há amostras). None se não houve resposta."""
    if result.status_code is None:
        return None
    if result.sampling and result.sampling.headline_total_ms > 0:
        return result.sampling.headline_total_ms
    return result.timings.total_ms


class Store:
    def __init__(self, path: str, retention_days: int = 14) -> None:
        self.path = path
        self.retention_days = retention_days
        self._lock = threading.RLock()
        memory = path == ":memory:"
        if not memory:
            Path(path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            ":memory:" if memory else str(Path(path).expanduser()),
            check_same_thread=False,
            isolation_level=None,  # autocommit; transações explícitas onde necessário
        )
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            c = self._conn
            c.execute("PRAGMA busy_timeout = 5000")
            if not memory:
                if c.execute("PRAGMA user_version").fetchone()[0] == 0:
                    c.execute("PRAGMA auto_vacuum = INCREMENTAL")  # só vale antes de existir qualquer tabela
                c.execute("PRAGMA journal_mode = WAL")
                c.execute("PRAGMA synchronous = NORMAL")
            self._migrate()
        if not memory:
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.chmod(str(Path(path).expanduser()) + suffix, 0o600)
                except OSError:
                    pass

    def _migrate(self) -> None:
        version = self._conn.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise RuntimeError(
                f"Banco criado por versão mais nova do Anhangá (schema {version} > {SCHEMA_VERSION})."
            )
        for target_version in range(version + 1, SCHEMA_VERSION + 1):
            self._conn.execute("BEGIN")
            try:
                for stmt in _MIGRATIONS[target_version].split(";"):
                    if stmt.strip():
                        self._conn.execute(stmt)
                self._conn.execute(f"PRAGMA user_version = {target_version}")
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # --- histórico ---
    def record_probe(self, result: ProbeResult) -> None:
        total = headline_ms(result)
        has_resp = result.status_code is not None
        with self._lock:
            self._conn.execute(
                "INSERT INTO probe_history (target, ts, health, status_code, total_ms, ttfb_ms, grade, score,"
                " tls_days, error_code) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    result.target_url,
                    result.timestamp.timestamp(),
                    result.health,
                    result.status_code,
                    total,
                    result.timings.ttfb_ms if has_resp else None,
                    result.security.grade if has_resp else None,
                    result.security.score if has_resp else None,
                    result.tls.days_remaining if result.tls else None,
                    result.error_code,
                ),
            )

    def recent_totals(self, target: str, n: int = 30) -> list[float]:
        """Últimas `n` latências (ordem cronológica) para repovoar o sparkline após reinício."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT total_ms FROM probe_history WHERE target = ? AND total_ms IS NOT NULL"
                " ORDER BY ts DESC LIMIT ?",
                (target, n),
            ).fetchall()
        return [r[0] for r in reversed(rows)]

    def history(self, target: str, since: float, until: float | None = None, max_points: int = 300) -> list[dict[str, Any]]:
        """Série agregada em buckets de tempo (no máx. `max_points`)."""
        until = until if until is not None else time.time()
        max_points = max(1, max_points)
        bucket = max(1.0, (until - since) / max_points)
        with self._lock:
            rows = self._conn.execute(
                "SELECT CAST(ts / :b AS INTEGER) * :b AS bucket, COUNT(*) AS checks,"
                " SUM(health = 'up') AS up, SUM(health = 'degraded') AS degraded, SUM(health = 'down') AS down,"
                " AVG(total_ms) AS avg_ms, MAX(total_ms) AS max_ms, MIN(total_ms) AS min_ms"
                " FROM probe_history WHERE target = :t AND ts >= :s AND ts <= :u"
                " GROUP BY bucket ORDER BY bucket",
                {"b": bucket, "t": target, "s": since, "u": until},
            ).fetchall()
        return [
            {
                "ts": r["bucket"],
                "checks": r["checks"],
                "up": r["up"],
                "degraded": r["degraded"],
                "down": r["down"],
                "avg_ms": None if r["avg_ms"] is None else round(r["avg_ms"], 2),
                "min_ms": r["min_ms"],
                "max_ms": r["max_ms"],
            }
            for r in rows
        ]

    def uptime(self, target: str, now: float | None = None) -> dict[str, Any]:
        """Uptime por janela. `uptime_pct`: health=up. `availability_pct`: HTTP respondeu (up ou degraded)."""
        now = now if now is not None else time.time()
        out: dict[str, Any] = {}
        for label, seconds in (("24h", 86400), ("7d", 7 * 86400), ("30d", 30 * 86400)):
            with self._lock:
                row = self._conn.execute(
                    "SELECT COUNT(*) AS n, SUM(health = 'up') AS up, SUM(health != 'down') AS avail,"
                    " MIN(ts) AS first FROM probe_history WHERE target = ? AND ts >= ?",
                    (target, now - seconds),
                ).fetchone()
            n = row["n"] or 0
            out[label] = {
                "checks": n,
                "uptime_pct": round(100.0 * (row["up"] or 0) / n, 3) if n else None,
                "availability_pct": round(100.0 * (row["avail"] or 0) / n, 3) if n else None,
                # janela só parcialmente coberta pelos dados (ex.: banco novo): não dá pra vender 30d com 2h de dados
                "covered_seconds": round(now - row["first"], 0) if n else 0,
            }
        return out

    # --- estado dos alertas ---
    def save_alert_state(self, target: str, rows: list[dict[str, Any]]) -> None:
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                self._conn.execute("DELETE FROM alert_state WHERE target = ?", (target,))
                self._conn.executemany(
                    "INSERT INTO alert_state (target, problem, streak, clear_streak, active, last_notified, first_seen)"
                    " VALUES (?,?,?,?,?,?,?)",
                    [
                        (target, r["problem"], r["streak"], r["clear_streak"], int(r["active"]),
                         r["last_notified"], r["first_seen"])
                        for r in rows
                    ],
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def load_alert_state(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM alert_state").fetchall()
        return [{**dict(r), "active": bool(r["active"])} for r in rows]

    def forget_targets(self, targets: list[str], now: float | None = None) -> None:
        """Alvo removido da configuração: apaga o estado de alertas e encerra incidentes abertos."""
        now = now if now is not None else time.time()
        with self._lock:
            for t in targets:
                self._conn.execute("DELETE FROM alert_state WHERE target = ?", (t,))
                self._conn.execute(
                    "UPDATE incidents SET ended_ts = ? WHERE target = ? AND ended_ts IS NULL", (now, t)
                )

    # --- incidentes ---
    def open_incident(self, target: str, problem: str, started_ts: float, message: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO incidents (target, problem, started_ts, message) VALUES (?,?,?,?)",
                (target, problem, started_ts, message),
            )

    def close_incident(self, target: str, problem: str, ended_ts: float) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE incidents SET ended_ts = ? WHERE target = ? AND problem = ? AND ended_ts IS NULL",
                (ended_ts, target, problem),
            )

    def incidents(self, target: str | None = None, open_only: bool = False, limit: int = 100) -> list[dict[str, Any]]:
        sql = "SELECT * FROM incidents WHERE 1=1"
        params: list[Any] = []
        if target:
            sql += " AND target = ?"
            params.append(target)
        if open_only:
            sql += " AND ended_ts IS NULL"
        sql += " ORDER BY started_ts DESC LIMIT ?"
        params.append(max(1, min(limit, 1000)))
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["duration_seconds"] = round((d["ended_ts"] or time.time()) - d["started_ts"], 1)
            d["open"] = d["ended_ts"] is None
            out.append(d)
        return out

    # --- outbox ---
    def enqueue(self, wh_key: str, target: str, kind: str, messages: list[str], result_json: str,
                now: float | None = None) -> None:
        now = now if now is not None else time.time()
        with self._lock:
            self._conn.execute(
                "INSERT INTO outbox (webhook_key, target, kind, messages, result_json, created_ts, attempts,"
                " next_attempt_ts) VALUES (?,?,?,?,?,?,0,?)",
                (wh_key, target, kind, json.dumps(messages), result_json, now, now + OUTBOX_BACKOFF_SECONDS[0]),
            )

    def due(self, now: float | None = None, limit: int = 20) -> list[dict[str, Any]]:
        now = now if now is not None else time.time()
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM outbox WHERE next_attempt_ts <= ? ORDER BY next_attempt_ts LIMIT ?", (now, limit)
            ).fetchall()
        return [{**dict(r), "messages": json.loads(r["messages"])} for r in rows]

    def mark_done(self, outbox_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM outbox WHERE id = ?", (outbox_id,))

    def reschedule(self, outbox_id: int, now: float | None = None) -> bool:
        """Registra mais uma falha. Retorna True se o item foi descartado (esgotou tentativas ou envelheceu)."""
        now = now if now is not None else time.time()
        with self._lock:
            row = self._conn.execute(
                "SELECT attempts, created_ts FROM outbox WHERE id = ?", (outbox_id,)
            ).fetchone()
            if row is None:
                return True
            attempts = row["attempts"] + 1
            if attempts >= len(OUTBOX_BACKOFF_SECONDS) or now - row["created_ts"] > OUTBOX_MAX_AGE_SECONDS:
                self._conn.execute("DELETE FROM outbox WHERE id = ?", (outbox_id,))
                return True
            self._conn.execute(
                "UPDATE outbox SET attempts = ?, next_attempt_ts = ? WHERE id = ?",
                (attempts, now + OUTBOX_BACKOFF_SECONDS[attempts], outbox_id),
            )
            return False

    # --- alvos gerenciados pela UI ---
    def add_managed_target(self, url: str, samples: int, limit: int, now: float | None = None) -> str:
        """'added' | 'exists' | 'limit'. O limite é checado na mesma instrução do INSERT (sem corrida)."""
        with self._lock:
            if self._conn.execute("SELECT 1 FROM managed_targets WHERE url = ?", (url,)).fetchone():
                return "exists"
            cur = self._conn.execute(
                "INSERT INTO managed_targets (url, samples, created_ts) "
                "SELECT ?, ?, ? WHERE (SELECT COUNT(*) FROM managed_targets) < ?",
                (url, samples, now if now is not None else time.time(), limit),
            )
            return "added" if cur.rowcount else "limit"

    def remove_managed_target(self, url: str) -> bool:
        with self._lock:
            return self._conn.execute("DELETE FROM managed_targets WHERE url = ?", (url,)).rowcount > 0

    def list_managed_targets(self) -> list[tuple[str, int]]:
        with self._lock:
            rows = self._conn.execute("SELECT url, samples FROM managed_targets ORDER BY created_ts, url").fetchall()
        return [(r["url"], r["samples"]) for r in rows]

    def outbox_size(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM outbox").fetchone()[0]

    # --- manutenção ---
    def prune(self, now: float | None = None) -> int:
        """Remove histórico e incidentes encerrados fora da retenção, e outbox envelhecida."""
        now = now if now is not None else time.time()
        cutoff = now - self.retention_days * 86400
        with self._lock:
            n = self._conn.execute("DELETE FROM probe_history WHERE ts < ?", (cutoff,)).rowcount
            self._conn.execute("DELETE FROM incidents WHERE ended_ts IS NOT NULL AND ended_ts < ?", (cutoff,))
            self._conn.execute("DELETE FROM outbox WHERE created_ts < ?", (now - OUTBOX_MAX_AGE_SECONDS,))
            if self.path != ":memory:":
                # em blocos de 256 páginas (~1 MiB) e no máximo 20 por poda: não segura o lock do banco por segundos. o resto é
                # liberado nas podas seguintes (a cada hora).
                # `executescript`: no Python 3.11 o `execute().fetchall()` libera só 1 página por chamada; o executescript esgota o
                # statement em qualquer versão (conexão em autocommit).
                # `auto_vacuum` só é definido ao criar o banco: banco antigo (NONE) nunca devolve páginas por aqui.
                incremental = self._conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 2
                for _ in range(VACUUM_MAX_CHUNKS if incremental else 0):
                    if self._conn.execute("PRAGMA freelist_count").fetchone()[0] == 0:
                        break
                    self._conn.executescript(f"PRAGMA incremental_vacuum({int(VACUUM_CHUNK_PAGES)})")
                self._conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
        return n


def backup_database(src: str, dest: str, force: bool = False) -> Path:
    """Cópia consistente do banco (API de backup do SQLite: segura com o servidor rodando e com WAL).

    O destino é gravado num arquivo temporário (0600) e só então renomeado; nunca sobrescreve sem `force`."""
    src_path, dest_path = Path(src).expanduser(), Path(dest).expanduser()
    if not src_path.is_file():
        raise FileNotFoundError(f"banco não encontrado: {src_path}")
    if dest_path.exists() and not force:
        raise FileExistsError(f"{dest_path} já existe; use --force para sobrescrever")
    if dest_path.resolve() == src_path.resolve():
        raise ValueError("o destino não pode ser o próprio banco")
    tmp = dest_path.with_name(dest_path.name + ".tmp")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    source: sqlite3.Connection | None = None
    target: sqlite3.Connection | None = None
    try:
        source = sqlite3.connect(f"{src_path.resolve().as_uri()}?mode=ro", uri=True)  # as_uri escapa ?, # e %
        target = sqlite3.connect(tmp)
        source.backup(target)
    except BaseException:
        for conn in (target, source):
            if conn is not None:
                with contextlib.suppress(sqlite3.Error):
                    conn.close()
        tmp.unlink(missing_ok=True)
        raise
    target.close()
    source.close()
    os.replace(tmp, dest_path)
    return dest_path

