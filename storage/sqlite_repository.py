"""
SQLite implementation of the NetGuard `Repository` interface.

Notes:

- Single-file DB, default path follows OS conventions
  (`%ProgramData%\\NetGuard\\edr.db` on Windows,
  `/var/lib/netguard/edr.db` on Linux). Caller can override via
  `db_path=...` or env `NETGUARD_EDR_DB`.

- WAL mode enabled — readers don't block writers. The detection engine
  often inserts while the dashboard is paginating; without WAL we'd
  see SQLite locked errors.

- One connection per call (sqlite3 default). Sufficient for thousands
  of events/sec; if we ever need more, switch to a connection pool.

- Dedup on `event_id` via UNIQUE constraint. `INSERT OR IGNORE`
  returns rowcount=0 for duplicates, which we surface as `False` from
  `insert_event`.

- Times stored as ISO-8601 strings (Z-suffix). Saves a CAST/strftime
  on every read; range queries use lexical comparison, which works
  for fixed-width ISO timestamps.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import sys
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .migrations import MIGRATIONS
from .repository import Alert, Event, Host, Repository

logger = logging.getLogger("netguard.storage.sqlite")


# ── schema ────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    applied_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
    host_id        TEXT PRIMARY KEY,
    hostname       TEXT NOT NULL DEFAULT '',
    platform       TEXT NOT NULL DEFAULT '',
    agent_version  TEXT NOT NULL DEFAULT '',
    last_seen      TEXT NOT NULL DEFAULT '',
    first_seen     TEXT NOT NULL DEFAULT '',
    risk_score     INTEGER NOT NULL DEFAULT 0,
    risk_level     TEXT NOT NULL DEFAULT 'LOW',
    tags_json      TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS events (
    event_id        TEXT PRIMARY KEY,
    host_id         TEXT NOT NULL,
    timestamp       TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'low',
    confidence      INTEGER NOT NULL DEFAULT 0,
    process_name    TEXT NOT NULL DEFAULT '',
    pid             INTEGER,
    ppid            INTEGER,
    command_line    TEXT NOT NULL DEFAULT '',
    user            TEXT NOT NULL DEFAULT '',
    src_ip          TEXT NOT NULL DEFAULT '',
    dst_ip          TEXT NOT NULL DEFAULT '',
    dst_port        INTEGER,
    mitre_tactic    TEXT NOT NULL DEFAULT '',
    mitre_technique TEXT NOT NULL DEFAULT '',
    evidence        TEXT NOT NULL DEFAULT '',
    raw_json        TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_events_host_ts ON events(host_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS ix_events_type_ts ON events(event_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS ix_events_severity ON events(severity, timestamp DESC);
CREATE INDEX IF NOT EXISTS ix_events_mitre    ON events(mitre_technique, timestamp DESC);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id        TEXT PRIMARY KEY,
    host_id         TEXT NOT NULL,
    rule_id         TEXT NOT NULL,
    severity        TEXT NOT NULL,
    confidence      INTEGER NOT NULL DEFAULT 0,
    timestamp       TEXT NOT NULL,
    title           TEXT NOT NULL DEFAULT '',
    evidence        TEXT NOT NULL DEFAULT '',
    mitre_tactic    TEXT NOT NULL DEFAULT '',
    mitre_technique TEXT NOT NULL DEFAULT '',
    event_ids_json  TEXT NOT NULL DEFAULT '[]',
    status          TEXT NOT NULL DEFAULT 'open'
);
CREATE INDEX IF NOT EXISTS ix_alerts_host_ts ON alerts(host_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS ix_alerts_severity ON alerts(severity, timestamp DESC);
CREATE INDEX IF NOT EXISTS ix_alerts_status ON alerts(status, timestamp DESC);
"""


def _default_db_path() -> Path:
    override = os.environ.get("NETGUARD_EDR_DB")
    if override:
        return Path(override)
    if sys.platform.startswith("win"):
        return Path(r"C:\ProgramData\NetGuard\edr.db")
    return Path("/var/lib/netguard/edr.db")


# ── implementation ────────────────────────────────────────────────────


class SqliteRepository(Repository):
    def __init__(self, db_path: str | Path | None = None):
        self.db_path = Path(db_path) if db_path else _default_db_path()
        self._lock = threading.RLock()
        self._initialized = False

    # ── connection management ──

    @contextmanager
    def _conn(self):
        # Per-call connection. SQLite allows it and we don't need a pool
        # at this scale; the lock guards write contention.
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=10.0,
            isolation_level=None,  # autocommit; explicit BEGIN/COMMIT for batches
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        try:
            # WAL + sane defaults. Run on every conn; cheap if already set.
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            yield conn
        finally:
            conn.close()

    def init_schema(self) -> None:
        with self._lock, self._conn() as conn:
            conn.executescript(_SCHEMA)
            self._record_schema_migrations(conn)
        self._initialized = True

    def _record_schema_migrations(self, conn) -> None:
        applied_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        conn.executemany(
            """
            INSERT OR IGNORE INTO schema_migrations (version, name, applied_at)
            VALUES (?, ?, ?)
            """,
            [(item["version"], item["name"], applied_at) for item in MIGRATIONS],
        )

    def schema_version(self) -> int:
        with self._conn() as conn:
            try:
                row = conn.execute(
                    "SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations",
                ).fetchone()
            except sqlite3.OperationalError:
                return 0
        return int(row["version"] or 0) if row else 0

    def migration_history(self) -> list[dict]:
        with self._conn() as conn:
            try:
                rows = conn.execute(
                    """
                    SELECT version, name, applied_at
                    FROM schema_migrations
                    ORDER BY version ASC
                    """,
                ).fetchall()
            except sqlite3.OperationalError:
                return []
        return [dict(row) for row in rows]

    def close(self) -> None:
        # Per-call connections — nothing pooled. No-op kept for ABC compliance.
        return

    # ── hosts ──

    def upsert_host(self, host: Host) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO hosts (host_id, hostname, platform, agent_version,
                                   last_seen, first_seen, risk_score, risk_level,
                                   tags_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(host_id) DO UPDATE SET
                    hostname      = excluded.hostname,
                    platform      = excluded.platform,
                    agent_version = excluded.agent_version,
                    last_seen     = excluded.last_seen,
                    tags_json     = excluded.tags_json
                """,
                (
                    host.host_id, host.hostname, host.platform,
                    host.agent_version, host.last_seen,
                    host.first_seen or host.last_seen,
                    int(host.risk_score), host.risk_level,
                    json.dumps(list(host.tags)),
                ),
            )

    def get_host(self, host_id: str) -> Host | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM hosts WHERE host_id = ?", (host_id,),
            ).fetchone()
        return _row_to_host(row) if row else None

    def list_hosts(self, *, limit: int = 200) -> list[Host]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM hosts ORDER BY last_seen DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        return [_row_to_host(r) for r in rows]

    def update_host_risk(self, host_id: str, score: int, level: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE hosts SET risk_score = ?, risk_level = ? WHERE host_id = ?",
                (max(0, min(100, int(score))), level, host_id),
            )

    def touch_host_seen(self, host_id: str, when_iso: str) -> None:
        with self._lock, self._conn() as conn:
            # Ensure the row exists — agents can post events for a host
            # the dashboard hasn't enrolled yet.
            conn.execute(
                """
                INSERT INTO hosts (host_id, last_seen, first_seen)
                VALUES (?, ?, ?)
                ON CONFLICT(host_id) DO UPDATE SET last_seen = excluded.last_seen
                """,
                (host_id, when_iso, when_iso),
            )

    # ── events ──

    def insert_event(self, event: Event) -> bool:
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                _INSERT_EVENT_SQL,
                _event_row(event),
            )
            return (cur.rowcount or 0) > 0

    def insert_events(self, events: Iterable[Event]) -> int:
        rows = [_event_row(e) for e in events]
        if not rows:
            return 0
        with self._lock, self._conn() as conn:
            conn.execute("BEGIN")
            try:
                cur = conn.executemany(_INSERT_EVENT_SQL, rows)
                conn.execute("COMMIT")
                # executemany doesn't reliably report rowcount across
                # SQLite versions; trust caller-side dedup or query back.
                return cur.rowcount if cur.rowcount and cur.rowcount > 0 else len(rows)
            except Exception:
                conn.execute("ROLLBACK")
                raise

    def list_events(
        self,
        *,
        host_id: str | None = None,
        event_type: str | None = None,
        since_iso: str | None = None,
        limit: int = 500,
    ) -> list[Event]:
        clauses = []
        params: list = []
        if host_id:
            clauses.append("host_id = ?")
            params.append(host_id)
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if since_iso:
            clauses.append("timestamp >= ?")
            params.append(since_iso)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM events {where} ORDER BY timestamp DESC LIMIT ?"
        params.append(int(limit))
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [_row_to_event(r) for r in rows]

    # ── alerts ──

    def insert_alert(self, alert: Alert) -> bool:
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO alerts (
                    alert_id, host_id, rule_id, severity, confidence,
                    timestamp, title, evidence, mitre_tactic, mitre_technique,
                    event_ids_json, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_id, alert.host_id, alert.rule_id,
                    alert.severity, int(alert.confidence), alert.timestamp,
                    alert.title, alert.evidence,
                    alert.mitre_tactic, alert.mitre_technique,
                    json.dumps(list(alert.event_ids)),
                    alert.status,
                ),
            )
            return (cur.rowcount or 0) > 0

    def list_alerts(
        self,
        *,
        host_id: str | None = None,
        since_iso: str | None = None,
        status: str | None = None,
        limit: int = 200,
    ) -> list[Alert]:
        clauses = []
        params: list = []
        if host_id:
            clauses.append("host_id = ?")
            params.append(host_id)
        if since_iso:
            clauses.append("timestamp >= ?")
            params.append(since_iso)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM alerts {where} ORDER BY timestamp DESC LIMIT ?"
        params.append(int(limit))
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [_row_to_alert(r) for r in rows]

    def update_alert_status(self, alert_id: str, status: str) -> None:
        if status not in {"open", "acknowledged", "closed"}:
            raise ValueError(f"invalid alert status: {status!r}")
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE alerts SET status = ? WHERE alert_id = ?",
                (status, alert_id),
            )

    # ── aggregates ──

    def alert_counts_by_severity(
        self, *, since_iso: str | None = None,
    ) -> dict[str, int]:
        sql = "SELECT severity, COUNT(*) AS c FROM alerts"
        params: list = []
        if since_iso:
            sql += " WHERE timestamp >= ?"
            params.append(since_iso)
        sql += " GROUP BY severity"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return {r["severity"]: int(r["c"]) for r in rows}

    def top_mitre_techniques(
        self, *, since_iso: str | None = None, limit: int = 10,
    ) -> list[tuple[str, int]]:
        sql = (
            "SELECT mitre_technique, COUNT(*) AS c FROM alerts "
            "WHERE mitre_technique <> ''"
        )
        params: list = []
        if since_iso:
            sql += " AND timestamp >= ?"
            params.append(since_iso)
        sql += " GROUP BY mitre_technique ORDER BY c DESC LIMIT ?"
        params.append(int(limit))
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [(r["mitre_technique"], int(r["c"])) for r in rows]


# ── row-mapping helpers ───────────────────────────────────────────────


_INSERT_EVENT_SQL = """
INSERT OR IGNORE INTO events (
    event_id, host_id, timestamp, event_type, severity, confidence,
    process_name, pid, ppid, command_line, user,
    src_ip, dst_ip, dst_port, mitre_tactic, mitre_technique,
    evidence, raw_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def _event_row(e: Event) -> tuple:
    return (
        e.event_id, e.host_id, e.timestamp, e.event_type, e.severity,
        int(e.confidence or 0),
        e.process_name, e.pid, e.ppid, (e.command_line or "")[:4096],
        e.user, e.src_ip, e.dst_ip, e.dst_port,
        e.mitre_tactic, e.mitre_technique, e.evidence,
        json.dumps(e.raw or {}, default=str),
    )


def _row_to_host(row: sqlite3.Row) -> Host:
    return Host(
        host_id=row["host_id"],
        hostname=row["hostname"] or "",
        platform=row["platform"] or "",
        agent_version=row["agent_version"] or "",
        last_seen=row["last_seen"] or "",
        first_seen=row["first_seen"] or "",
        risk_score=int(row["risk_score"] or 0),
        risk_level=row["risk_level"] or "LOW",
        tags=_safe_load_list(row["tags_json"]),
    )


def _row_to_event(row: sqlite3.Row) -> Event:
    return Event(
        event_id=row["event_id"],
        host_id=row["host_id"],
        timestamp=row["timestamp"],
        event_type=row["event_type"],
        severity=row["severity"] or "low",
        confidence=int(row["confidence"] or 0),
        process_name=row["process_name"] or "",
        pid=row["pid"],
        ppid=row["ppid"],
        command_line=row["command_line"] or "",
        user=row["user"] or "",
        src_ip=row["src_ip"] or "",
        dst_ip=row["dst_ip"] or "",
        dst_port=row["dst_port"],
        mitre_tactic=row["mitre_tactic"] or "",
        mitre_technique=row["mitre_technique"] or "",
        evidence=row["evidence"] or "",
        raw=_safe_load_dict(row["raw_json"]),
    )


def _row_to_alert(row: sqlite3.Row) -> Alert:
    return Alert(
        alert_id=row["alert_id"],
        host_id=row["host_id"],
        rule_id=row["rule_id"],
        severity=row["severity"],
        confidence=int(row["confidence"] or 0),
        timestamp=row["timestamp"],
        title=row["title"] or "",
        evidence=row["evidence"] or "",
        mitre_tactic=row["mitre_tactic"] or "",
        mitre_technique=row["mitre_technique"] or "",
        event_ids=_safe_load_list(row["event_ids_json"]),
        status=row["status"] or "open",
    )


def _safe_load_list(text: str | None) -> list:
    if not text:
        return []
    try:
        v = json.loads(text)
        return list(v) if isinstance(v, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


def _safe_load_dict(text: str | None) -> dict:
    if not text:
        return {}
    try:
        v = json.loads(text)
        return v if isinstance(v, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}
