"""
PostgreSQL implementation of `Repository` for production / multi-tenant.

Lazy-imports `psycopg` (psycopg3) so the rest of the codebase doesn't
incur a hard dependency. If you're using psycopg2, swap the connect call;
the SQL is portable.

DSN comes from `dsn=` arg or `NETGUARD_PG_DSN` env. Connection pool is a
simple `psycopg_pool.ConnectionPool` if available, falling back to a
single connection per call.

Schema is created idempotently on `init_schema()`. Use `INSERT ... ON
CONFLICT DO NOTHING` for dedup; the primary keys mirror the SQLite
backend so swapping is transparent.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Iterable

from .migrations import MIGRATIONS, SCHEMA_VERSION, expected_migration_map
from .repository import Alert, Event, Host, Repository

logger = logging.getLogger("netguard.storage.postgres")


_SCHEMA_PG = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    checksum    TEXT NOT NULL DEFAULT '',
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS hosts (
    host_id        TEXT PRIMARY KEY,
    hostname       TEXT NOT NULL DEFAULT '',
    platform       TEXT NOT NULL DEFAULT '',
    agent_version  TEXT NOT NULL DEFAULT '',
    last_seen      TIMESTAMPTZ,
    first_seen     TIMESTAMPTZ,
    risk_score     INTEGER NOT NULL DEFAULT 0,
    risk_level     TEXT NOT NULL DEFAULT 'LOW',
    tags           JSONB NOT NULL DEFAULT '[]'::jsonb,
    metadata       JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS events (
    event_id        TEXT PRIMARY KEY,
    host_id         TEXT NOT NULL,
    ts              TIMESTAMPTZ NOT NULL,
    event_type      TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'low',
    confidence      INTEGER NOT NULL DEFAULT 0,
    process_name    TEXT NOT NULL DEFAULT '',
    pid             INTEGER,
    ppid            INTEGER,
    command_line    TEXT NOT NULL DEFAULT '',
    user_name       TEXT NOT NULL DEFAULT '',
    src_ip          TEXT NOT NULL DEFAULT '',
    dst_ip          TEXT NOT NULL DEFAULT '',
    dst_port        INTEGER,
    mitre_tactic    TEXT NOT NULL DEFAULT '',
    mitre_technique TEXT NOT NULL DEFAULT '',
    evidence        TEXT NOT NULL DEFAULT '',
    raw             JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS ix_events_host_ts ON events(host_id, ts DESC);
CREATE INDEX IF NOT EXISTS ix_events_type_ts ON events(event_type, ts DESC);
CREATE INDEX IF NOT EXISTS ix_events_severity ON events(severity, ts DESC);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id        TEXT PRIMARY KEY,
    host_id         TEXT NOT NULL,
    rule_id         TEXT NOT NULL,
    severity        TEXT NOT NULL,
    confidence      INTEGER NOT NULL DEFAULT 0,
    ts              TIMESTAMPTZ NOT NULL,
    title           TEXT NOT NULL DEFAULT '',
    evidence        TEXT NOT NULL DEFAULT '',
    mitre_tactic    TEXT NOT NULL DEFAULT '',
    mitre_technique TEXT NOT NULL DEFAULT '',
    event_ids       JSONB NOT NULL DEFAULT '[]'::jsonb,
    status          TEXT NOT NULL DEFAULT 'open'
);
CREATE INDEX IF NOT EXISTS ix_alerts_host_ts ON alerts(host_id, ts DESC);
CREATE INDEX IF NOT EXISTS ix_alerts_severity ON alerts(severity, ts DESC);
"""


def _import_psycopg():
    try:
        import psycopg  # type: ignore
        return psycopg
    except ImportError as exc:
        raise RuntimeError(
            "PostgresRepository requires psycopg (psycopg3). "
            "Install with: pip install 'psycopg[binary]'"
        ) from exc


class PostgresRepository(Repository):
    def __init__(self, dsn: str | None = None):
        self.dsn = dsn or os.environ.get("NETGUARD_PG_DSN", "")
        if not self.dsn:
            raise ValueError(
                "PostgresRepository requires a DSN. Set NETGUARD_PG_DSN "
                "or pass dsn=... explicitly."
            )
        self._psycopg = _import_psycopg()
        self._pool = self._build_pool()

    def _build_pool(self):
        try:
            from psycopg_pool import ConnectionPool  # type: ignore
            return ConnectionPool(self.dsn, min_size=1, max_size=5,
                                  kwargs={"autocommit": True})
        except ImportError:
            logger.info("psycopg_pool unavailable — using per-call connections")
            return None

    def _conn_ctx(self):
        if self._pool is not None:
            return self._pool.connection()
        return self._psycopg.connect(self.dsn, autocommit=True)

    def init_schema(self) -> None:
        with self._conn_ctx() as conn:
            with conn.cursor() as cur:
                cur.execute(_SCHEMA_PG)
                cur.execute(
                    "ALTER TABLE hosts "
                    "ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb"
                )
                self._record_schema_migrations(cur)

    def _record_schema_migrations(self, cur) -> None:
        cur.execute(
            "ALTER TABLE schema_migrations "
            "ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT ''"
        )
        cur.execute(
            "ALTER TABLE schema_migrations "
            "ADD COLUMN IF NOT EXISTS checksum TEXT NOT NULL DEFAULT ''"
        )
        cur.executemany(
            """
            INSERT INTO schema_migrations (version, name, description, checksum)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (version) DO NOTHING
            """,
            [
                (
                    item["version"],
                    item["name"],
                    item.get("description", ""),
                    item.get("checksum", ""),
                )
                for item in MIGRATIONS
            ],
        )
        cur.executemany(
            """
            UPDATE schema_migrations
            SET name = %s, description = %s, checksum = %s
            WHERE version = %s
            """,
            [
                (
                    item["name"],
                    item.get("description", ""),
                    item.get("checksum", ""),
                    item["version"],
                )
                for item in MIGRATIONS
            ],
        )

    def schema_version(self) -> int:
        with self._conn_ctx() as conn:
            with conn.cursor() as cur:
                try:
                    cur.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations")
                    row = cur.fetchone()
                except Exception:
                    return 0
        return int(row[0] or 0) if row else 0

    def migration_history(self) -> list[dict]:
        with self._conn_ctx() as conn:
            with conn.cursor() as cur:
                try:
                    cur.execute(
                        """
                        SELECT version, name, description, checksum, applied_at
                        FROM schema_migrations
                        ORDER BY version ASC
                        """,
                    )
                    rows = cur.fetchall()
                    cols = [d.name for d in (cur.description or [])]
                except Exception:
                    return []
        return [dict(zip(cols, row)) for row in rows]

    def migration_status(self) -> dict:
        history = self.migration_history()
        expected = expected_migration_map()
        applied = {int(item["version"]): item for item in history}
        pending = [
            expected_item
            for version, expected_item in expected.items()
            if version not in applied
        ]
        mismatched = [
            {
                "version": version,
                "name": row.get("name", ""),
                "expected_checksum": expected[version].get("checksum", ""),
                "actual_checksum": row.get("checksum", ""),
            }
            for version, row in applied.items()
            if version in expected
            and row.get("checksum")
            and row.get("checksum") != expected[version].get("checksum")
        ]
        unknown = [
            row for version, row in applied.items()
            if version not in expected
        ]
        current = self.schema_version()
        return {
            "ok": current == SCHEMA_VERSION and not pending and not mismatched and not unknown,
            "schema_version": current,
            "latest_version": SCHEMA_VERSION,
            "pending": pending,
            "mismatched": mismatched,
            "unknown": unknown,
            "history": history,
        }

    def close(self) -> None:
        if self._pool is not None:
            self._pool.close()

    # ── hosts ──

    def upsert_host(self, host: Host) -> None:
        sql = """
            INSERT INTO hosts (host_id, hostname, platform, agent_version,
                               last_seen, first_seen, risk_score, risk_level, tags, metadata)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb)
            ON CONFLICT (host_id) DO UPDATE SET
                hostname      = EXCLUDED.hostname,
                platform      = EXCLUDED.platform,
                agent_version = EXCLUDED.agent_version,
                last_seen     = EXCLUDED.last_seen,
                tags          = EXCLUDED.tags,
                metadata      = EXCLUDED.metadata
        """
        params = (
            host.host_id, host.hostname, host.platform, host.agent_version,
            host.last_seen or None, host.first_seen or host.last_seen or None,
            int(host.risk_score), host.risk_level, json.dumps(host.tags),
            json.dumps(dict(host.metadata or {}), default=str),
        )
        with self._conn_ctx() as conn, conn.cursor() as cur:
            cur.execute(sql, params)

    def get_host(self, host_id: str) -> Host | None:
        sql = "SELECT * FROM hosts WHERE host_id = %s"
        with self._conn_ctx() as conn, conn.cursor() as cur:
            cur.execute(sql, (host_id,))
            row = cur.fetchone()
            cols = [d.name for d in (cur.description or [])]
        return _row_to_host(dict(zip(cols, row))) if row else None

    def list_hosts(self, *, limit: int = 200) -> list[Host]:
        sql = "SELECT * FROM hosts ORDER BY last_seen DESC NULLS LAST LIMIT %s"
        with self._conn_ctx() as conn, conn.cursor() as cur:
            cur.execute(sql, (int(limit),))
            rows = cur.fetchall()
            cols = [d.name for d in (cur.description or [])]
        return [_row_to_host(dict(zip(cols, r))) for r in rows]

    def update_host_risk(self, host_id: str, score: int, level: str) -> None:
        with self._conn_ctx() as conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE hosts SET risk_score = %s, risk_level = %s WHERE host_id = %s",
                (max(0, min(100, int(score))), level, host_id),
            )

    def touch_host_seen(self, host_id: str, when_iso: str) -> None:
        sql = """
            INSERT INTO hosts (host_id, last_seen, first_seen)
            VALUES (%s, %s, %s)
            ON CONFLICT (host_id) DO UPDATE SET last_seen = EXCLUDED.last_seen
        """
        with self._conn_ctx() as conn, conn.cursor() as cur:
            cur.execute(sql, (host_id, when_iso, when_iso))

    # ── events ──

    def insert_event(self, event: Event) -> bool:
        with self._conn_ctx() as conn, conn.cursor() as cur:
            cur.execute(_INSERT_EVENT_SQL_PG, _event_params(event))
            return (cur.rowcount or 0) > 0

    def insert_events(self, events: Iterable[Event]) -> int:
        rows = [_event_params(e) for e in events]
        if not rows:
            return 0
        with self._conn_ctx() as conn, conn.cursor() as cur:
            cur.executemany(_INSERT_EVENT_SQL_PG, rows)
            return cur.rowcount or len(rows)

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
            clauses.append("host_id = %s")
            params.append(host_id)
        if event_type:
            clauses.append("event_type = %s")
            params.append(event_type)
        if since_iso:
            clauses.append("ts >= %s")
            params.append(since_iso)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM events {where} ORDER BY ts DESC LIMIT %s"
        params.append(int(limit))
        with self._conn_ctx() as conn, conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
            cols = [d.name for d in (cur.description or [])]
        return [_row_to_event(dict(zip(cols, r))) for r in rows]

    # ── alerts ──

    def insert_alert(self, alert: Alert) -> bool:
        sql = """
            INSERT INTO alerts (
                alert_id, host_id, rule_id, severity, confidence, ts,
                title, evidence, mitre_tactic, mitre_technique,
                event_ids, status
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
            ON CONFLICT (alert_id) DO NOTHING
        """
        params = (
            alert.alert_id, alert.host_id, alert.rule_id, alert.severity,
            int(alert.confidence), alert.timestamp, alert.title, alert.evidence,
            alert.mitre_tactic, alert.mitre_technique,
            json.dumps(list(alert.event_ids)), alert.status,
        )
        with self._conn_ctx() as conn, conn.cursor() as cur:
            cur.execute(sql, params)
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
            clauses.append("host_id = %s")
            params.append(host_id)
        if since_iso:
            clauses.append("ts >= %s")
            params.append(since_iso)
        if status:
            clauses.append("status = %s")
            params.append(status)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM alerts {where} ORDER BY ts DESC LIMIT %s"
        params.append(int(limit))
        with self._conn_ctx() as conn, conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
            cols = [d.name for d in (cur.description or [])]
        return [_row_to_alert(dict(zip(cols, r))) for r in rows]

    def update_alert_status(self, alert_id: str, status: str) -> None:
        if status not in {"open", "acknowledged", "closed"}:
            raise ValueError(f"invalid alert status: {status!r}")
        with self._conn_ctx() as conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE alerts SET status = %s WHERE alert_id = %s",
                (status, alert_id),
            )

    # ── aggregates ──

    def alert_counts_by_severity(
        self, *, since_iso: str | None = None,
    ) -> dict[str, int]:
        sql = "SELECT severity, COUNT(*) FROM alerts"
        params: list = []
        if since_iso:
            sql += " WHERE ts >= %s"
            params.append(since_iso)
        sql += " GROUP BY severity"
        with self._conn_ctx() as conn, conn.cursor() as cur:
            cur.execute(sql, params)
            return {sev: int(c) for sev, c in cur.fetchall()}

    def top_mitre_techniques(
        self, *, since_iso: str | None = None, limit: int = 10,
    ) -> list[tuple[str, int]]:
        sql = (
            "SELECT mitre_technique, COUNT(*) FROM alerts "
            "WHERE mitre_technique <> ''"
        )
        params: list = []
        if since_iso:
            sql += " AND ts >= %s"
            params.append(since_iso)
        sql += " GROUP BY mitre_technique ORDER BY 2 DESC LIMIT %s"
        params.append(int(limit))
        with self._conn_ctx() as conn, conn.cursor() as cur:
            cur.execute(sql, params)
            return [(t, int(c)) for t, c in cur.fetchall()]


# ── helpers ───────────────────────────────────────────────────────────


_INSERT_EVENT_SQL_PG = """
INSERT INTO events (
    event_id, host_id, ts, event_type, severity, confidence,
    process_name, pid, ppid, command_line, user_name,
    src_ip, dst_ip, dst_port, mitre_tactic, mitre_technique,
    evidence, raw
) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
ON CONFLICT (event_id) DO NOTHING
"""


def _event_params(e: Event) -> tuple:
    return (
        e.event_id, e.host_id, e.timestamp, e.event_type, e.severity,
        int(e.confidence or 0),
        e.process_name, e.pid, e.ppid, (e.command_line or "")[:4096],
        e.user, e.src_ip, e.dst_ip, e.dst_port,
        e.mitre_tactic, e.mitre_technique, e.evidence,
        json.dumps(e.raw or {}, default=str),
    )


def _row_to_host(row: dict) -> Host:
    tags = row.get("tags") or []
    if isinstance(tags, str):
        try:
            tags = json.loads(tags)
        except json.JSONDecodeError:
            tags = []
    metadata = row.get("metadata") or {}
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except json.JSONDecodeError:
            metadata = {}
    return Host(
        host_id=row["host_id"],
        hostname=row.get("hostname") or "",
        platform=row.get("platform") or "",
        agent_version=row.get("agent_version") or "",
        last_seen=str(row.get("last_seen") or ""),
        first_seen=str(row.get("first_seen") or ""),
        risk_score=int(row.get("risk_score") or 0),
        risk_level=row.get("risk_level") or "LOW",
        tags=list(tags) if isinstance(tags, list) else [],
        metadata=dict(metadata) if isinstance(metadata, dict) else {},
    )


def _row_to_event(row: dict) -> Event:
    raw = row.get("raw") or {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            raw = {}
    return Event(
        event_id=row["event_id"],
        host_id=row["host_id"],
        timestamp=str(row.get("ts") or ""),
        event_type=row["event_type"],
        severity=row.get("severity") or "low",
        confidence=int(row.get("confidence") or 0),
        process_name=row.get("process_name") or "",
        pid=row.get("pid"),
        ppid=row.get("ppid"),
        command_line=row.get("command_line") or "",
        user=row.get("user_name") or "",
        src_ip=row.get("src_ip") or "",
        dst_ip=row.get("dst_ip") or "",
        dst_port=row.get("dst_port"),
        mitre_tactic=row.get("mitre_tactic") or "",
        mitre_technique=row.get("mitre_technique") or "",
        evidence=row.get("evidence") or "",
        raw=raw if isinstance(raw, dict) else {},
    )


def _row_to_alert(row: dict) -> Alert:
    eids = row.get("event_ids") or []
    if isinstance(eids, str):
        try:
            eids = json.loads(eids)
        except json.JSONDecodeError:
            eids = []
    return Alert(
        alert_id=row["alert_id"],
        host_id=row["host_id"],
        rule_id=row["rule_id"],
        severity=row["severity"],
        confidence=int(row.get("confidence") or 0),
        timestamp=str(row.get("ts") or ""),
        title=row.get("title") or "",
        evidence=row.get("evidence") or "",
        mitre_tactic=row.get("mitre_tactic") or "",
        mitre_technique=row.get("mitre_technique") or "",
        event_ids=list(eids) if isinstance(eids, list) else [],
        status=row.get("status") or "open",
    )
