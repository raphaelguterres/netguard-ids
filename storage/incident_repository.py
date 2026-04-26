"""Repository abstraction for incidents and timelines."""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from . import event_repository as event_storage

logger = logging.getLogger("netguard.incident_repo")

USE_POSTGRES = event_storage.USE_POSTGRES
DEFAULT_DB = event_storage.DEFAULT_DB
DATABASE_URL = event_storage.DATABASE_URL

if USE_POSTGRES:
    psycopg2 = event_storage.psycopg2
    psycopg2_extras = event_storage.psycopg2.extras
else:  # pragma: no cover - covered via repository calls
    import sqlite3


_DDL_SQLITE = """
CREATE TABLE IF NOT EXISTS incidents (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id    TEXT    NOT NULL DEFAULT 'default',
    title        TEXT    NOT NULL,
    severity     TEXT    NOT NULL DEFAULT 'medium',
    status       TEXT    NOT NULL DEFAULT 'open',
    source       TEXT    NOT NULL DEFAULT 'edr',
    source_ip    TEXT,
    host_id      TEXT,
    event_ids    TEXT    NOT NULL DEFAULT '[]',
    tags         TEXT    NOT NULL DEFAULT '[]',
    summary      TEXT    NOT NULL DEFAULT '',
    opened_at    TEXT    NOT NULL,
    updated_at   TEXT    NOT NULL,
    closed_at    TEXT,
    assigned_to  TEXT,
    mitre_tactic TEXT,
    mitre_tech   TEXT
);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_status
    ON incidents(tenant_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_host
    ON incidents(tenant_id, host_id, updated_at DESC);
CREATE TABLE IF NOT EXISTS incident_timeline (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    tenant_id   TEXT    NOT NULL DEFAULT 'default',
    ts          TEXT    NOT NULL,
    actor       TEXT    NOT NULL DEFAULT 'system',
    action      TEXT    NOT NULL,
    detail      TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_incident_timeline_lookup
    ON incident_timeline(tenant_id, incident_id, id ASC);
"""

_DDL_POSTGRES = """
CREATE TABLE IF NOT EXISTS incidents (
    id           BIGSERIAL PRIMARY KEY,
    tenant_id    TEXT    NOT NULL DEFAULT 'default',
    title        TEXT    NOT NULL,
    severity     TEXT    NOT NULL DEFAULT 'medium',
    status       TEXT    NOT NULL DEFAULT 'open',
    source       TEXT    NOT NULL DEFAULT 'edr',
    source_ip    TEXT,
    host_id      TEXT,
    event_ids    JSONB   NOT NULL DEFAULT '[]'::jsonb,
    tags         JSONB   NOT NULL DEFAULT '[]'::jsonb,
    summary      TEXT    NOT NULL DEFAULT '',
    opened_at    TIMESTAMPTZ NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL,
    closed_at    TIMESTAMPTZ,
    assigned_to  TEXT,
    mitre_tactic TEXT,
    mitre_tech   TEXT
);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_status
    ON incidents(tenant_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_host
    ON incidents(tenant_id, host_id, updated_at DESC);
CREATE TABLE IF NOT EXISTS incident_timeline (
    id          BIGSERIAL PRIMARY KEY,
    incident_id BIGINT NOT NULL,
    tenant_id   TEXT   NOT NULL DEFAULT 'default',
    ts          TIMESTAMPTZ NOT NULL,
    actor       TEXT   NOT NULL DEFAULT 'system',
    action      TEXT   NOT NULL,
    detail      TEXT   NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_incident_timeline_lookup
    ON incident_timeline(tenant_id, incident_id, id ASC);
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class IncidentRepository:
    """Storage backend for incident lifecycle operations."""

    def __init__(self, db_path: str | None = None, tenant_id: str = "default"):
        self.db_path = str(db_path or DEFAULT_DB)
        self.tenant_id = tenant_id
        self._lock = threading.RLock()
        self._local = threading.local()
        self._init_db()

    def _conn(self):
        if USE_POSTGRES:
            if (
                not hasattr(self._local, "pg_conn")
                or self._local.pg_conn is None
                or self._local.pg_conn.closed
            ):
                self._local.pg_conn = psycopg2.connect(
                    DATABASE_URL,
                    cursor_factory=psycopg2_extras.RealDictCursor,
                )
                self._local.pg_conn.autocommit = False
            return self._local.pg_conn

        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
        return self._local.conn

    def _init_db(self) -> None:
        if USE_POSTGRES:
            conn = psycopg2.connect(
                DATABASE_URL,
                cursor_factory=psycopg2_extras.RealDictCursor,
            )
            try:
                with conn.cursor() as cur:
                    cur.execute(_DDL_POSTGRES)
                conn.commit()
            finally:
                conn.close()
            return

        conn = sqlite3.connect(self.db_path)
        try:
            conn.executescript(_DDL_SQLITE)
            conn.commit()
        finally:
            conn.close()

    def _placeholder(self) -> str:
        return "%s" if USE_POSTGRES else "?"

    @staticmethod
    def _decode_json(value: Any, *, default):
        if value in (None, ""):
            return default
        if isinstance(value, (list, dict)):
            return value
        try:
            return json.loads(value)
        except Exception:
            return default

    @staticmethod
    def _encode_json(value: Any, *, default: str) -> str:
        if value in (None, ""):
            return default
        return json.dumps(value)

    def _serialize_incident(self, row: Optional[dict]) -> Optional[dict]:
        if not row:
            return None
        incident = dict(row)
        incident["event_ids"] = self._decode_json(incident.get("event_ids"), default=[])
        incident["tags"] = self._decode_json(incident.get("tags"), default=[])
        incident["age_minutes"] = None
        try:
            opened = str(incident.get("opened_at") or "").replace("Z", "+00:00")
            opened_at = datetime.fromisoformat(opened)
            incident["age_minutes"] = int(
                (datetime.now(timezone.utc) - opened_at).total_seconds() / 60,
            )
        except Exception:
            pass
        return incident

    def create_incident(
        self,
        *,
        title: str,
        severity: str = "medium",
        status: str = "open",
        source: str = "edr",
        source_ip: str | None = None,
        host_id: str | None = None,
        summary: str = "",
        event_ids: list[str] | None = None,
        tags: list[str] | None = None,
        assigned_to: str | None = None,
        mitre_tactic: str | None = None,
        mitre_tech: str | None = None,
        actor: str = "system",
        detail: str = "",
        tenant_id: str | None = None,
    ) -> dict:
        tid = tenant_id or self.tenant_id
        now = _utc_now()
        ph = self._placeholder()
        params = (
            tid,
            title,
            severity,
            status,
            source,
            source_ip,
            host_id,
            self._encode_json(event_ids or [], default="[]"),
            self._encode_json(tags or [], default="[]"),
            summary,
            now,
            now,
            assigned_to,
            mitre_tactic,
            mitre_tech,
        )
        with self._lock:
            if USE_POSTGRES:
                cur = self._conn().cursor()
                cur.execute(
                    f"""
                    INSERT INTO incidents(
                        tenant_id, title, severity, status, source, source_ip, host_id,
                        event_ids, tags, summary, opened_at, updated_at, assigned_to,
                        mitre_tactic, mitre_tech
                    ) VALUES (
                        {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph},
                        {ph}::jsonb, {ph}::jsonb, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}
                    )
                    RETURNING id
                    """,
                    params,
                )
                created = cur.fetchone()
                incident_id = int(created["id"])
                self._insert_timeline(
                    incident_id=incident_id,
                    actor=actor,
                    action="opened",
                    detail=detail or f"Incident created: {title}",
                    tenant_id=tid,
                    cursor=cur,
                )
                self._conn().commit()
                cur.close()
            else:
                cur = self._conn().execute(
                    f"""
                    INSERT INTO incidents(
                        tenant_id, title, severity, status, source, source_ip, host_id,
                        event_ids, tags, summary, opened_at, updated_at, assigned_to,
                        mitre_tactic, mitre_tech
                    ) VALUES (
                        {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph},
                        {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}
                    )
                    """,
                    params,
                )
                incident_id = int(cur.lastrowid)
                self._insert_timeline(
                    incident_id=incident_id,
                    actor=actor,
                    action="opened",
                    detail=detail or f"Incident created: {title}",
                    tenant_id=tid,
                )
                self._conn().commit()
        return self.get_incident(incident_id, tenant_id=tid) or {}

    def update_status(
        self,
        incident_id: int,
        *,
        status: str,
        actor: str = "analyst",
        note: str = "",
        tenant_id: str | None = None,
    ) -> Optional[dict]:
        tid = tenant_id or self.tenant_id
        now = _utc_now()
        closed_at = now if status in {"resolved", "false_positive"} else None
        ph = self._placeholder()
        with self._lock:
            if USE_POSTGRES:
                cur = self._conn().cursor()
                cur.execute(
                    f"""
                    UPDATE incidents
                    SET status={ph}, updated_at={ph},
                        closed_at=COALESCE({ph}, closed_at)
                    WHERE id={ph} AND tenant_id={ph}
                    """,
                    (status, now, closed_at, incident_id, tid),
                )
                self._insert_timeline(
                    incident_id=incident_id,
                    actor=actor,
                    action=f"status->{status}",
                    detail=note,
                    tenant_id=tid,
                    cursor=cur,
                )
                self._conn().commit()
                cur.close()
            else:
                self._conn().execute(
                    f"""
                    UPDATE incidents
                    SET status={ph}, updated_at={ph},
                        closed_at=COALESCE({ph}, closed_at)
                    WHERE id={ph} AND tenant_id={ph}
                    """,
                    (status, now, closed_at, incident_id, tid),
                )
                self._insert_timeline(
                    incident_id=incident_id,
                    actor=actor,
                    action=f"status->{status}",
                    detail=note,
                    tenant_id=tid,
                )
                self._conn().commit()
        return self.get_incident(incident_id, tenant_id=tid)

    def update_severity(
        self,
        incident_id: int,
        *,
        severity: str,
        actor: str = "analyst",
        note: str = "",
        tenant_id: str | None = None,
    ) -> Optional[dict]:
        tid = tenant_id or self.tenant_id
        now = _utc_now()
        ph = self._placeholder()
        detail = note or f"Severity updated to {severity}"
        with self._lock:
            if USE_POSTGRES:
                cur = self._conn().cursor()
                cur.execute(
                    f"""
                    UPDATE incidents
                    SET severity={ph}, updated_at={ph}
                    WHERE id={ph} AND tenant_id={ph}
                    """,
                    (severity, now, incident_id, tid),
                )
                self._insert_timeline(
                    incident_id=incident_id,
                    actor=actor,
                    action=f"severity->{severity}",
                    detail=detail,
                    tenant_id=tid,
                    cursor=cur,
                )
                self._conn().commit()
                cur.close()
            else:
                self._conn().execute(
                    f"""
                    UPDATE incidents
                    SET severity={ph}, updated_at={ph}
                    WHERE id={ph} AND tenant_id={ph}
                    """,
                    (severity, now, incident_id, tid),
                )
                self._insert_timeline(
                    incident_id=incident_id,
                    actor=actor,
                    action=f"severity->{severity}",
                    detail=detail,
                    tenant_id=tid,
                )
                self._conn().commit()
        return self.get_incident(incident_id, tenant_id=tid)

    def assign(
        self,
        incident_id: int,
        *,
        assignee: str,
        actor: str = "analyst",
        tenant_id: str | None = None,
    ) -> Optional[dict]:
        tid = tenant_id or self.tenant_id
        now = _utc_now()
        ph = self._placeholder()
        detail = f"Assigned to: {assignee}"
        with self._lock:
            if USE_POSTGRES:
                cur = self._conn().cursor()
                cur.execute(
                    f"""
                    UPDATE incidents
                    SET assigned_to={ph}, updated_at={ph}
                    WHERE id={ph} AND tenant_id={ph}
                    """,
                    (assignee, now, incident_id, tid),
                )
                self._insert_timeline(
                    incident_id=incident_id,
                    actor=actor,
                    action="assigned",
                    detail=detail,
                    tenant_id=tid,
                    cursor=cur,
                )
                self._conn().commit()
                cur.close()
            else:
                self._conn().execute(
                    f"""
                    UPDATE incidents
                    SET assigned_to={ph}, updated_at={ph}
                    WHERE id={ph} AND tenant_id={ph}
                    """,
                    (assignee, now, incident_id, tid),
                )
                self._insert_timeline(
                    incident_id=incident_id,
                    actor=actor,
                    action="assigned",
                    detail=detail,
                    tenant_id=tid,
                )
                self._conn().commit()
        return self.get_incident(incident_id, tenant_id=tid)

    def add_comment(
        self,
        incident_id: int,
        *,
        comment: str,
        actor: str = "analyst",
        tenant_id: str | None = None,
    ) -> Optional[dict]:
        tid = tenant_id or self.tenant_id
        now = _utc_now()
        ph = self._placeholder()
        with self._lock:
            if USE_POSTGRES:
                cur = self._conn().cursor()
                cur.execute(
                    f"""
                    UPDATE incidents
                    SET updated_at={ph}
                    WHERE id={ph} AND tenant_id={ph}
                    """,
                    (now, incident_id, tid),
                )
                self._insert_timeline(
                    incident_id=incident_id,
                    actor=actor,
                    action="comment",
                    detail=comment,
                    tenant_id=tid,
                    cursor=cur,
                )
                self._conn().commit()
                cur.close()
            else:
                self._conn().execute(
                    f"""
                    UPDATE incidents
                    SET updated_at={ph}
                    WHERE id={ph} AND tenant_id={ph}
                    """,
                    (now, incident_id, tid),
                )
                self._insert_timeline(
                    incident_id=incident_id,
                    actor=actor,
                    action="comment",
                    detail=comment,
                    tenant_id=tid,
                )
                self._conn().commit()
        return self.get_incident(incident_id, tenant_id=tid)

    def get_incident(
        self,
        incident_id: int,
        *,
        tenant_id: str | None = None,
    ) -> Optional[dict]:
        tid = tenant_id or self.tenant_id
        ph = self._placeholder()
        if USE_POSTGRES:
            cur = self._conn().cursor()
            cur.execute(
                f"SELECT * FROM incidents WHERE id={ph} AND tenant_id={ph}",
                (incident_id, tid),
            )
            row = cur.fetchone()
            cur.close()
            return self._serialize_incident(dict(row) if row else None)
        row = self._conn().execute(
            f"SELECT * FROM incidents WHERE id={ph} AND tenant_id={ph}",
            (incident_id, tid),
        ).fetchone()
        return self._serialize_incident(dict(row) if row else None)

    def list_incidents(
        self,
        *,
        tenant_id: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        host_id: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        tid = tenant_id or self.tenant_id
        safe_limit = max(1, min(int(limit), 500))
        ph = self._placeholder()
        sql = f"SELECT * FROM incidents WHERE tenant_id={ph}"
        params: list[Any] = [tid]
        if status:
            sql += f" AND status={ph}"
            params.append(status)
        if severity:
            sql += f" AND severity={ph}"
            params.append(severity)
        if host_id:
            sql += f" AND host_id={ph}"
            params.append(host_id)
        sql += f" ORDER BY updated_at DESC, id DESC LIMIT {ph}"
        params.append(safe_limit)

        if USE_POSTGRES:
            cur = self._conn().cursor()
            cur.execute(sql, params)
            rows = cur.fetchall()
            cur.close()
            return [self._serialize_incident(dict(row)) for row in rows]
        rows = self._conn().execute(sql, params).fetchall()
        return [self._serialize_incident(dict(row)) for row in rows]

    def get_timeline(
        self,
        incident_id: int,
        *,
        tenant_id: str | None = None,
    ) -> list[dict]:
        tid = tenant_id or self.tenant_id
        ph = self._placeholder()
        if USE_POSTGRES:
            cur = self._conn().cursor()
            cur.execute(
                f"""
                SELECT * FROM incident_timeline
                WHERE incident_id={ph} AND tenant_id={ph}
                ORDER BY id ASC
                """,
                (incident_id, tid),
            )
            rows = cur.fetchall()
            cur.close()
            return [dict(row) for row in rows]
        rows = self._conn().execute(
            f"""
            SELECT * FROM incident_timeline
            WHERE incident_id={ph} AND tenant_id={ph}
            ORDER BY id ASC
            """,
            (incident_id, tid),
        ).fetchall()
        return [dict(row) for row in rows]

    def stats(self, *, tenant_id: str | None = None) -> dict:
        tid = tenant_id or self.tenant_id
        ph = self._placeholder()
        if USE_POSTGRES:
            cur = self._conn().cursor()
            cur.execute(
                f"SELECT COUNT(*) AS total FROM incidents WHERE tenant_id={ph}",
                (tid,),
            )
            total = int((cur.fetchone() or {}).get("total", 0))
            cur.execute(
                f"""
                SELECT COUNT(*) AS total
                FROM incidents
                WHERE tenant_id={ph} AND status='open'
                """,
                (tid,),
            )
            open_count = int((cur.fetchone() or {}).get("total", 0))
            cur.execute(
                f"""
                SELECT COUNT(*) AS total
                FROM incidents
                WHERE tenant_id={ph} AND severity='critical'
                  AND status NOT IN ('resolved', 'false_positive')
                """,
                (tid,),
            )
            critical_open = int((cur.fetchone() or {}).get("total", 0))
            cur.execute(
                f"""
                SELECT AVG(EXTRACT(EPOCH FROM (closed_at - opened_at)) / 60.0) AS mttr
                FROM incidents
                WHERE tenant_id={ph} AND closed_at IS NOT NULL
                """,
                (tid,),
            )
            mttr_row = cur.fetchone() or {}
            cur.close()
            mttr = mttr_row.get("mttr")
        else:
            conn = self._conn()
            total = int(
                conn.execute(
                    f"SELECT COUNT(*) FROM incidents WHERE tenant_id={ph}",
                    (tid,),
                ).fetchone()[0],
            )
            open_count = int(
                conn.execute(
                    f"""
                    SELECT COUNT(*) FROM incidents
                    WHERE tenant_id={ph} AND status='open'
                    """,
                    (tid,),
                ).fetchone()[0],
            )
            critical_open = int(
                conn.execute(
                    f"""
                    SELECT COUNT(*) FROM incidents
                    WHERE tenant_id={ph} AND severity='critical'
                      AND status!='resolved' AND status!='false_positive'
                    """,
                    (tid,),
                ).fetchone()[0],
            )
            mttr = conn.execute(
                f"""
                SELECT AVG((julianday(closed_at)-julianday(opened_at))*1440)
                FROM incidents
                WHERE tenant_id={ph} AND closed_at IS NOT NULL
                """,
                (tid,),
            ).fetchone()[0]

        return {
            "total": total,
            "open": open_count,
            "critical_open": critical_open,
            "mttr_minutes": round(mttr, 1) if mttr else None,
        }

    def find_recent_open_incident(
        self,
        *,
        tenant_id: str | None = None,
        host_id: str,
        source: str,
        within_minutes: int = 30,
    ) -> Optional[dict]:
        tid = tenant_id or self.tenant_id
        cutoff = (
            datetime.now(timezone.utc) - timedelta(minutes=max(1, int(within_minutes)))
        ).isoformat().replace("+00:00", "Z")
        ph = self._placeholder()
        if USE_POSTGRES:
            cur = self._conn().cursor()
            cur.execute(
                f"""
                SELECT * FROM incidents
                WHERE tenant_id={ph} AND host_id={ph} AND source={ph}
                  AND status='open' AND opened_at > {ph}
                ORDER BY id DESC LIMIT 1
                """,
                (tid, host_id, source, cutoff),
            )
            row = cur.fetchone()
            cur.close()
            return self._serialize_incident(dict(row) if row else None)
        row = self._conn().execute(
            f"""
            SELECT * FROM incidents
            WHERE tenant_id={ph} AND host_id={ph} AND source={ph}
              AND status='open' AND opened_at > {ph}
            ORDER BY id DESC LIMIT 1
            """,
            (tid, host_id, source, cutoff),
        ).fetchone()
        return self._serialize_incident(dict(row) if row else None)

    def _insert_timeline(
        self,
        *,
        incident_id: int,
        actor: str,
        action: str,
        detail: str,
        tenant_id: str,
        cursor=None,
    ) -> None:
        ph = self._placeholder()
        params = (incident_id, tenant_id, _utc_now(), actor, action, detail or "")
        sql = (
            "INSERT INTO incident_timeline"
            f"(incident_id, tenant_id, ts, actor, action, detail)"
            f" VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph})"
        )
        if USE_POSTGRES and cursor is not None:
            cursor.execute(sql, params)
            return
        self._conn().execute(sql, params)
