"""Persistent server-to-agent response action queue."""

from __future__ import annotations

import json
import logging
import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from . import event_repository as event_storage

logger = logging.getLogger("netguard.agent_actions")

USE_POSTGRES = event_storage.USE_POSTGRES
DEFAULT_DB = event_storage.DEFAULT_DB
DATABASE_URL = event_storage.DATABASE_URL

if USE_POSTGRES:
    psycopg2 = event_storage.psycopg2
    psycopg2_extras = event_storage.psycopg2.extras
else:  # pragma: no cover - exercised through repository methods
    import sqlite3


TERMINAL_STATUSES = {"succeeded", "failed", "refused", "expired", "cancelled"}
ACTIVE_STATUSES = {"pending", "leased", "running"}

_DDL_SQLITE = """
CREATE TABLE IF NOT EXISTS agent_actions (
    action_id    TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL DEFAULT 'default',
    host_id      TEXT NOT NULL,
    action_type  TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    requested_by TEXT NOT NULL DEFAULT '',
    reason       TEXT NOT NULL DEFAULT '',
    payload      TEXT NOT NULL DEFAULT '{}',
    result       TEXT NOT NULL DEFAULT '{}',
    attempts     INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    lease_until  TEXT,
    expires_at   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_agent_actions_host_status
    ON agent_actions(tenant_id, host_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_agent_actions_expires
    ON agent_actions(status, expires_at);
"""

_DDL_POSTGRES = """
CREATE TABLE IF NOT EXISTS agent_actions (
    action_id    TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL DEFAULT 'default',
    host_id      TEXT NOT NULL,
    action_type  TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    requested_by TEXT NOT NULL DEFAULT '',
    reason       TEXT NOT NULL DEFAULT '',
    payload      JSONB NOT NULL DEFAULT '{}'::jsonb,
    result       JSONB NOT NULL DEFAULT '{}'::jsonb,
    attempts     INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    lease_until  TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_agent_actions_host_status
    ON agent_actions(tenant_id, host_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_agent_actions_expires
    ON agent_actions(status, expires_at);
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _utc_plus(seconds: int) -> str:
    return (
        datetime.now(timezone.utc) + timedelta(seconds=max(1, int(seconds)))
    ).isoformat().replace("+00:00", "Z")


def _parse_ts(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        value = str(raw).strip()
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def generate_action_id() -> str:
    return "act_" + secrets.token_urlsafe(18)


class AgentActionRepository:
    """Queue for response actions delivered to endpoint agents."""

    def __init__(self, db_path: str | None = None):
        self.db_path = str(db_path or DEFAULT_DB)
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
    def _json_dump(value: Any, *, default: str = "{}") -> str:
        if value in (None, ""):
            return default
        return json.dumps(value)

    @staticmethod
    def _json_load(value: Any, *, default):
        if value in (None, ""):
            return default
        if isinstance(value, (dict, list)):
            return value
        try:
            return json.loads(value)
        except Exception:
            return default

    def _serialize(self, row: Optional[dict]) -> Optional[dict]:
        if not row:
            return None
        action = dict(row)
        action["payload"] = self._json_load(action.get("payload"), default={})
        action["result"] = self._json_load(action.get("result"), default={})
        action["expired"] = bool(
            _parse_ts(action.get("expires_at"))
            and _parse_ts(action.get("expires_at")) <= datetime.now(timezone.utc)
        )
        return action

    def _refresh_expired_locked(self) -> None:
        ph = self._placeholder()
        now = _utc_now()
        if USE_POSTGRES:
            cur = self._conn().cursor()
            cur.execute(
                f"""
                UPDATE agent_actions
                SET status='pending', lease_until=NULL, updated_at={ph}
                WHERE status='leased' AND lease_until IS NOT NULL AND lease_until <= {ph}
                """,
                (now, now),
            )
            cur.execute(
                f"""
                UPDATE agent_actions
                SET status='expired', completed_at={ph}, updated_at={ph}
                WHERE status IN ('pending', 'leased') AND expires_at <= {ph}
                """,
                (now, now, now),
            )
            cur.close()
            return
        self._conn().execute(
            f"""
            UPDATE agent_actions
            SET status='pending', lease_until=NULL, updated_at={ph}
            WHERE status='leased' AND lease_until IS NOT NULL AND lease_until <= {ph}
            """,
            (now, now),
        )
        self._conn().execute(
            f"""
            UPDATE agent_actions
            SET status='expired', completed_at={ph}, updated_at={ph}
            WHERE status IN ('pending', 'leased') AND expires_at <= {ph}
            """,
            (now, now, now),
        )

    def create_action(
        self,
        *,
        tenant_id: str,
        host_id: str,
        action_type: str,
        payload: dict[str, Any] | None = None,
        requested_by: str = "",
        reason: str = "",
        ttl_seconds: int = 3600,
        max_attempts: int = 3,
    ) -> dict:
        action_id = generate_action_id()
        now = _utc_now()
        ph = self._placeholder()
        params = (
            action_id,
            tenant_id or "default",
            host_id,
            action_type,
            "pending",
            requested_by or "",
            reason or "",
            self._json_dump(payload or {}),
            "{}",
            0,
            max(1, min(int(max_attempts or 3), 10)),
            None,
            _utc_plus(min(max(int(ttl_seconds or 3600), 60), 24 * 3600)),
            now,
            now,
            None,
        )
        with self._lock:
            if USE_POSTGRES:
                cur = self._conn().cursor()
                cur.execute(
                    f"""
                    INSERT INTO agent_actions (
                        action_id, tenant_id, host_id, action_type, status,
                        requested_by, reason, payload, result, attempts,
                        max_attempts, lease_until, expires_at, created_at,
                        updated_at, completed_at
                    ) VALUES (
                        {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph},
                        {ph}::jsonb, {ph}::jsonb, {ph}, {ph}, {ph},
                        {ph}, {ph}, {ph}, {ph}
                    )
                    """,
                    params,
                )
                self._conn().commit()
                cur.close()
            else:
                self._conn().execute(
                    f"""
                    INSERT INTO agent_actions (
                        action_id, tenant_id, host_id, action_type, status,
                        requested_by, reason, payload, result, attempts,
                        max_attempts, lease_until, expires_at, created_at,
                        updated_at, completed_at
                    ) VALUES (
                        {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph},
                        {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}
                    )
                    """,
                    params,
                )
                self._conn().commit()
        return self.get_action(action_id, tenant_id=tenant_id) or {}

    def get_action(self, action_id: str, *, tenant_id: str | None = None) -> Optional[dict]:
        if not action_id:
            return None
        ph = self._placeholder()
        params: tuple[Any, ...]
        where = f"action_id={ph}"
        params = (action_id,)
        if tenant_id:
            where += f" AND tenant_id={ph}"
            params = (action_id, tenant_id)
        if USE_POSTGRES:
            cur = self._conn().cursor()
            cur.execute(f"SELECT * FROM agent_actions WHERE {where} LIMIT 1", params)
            row = cur.fetchone()
            cur.close()
            return self._serialize(dict(row) if row else None)
        row = self._conn().execute(
            f"SELECT * FROM agent_actions WHERE {where} LIMIT 1",
            params,
        ).fetchone()
        return self._serialize(dict(row) if row else None)

    def list_actions(
        self,
        *,
        tenant_id: str,
        host_id: str | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        ph = self._placeholder()
        clauses = [f"tenant_id={ph}"]
        params: list[Any] = [tenant_id]
        if host_id:
            clauses.append(f"host_id={ph}")
            params.append(host_id)
        if status:
            clauses.append(f"status={ph}")
            params.append(status)
        params.append(max(1, min(int(limit), 500)))
        where = " AND ".join(clauses)
        if USE_POSTGRES:
            cur = self._conn().cursor()
            cur.execute(
                f"""
                SELECT * FROM agent_actions
                WHERE {where}
                ORDER BY created_at DESC
                LIMIT {ph}
                """,
                tuple(params),
            )
            rows = cur.fetchall()
            cur.close()
            return [self._serialize(dict(row)) for row in rows]
        rows = self._conn().execute(
            f"""
            SELECT * FROM agent_actions
            WHERE {where}
            ORDER BY created_at DESC
            LIMIT {ph}
            """,
            tuple(params),
        ).fetchall()
        return [self._serialize(dict(row)) for row in rows]

    def lease_actions(
        self,
        *,
        tenant_id: str,
        host_id: str,
        limit: int = 10,
        lease_seconds: int = 120,
    ) -> list[dict]:
        ph = self._placeholder()
        now = _utc_now()
        lease_until = _utc_plus(min(max(int(lease_seconds or 120), 30), 600))
        safe_limit = max(1, min(int(limit), 50))
        leased_ids: list[str] = []
        with self._lock:
            self._refresh_expired_locked()
            if USE_POSTGRES:
                cur = self._conn().cursor()
                cur.execute(
                    f"""
                    SELECT action_id FROM agent_actions
                    WHERE tenant_id={ph} AND host_id={ph} AND status='pending'
                      AND attempts < max_attempts
                    ORDER BY created_at ASC
                    LIMIT {ph}
                    FOR UPDATE SKIP LOCKED
                    """,
                    (tenant_id, host_id, safe_limit),
                )
                leased_ids = [str(row["action_id"]) for row in cur.fetchall()]
                for action_id in leased_ids:
                    cur.execute(
                        f"""
                        UPDATE agent_actions
                        SET status='leased', attempts=attempts+1,
                            lease_until={ph}, updated_at={ph}
                        WHERE action_id={ph}
                        """,
                        (lease_until, now, action_id),
                    )
                self._conn().commit()
                cur.close()
            else:
                rows = self._conn().execute(
                    f"""
                    SELECT action_id FROM agent_actions
                    WHERE tenant_id={ph} AND host_id={ph} AND status='pending'
                      AND attempts < max_attempts
                    ORDER BY created_at ASC
                    LIMIT {ph}
                    """,
                    (tenant_id, host_id, safe_limit),
                ).fetchall()
                leased_ids = [str(row["action_id"]) for row in rows]
                for action_id in leased_ids:
                    self._conn().execute(
                        f"""
                        UPDATE agent_actions
                        SET status='leased', attempts=attempts+1,
                            lease_until={ph}, updated_at={ph}
                        WHERE action_id={ph}
                        """,
                        (lease_until, now, action_id),
                    )
                self._conn().commit()
        return [
            action
            for action_id in leased_ids
            if (action := self.get_action(action_id, tenant_id=tenant_id)) is not None
        ]

    def ack_action(
        self,
        *,
        tenant_id: str,
        host_id: str,
        action_id: str,
        status: str,
        result: dict[str, Any] | None = None,
    ) -> Optional[dict]:
        normalized = (status or "").strip().lower()
        if normalized not in TERMINAL_STATUSES:
            raise ValueError("invalid_action_status")
        ph = self._placeholder()
        now = _utc_now()
        with self._lock:
            if USE_POSTGRES:
                cur = self._conn().cursor()
                cur.execute(
                    f"""
                    UPDATE agent_actions
                    SET status={ph}, result={ph}::jsonb, completed_at={ph},
                        lease_until=NULL, updated_at={ph}
                    WHERE action_id={ph} AND tenant_id={ph} AND host_id={ph}
                    """,
                    (
                        normalized,
                        self._json_dump(result or {}),
                        now,
                        now,
                        action_id,
                        tenant_id,
                        host_id,
                    ),
                )
                changed = bool(cur.rowcount)
                self._conn().commit()
                cur.close()
                return self.get_action(action_id, tenant_id=tenant_id) if changed else None
            cur = self._conn().execute(
                f"""
                UPDATE agent_actions
                SET status={ph}, result={ph}, completed_at={ph},
                    lease_until=NULL, updated_at={ph}
                WHERE action_id={ph} AND tenant_id={ph} AND host_id={ph}
                """,
                (
                    normalized,
                    self._json_dump(result or {}),
                    now,
                    now,
                    action_id,
                    tenant_id,
                    host_id,
                ),
            )
            self._conn().commit()
            return self.get_action(action_id, tenant_id=tenant_id) if cur.rowcount else None

    def cancel_action(
        self,
        *,
        tenant_id: str,
        action_id: str,
        result: dict[str, Any] | None = None,
    ) -> Optional[dict]:
        ph = self._placeholder()
        now = _utc_now()
        with self._lock:
            if USE_POSTGRES:
                cur = self._conn().cursor()
                cur.execute(
                    f"""
                    UPDATE agent_actions
                    SET status='cancelled', result={ph}::jsonb, completed_at={ph},
                        lease_until=NULL, updated_at={ph}
                    WHERE action_id={ph} AND tenant_id={ph}
                      AND status NOT IN ('succeeded', 'failed', 'refused', 'expired', 'cancelled')
                    """,
                    (self._json_dump(result or {}), now, now, action_id, tenant_id),
                )
                changed = bool(cur.rowcount)
                self._conn().commit()
                cur.close()
                return self.get_action(action_id, tenant_id=tenant_id) if changed else None
            cur = self._conn().execute(
                f"""
                UPDATE agent_actions
                SET status='cancelled', result={ph}, completed_at={ph},
                    lease_until=NULL, updated_at={ph}
                WHERE action_id={ph} AND tenant_id={ph}
                  AND status NOT IN ('succeeded', 'failed', 'refused', 'expired', 'cancelled')
                """,
                (self._json_dump(result or {}), now, now, action_id, tenant_id),
            )
            self._conn().commit()
            return self.get_action(action_id, tenant_id=tenant_id) if cur.rowcount else None
