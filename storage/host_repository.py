"""Host registry and agent enrollment repository."""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from typing import Any, Optional

from . import event_repository as event_storage

logger = logging.getLogger("netguard.hosts")

USE_POSTGRES = event_storage.USE_POSTGRES
DEFAULT_DB = event_storage.DEFAULT_DB
DATABASE_URL = event_storage.DATABASE_URL

if USE_POSTGRES:
    psycopg2 = event_storage.psycopg2
    psycopg2_extras = event_storage.psycopg2.extras
else:  # pragma: no cover - exercised indirectly via repository methods
    import sqlite3


_DDL_SQLITE = """
CREATE TABLE IF NOT EXISTS managed_hosts (
    tenant_id         TEXT NOT NULL DEFAULT 'default',
    host_id           TEXT NOT NULL,
    display_name      TEXT NOT NULL,
    api_key_hash      TEXT,
    api_key_prefix    TEXT,
    enrollment_method TEXT NOT NULL DEFAULT 'manual',
    agent_version     TEXT NOT NULL DEFAULT '',
    platform          TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL DEFAULT 'enrolled',
    last_ip           TEXT NOT NULL DEFAULT '',
    last_seen         TEXT,
    last_event_at     TEXT,
    metadata          TEXT NOT NULL DEFAULT '{}',
    tags              TEXT NOT NULL DEFAULT '[]',
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    PRIMARY KEY (tenant_id, host_id)
);
CREATE INDEX IF NOT EXISTS idx_managed_hosts_tenant_last_seen
    ON managed_hosts(tenant_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_managed_hosts_status
    ON managed_hosts(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_managed_hosts_api_key_hash
    ON managed_hosts(api_key_hash);

CREATE TABLE IF NOT EXISTS agent_enrollment_tokens (
    token_hash   TEXT PRIMARY KEY,
    token_prefix TEXT NOT NULL,
    tenant_id    TEXT NOT NULL DEFAULT 'default',
    created_by   TEXT NOT NULL DEFAULT '',
    expires_at   TEXT NOT NULL,
    max_uses     INTEGER NOT NULL DEFAULT 1,
    uses         INTEGER NOT NULL DEFAULT 0,
    revoked_at   TEXT,
    last_used_at TEXT,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agent_enrollment_tenant
    ON agent_enrollment_tokens(tenant_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_agent_enrollment_prefix
    ON agent_enrollment_tokens(token_prefix);
"""

_DDL_POSTGRES = """
CREATE TABLE IF NOT EXISTS managed_hosts (
    tenant_id         TEXT NOT NULL DEFAULT 'default',
    host_id           TEXT NOT NULL,
    display_name      TEXT NOT NULL,
    api_key_hash      TEXT,
    api_key_prefix    TEXT,
    enrollment_method TEXT NOT NULL DEFAULT 'manual',
    agent_version     TEXT NOT NULL DEFAULT '',
    platform          TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL DEFAULT 'enrolled',
    last_ip           TEXT NOT NULL DEFAULT '',
    last_seen         TIMESTAMPTZ,
    last_event_at     TIMESTAMPTZ,
    metadata          JSONB NOT NULL DEFAULT '{}'::jsonb,
    tags              JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, host_id)
);
CREATE INDEX IF NOT EXISTS idx_managed_hosts_tenant_last_seen
    ON managed_hosts(tenant_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_managed_hosts_status
    ON managed_hosts(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_managed_hosts_api_key_hash
    ON managed_hosts(api_key_hash);

CREATE TABLE IF NOT EXISTS agent_enrollment_tokens (
    token_hash   TEXT PRIMARY KEY,
    token_prefix TEXT NOT NULL,
    tenant_id    TEXT NOT NULL DEFAULT 'default',
    created_by   TEXT NOT NULL DEFAULT '',
    expires_at   TIMESTAMPTZ NOT NULL,
    max_uses     INTEGER NOT NULL DEFAULT 1,
    uses         INTEGER NOT NULL DEFAULT 0,
    revoked_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_agent_enrollment_tenant
    ON agent_enrollment_tokens(tenant_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_agent_enrollment_prefix
    ON agent_enrollment_tokens(token_prefix);
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


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


class HostRepository:
    """Persistent registry for enrolled hosts and agent API keys."""

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
    def _json_dump(value: Any, *, default: str) -> str:
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

    def _serialize_host(self, row: Optional[dict]) -> Optional[dict]:
        if not row:
            return None
        host = dict(row)
        host["metadata"] = self._json_load(host.get("metadata"), default={})
        host["tags"] = self._json_load(host.get("tags"), default=[])
        host.pop("api_key_hash", None)
        last_seen = _parse_ts(host.get("last_seen"))
        if str(host.get("status") or "").lower() == "revoked":
            host["status"] = "revoked"
            host["last_seen_age_seconds"] = (
                None
                if last_seen is None
                else max(0, int((datetime.now(timezone.utc) - last_seen).total_seconds()))
            )
            return host
        if last_seen is None:
            host["status"] = host.get("status") or "enrolled"
            host["last_seen_age_seconds"] = None
            return host
        age_seconds = max(
            0,
            int((datetime.now(timezone.utc) - last_seen).total_seconds()),
        )
        host["last_seen_age_seconds"] = age_seconds
        host["status"] = "online" if age_seconds <= 180 else "offline"
        return host

    def _serialize_enrollment_token(self, row: Optional[dict]) -> Optional[dict]:
        if not row:
            return None
        item = dict(row)
        item.pop("token_hash", None)
        expires_at = _parse_ts(item.get("expires_at"))
        revoked_at = _parse_ts(item.get("revoked_at"))
        item["expired"] = bool(
            expires_at and expires_at <= datetime.now(timezone.utc)
        )
        item["revoked"] = bool(revoked_at)
        item["remaining_uses"] = max(
            0,
            int(item.get("max_uses") or 0) - int(item.get("uses") or 0),
        )
        return item

    def _fetch_host_row(
        self,
        host_id: str,
        *,
        tenant_id: str | None = None,
    ) -> Optional[dict]:
        tid = tenant_id or self.tenant_id
        ph = self._placeholder()
        if USE_POSTGRES:
            cur = self._conn().cursor()
            cur.execute(
                f"SELECT * FROM managed_hosts WHERE tenant_id={ph} AND host_id={ph}",
                (tid, host_id),
            )
            row = cur.fetchone()
            cur.close()
            return dict(row) if row else None
        row = self._conn().execute(
            f"SELECT * FROM managed_hosts WHERE tenant_id={ph} AND host_id={ph}",
            (tid, host_id),
        ).fetchone()
        return dict(row) if row else None

    def count_hosts(self, tenant_id: str | None = None) -> int:
        tid = tenant_id or self.tenant_id
        ph = self._placeholder()
        if USE_POSTGRES:
            cur = self._conn().cursor()
            cur.execute(
                f"SELECT COUNT(*) AS total FROM managed_hosts WHERE tenant_id={ph}",
                (tid,),
            )
            row = cur.fetchone()
            cur.close()
            return int(row["total"] if row else 0)
        row = self._conn().execute(
            f"SELECT COUNT(*) AS total FROM managed_hosts WHERE tenant_id={ph}",
            (tid,),
        ).fetchone()
        return int(row["total"] if row else 0)

    def delete_hosts_for_tenant(self, tenant_id: str | None = None) -> int:
        """
        Apaga TODOS os hosts (managed_hosts) do tenant e retorna o número de
        linhas removidas.

        Por que existe:
            Operadores admin precisam zerar o registro de máquinas conectadas
            de um cliente — ex.: tenant pediu reset, demo precisa começar
            limpo, ou um agente vazou e suspeita-se que múltiplos hosts
            falsificados foram registrados. Eventos históricos NÃO são
            apagados (continuam sendo dado de auditoria).

        Operação atômica: a transação é commitada ao final. Se alguma row
        falhar, nenhum host é removido.
        """
        tid = tenant_id or self.tenant_id
        ph = self._placeholder()
        with self._lock:
            if USE_POSTGRES:
                cur = self._conn().cursor()
                cur.execute(
                    f"DELETE FROM managed_hosts WHERE tenant_id={ph}",
                    (tid,),
                )
                deleted = int(cur.rowcount or 0)
                cur.close()
                self._conn().commit()
                return deleted
            cur = self._conn().execute(
                f"DELETE FROM managed_hosts WHERE tenant_id={ph}",
                (tid,),
            )
            self._conn().commit()
            return int(cur.rowcount or 0)

    def get_host(self, host_id: str, *, tenant_id: str | None = None) -> Optional[dict]:
        return self._serialize_host(
            self._fetch_host_row(host_id, tenant_id=tenant_id),
        )

    def list_hosts(self, *, limit: int = 200, tenant_id: str | None = None) -> list[dict]:
        tid = tenant_id or self.tenant_id
        ph = self._placeholder()
        safe_limit = max(1, min(int(limit), 1000))
        if USE_POSTGRES:
            cur = self._conn().cursor()
            cur.execute(
                f"""
                SELECT * FROM managed_hosts
                WHERE tenant_id={ph}
                ORDER BY COALESCE(last_seen, created_at) DESC, host_id ASC
                LIMIT {ph}
                """,
                (tid, safe_limit),
            )
            rows = cur.fetchall()
            cur.close()
            return [self._serialize_host(dict(row)) for row in rows]
        rows = self._conn().execute(
            f"""
            SELECT * FROM managed_hosts
            WHERE tenant_id={ph}
            ORDER BY COALESCE(last_seen, created_at) DESC, host_id ASC
            LIMIT {ph}
            """,
            (tid, safe_limit),
        ).fetchall()
        return [self._serialize_host(dict(row)) for row in rows]

    def register_host(
        self,
        *,
        host_id: str,
        display_name: str = "",
        api_key_hash: str | None = None,
        api_key_prefix: str | None = None,
        enrollment_method: str = "manual",
        agent_version: str = "",
        platform: str = "",
        metadata: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        tenant_id: str | None = None,
    ) -> dict:
        tid = tenant_id or self.tenant_id
        existing = self._fetch_host_row(host_id, tenant_id=tid) or {}
        now = _utc_now()
        merged_metadata = dict(self._json_load(existing.get("metadata"), default={}))
        merged_metadata.update(metadata or {})
        merged_tags = list(
            dict.fromkeys(
                list(self._json_load(existing.get("tags"), default=[]))
                + list(tags or []),
            )
        )
        record = {
            "tenant_id": tid,
            "host_id": host_id,
            "display_name": display_name or existing.get("display_name") or host_id,
            "api_key_hash": api_key_hash or existing.get("api_key_hash"),
            "api_key_prefix": api_key_prefix or existing.get("api_key_prefix"),
            "enrollment_method": enrollment_method or existing.get("enrollment_method") or "manual",
            "agent_version": agent_version or existing.get("agent_version") or "",
            "platform": platform or existing.get("platform") or "",
            "status": existing.get("status") or "enrolled",
            "last_ip": existing.get("last_ip") or "",
            "last_seen": existing.get("last_seen"),
            "last_event_at": existing.get("last_event_at"),
            "metadata": merged_metadata,
            "tags": merged_tags,
            "created_at": existing.get("created_at") or now,
            "updated_at": now,
        }
        self._write_host(record)
        return self.get_host(host_id, tenant_id=tid) or {}

    def touch_host(
        self,
        host_id: str,
        *,
        display_name: str = "",
        agent_version: str = "",
        platform: str = "",
        source_ip: str = "",
        metadata: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        tenant_id: str | None = None,
        mark_event: bool = False,
    ) -> dict:
        tid = tenant_id or self.tenant_id
        existing = self._fetch_host_row(host_id, tenant_id=tid) or {}
        now = _utc_now()
        merged_metadata = dict(self._json_load(existing.get("metadata"), default={}))
        merged_metadata.update(metadata or {})
        merged_tags = list(
            dict.fromkeys(
                list(self._json_load(existing.get("tags"), default=[]))
                + list(tags or []),
            )
        )
        record = {
            "tenant_id": tid,
            "host_id": host_id,
            "display_name": display_name or existing.get("display_name") or host_id,
            "api_key_hash": existing.get("api_key_hash"),
            "api_key_prefix": existing.get("api_key_prefix"),
            "enrollment_method": existing.get("enrollment_method") or "manual",
            "agent_version": agent_version or existing.get("agent_version") or "",
            "platform": platform or existing.get("platform") or "",
            "status": "online",
            "last_ip": source_ip or existing.get("last_ip") or "",
            "last_seen": now,
            "last_event_at": now if mark_event else existing.get("last_event_at"),
            "metadata": merged_metadata,
            "tags": merged_tags,
            "created_at": existing.get("created_at") or now,
            "updated_at": now,
        }
        self._write_host(record)
        return self.get_host(host_id, tenant_id=tid) or {}

    def rotate_api_key(
        self,
        host_id: str,
        *,
        api_key_hash: str,
        api_key_prefix: str,
        tenant_id: str | None = None,
    ) -> bool:
        tid = tenant_id or self.tenant_id
        existing = self._fetch_host_row(host_id, tenant_id=tid)
        if not existing:
            return False
        existing["api_key_hash"] = api_key_hash
        existing["api_key_prefix"] = api_key_prefix
        existing["updated_at"] = _utc_now()
        self._write_host(existing)
        return True

    def revoke_host_key(
        self,
        host_id: str,
        *,
        tenant_id: str | None = None,
    ) -> bool:
        tid = tenant_id or self.tenant_id
        existing = self._fetch_host_row(host_id, tenant_id=tid)
        if not existing:
            return False
        existing["api_key_hash"] = None
        existing["api_key_prefix"] = None
        existing["status"] = "revoked"
        existing["updated_at"] = _utc_now()
        self._write_host(existing)
        return True

    def verify_api_key(self, api_key_hash: str) -> Optional[dict]:
        if not api_key_hash:
            return None
        ph = self._placeholder()
        if USE_POSTGRES:
            cur = self._conn().cursor()
            cur.execute(
                f"SELECT * FROM managed_hosts WHERE api_key_hash={ph} LIMIT 1",
                (api_key_hash,),
            )
            row = cur.fetchone()
            cur.close()
            return self._serialize_host(dict(row) if row else None)
        row = self._conn().execute(
            f"SELECT * FROM managed_hosts WHERE api_key_hash={ph} LIMIT 1",
            (api_key_hash,),
        ).fetchone()
        return self._serialize_host(dict(row) if row else None)

    def create_enrollment_token(
        self,
        *,
        token_hash: str,
        token_prefix: str,
        tenant_id: str,
        created_by: str = "",
        expires_at: str,
        max_uses: int = 1,
    ) -> dict:
        now = _utc_now()
        ph = self._placeholder()
        params = (
            token_hash,
            token_prefix,
            tenant_id or self.tenant_id,
            created_by or "",
            expires_at,
            max(1, int(max_uses)),
            0,
            None,
            None,
            now,
            now,
        )
        with self._lock:
            if USE_POSTGRES:
                cur = self._conn().cursor()
                cur.execute(
                    f"""
                    INSERT INTO agent_enrollment_tokens (
                        token_hash, token_prefix, tenant_id, created_by,
                        expires_at, max_uses, uses, revoked_at, last_used_at,
                        created_at, updated_at
                    ) VALUES (
                        {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph},
                        {ph}, {ph}, {ph}, {ph}
                    )
                    ON CONFLICT (token_hash) DO UPDATE SET
                        token_prefix=EXCLUDED.token_prefix,
                        tenant_id=EXCLUDED.tenant_id,
                        created_by=EXCLUDED.created_by,
                        expires_at=EXCLUDED.expires_at,
                        max_uses=EXCLUDED.max_uses,
                        uses=EXCLUDED.uses,
                        revoked_at=EXCLUDED.revoked_at,
                        last_used_at=EXCLUDED.last_used_at,
                        updated_at=EXCLUDED.updated_at
                    """,
                    params,
                )
                self._conn().commit()
                cur.close()
            else:
                self._conn().execute(
                    f"""
                    INSERT OR REPLACE INTO agent_enrollment_tokens (
                        token_hash, token_prefix, tenant_id, created_by,
                        expires_at, max_uses, uses, revoked_at, last_used_at,
                        created_at, updated_at
                    ) VALUES (
                        {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph},
                        {ph}, {ph}, {ph}, {ph}
                    )
                    """,
                    params,
                )
                self._conn().commit()
        return self.get_enrollment_token(token_hash=token_hash) or {}

    def get_enrollment_token(
        self,
        *,
        token_hash: str | None = None,
        token_prefix: str | None = None,
    ) -> Optional[dict]:
        ph = self._placeholder()
        if token_hash:
            where = f"token_hash={ph}"
            params = (token_hash,)
        elif token_prefix:
            where = f"token_prefix={ph}"
            params = (token_prefix,)
        else:
            return None
        if USE_POSTGRES:
            cur = self._conn().cursor()
            cur.execute(f"SELECT * FROM agent_enrollment_tokens WHERE {where} LIMIT 1", params)
            row = cur.fetchone()
            cur.close()
            return self._serialize_enrollment_token(dict(row) if row else None)
        row = self._conn().execute(
            f"SELECT * FROM agent_enrollment_tokens WHERE {where} LIMIT 1",
            params,
        ).fetchone()
        return self._serialize_enrollment_token(dict(row) if row else None)

    def consume_enrollment_token(self, token_hash: str) -> Optional[dict]:
        if not token_hash:
            return None
        ph = self._placeholder()
        now = _utc_now()
        with self._lock:
            if USE_POSTGRES:
                cur = self._conn().cursor()
                cur.execute(
                    f"SELECT * FROM agent_enrollment_tokens WHERE token_hash={ph} FOR UPDATE",
                    (token_hash,),
                )
                row = cur.fetchone()
                if not row or not _enrollment_row_usable(dict(row)):
                    self._conn().rollback()
                    cur.close()
                    return None
                cur.execute(
                    f"""
                    UPDATE agent_enrollment_tokens
                    SET uses=uses+1, last_used_at={ph}, updated_at={ph}
                    WHERE token_hash={ph}
                    """,
                    (now, now, token_hash),
                )
                self._conn().commit()
                cur.close()
            else:
                row = self._conn().execute(
                    f"SELECT * FROM agent_enrollment_tokens WHERE token_hash={ph}",
                    (token_hash,),
                ).fetchone()
                row_dict = dict(row) if row else None
                if not row_dict or not _enrollment_row_usable(row_dict):
                    return None
                self._conn().execute(
                    f"""
                    UPDATE agent_enrollment_tokens
                    SET uses=uses+1, last_used_at={ph}, updated_at={ph}
                    WHERE token_hash={ph}
                    """,
                    (now, now, token_hash),
                )
                self._conn().commit()
        return self.get_enrollment_token(token_hash=token_hash)

    def revoke_enrollment_token(self, token_hash: str) -> bool:
        if not token_hash:
            return False
        ph = self._placeholder()
        now = _utc_now()
        with self._lock:
            if USE_POSTGRES:
                cur = self._conn().cursor()
                cur.execute(
                    f"""
                    UPDATE agent_enrollment_tokens
                    SET revoked_at={ph}, updated_at={ph}
                    WHERE token_hash={ph} AND revoked_at IS NULL
                    """,
                    (now, now, token_hash),
                )
                changed = bool(cur.rowcount)
                self._conn().commit()
                cur.close()
                return changed
            cur = self._conn().execute(
                f"""
                UPDATE agent_enrollment_tokens
                SET revoked_at={ph}, updated_at={ph}
                WHERE token_hash={ph} AND revoked_at IS NULL
                """,
                (now, now, token_hash),
            )
            self._conn().commit()
            return bool(cur.rowcount)

    def _write_host(self, record: dict[str, Any]) -> None:
        ph = self._placeholder()
        params = (
            record["tenant_id"],
            record["host_id"],
            record["display_name"],
            record.get("api_key_hash"),
            record.get("api_key_prefix"),
            record.get("enrollment_method") or "manual",
            record.get("agent_version") or "",
            record.get("platform") or "",
            record.get("status") or "enrolled",
            record.get("last_ip") or "",
            record.get("last_seen"),
            record.get("last_event_at"),
            self._json_dump(record.get("metadata"), default="{}"),
            self._json_dump(record.get("tags"), default="[]"),
            record["created_at"],
            record["updated_at"],
        )
        with self._lock:
            if USE_POSTGRES:
                cur = self._conn().cursor()
                cur.execute(
                    f"""
                    INSERT INTO managed_hosts (
                        tenant_id, host_id, display_name, api_key_hash, api_key_prefix,
                        enrollment_method, agent_version, platform, status, last_ip,
                        last_seen, last_event_at, metadata, tags, created_at, updated_at
                    ) VALUES (
                        {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph},
                        {ph}, {ph}, {ph}, {ph}, {ph}::jsonb, {ph}::jsonb, {ph}, {ph}
                    )
                    ON CONFLICT (tenant_id, host_id) DO UPDATE SET
                        display_name=EXCLUDED.display_name,
                        api_key_hash=EXCLUDED.api_key_hash,
                        api_key_prefix=EXCLUDED.api_key_prefix,
                        enrollment_method=EXCLUDED.enrollment_method,
                        agent_version=EXCLUDED.agent_version,
                        platform=EXCLUDED.platform,
                        status=EXCLUDED.status,
                        last_ip=EXCLUDED.last_ip,
                        last_seen=EXCLUDED.last_seen,
                        last_event_at=EXCLUDED.last_event_at,
                        metadata=EXCLUDED.metadata,
                        tags=EXCLUDED.tags,
                        updated_at=EXCLUDED.updated_at
                    """,
                    params,
                )
                self._conn().commit()
                cur.close()
                return
            self._conn().execute(
                f"""
                INSERT INTO managed_hosts (
                    tenant_id, host_id, display_name, api_key_hash, api_key_prefix,
                    enrollment_method, agent_version, platform, status, last_ip,
                    last_seen, last_event_at, metadata, tags, created_at, updated_at
                ) VALUES (
                    {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph},
                    {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}
                )
                ON CONFLICT(tenant_id, host_id) DO UPDATE SET
                    display_name=excluded.display_name,
                    api_key_hash=excluded.api_key_hash,
                    api_key_prefix=excluded.api_key_prefix,
                    enrollment_method=excluded.enrollment_method,
                    agent_version=excluded.agent_version,
                    platform=excluded.platform,
                    status=excluded.status,
                    last_ip=excluded.last_ip,
                    last_seen=excluded.last_seen,
                    last_event_at=excluded.last_event_at,
                    metadata=excluded.metadata,
                    tags=excluded.tags,
                    updated_at=excluded.updated_at
                """,
                params,
            )
            self._conn().commit()


def _enrollment_row_usable(row: dict[str, Any]) -> bool:
    if not row:
        return False
    if row.get("revoked_at"):
        return False
    expires_at = _parse_ts(row.get("expires_at"))
    if expires_at is None or expires_at <= datetime.now(timezone.utc):
        return False
    return int(row.get("uses") or 0) < int(row.get("max_uses") or 0)
