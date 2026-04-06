"""
NetGuard — Event Repository
Camada de armazenamento de eventos de segurança.

Suporta dois backends via DATABASE_URL:
  - SQLite  (padrão, desenvolvimento/desktop):  não definir DATABASE_URL
  - PostgreSQL (produção/VPS/SaaS):             DATABASE_URL=postgresql://user:pass@host/db

Multi-tenant: todos os registros carregam tenant_id.
O tenant é identificado pelo token do agente (mapeado em app.py).
"""

import os
import json
import logging
import threading
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any  # noqa: F401
from pathlib import Path

logger = logging.getLogger("netguard.storage")

DEFAULT_DB   = Path(__file__).parent.parent / "netguard_events.db"
DATABASE_URL = os.environ.get("DATABASE_URL", "")

# ── Backend detection ─────────────────────────────────────────────
USE_POSTGRES = DATABASE_URL.startswith("postgresql") or DATABASE_URL.startswith("postgres")

if USE_POSTGRES:
    try:
        import psycopg2
        import psycopg2.extras
        PSYCOPG2_OK = True
        logger.info("Storage backend: PostgreSQL (%s)", DATABASE_URL.split("@")[-1])
    except ImportError:
        PSYCOPG2_OK = False
        USE_POSTGRES = False
        logger.warning("psycopg2 não instalado — usando SQLite. "
                       "Instale com: pip install psycopg2-binary")
else:
    PSYCOPG2_OK = False
    logger.info("Storage backend: SQLite (%s)", DEFAULT_DB)

if not USE_POSTGRES:
    import sqlite3


# ══════════════════════════════════════════════════════════════════
#  DDL — Schema compartilhado (SQLite e PostgreSQL)
# ══════════════════════════════════════════════════════════════════

_DDL_SQLITE = """
    CREATE TABLE IF NOT EXISTS events (
        event_id     TEXT PRIMARY KEY,
        tenant_id    TEXT NOT NULL DEFAULT 'default',
        timestamp    TEXT NOT NULL,
        host_id      TEXT NOT NULL,
        event_type   TEXT NOT NULL,
        severity     TEXT NOT NULL,
        source       TEXT NOT NULL,
        rule_id      TEXT,
        rule_name    TEXT,
        details      TEXT,
        mitre        TEXT,
        tags         TEXT,
        raw          TEXT,
        acknowledged INTEGER DEFAULT 0,
        created_at   TEXT DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_events_tenant    ON events(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_events_severity  ON events(severity);
    CREATE INDEX IF NOT EXISTS idx_events_type      ON events(event_type);
    CREATE INDEX IF NOT EXISTS idx_events_host      ON events(host_id);
    CREATE INDEX IF NOT EXISTS idx_events_rule      ON events(rule_id);

    CREATE TABLE IF NOT EXISTS baselines (
        tenant_id     TEXT NOT NULL DEFAULT 'default',
        host_id       TEXT NOT NULL,
        baseline_type TEXT NOT NULL,
        value         TEXT NOT NULL,
        first_seen    TEXT NOT NULL,
        last_seen     TEXT NOT NULL,
        count         INTEGER DEFAULT 1,
        PRIMARY KEY (tenant_id, host_id, baseline_type, value)
    );

    CREATE TABLE IF NOT EXISTS event_stats (
        tenant_id  TEXT NOT NULL DEFAULT 'default',
        date       TEXT NOT NULL,
        event_type TEXT NOT NULL,
        severity   TEXT NOT NULL,
        count      INTEGER DEFAULT 0,
        PRIMARY KEY (tenant_id, date, event_type, severity)
    );

    CREATE TABLE IF NOT EXISTS tenants (
        tenant_id              TEXT PRIMARY KEY,
        name                   TEXT NOT NULL,
        token                  TEXT NOT NULL UNIQUE,
        token_hash             TEXT,
        role                   TEXT NOT NULL DEFAULT 'analyst',
        plan                   TEXT NOT NULL DEFAULT 'free',
        max_hosts              INTEGER DEFAULT 1,
        created_at             TEXT DEFAULT (datetime('now')),
        active                 INTEGER DEFAULT 1,
        email                  TEXT,
        stripe_customer_id     TEXT,
        stripe_subscription_id TEXT
    );
"""

# Migration SQL — adicionado às colunas de tenants existentes de forma segura
_DDL_MIGRATION_SQLITE = """
    ALTER TABLE tenants ADD COLUMN token_hash TEXT;
    ALTER TABLE tenants ADD COLUMN role TEXT NOT NULL DEFAULT 'analyst';
"""

_DDL_MIGRATION_POSTGRES = """
    ALTER TABLE tenants ADD COLUMN IF NOT EXISTS token_hash TEXT;
    ALTER TABLE tenants ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'analyst';
"""

_DDL_POSTGRES = """
    CREATE TABLE IF NOT EXISTS events (
        event_id     TEXT PRIMARY KEY,
        tenant_id    TEXT NOT NULL DEFAULT 'default',
        timestamp    TIMESTAMPTZ NOT NULL,
        host_id      TEXT NOT NULL,
        event_type   TEXT NOT NULL,
        severity     TEXT NOT NULL,
        source       TEXT NOT NULL,
        rule_id      TEXT,
        rule_name    TEXT,
        details      JSONB,
        mitre        JSONB,
        tags         JSONB,
        raw          TEXT,
        acknowledged BOOLEAN DEFAULT FALSE,
        created_at   TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_events_tenant    ON events(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_events_severity  ON events(severity);
    CREATE INDEX IF NOT EXISTS idx_events_type      ON events(event_type);
    CREATE INDEX IF NOT EXISTS idx_events_host      ON events(host_id);
    CREATE INDEX IF NOT EXISTS idx_events_ts_tenant ON events(tenant_id, timestamp DESC);

    CREATE TABLE IF NOT EXISTS baselines (
        tenant_id     TEXT NOT NULL DEFAULT 'default',
        host_id       TEXT NOT NULL,
        baseline_type TEXT NOT NULL,
        value         TEXT NOT NULL,
        first_seen    TIMESTAMPTZ NOT NULL,
        last_seen     TIMESTAMPTZ NOT NULL,
        count         INTEGER DEFAULT 1,
        PRIMARY KEY (tenant_id, host_id, baseline_type, value)
    );

    CREATE TABLE IF NOT EXISTS event_stats (
        tenant_id  TEXT NOT NULL DEFAULT 'default',
        date       DATE NOT NULL,
        event_type TEXT NOT NULL,
        severity   TEXT NOT NULL,
        count      INTEGER DEFAULT 0,
        PRIMARY KEY (tenant_id, date, event_type, severity)
    );

    CREATE TABLE IF NOT EXISTS tenants (
        tenant_id              TEXT PRIMARY KEY,
        name                   TEXT NOT NULL,
        token                  TEXT NOT NULL UNIQUE,
        token_hash             TEXT,
        role                   TEXT NOT NULL DEFAULT 'analyst',
        plan                   TEXT NOT NULL DEFAULT 'free',
        max_hosts              INTEGER DEFAULT 1,
        created_at             TIMESTAMPTZ DEFAULT NOW(),
        active                 BOOLEAN DEFAULT TRUE,
        email                  TEXT,
        stripe_customer_id     TEXT,
        stripe_subscription_id TEXT
    );
"""


# ══════════════════════════════════════════════════════════════════
#  EVENT REPOSITORY
# ══════════════════════════════════════════════════════════════════

class EventRepository:
    """
    Repositório de eventos de segurança.
    Thread-safe. Suporta SQLite (dev) e PostgreSQL (produção).
    Todos os dados são isolados por tenant_id.
    """

    def __init__(self, db_path: str = None, tenant_id: str = "default"):
        self.db_path   = str(db_path or DEFAULT_DB)
        self.tenant_id = tenant_id
        self._lock     = threading.RLock()

        self._local = threading.local()  # sempre inicializado (SQLite e PostgreSQL)
        if USE_POSTGRES:
            self._pg_pool = []  # simple connection reuse
            self._pg_lock = threading.RLock()

        self._init_db()
        logger.info("EventRepository iniciado | backend=%s | tenant=%s",
                    "postgres" if USE_POSTGRES else "sqlite", tenant_id)

    # ── Connection management ─────────────────────────────────────

    def _conn(self):
        """Retorna conexão ativa para o backend configurado."""
        if USE_POSTGRES:
            return self._pg_conn()
        return self._sqlite_conn()

    def _sqlite_conn(self):
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
        return self._local.conn

    def _pg_conn(self):
        """Retorna conexão PostgreSQL (thread-local via pool simples)."""
        if not hasattr(self._local, "pg_conn") or self._local.pg_conn is None or self._local.pg_conn.closed:
            self._local.pg_conn = psycopg2.connect(
                DATABASE_URL,
                cursor_factory=psycopg2.extras.RealDictCursor,
            )
            self._local.pg_conn.autocommit = False
        return self._local.pg_conn

    def _init_db(self):
        """Cria tabelas se não existirem e aplica migrations."""
        if USE_POSTGRES:
            conn = psycopg2.connect(DATABASE_URL)
            try:
                with conn.cursor() as cur:
                    cur.execute(_DDL_POSTGRES)
                conn.commit()
            finally:
                conn.close()
        else:
            conn = sqlite3.connect(self.db_path)
            # Executa cada statement individualmente para tolerar schema antigo
            for stmt in _DDL_SQLITE.split(";"):
                stmt = stmt.strip()
                if stmt:
                    try:
                        conn.execute(stmt)
                    except Exception as _e:
                        logger.debug("DDL skip (schema antigo): %s | %s", _e, stmt[:60])
            conn.commit()
            conn.close()
        # Aplica migrations (adiciona colunas novas em bancos pré-existentes)
        self._migrate_schema()

    def _placeholder(self) -> str:
        """Retorna placeholder de query correto para o backend."""
        return "%s" if USE_POSTGRES else "?"

    # ── Save ──────────────────────────────────────────────────────

    def save(self, event) -> bool:
        """Salva um SecurityEvent no banco."""
        ph = self._placeholder()
        try:
            details = json.dumps(event.details) if not USE_POSTGRES else event.details
            mitre   = json.dumps(event.mitre.to_dict() if hasattr(event.mitre, "to_dict") else {})
            tags    = json.dumps(event.tags) if not USE_POSTGRES else event.tags
            ack     = (1 if event.acknowledged else 0) if not USE_POSTGRES else bool(event.acknowledged)

            conn = self._conn()
            if USE_POSTGRES:
                cur = conn.cursor()
                cur.execute(f"""
                    INSERT INTO events
                        (event_id, tenant_id, timestamp, host_id, event_type, severity,
                         source, rule_id, rule_name, details, mitre, tags, raw, acknowledged)
                    VALUES ({ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph}::jsonb,{ph}::jsonb,{ph}::jsonb,{ph},{ph})
                    ON CONFLICT (event_id) DO UPDATE SET acknowledged = EXCLUDED.acknowledged
                """, (
                    event.event_id, self.tenant_id, event.timestamp, event.host_id,
                    event.event_type, event.severity, event.source, event.rule_id,
                    event.rule_name,
                    json.dumps(event.details),
                    json.dumps(event.mitre.to_dict() if hasattr(event.mitre, "to_dict") else {}),
                    json.dumps(event.tags),
                    event.raw, ack,
                ))
                date = event.timestamp[:10]
                cur.execute(f"""
                    INSERT INTO event_stats (tenant_id, date, event_type, severity, count)
                    VALUES ({ph},{ph},{ph},{ph},1)
                    ON CONFLICT (tenant_id, date, event_type, severity)
                    DO UPDATE SET count = event_stats.count + 1
                """, (self.tenant_id, date, event.event_type, event.severity))
                conn.commit()
                cur.close()
            else:
                conn.execute(f"""
                    INSERT OR REPLACE INTO events
                    (event_id, tenant_id, timestamp, host_id, event_type, severity,
                     source, rule_id, rule_name, details, mitre, tags, raw, acknowledged)
                    VALUES ({ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph})
                """, (
                    event.event_id, self.tenant_id, event.timestamp, event.host_id,
                    event.event_type, event.severity, event.source, event.rule_id,
                    event.rule_name, details, mitre, tags, event.raw, ack,
                ))
                date = event.timestamp[:10]
                conn.execute(f"""
                    INSERT INTO event_stats (tenant_id, date, event_type, severity, count)
                    VALUES ({ph},{ph},{ph},{ph},1)
                    ON CONFLICT(tenant_id, date, event_type, severity)
                    DO UPDATE SET count = count + 1
                """, (self.tenant_id, date, event.event_type, event.severity))
                conn.commit()

            # ── Dispara alerta de e-mail para eventos CRITICAL/HIGH ───
            try:
                sev = (getattr(event, "severity", None) or "").upper()
                if sev in ("CRITICAL", "HIGH"):
                    from alerts.email_alert import get_alert_manager
                    event_dict = {
                        "severity":   sev,
                        "rule_name":  getattr(event, "rule_name", None),
                        "event_type": getattr(event, "event_type", None),
                        "source":     getattr(event, "source", None),
                        "host_id":    getattr(event, "host_id", None),
                        "timestamp":  getattr(event, "timestamp", None),
                        "raw":        getattr(event, "raw", None),
                    }
                    tenant_dict = self.get_tenant_by_id(self.tenant_id) or {}
                    get_alert_manager().trigger(event_dict, tenant_dict)
            except Exception as _alert_err:
                logger.debug("Alert trigger skipped: %s", _alert_err)

            return True
        except Exception as e:
            logger.error("Error saving event: %s", e)
            if USE_POSTGRES:
                try:
                    self._conn().rollback()
                except Exception:
                    pass
            return False

    def save_batch(self, events: list) -> int:
        return sum(1 for e in events if self.save(e))

    # ── Query ─────────────────────────────────────────────────────

    def query(
        self,
        limit:        int  = 100,
        offset:       int  = 0,
        severity:     str  = None,
        event_type:   str  = None,
        host_id:      str  = None,
        rule_id:      str  = None,
        since:        str  = None,
        acknowledged: bool = None,
        tenant_id:    str  = None,
    ) -> List[dict]:
        ph = self._placeholder()
        tid = tenant_id or self.tenant_id
        sql    = f"SELECT * FROM events WHERE tenant_id = {ph}"
        params = [tid]

        if severity:
            sql += f" AND severity = {ph}"; params.append(severity.upper())
        if event_type:
            sql += f" AND event_type = {ph}"; params.append(event_type)
        if host_id:
            sql += f" AND host_id = {ph}"; params.append(host_id)
        if rule_id:
            sql += f" AND rule_id = {ph}"; params.append(rule_id)
        if since:
            sql += f" AND timestamp >= {ph}"; params.append(since)
        if acknowledged is not None:
            val = acknowledged if USE_POSTGRES else (1 if acknowledged else 0)
            sql += f" AND acknowledged = {ph}"; params.append(val)

        sql += f" ORDER BY timestamp DESC LIMIT {ph} OFFSET {ph}"
        params += [limit, offset]

        try:
            if USE_POSTGRES:
                cur = self._conn().cursor()
                cur.execute(sql, params)
                rows = cur.fetchall()
                cur.close()
                return [self._pg_row_to_dict(r) for r in rows]
            else:
                rows = self._conn().execute(sql, params).fetchall()
                return [self._sqlite_row_to_dict(r) for r in rows]
        except Exception as e:
            logger.error("Query error: %s", e)
            return []

    def count(self, tenant_id: str = None, **filters) -> int:
        ph  = self._placeholder()
        tid = tenant_id or self.tenant_id
        sql    = f"SELECT COUNT(*) FROM events WHERE tenant_id = {ph}"
        params = [tid]
        if filters.get("severity"):
            sql += f" AND severity = {ph}"; params.append(filters["severity"].upper())
        if filters.get("event_type"):
            sql += f" AND event_type = {ph}"; params.append(filters["event_type"])
        if filters.get("since"):
            sql += f" AND timestamp >= {ph}"; params.append(filters["since"])
        try:
            if USE_POSTGRES:
                cur = self._conn().cursor()
                cur.execute(sql, params)
                result = cur.fetchone()
                cur.close()
                return result["count"] if result else 0
            else:
                return self._conn().execute(sql, params).fetchone()[0]
        except Exception:
            return 0

    def stats(self, tenant_id: str = None) -> dict:
        ph  = self._placeholder()
        tid = tenant_id or self.tenant_id
        try:
            if USE_POSTGRES:
                return self._stats_postgres(tid, ph)
            return self._stats_sqlite(tid, ph)
        except Exception as e:
            logger.error("Stats error: %s", e)
            return {}

    def _stats_sqlite(self, tid, ph) -> dict:
        conn = self._conn()
        total  = conn.execute(f"SELECT COUNT(*) FROM events WHERE tenant_id={ph}", (tid,)).fetchone()[0]
        by_sev = {r["severity"]: r["c"] for r in conn.execute(
            f"SELECT severity, COUNT(*) as c FROM events WHERE tenant_id={ph} GROUP BY severity", (tid,))}
        by_type = {r["event_type"]: r["c"] for r in conn.execute(
            f"SELECT event_type, COUNT(*) as c FROM events WHERE tenant_id={ph} "
            f"GROUP BY event_type ORDER BY c DESC LIMIT 10", (tid,))}
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        last24 = conn.execute(
            f"SELECT COUNT(*) FROM events WHERE tenant_id={ph} AND timestamp>={ph}", (tid, since)
        ).fetchone()[0]
        hourly = [{"hour": r["hour"], "c": r["c"]} for r in conn.execute(f"""
            SELECT strftime('%Y-%m-%dT%H:00:00Z', timestamp) as hour, COUNT(*) as c
            FROM events WHERE tenant_id={ph} AND timestamp>={ph}
            GROUP BY hour ORDER BY hour
        """, (tid, since))]
        return {"total": total, "by_severity": by_sev, "by_type": by_type,
                "last_24h": last24, "hourly": hourly}

    def _stats_postgres(self, tid, ph) -> dict:
        cur = self._conn().cursor()
        cur.execute(f"SELECT COUNT(*) FROM events WHERE tenant_id={ph}", (tid,))
        total = cur.fetchone()["count"]
        cur.execute(f"SELECT severity, COUNT(*) as c FROM events WHERE tenant_id={ph} GROUP BY severity", (tid,))
        by_sev = {r["severity"]: r["c"] for r in cur.fetchall()}
        cur.execute(f"""SELECT event_type, COUNT(*) as c FROM events WHERE tenant_id={ph}
                        GROUP BY event_type ORDER BY c DESC LIMIT 10""", (tid,))
        by_type = {r["event_type"]: r["c"] for r in cur.fetchall()}
        since   = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        cur.execute(f"SELECT COUNT(*) FROM events WHERE tenant_id={ph} AND timestamp>={ph}", (tid, since))
        last24  = cur.fetchone()["count"]
        cur.execute(f"""
            SELECT date_trunc('hour', timestamp) as hour, COUNT(*) as c
            FROM events WHERE tenant_id={ph} AND timestamp>={ph}
            GROUP BY hour ORDER BY hour
        """, (tid, since))
        hourly = [{"hour": str(r["hour"]), "c": r["c"]} for r in cur.fetchall()]
        cur.close()
        return {"total": total, "by_severity": by_sev, "by_type": by_type,
                "last_24h": last24, "hourly": hourly}

    # ── Baseline management ───────────────────────────────────────

    def get_baseline(self, host_id: str, baseline_type: str) -> set:
        ph  = self._placeholder()
        tid = self.tenant_id
        try:
            if USE_POSTGRES:
                cur = self._conn().cursor()
                cur.execute(
                    f"SELECT value FROM baselines WHERE tenant_id={ph} AND host_id={ph} AND baseline_type={ph}",
                    (tid, host_id, baseline_type)
                )
                result = {r["value"] for r in cur.fetchall()}
                cur.close()
                return result
            else:
                rows = self._conn().execute(
                    f"SELECT value FROM baselines WHERE tenant_id={ph} AND host_id={ph} AND baseline_type={ph}",
                    (tid, host_id, baseline_type)
                ).fetchall()
                return {r["value"] for r in rows}
        except Exception:
            return set()

    def update_baseline(self, host_id: str, baseline_type: str, value: str):
        ph  = self._placeholder()
        tid = self.tenant_id
        now = datetime.now(timezone.utc).isoformat()
        try:
            if USE_POSTGRES:
                cur = self._conn().cursor()
                cur.execute(f"""
                    INSERT INTO baselines (tenant_id, host_id, baseline_type, value, first_seen, last_seen, count)
                    VALUES ({ph},{ph},{ph},{ph},{ph},{ph},1)
                    ON CONFLICT (tenant_id, host_id, baseline_type, value)
                    DO UPDATE SET last_seen={ph}, count=baselines.count+1
                """, (tid, host_id, baseline_type, value, now, now, now))
                self._conn().commit()
                cur.close()
            else:
                self._conn().execute(f"""
                    INSERT INTO baselines (tenant_id, host_id, baseline_type, value, first_seen, last_seen, count)
                    VALUES ({ph},{ph},{ph},{ph},{ph},{ph},1)
                    ON CONFLICT(tenant_id, host_id, baseline_type, value)
                    DO UPDATE SET last_seen={ph}, count=count+1
                """, (tid, host_id, baseline_type, value, now, now, now))
                self._conn().commit()
        except Exception as e:
            logger.error("Baseline update error: %s", e)

    def update_baseline_batch(self, host_id: str, baseline_type: str, values: list):
        for v in values:
            self.update_baseline(host_id, baseline_type, str(v))

    # ── Tenant management ─────────────────────────────────────────

    def get_tenant_by_id(self, tenant_id: str) -> Optional[dict]:
        """Retorna dados completos do tenant pelo tenant_id (inclui email para alertas)."""
        ph = self._placeholder()
        try:
            if USE_POSTGRES:
                cur = self._conn().cursor()
                cur.execute(
                    f"SELECT * FROM tenants WHERE tenant_id={ph} AND active=TRUE", (tenant_id,)
                )
                row = cur.fetchone()
                cur.close()
                return dict(row) if row else None
            else:
                row = self._conn().execute(
                    f"SELECT * FROM tenants WHERE tenant_id={ph} AND active=1", (tenant_id,)
                ).fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.debug("get_tenant_by_id error: %s", e)
            return None

    def get_tenant_by_token(self, token: str) -> Optional[dict]:
        """
        Resolve um token de agente para seu tenant.
        Tenta lookup por token_hash primeiro (mais seguro);
        faz fallback para plaintext se token_hash ainda não estiver definido
        (compatibilidade com tenants criados antes da migração de segurança).
        """
        if not token:
            return None
        ph = self._placeholder()

        # Tenta por hash (preferred path)
        try:
            from security import hash_token
            token_hash = hash_token(token)
            tenant = self.get_tenant_by_token_hash(token_hash)
            if tenant:
                return tenant
        except Exception:
            pass

        # Fallback legacy: busca por plaintext e faz upgrade para hash se encontrado
        try:
            if USE_POSTGRES:
                cur = self._conn().cursor()
                cur.execute(
                    f"SELECT * FROM tenants WHERE token={ph} AND active=TRUE", (token,)
                )
                row = cur.fetchone()
                cur.close()
                result = dict(row) if row else None
            else:
                row = self._conn().execute(
                    f"SELECT * FROM tenants WHERE token={ph} AND active=1", (token,)
                ).fetchone()
                result = dict(row) if row else None

            # Upgrade automático: salva hash e mantém plaintext para rollback
            if result and result.get("token_hash") is None:
                try:
                    from security import hash_token
                    self.set_tenant_token_hash(result["tenant_id"], hash_token(token))
                    logger.info("[security] Token hash atualizado (migration) | tenant=%s",
                                result["tenant_id"])
                except Exception:
                    pass
            return result
        except Exception as e:
            logger.debug("get_tenant_by_token error: %s", e)
            return None

    def get_tenant_by_token_hash(self, token_hash: str) -> Optional[dict]:
        """Busca tenant pelo hash HMAC-SHA256 do token (caminho seguro)."""
        if not token_hash:
            return None
        ph = self._placeholder()
        try:
            if USE_POSTGRES:
                cur = self._conn().cursor()
                cur.execute(
                    f"SELECT * FROM tenants WHERE token_hash={ph} AND active=TRUE",
                    (token_hash,)
                )
                row = cur.fetchone()
                cur.close()
                return dict(row) if row else None
            else:
                row = self._conn().execute(
                    f"SELECT * FROM tenants WHERE token_hash={ph} AND active=1",
                    (token_hash,)
                ).fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.debug("get_tenant_by_token_hash error: %s", e)
            return None

    def set_tenant_token_hash(self, tenant_id: str, token_hash: str) -> bool:
        """Atualiza o hash do token de um tenant (usado em migration e rotação)."""
        ph = self._placeholder()
        try:
            if USE_POSTGRES:
                cur = self._conn().cursor()
                cur.execute(
                    f"UPDATE tenants SET token_hash={ph} WHERE tenant_id={ph}",
                    (token_hash, tenant_id)
                )
                self._conn().commit()
                cur.close()
            else:
                self._conn().execute(
                    f"UPDATE tenants SET token_hash={ph} WHERE tenant_id={ph}",
                    (token_hash, tenant_id)
                )
                self._conn().commit()
            return True
        except Exception as e:
            logger.error("set_tenant_token_hash error: %s", e)
            return False

    def update_tenant_token(self, tenant_id: str, new_token: str,
                            new_token_hash: str) -> bool:
        """Rotaciona o token de um tenant (token + hash atualizados atomicamente)."""
        ph = self._placeholder()
        try:
            if USE_POSTGRES:
                cur = self._conn().cursor()
                cur.execute(
                    f"UPDATE tenants SET token={ph}, token_hash={ph} WHERE tenant_id={ph}",
                    (new_token, new_token_hash, tenant_id)
                )
                self._conn().commit()
                cur.close()
            else:
                self._conn().execute(
                    f"UPDATE tenants SET token={ph}, token_hash={ph} WHERE tenant_id={ph}",
                    (new_token, new_token_hash, tenant_id)
                )
                self._conn().commit()
            return True
        except Exception as e:
            logger.error("update_tenant_token error: %s", e)
            return False

    def create_tenant(self, tenant_id: str, name: str, token: str,
                      plan: str = "free", max_hosts: int = 1,
                      email: str = "",
                      stripe_customer_id: str = "",
                      stripe_subscription_id: str = "") -> bool:
        ph = self._placeholder()
        try:
            if USE_POSTGRES:
                # Hash token antes de salvar — nunca armazena plaintext
                try:
                    from security import hash_token as _ht
                    _token_hash = _ht(token)
                except Exception:
                    _token_hash = None

                cur = self._conn().cursor()
                cur.execute(f"""
                    INSERT INTO tenants
                        (tenant_id, name, token, token_hash, plan, max_hosts, email,
                         stripe_customer_id, stripe_subscription_id)
                    VALUES ({ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph})
                    ON CONFLICT (tenant_id) DO NOTHING
                """, (tenant_id, name, token, _token_hash, plan, max_hosts, email,
                      stripe_customer_id, stripe_subscription_id))
                self._conn().commit()
                cur.close()
            else:
                try:
                    from security import hash_token as _ht
                    _token_hash = _ht(token)
                except Exception:
                    _token_hash = None

                self._conn().execute(f"""
                    INSERT OR IGNORE INTO tenants
                        (tenant_id, name, token, token_hash, plan, max_hosts, email,
                         stripe_customer_id, stripe_subscription_id)
                    VALUES ({ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph})
                """, (tenant_id, name, token, _token_hash, plan, max_hosts, email,
                      stripe_customer_id, stripe_subscription_id))
                self._conn().commit()
            return True
        except Exception as e:
            logger.error("create_tenant error: %s", e)
            return False

    def _exec_sql(self, sql: str, params: tuple = ()) -> bool:
        """
        Executa SQL arbitrário de forma segura (usado pelo webhook handler).
        Suporta ? (SQLite) e %s (PostgreSQL) automaticamente.
        """
        ph = self._placeholder()
        # Normaliza placeholder para o backend correto
        if ph == "%s" and "?" in sql:
            sql = sql.replace("?", "%s")
        elif ph == "?" and "%s" in sql:
            sql = sql.replace("%s", "?")
        try:
            conn = self._conn()
            if USE_POSTGRES:
                cur = conn.cursor()
                cur.execute(sql, params)
                conn.commit()
                cur.close()
            else:
                conn.execute(sql, params)
                conn.commit()
            return True
        except Exception as exc:
            logger.error("_exec_sql error: %s | sql=%s", exc, sql[:80])
            return False

    # ── Migrations (adiciona colunas novas em DBs existentes) ─────

    def _migrate_schema(self):
        """
        Adiciona colunas ausentes em bancos pré-existentes.
        Seguro de rodar múltiplas vezes — ignora colunas que já existem.
        """
        migrations = {
            # tabela: [(coluna, definição), ...]
            "events": [
                ("tenant_id",    "TEXT NOT NULL DEFAULT 'default'"),
            ],
            "baselines": [
                ("tenant_id",    "TEXT NOT NULL DEFAULT 'default'"),
            ],
            "event_stats": [
                ("tenant_id",    "TEXT NOT NULL DEFAULT 'default'"),
            ],
            "tenants": [
                ("email",                  "TEXT DEFAULT ''"),
                ("stripe_customer_id",     "TEXT DEFAULT ''"),
                ("stripe_subscription_id", "TEXT DEFAULT ''"),
                # Security migrations — token hashing e RBAC
                ("token_hash",             "TEXT"),
                ("role",                   "TEXT NOT NULL DEFAULT 'analyst'"),
            ],
        }

        for table, cols in migrations.items():
            for col, definition in cols:
                try:
                    if USE_POSTGRES:
                        cur = self._conn().cursor()
                        cur.execute(
                            f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col} {definition}"
                        )
                        self._conn().commit()
                        cur.close()
                    else:
                        self._conn().execute(
                            f"ALTER TABLE {table} ADD COLUMN {col} {definition}"
                        )
                        self._conn().commit()
                    logger.debug("Migration OK: %s.%s", table, col)
                except Exception:
                    pass  # Coluna já existe ou tabela não existe ainda — ignorar

    # ── Row converters ────────────────────────────────────────────

    @staticmethod
    def _sqlite_row_to_dict(row: "sqlite3.Row") -> dict:
        d = dict(row)
        for field in ("details", "mitre", "tags"):
            if d.get(field):
                try:
                    d[field] = json.loads(d[field])
                except Exception:
                    pass
        return d

    @staticmethod
    def _pg_row_to_dict(row: dict) -> dict:
        """PostgreSQL rows via RealDictCursor já são dicts com JSONB parsed."""
        return dict(row) if row else {}
