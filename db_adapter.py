"""
NetGuard IDS — Database Adapter
Abstrai SQLite (dev/padrão) e PostgreSQL (produção) via DATABASE_URL.

Uso:
    from db_adapter import get_db
    db = get_db()
    db.execute("SELECT * FROM detections LIMIT 10")
    rows = db.fetchall()
    db.commit()

Variáveis de ambiente:
    DATABASE_URL   postgresql://user:pass@host:5432/dbname   → usa PostgreSQL
    DATABASE_URL   (não definida ou sqlite:///...)            → usa SQLite

SQLite path:
    IDS_DB_PATH    caminho do arquivo .db (default: ids_detections.db)
"""

from __future__ import annotations

import os
import logging
import threading
from contextlib import contextmanager
from typing import Any, Iterator

logger = logging.getLogger("netguard.db")

DATABASE_URL = os.environ.get("DATABASE_URL", "")
_USING_PG    = DATABASE_URL.startswith("postgresql://") or DATABASE_URL.startswith("postgres://")

# ── SQLite backend ────────────────────────────────────────────────

class _SQLiteAdapter:
    """Wrapper sobre sqlite3 com interface unificada."""

    def __init__(self, db_path: str):
        import sqlite3
        self._sqlite3 = sqlite3
        self.db_path  = db_path
        self._local   = threading.local()

    def _conn(self):
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = self._sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = self._sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA cache_size=-8000")  # 8 MB
            self._local.conn = conn
        return self._local.conn

    def execute(self, sql: str, params=()) -> Any:
        # Converte placeholders PostgreSQL (%s) para SQLite (?)
        sql = sql.replace("%s", "?")
        cur = self._conn().execute(sql, params)
        self._last_cur = cur
        return cur

    def executemany(self, sql: str, params_list) -> None:
        sql = sql.replace("%s", "?")
        self._conn().executemany(sql, params_list)

    def executescript(self, script: str) -> None:
        # Converta CREATE TABLE com tipos PostgreSQL para SQLite
        script = _pg_to_sqlite_schema(script)
        self._conn().executescript(script)

    def fetchall(self) -> list:
        return [dict(r) for r in self._last_cur.fetchall()] if hasattr(self, "_last_cur") else []

    def fetchone(self) -> dict | None:
        row = self._last_cur.fetchone() if hasattr(self, "_last_cur") else None
        return dict(row) if row else None

    def commit(self) -> None:
        self._conn().commit()

    def rollback(self) -> None:
        self._conn().rollback()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        try:
            yield
            self.commit()
        except Exception:
            self.rollback()
            raise

    @property
    def lastrowid(self) -> int | None:
        return self._last_cur.lastrowid if hasattr(self, "_last_cur") else None

    @property
    def rowcount(self) -> int:
        return self._last_cur.rowcount if hasattr(self, "_last_cur") else 0

    @property
    def backend(self) -> str:
        return "sqlite"


# ── PostgreSQL backend ────────────────────────────────────────────

class _PostgreSQLAdapter:
    """Wrapper sobre psycopg2 com interface unificada."""

    _pool_lock = threading.Lock()
    _pool: list = []
    _MAX_POOL = 10

    def __init__(self, dsn: str):
        self._dsn   = dsn
        self._local = threading.local()
        self._verify_connection()

    def _verify_connection(self):
        try:
            import psycopg2
            self._psycopg2 = psycopg2
            conn = psycopg2.connect(self._dsn)
            conn.close()
            logger.info("PostgreSQL connection verified: %s", self._dsn.split("@")[-1])
        except Exception as e:
            logger.error("PostgreSQL connection failed: %s", e)
            raise

    def _conn(self):
        if not hasattr(self._local, "conn") or self._local.conn is None or self._local.conn.closed:
            self._local.conn = self._psycopg2.connect(
                self._dsn,
                connect_timeout=10,
                options="-c statement_timeout=30000",  # 30s timeout
            )
            self._local.conn.autocommit = False
        return self._local.conn

    def _cur(self):
        if not hasattr(self._local, "cur") or self._local.cur.closed:
            self._local.cur = self._conn().cursor()
        return self._local.cur

    def execute(self, sql: str, params=()) -> Any:
        # Converte placeholders SQLite (?) para PostgreSQL (%s)
        sql = sql.replace("?", "%s")
        # Converte funções SQLite específicas
        sql = _sqlite_to_pg_sql(sql)
        cur = self._cur()
        cur.execute(sql, params or None)
        self._last_cur = cur
        return cur

    def executemany(self, sql: str, params_list) -> None:
        sql = sql.replace("?", "%s")
        sql = _sqlite_to_pg_sql(sql)
        self._cur().executemany(sql, params_list)

    def executescript(self, script: str) -> None:
        # Converte schema SQLite para PostgreSQL
        script = _sqlite_to_pg_schema(script)
        cur = self._conn().cursor()
        cur.execute(script)
        self._conn().commit()

    def fetchall(self) -> list:
        if not hasattr(self, "_last_cur"):
            return []
        cols = [d[0] for d in self._last_cur.description or []]
        return [dict(zip(cols, row)) for row in self._last_cur.fetchall()]

    def fetchone(self) -> dict | None:
        if not hasattr(self, "_last_cur"):
            return None
        cols = [d[0] for d in self._last_cur.description or []]
        row  = self._last_cur.fetchone()
        return dict(zip(cols, row)) if row else None

    def commit(self) -> None:
        self._conn().commit()

    def rollback(self) -> None:
        try:
            self._conn().rollback()
        except Exception:
            pass

    @contextmanager
    def transaction(self) -> Iterator[None]:
        try:
            yield
            self.commit()
        except Exception:
            self.rollback()
            raise

    @property
    def lastrowid(self) -> int | None:
        try:
            self._last_cur.execute("SELECT lastval()")
            return self._last_cur.fetchone()[0]
        except Exception:
            return None

    @property
    def rowcount(self) -> int:
        return self._last_cur.rowcount if hasattr(self, "_last_cur") else 0

    @property
    def backend(self) -> str:
        return "postgresql"


# ── Schema converters ─────────────────────────────────────────────

def _pg_to_sqlite_schema(sql: str) -> str:
    """Converte tipos PostgreSQL → SQLite para uso com _SQLiteAdapter.executescript."""
    replacements = [
        ("SERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("BIGSERIAL",           "INTEGER"),
        ("VARCHAR(",            "TEXT ("),     # aproximado
        ("BOOLEAN",             "INTEGER"),
        ("TIMESTAMPTZ",         "TEXT"),
        ("TIMESTAMP WITH TIME ZONE", "TEXT"),
        ("::text",              ""),
        ("RETURNING id",        ""),
    ]
    for old, new in replacements:
        sql = sql.replace(old, new)
    return sql

def _sqlite_to_pg_schema(sql: str) -> str:
    """Converte tipos SQLite → PostgreSQL."""
    replacements = [
        ("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY"),
        ("strftime('%Y-%m-%dT%H:%M:%SZ','now')", "NOW()"),
        ("datetime('now')",    "NOW()"),
        ("INSERT OR REPLACE",  "INSERT"),
        ("INSERT OR IGNORE",   "INSERT"),
    ]
    for old, new in replacements:
        sql = sql.replace(old, new)
    return sql

def _sqlite_to_pg_sql(sql: str) -> str:
    """Converte funções SQLite → PostgreSQL em queries dinâmicas."""
    import re
    sql = sql.replace("datetime('now'", "NOW()")
    sql = sql.replace("datetime('now',", "NOW() +")
    # strftime('%Y-%m-%dT%H:00:00', col) → date_trunc('hour', col)
    sql = re.sub(
        r"strftime\('%Y-%m-%dT%H:00:00',\s*(\w+)\)",
        r"date_trunc('hour', \1::timestamptz)",
        sql,
    )
    sql = sql.replace("strftime('%Y-%m-%dT%H:%M:%SZ','now')", "TO_CHAR(NOW(),'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')")
    return sql


# ── Factory & singleton ───────────────────────────────────────────

_db_instance: _SQLiteAdapter | _PostgreSQLAdapter | None = None
_db_lock = threading.Lock()

def get_db(db_path: str | None = None) -> _SQLiteAdapter | _PostgreSQLAdapter:
    """Retorna a instância singleton do adapter de banco.

    Prioridade:
      1. DATABASE_URL=postgresql://...  → PostgreSQL
      2. db_path ou IDS_DB_PATH         → SQLite
    """
    global _db_instance
    if _db_instance is not None:
        return _db_instance
    with _db_lock:
        if _db_instance is not None:
            return _db_instance
        if _USING_PG:
            logger.info("DB backend: PostgreSQL (%s)", DATABASE_URL.split("@")[-1])
            _db_instance = _PostgreSQLAdapter(DATABASE_URL)
        else:
            path = db_path or os.environ.get("IDS_DB_PATH", "ids_detections.db")
            logger.info("DB backend: SQLite (%s)", path)
            _db_instance = _SQLiteAdapter(path)
    return _db_instance

def reset_db() -> None:
    """Força recriação do singleton (útil em testes)."""
    global _db_instance
    with _db_lock:
        _db_instance = None

def db_info() -> dict:
    """Retorna informações sobre o backend ativo."""
    db = get_db()
    return {
        "backend":      db.backend,
        "database_url": DATABASE_URL.split("@")[-1] if _USING_PG else os.environ.get("IDS_DB_PATH","ids_detections.db"),
        "using_pg":     _USING_PG,
    }
