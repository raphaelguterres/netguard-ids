"""
NetGuard — Event Repository
Camada de armazenamento de eventos de segurança.
SQLite com índices otimizados para queries SIEM.
Suporta upgrade futuro para PostgreSQL / Elasticsearch.
"""

import sqlite3
import json
import logging
import threading
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger("netguard.storage")

DEFAULT_DB = Path(__file__).parent.parent / "netguard_events.db"


class EventRepository:
    """
    Repositório de eventos de segurança.
    Thread-safe, com índices para queries rápidas.
    """

    def __init__(self, db_path: str = None):
        self.db_path = str(db_path or DEFAULT_DB)
        self._local = threading.local()
        self._init_db()
        logger.info("EventRepository iniciado: %s", self.db_path)

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
        return self._local.conn

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                event_id     TEXT PRIMARY KEY,
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

            CREATE INDEX IF NOT EXISTS idx_events_timestamp  ON events(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_events_severity   ON events(severity);
            CREATE INDEX IF NOT EXISTS idx_events_type       ON events(event_type);
            CREATE INDEX IF NOT EXISTS idx_events_host       ON events(host_id);
            CREATE INDEX IF NOT EXISTS idx_events_rule       ON events(rule_id);

            CREATE TABLE IF NOT EXISTS baselines (
                host_id      TEXT NOT NULL,
                baseline_type TEXT NOT NULL,
                value        TEXT NOT NULL,
                first_seen   TEXT NOT NULL,
                last_seen    TEXT NOT NULL,
                count        INTEGER DEFAULT 1,
                PRIMARY KEY (host_id, baseline_type, value)
            );

            CREATE TABLE IF NOT EXISTS event_stats (
                date         TEXT NOT NULL,
                event_type   TEXT NOT NULL,
                severity     TEXT NOT NULL,
                count        INTEGER DEFAULT 0,
                PRIMARY KEY (date, event_type, severity)
            );
        """)
        conn.commit()
        conn.close()

    def save(self, event) -> bool:
        """Salva um SecurityEvent no banco."""
        try:
            conn = self._conn()
            conn.execute("""
                INSERT OR REPLACE INTO events
                (event_id, timestamp, host_id, event_type, severity, source,
                 rule_id, rule_name, details, mitre, tags, raw, acknowledged)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                event.event_id,
                event.timestamp,
                event.host_id,
                event.event_type,
                event.severity,
                event.source,
                event.rule_id,
                event.rule_name,
                json.dumps(event.details),
                json.dumps(event.mitre.to_dict() if hasattr(event.mitre, 'to_dict') else {}),
                json.dumps(event.tags),
                event.raw,
                1 if event.acknowledged else 0,
            ))
            # Update stats
            date = event.timestamp[:10]
            conn.execute("""
                INSERT INTO event_stats (date, event_type, severity, count)
                VALUES (?,?,?,1)
                ON CONFLICT(date, event_type, severity)
                DO UPDATE SET count = count + 1
            """, (date, event.event_type, event.severity))
            conn.commit()
            return True
        except Exception as e:
            logger.error("Error saving event: %s", e)
            return False

    def save_batch(self, events: list) -> int:
        """Salva múltiplos eventos em batch."""
        saved = 0
        for e in events:
            if self.save(e):
                saved += 1
        return saved

    def query(
        self,
        limit:      int  = 100,
        offset:     int  = 0,
        severity:   str  = None,
        event_type: str  = None,
        host_id:    str  = None,
        rule_id:    str  = None,
        since:      str  = None,
        acknowledged: bool = None,
    ) -> List[dict]:
        """Query flexível de eventos."""
        sql    = "SELECT * FROM events WHERE 1=1"
        params = []

        if severity:
            sql += " AND severity = ?"
            params.append(severity.upper())
        if event_type:
            sql += " AND event_type = ?"
            params.append(event_type)
        if host_id:
            sql += " AND host_id = ?"
            params.append(host_id)
        if rule_id:
            sql += " AND rule_id = ?"
            params.append(rule_id)
        if since:
            sql += " AND timestamp >= ?"
            params.append(since)
        if acknowledged is not None:
            sql += " AND acknowledged = ?"
            params.append(1 if acknowledged else 0)

        sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params += [limit, offset]

        try:
            rows = self._conn().execute(sql, params).fetchall()
            return [self._row_to_dict(r) for r in rows]
        except Exception as e:
            logger.error("Query error: %s", e)
            return []

    def count(self, **filters) -> int:
        sql    = "SELECT COUNT(*) FROM events WHERE 1=1"
        params = []
        if filters.get('severity'):
            sql += " AND severity = ?"; params.append(filters['severity'].upper())
        if filters.get('event_type'):
            sql += " AND event_type = ?"; params.append(filters['event_type'])
        if filters.get('since'):
            sql += " AND timestamp >= ?"; params.append(filters['since'])
        try:
            return self._conn().execute(sql, params).fetchone()[0]
        except:
            return 0

    def stats(self) -> dict:
        """Estatísticas agregadas para o dashboard."""
        conn = self._conn()
        try:
            total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            by_sev = {}
            for row in conn.execute(
                "SELECT severity, COUNT(*) as c FROM events GROUP BY severity"
            ):
                by_sev[row['severity']] = row['c']

            by_type = {}
            for row in conn.execute(
                "SELECT event_type, COUNT(*) as c FROM events GROUP BY event_type ORDER BY c DESC LIMIT 10"
            ):
                by_type[row['event_type']] = row['c']

            # Last 24h
            since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
            last24 = conn.execute(
                "SELECT COUNT(*) FROM events WHERE timestamp >= ?", (since,)
            ).fetchone()[0]

            # Hourly last 24h
            hourly = []
            for row in conn.execute("""
                SELECT strftime('%Y-%m-%dT%H:00:00Z', timestamp) as hour,
                       COUNT(*) as c
                FROM events
                WHERE timestamp >= ?
                GROUP BY hour ORDER BY hour
            """, (since,)):
                hourly.append({"hour": row['hour'], "c": row['c']})

            return {
                "total":      total,
                "by_severity": by_sev,
                "by_type":    by_type,
                "last_24h":   last24,
                "hourly":     hourly,
            }
        except Exception as e:
            logger.error("Stats error: %s", e)
            return {}

    # ── Baseline management ───────────────────────────────────────

    def get_baseline(self, host_id: str, baseline_type: str) -> set:
        """Retorna baseline como set de valores."""
        try:
            rows = self._conn().execute(
                "SELECT value FROM baselines WHERE host_id=? AND baseline_type=?",
                (host_id, baseline_type)
            ).fetchall()
            return {r['value'] for r in rows}
        except:
            return set()

    def update_baseline(self, host_id: str, baseline_type: str, value: str):
        """Adiciona ou atualiza um valor no baseline."""
        now = datetime.now(timezone.utc).isoformat()
        try:
            self._conn().execute("""
                INSERT INTO baselines (host_id, baseline_type, value, first_seen, last_seen, count)
                VALUES (?,?,?,?,?,1)
                ON CONFLICT(host_id, baseline_type, value)
                DO UPDATE SET last_seen=?, count=count+1
            """, (host_id, baseline_type, value, now, now, now))
            self._conn().commit()
        except Exception as e:
            logger.error("Baseline update error: %s", e)

    def update_baseline_batch(self, host_id: str, baseline_type: str, values: list):
        for v in values:
            self.update_baseline(host_id, baseline_type, str(v))

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        for field in ('details', 'mitre', 'tags'):
            if d.get(field):
                try:
                    d[field] = json.loads(d[field])
                except:
                    pass
        return d
