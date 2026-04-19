"""
NetGuard IDS — Incident Engine
Agrupa eventos e alertas EDR em incidentes rastreáveis com severidade, timeline e status.
"""
from __future__ import annotations  # noqa: F401

import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger("netguard.incident")

SCHEMA = """
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
CREATE TABLE IF NOT EXISTS incident_timeline (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    tenant_id   TEXT    NOT NULL DEFAULT 'default',
    ts          TEXT    NOT NULL,
    actor       TEXT    NOT NULL DEFAULT 'system',
    action      TEXT    NOT NULL,
    detail      TEXT    NOT NULL DEFAULT ''
);
"""

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class IncidentEngine:
    def __init__(self, db_path: str, tenant_id: str = "default"):
        self.db_path   = db_path
        self.tenant_id = tenant_id
        self._lock     = threading.Lock()
        self._init_db()

    def _db(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        with self._db() as c:
            c.executescript(SCHEMA)

    # ── Criar incidente ───────────────────────────────────────────
    def open_incident(self, title: str, severity: str = "medium",
                      source: str = "edr", source_ip: str = None,
                      host_id: str = None, summary: str = "",
                      event_ids: list = None, tags: list = None,
                      mitre_tactic: str = None, mitre_tech: str = None) -> dict:
        now = _now()
        with self._db() as c:
            cur = c.execute(
                "INSERT INTO incidents(tenant_id,title,severity,status,source,source_ip,"
                "host_id,event_ids,tags,summary,opened_at,updated_at,mitre_tactic,mitre_tech) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (self.tenant_id, title, severity, "open", source,
                 source_ip, host_id,
                 json.dumps(event_ids or []),
                 json.dumps(tags or []),
                 summary, now, now, mitre_tactic, mitre_tech)
            )
            iid = cur.lastrowid
            c.execute(
                "INSERT INTO incident_timeline(incident_id,tenant_id,ts,actor,action,detail) "
                "VALUES(?,?,?,?,?,?)",
                (iid, self.tenant_id, now, "system", "opened",
                 f"Incidente criado por {source}: {title}")
            )
        logger.warning("INCIDENT OPENED | id=%d | sev=%s | %s", iid, severity, title)
        return self.get_incident(iid)

    # ── Atualizar status ──────────────────────────────────────────
    def update_status(self, iid: int, status: str, actor: str = "analyst",
                      note: str = "") -> dict:
        allowed = {"open", "investigating", "contained", "resolved", "false_positive"}
        if status not in allowed:
            raise ValueError(f"Status inválido: {status}")
        now = _now()
        closed = now if status in ("resolved", "false_positive") else None
        with self._db() as c:
            c.execute(
                "UPDATE incidents SET status=?,updated_at=?,closed_at=COALESCE(?,closed_at) "
                "WHERE id=? AND tenant_id=?",
                (status, now, closed, iid, self.tenant_id)
            )
            c.execute(
                "INSERT INTO incident_timeline(incident_id,tenant_id,ts,actor,action,detail) "
                "VALUES(?,?,?,?,?,?)",
                (iid, self.tenant_id, now, actor, f"status→{status}", note)
            )
        return self.get_incident(iid)

    def assign(self, iid: int, assignee: str, actor: str = "analyst") -> dict:
        now = _now()
        with self._db() as c:
            c.execute("UPDATE incidents SET assigned_to=?,updated_at=? WHERE id=? AND tenant_id=?",
                      (assignee, now, iid, self.tenant_id))
            c.execute(
                "INSERT INTO incident_timeline(incident_id,tenant_id,ts,actor,action,detail) "
                "VALUES(?,?,?,?,?,?)",
                (iid, self.tenant_id, now, actor, "assigned", f"Atribuído a: {assignee}")
            )
        return self.get_incident(iid)

    def add_note(self, iid: int, note: str, actor: str = "analyst") -> dict:
        now = _now()
        with self._db() as c:
            c.execute("UPDATE incidents SET updated_at=? WHERE id=? AND tenant_id=?",
                      (now, iid, self.tenant_id))
            c.execute(
                "INSERT INTO incident_timeline(incident_id,tenant_id,ts,actor,action,detail) "
                "VALUES(?,?,?,?,?,?)",
                (iid, self.tenant_id, now, actor, "note", note)
            )
        return self.get_incident(iid)

    # ── Leitura ───────────────────────────────────────────────────
    def get_incident(self, iid: int) -> Optional[dict]:
        with self._db() as c:
            row = c.execute(
                "SELECT * FROM incidents WHERE id=? AND tenant_id=?",
                (iid, self.tenant_id)
            ).fetchone()
        return _enrich(dict(row)) if row else None

    def list_incidents(self, status: str = None, severity: str = None,
                       limit: int = 50) -> list:
        q, p = "SELECT * FROM incidents WHERE tenant_id=?", [self.tenant_id]
        if status:
            q += " AND status=?"; p.append(status)
        if severity:
            q += " AND severity=?"; p.append(severity)
        q += " ORDER BY id DESC LIMIT ?"
        p.append(limit)
        with self._db() as c:
            rows = c.execute(q, p).fetchall()
        return [_enrich(dict(r)) for r in rows]

    def get_timeline(self, iid: int) -> list:
        with self._db() as c:
            rows = c.execute(
                "SELECT * FROM incident_timeline WHERE incident_id=? AND tenant_id=? ORDER BY id ASC",
                (iid, self.tenant_id)
            ).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> dict:
        with self._db() as c:
            total  = c.execute("SELECT COUNT(*) FROM incidents WHERE tenant_id=?",
                               (self.tenant_id,)).fetchone()[0]
            open_n = c.execute("SELECT COUNT(*) FROM incidents WHERE tenant_id=? AND status='open'",
                               (self.tenant_id,)).fetchone()[0]
            crit   = c.execute("SELECT COUNT(*) FROM incidents WHERE tenant_id=? AND severity='critical' AND status!='resolved' AND status!='false_positive'",
                               (self.tenant_id,)).fetchone()[0]
            mttr_row = c.execute(
                "SELECT AVG((julianday(closed_at)-julianday(opened_at))*1440) "
                "FROM incidents WHERE tenant_id=? AND closed_at IS NOT NULL",
                (self.tenant_id,)
            ).fetchone()[0]
        return {
            "total": total, "open": open_n, "critical_open": crit,
            "mttr_minutes": round(mttr_row, 1) if mttr_row else None,
        }

    # ── Auto-agrupamento de eventos EDR ──────────────────────────
    def ingest_edr_alert(self, alert: dict) -> Optional[dict]:
        """
        Recebe um alerta do EDR Sentinel e decide se abre um novo incidente
        ou agrupa em um existente (mesmo host + mesma hora).
        Retorna o incidente criado/atualizado, ou None se abaixo do limiar.
        """
        score = alert.get("score", 0)
        if score < 30:
            return None  # abaixo do limiar mínimo

        severity = ("critical" if score >= 75 else
                    "high"     if score >= 55 else
                    "medium"   if score >= 30 else "low")
        host     = alert.get("host_id") or alert.get("hostname", "unknown")
        proc     = alert.get("process_name", "?")
        title    = f"[EDR] Processo suspeito: {proc} em {host}"
        findings = alert.get("findings", [])
        summary  = "; ".join(f.get("reason", "") for f in findings if f.get("reason"))

        # Verifica incidente aberto recente para o mesmo host (janela 30 min)
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=30)
        with self._db() as c:
            existing = c.execute(
                "SELECT id FROM incidents WHERE tenant_id=? AND host_id=? "
                "AND source='edr' AND status='open' AND opened_at > ? ORDER BY id DESC LIMIT 1",
                (self.tenant_id, host, cutoff.strftime("%Y-%m-%dT%H:%M:%SZ"))
            ).fetchone()

        if existing:
            iid = existing["id"]
            self.add_note(iid, f"Novo alerta EDR agrupado: {proc} (score={score})", actor="edr")
            # Escalona severidade se necessário
            inc = self.get_incident(iid)
            if SEV_ORDER.get(severity, 0) > SEV_ORDER.get(inc["severity"], 0):
                with self._db() as c:
                    c.execute("UPDATE incidents SET severity=?,updated_at=? WHERE id=?",
                              (severity, _now(), iid))
            return self.get_incident(iid)

        return self.open_incident(
            title=title, severity=severity, source="edr",
            source_ip=alert.get("source_ip"),
            host_id=host,
            summary=summary,
            tags=["edr", proc],
        )


# ── Helpers ───────────────────────────────────────────────────────
def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _enrich(d: dict) -> dict:
    for f in ("event_ids", "tags"):
        try:
            d[f] = json.loads(d.get(f) or "[]")
        except Exception:
            d[f] = []
    d["age_minutes"] = None
    try:
        opened = datetime.strptime(d["opened_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        d["age_minutes"] = int((datetime.now(timezone.utc) - opened).total_seconds() / 60)
    except Exception:
        pass
    return d


# ── Singleton ─────────────────────────────────────────────────────
_engines: dict[str, IncidentEngine] = {}
_engines_lock = threading.Lock()

def get_incident_engine(db_path: str, tenant_id: str = "default") -> IncidentEngine:
    key = f"{db_path}::{tenant_id}"
    with _engines_lock:
        if key not in _engines:
            _engines[key] = IncidentEngine(db_path, tenant_id)
    return _engines[key]
