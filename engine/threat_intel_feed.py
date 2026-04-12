"""
NetGuard IDS — Threat Intelligence Auto-Feed Engine
Puxa IOCs automaticamente de fontes abertas:
  • Abuse.ch URLhaus   — URLs de malware
  • Abuse.ch ThreatFox — IOCs (IP:porta, domínio, hash)
  • Feodo Tracker      — IPs de C2 botnet
  • Spamhaus DROP      — IPs/ASNs de spam
"""
from __future__ import annotations

import gzip
import io  # noqa: F401
import json
import logging
import re  # noqa: F401
import sqlite3
import threading
import time
from datetime import datetime, timezone, timedelta  # noqa: F401
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError  # noqa: F401

logger = logging.getLogger("netguard.threat_intel")

# ── Schema ────────────────────────────────────────────────────────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS ti_iocs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type     TEXT NOT NULL,           -- ip, domain, url, md5, sha256
    ioc_value    TEXT NOT NULL,
    source       TEXT NOT NULL,           -- urlhaus, threatfox, feodo, spamhaus
    threat_type  TEXT NOT NULL DEFAULT '',
    confidence   INTEGER NOT NULL DEFAULT 50,
    severity     TEXT NOT NULL DEFAULT 'medium',
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    tags         TEXT NOT NULL DEFAULT '[]',
    active       INTEGER NOT NULL DEFAULT 1,
    tenant_id    TEXT NOT NULL DEFAULT 'global',
    UNIQUE(ioc_value, source, tenant_id)
);

CREATE TABLE IF NOT EXISTS ti_feed_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    feed        TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    status      TEXT NOT NULL DEFAULT 'running',  -- running, ok, error
    added       INTEGER NOT NULL DEFAULT 0,
    updated     INTEGER NOT NULL DEFAULT 0,
    removed     INTEGER NOT NULL DEFAULT 0,
    error_msg   TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_ti_iocs_value  ON ti_iocs(ioc_value);
CREATE INDEX IF NOT EXISTS idx_ti_iocs_type   ON ti_iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_ti_iocs_source ON ti_iocs(source);
CREATE INDEX IF NOT EXISTS idx_ti_iocs_active ON ti_iocs(active, tenant_id);
"""

# ── Feed config ───────────────────────────────────────────────────────────────
FEEDS = {
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "label": "Abuse.ch URLhaus",
        "description": "URLs de distribuição de malware (últimas 30 dias)",
        "interval_h": 6,
        "timeout": 30,
    },
    "threatfox_ip": {
        "url": "https://threatfox-api.abuse.ch/api/v1/",
        "label": "Abuse.ch ThreatFox — IPs",
        "description": "IPs de C2 e infraestrutura de malware",
        "interval_h": 6,
        "timeout": 30,
    },
    "feodo": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "label": "Feodo Tracker",
        "description": "IPs de botnets (Emotet, TrickBot, Dridex, QakBot)",
        "interval_h": 4,
        "timeout": 30,
    },
    "threatfox_domain": {
        "url": "https://threatfox-api.abuse.ch/api/v1/",
        "label": "Abuse.ch ThreatFox — Domínios",
        "description": "Domínios de C2 e phishing",
        "interval_h": 12,
        "timeout": 30,
    },
}


class ThreatIntelFeed:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock   = threading.Lock()
        self._stop   = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_run: dict[str, float] = {}
        self._init_db()

    def _db(self):
        conn = sqlite3.connect(self.db_path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self):
        with self._db() as c:
            c.executescript(SCHEMA)

    # ── Public API ────────────────────────────────────────────────────────────

    def start_scheduler(self, interval_check_s: int = 300):
        """Inicia thread de agendamento de feeds em background."""
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._scheduler_loop,
            args=(interval_check_s,),
            daemon=True,
            name="ti-feed-scheduler",
        )
        self._thread.start()
        logger.info("ThreatIntel feed scheduler iniciado (check=%ds)", interval_check_s)

    def stop_scheduler(self):
        self._stop.set()

    def refresh_feed(self, feed_name: str) -> dict:
        """Executa refresh imediato de um feed específico."""
        fn = {
            "urlhaus":        self._pull_urlhaus,
            "threatfox_ip":   self._pull_threatfox_ips,
            "feodo":          self._pull_feodo,
            "threatfox_domain": self._pull_threatfox_domains,
        }.get(feed_name)
        if not fn:
            return {"ok": False, "error": f"Feed desconhecido: {feed_name}"}
        return fn()

    def refresh_all(self) -> dict:
        """Executa refresh de todos os feeds."""
        results = {}
        for feed_name in FEEDS:
            try:
                results[feed_name] = self.refresh_feed(feed_name)
            except Exception as e:
                results[feed_name] = {"ok": False, "error": str(e)}
        return results

    def lookup(self, value: str, tenant_id: str = "global") -> Optional[dict]:
        """Procura um IOC na base TI. Retorna None se não encontrado."""
        v = value.strip().lower()
        with self._db() as c:
            row = c.execute(
                "SELECT * FROM ti_iocs WHERE ioc_value=? AND active=1 "
                "AND (tenant_id='global' OR tenant_id=?) "
                "ORDER BY confidence DESC LIMIT 1",
                (v, tenant_id),
            ).fetchone()
        return dict(row) if row else None

    def bulk_lookup(self, values: list[str], tenant_id: str = "global") -> dict:
        """Verifica múltiplos valores. Retorna dict valor→match."""
        if not values:
            return {}
        vs = [v.strip().lower() for v in values]
        ph = ",".join("?" * len(vs))
        with self._db() as c:
            rows = c.execute(
                f"SELECT * FROM ti_iocs WHERE ioc_value IN ({ph}) AND active=1 "
                f"AND (tenant_id='global' OR tenant_id=?)",
                vs + [tenant_id],
            ).fetchall()
        out = {}
        for r in rows:
            d = dict(r)
            key = d["ioc_value"]
            if key not in out or d["confidence"] > out[key]["confidence"]:
                out[key] = d
        return out

    def stats(self, tenant_id: str = "global") -> dict:
        with self._db() as c:
            total   = c.execute("SELECT COUNT(*) FROM ti_iocs WHERE active=1 AND (tenant_id='global' OR tenant_id=?)", (tenant_id,)).fetchone()[0]
            by_type = c.execute(
                "SELECT ioc_type, COUNT(*) as cnt FROM ti_iocs WHERE active=1 AND (tenant_id='global' OR tenant_id=?) GROUP BY ioc_type",
                (tenant_id,),
            ).fetchall()
            by_src  = c.execute(
                "SELECT source, COUNT(*) as cnt FROM ti_iocs WHERE active=1 AND (tenant_id='global' OR tenant_id=?) GROUP BY source",
                (tenant_id,),
            ).fetchall()
            runs    = c.execute(
                "SELECT * FROM ti_feed_runs ORDER BY id DESC LIMIT 20",
            ).fetchall()
        return {
            "total_iocs": total,
            "by_type":  {r["ioc_type"]: r["cnt"] for r in by_type},
            "by_source":{r["source"]:   r["cnt"] for r in by_src},
            "last_runs": [dict(r) for r in runs],
            "feeds": {
                name: {
                    **cfg,
                    "last_run_ago_h": round(
                        (time.time() - self._last_run.get(name, 0)) / 3600, 1
                    ) if self._last_run.get(name) else None,
                }
                for name, cfg in FEEDS.items()
            },
        }

    def list_iocs(self, source: str = None, ioc_type: str = None,
                  limit: int = 500, offset: int = 0,
                  tenant_id: str = "global") -> list:
        clauses = ["active=1", "(tenant_id='global' OR tenant_id=?)"]
        params  = [tenant_id]
        if source:
            clauses.append("source=?"); params.append(source)
        if ioc_type:
            clauses.append("ioc_type=?"); params.append(ioc_type)
        where = " AND ".join(clauses)
        params += [limit, offset]
        with self._db() as c:
            rows = c.execute(
                f"SELECT * FROM ti_iocs WHERE {where} ORDER BY last_seen DESC LIMIT ? OFFSET ?",
                params,
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Scheduler ─────────────────────────────────────────────────────────────

    def _scheduler_loop(self, interval_s: int):
        # Stagger first run by 30s to let app boot
        time.sleep(30)
        while not self._stop.is_set():
            now = time.time()
            for feed_name, cfg in FEEDS.items():
                last = self._last_run.get(feed_name, 0)
                due  = last + cfg["interval_h"] * 3600
                if now >= due:
                    logger.info("TI Feed due: %s", feed_name)
                    try:
                        res = self.refresh_feed(feed_name)
                        self._last_run[feed_name] = time.time()
                        logger.info("TI Feed %s: added=%d updated=%d",
                                    feed_name, res.get("added", 0), res.get("updated", 0))
                    except Exception as e:
                        logger.error("TI Feed %s error: %s", feed_name, e)
            self._stop.wait(interval_s)

    # ── URLhaus ───────────────────────────────────────────────────────────────

    def _pull_urlhaus(self) -> dict:
        run_id = self._start_run("urlhaus")
        added = updated = 0
        try:
            data = _http_get(FEEDS["urlhaus"]["url"], timeout=30, gzip_ok=True)
            lines = data.decode("utf-8", errors="replace").splitlines()
            now = _now()
            batch = []
            for line in lines:
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.split(",")
                if len(parts) < 6:
                    continue
                # id, dateadded, url, url_status, threat, tags, urlhaus_link, reporter
                try:
                    url   = parts[2].strip().strip('"')
                    sev   = "critical" if parts[4].strip('"') in ("malware_download",) else "high"
                    tags  = parts[5].strip().strip('"') if len(parts) > 5 else ""
                    batch.append(("url", url, "urlhaus", parts[4].strip('"'), 80, sev, now, now, json.dumps(tags.split(","))))
                except Exception:
                    pass
            a, u = self._upsert_batch(batch)
            added, updated = a, u
            self._finish_run(run_id, "ok", added, updated)
            return {"ok": True, "added": added, "updated": updated, "feed": "urlhaus"}
        except Exception as e:
            logger.error("URLhaus pull error: %s", e)
            self._finish_run(run_id, "error", 0, 0, str(e))
            return {"ok": False, "error": str(e), "feed": "urlhaus"}

    # ── ThreatFox ─────────────────────────────────────────────────────────────

    def _pull_threatfox_ips(self) -> dict:
        return self._pull_threatfox("ip:port", "threatfox_ip", "ip")

    def _pull_threatfox_domains(self) -> dict:
        return self._pull_threatfox("domain", "threatfox_domain", "domain")

    def _pull_threatfox(self, ioc_type_filter: str, feed_key: str, ioc_type: str) -> dict:
        run_id = self._start_run(feed_key)
        added = updated = 0
        try:
            payload = json.dumps({
                "query": "get_iocs",
                "days": 7,
            }).encode()
            resp = _http_post(FEEDS["threatfox_ip"]["url"], payload, timeout=30)
            data = json.loads(resp)
            if data.get("query_status") != "ok":
                raise ValueError(f"ThreatFox status: {data.get('query_status')}")

            now   = _now()
            batch = []
            for ioc in (data.get("data") or []):
                if ioc.get("ioc_type") != ioc_type_filter:
                    continue
                val  = ioc.get("ioc", "").strip().lower()
                if not val:
                    continue
                # ip:port → extract IP
                if ":" in val and ioc_type == "ip":
                    val = val.split(":")[0]
                threat = ioc.get("threat_type", "")
                conf   = int(ioc.get("confidence_level", 50))
                sev    = "critical" if conf >= 90 else "high" if conf >= 70 else "medium"
                tags   = json.dumps(ioc.get("tags") or [])
                batch.append((ioc_type, val, feed_key, threat, conf, sev, now, now, tags))

            a, u = self._upsert_batch(batch)
            added, updated = a, u
            self._finish_run(run_id, "ok", added, updated)
            return {"ok": True, "added": added, "updated": updated, "feed": feed_key}
        except Exception as e:
            logger.error("ThreatFox pull error [%s]: %s", feed_key, e)
            self._finish_run(run_id, "error", 0, 0, str(e))
            return {"ok": False, "error": str(e), "feed": feed_key}

    # ── Feodo Tracker ─────────────────────────────────────────────────────────

    def _pull_feodo(self) -> dict:
        run_id = self._start_run("feodo")
        added = updated = 0
        try:
            data = _http_get(FEEDS["feodo"]["url"], timeout=30)
            entries = json.loads(data)
            now = _now()
            batch = []
            for e in entries:
                ip     = e.get("ip_address", "").strip()
                if not ip:
                    continue
                malware = e.get("malware", "Unknown")
                country = e.get("country", "")
                sev     = "critical"
                tags    = json.dumps([malware, country] if country else [malware])
                batch.append(("ip", ip, "feodo", malware, 90, sev, now, now, tags))
            a, u = self._upsert_batch(batch)
            added, updated = a, u
            self._finish_run(run_id, "ok", added, updated)
            return {"ok": True, "added": added, "updated": updated, "feed": "feodo"}
        except Exception as e:
            logger.error("Feodo pull error: %s", e)
            self._finish_run(run_id, "error", 0, 0, str(e))
            return {"ok": False, "error": str(e), "feed": "feodo"}

    # ── DB helpers ────────────────────────────────────────────────────────────

    def _upsert_batch(self, batch: list) -> tuple[int, int]:
        """Insere/atualiza IOCs. Retorna (added, updated)."""
        added = updated = 0
        with self._db() as c:
            for ioc_type, val, source, threat_type, conf, sev, first_seen, last_seen, tags in batch:
                if not val or len(val) > 2048:
                    continue
                val = val.lower().strip()
                existing = c.execute(
                    "SELECT id FROM ti_iocs WHERE ioc_value=? AND source=? AND tenant_id='global'",
                    (val, source),
                ).fetchone()
                if existing:
                    c.execute(
                        "UPDATE ti_iocs SET last_seen=?, confidence=?, active=1 WHERE id=?",
                        (last_seen, conf, existing["id"]),
                    )
                    updated += 1
                else:
                    try:
                        c.execute(
                            "INSERT INTO ti_iocs(ioc_type,ioc_value,source,threat_type,confidence,"
                            "severity,first_seen,last_seen,tags,active,tenant_id) "
                            "VALUES(?,?,?,?,?,?,?,?,?,1,'global')",
                            (ioc_type, val, source, threat_type, conf, sev, first_seen, last_seen, tags),
                        )
                        added += 1
                    except sqlite3.IntegrityError:
                        updated += 1
        return added, updated

    def _start_run(self, feed: str) -> int:
        with self._db() as c:
            cur = c.execute(
                "INSERT INTO ti_feed_runs(feed, started_at, status) VALUES(?,?,?)",
                (feed, _now(), "running"),
            )
            return cur.lastrowid

    def _finish_run(self, run_id: int, status: str, added: int, updated: int, error: str = ""):
        with self._db() as c:
            c.execute(
                "UPDATE ti_feed_runs SET finished_at=?, status=?, added=?, updated=?, error_msg=? WHERE id=?",
                (_now(), status, added, updated, error, run_id),
            )


# ── HTTP helpers ─────────────────────────────────────────────────────────────

def _http_get(url: str, timeout: int = 30, gzip_ok: bool = False) -> bytes:
    headers = {
        "User-Agent": "NetGuard-IDS/1.0 ThreatIntelFeed (security research)",
        "Accept": "application/json, text/csv, */*",
    }
    if gzip_ok:
        headers["Accept-Encoding"] = "gzip"
    req = Request(url, headers=headers)
    with urlopen(req, timeout=timeout) as r:
        raw = r.read()
        # Auto-decompress gzip
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        return raw


def _http_post(url: str, data: bytes, timeout: int = 30) -> bytes:
    headers = {
        "User-Agent": "NetGuard-IDS/1.0 ThreatIntelFeed",
        "Content-Type": "application/json",
    }
    req = Request(url, data=data, headers=headers, method="POST")
    with urlopen(req, timeout=timeout) as r:
        return r.read()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Singleton ────────────────────────────────────────────────────────────────

_feed_instance: Optional[ThreatIntelFeed] = None
_feed_lock = threading.Lock()


def get_ti_feed(db_path: str) -> ThreatIntelFeed:
    global _feed_instance
    with _feed_lock:
        if _feed_instance is None:
            _feed_instance = ThreatIntelFeed(db_path)
    return _feed_instance
