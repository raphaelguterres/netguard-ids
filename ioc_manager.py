"""
NetGuard IDS — IOC Manager
Gerencia Indicadores de Comprometimento (IOCs) customizados por tenant.

Suporta:
  - IP addresses (IPv4 / IPv6)
  - Domains / hostnames
  - File hashes (MD5, SHA1, SHA256)
  - URLs

Uso:
    from ioc_manager import IOCManager, get_ioc_manager
    mgr = get_ioc_manager(repo)
    hit = mgr.check_ip("1.2.3.4", tenant_id="abc")
    # hit = {"type": "ip", "value": "1.2.3.4", "threat": "C2 Server", ...}
"""

from __future__ import annotations  # noqa: F401

import csv
import hashlib  # noqa: F401
import io
import ipaddress
import json
import logging
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("ids.ioc")

# ── Tipos suportados ──────────────────────────────────────────────────────────
IOC_TYPES = {"ip", "domain", "hash", "url"}

# ── Regex helpers ─────────────────────────────────────────────────────────────
_RE_IPV4    = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_RE_HASH_MD5    = re.compile(r"^[a-fA-F0-9]{32}$")
_RE_HASH_SHA1   = re.compile(r"^[a-fA-F0-9]{40}$")
_RE_HASH_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_RE_URL     = re.compile(r"^https?://", re.IGNORECASE)
_RE_DOMAIN  = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]{1,253}[a-zA-Z0-9]$")


def _detect_ioc_type(value: str) -> Optional[str]:
    """Detecta automaticamente o tipo de IOC a partir do valor."""
    v = value.strip()
    if _RE_IPV4.match(v):
        try:
            ipaddress.ip_address(v)
            return "ip"
        except ValueError:
            pass
    if ":" in v:
        try:
            ipaddress.ip_address(v)
            return "ip"
        except ValueError:
            pass
    if _RE_HASH_MD5.match(v) or _RE_HASH_SHA1.match(v) or _RE_HASH_SHA256.match(v):
        return "hash"
    if _RE_URL.match(v):
        return "url"
    if _RE_DOMAIN.match(v) and "." in v:
        return "domain"
    return None


def _normalize(value: str, ioc_type: str) -> str:
    """Normaliza o valor do IOC para comparação."""
    v = value.strip().lower()
    if ioc_type == "hash":
        return v  # hashes já são hex
    if ioc_type == "ip":
        return v
    if ioc_type == "domain":
        return v.rstrip(".")
    return v


# ── DDL ───────────────────────────────────────────────────────────────────────
DDL_IOCS = """
CREATE TABLE IF NOT EXISTS ioc_list (
    ioc_id      TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL DEFAULT 'default',
    ioc_type    TEXT NOT NULL,          -- ip | domain | hash | url
    value       TEXT NOT NULL,          -- valor normalizado
    value_raw   TEXT NOT NULL,          -- valor original
    threat_name TEXT NOT NULL DEFAULT '',
    confidence  INTEGER NOT NULL DEFAULT 80,   -- 0-100
    source      TEXT NOT NULL DEFAULT 'manual',
    tags        TEXT NOT NULL DEFAULT '[]',    -- JSON array
    notes       TEXT DEFAULT '',
    active      INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    hit_count   INTEGER NOT NULL DEFAULT 0,
    last_hit    TEXT DEFAULT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ioc_tenant_type_val
    ON ioc_list (tenant_id, ioc_type, value);
CREATE INDEX IF NOT EXISTS idx_ioc_tenant_active
    ON ioc_list (tenant_id, active);
CREATE INDEX IF NOT EXISTS idx_ioc_type
    ON ioc_list (ioc_type, active);
"""

DDL_IOC_HITS = """
CREATE TABLE IF NOT EXISTS ioc_hits (
    hit_id      TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    ioc_id      TEXT NOT NULL,
    event_id    TEXT,
    matched_val TEXT NOT NULL,
    context     TEXT DEFAULT '{}',
    hit_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ioc_hits_tenant
    ON ioc_hits (tenant_id, hit_at DESC);
"""


class IOCManager:
    """
    Gerencia IOCs por tenant. Thread-safe via SQLite WAL.

    Uso básico:
        mgr = IOCManager(db_path="netguard_events.db", tenant_id="abc")
        mgr.import_csv(csv_bytes)
        hit = mgr.check_ip("1.2.3.4")
    """

    def __init__(self, db_path: str = "netguard_events.db",
                 tenant_id: str = "default"):
        self.db_path  = db_path
        self.tenant_id = tenant_id
        self._init_db()

        # Cache em memória para performance (invalidado em imports)
        self._cache_ip:     dict[str, dict]  = {}
        self._cache_domain: dict[str, dict]  = {}
        self._cache_hash:   dict[str, dict]  = {}
        self._cache_loaded = False

    # ── Init ──────────────────────────────────────────────────────────────────

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(DDL_IOCS + DDL_IOC_HITS)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    # ── Cache ─────────────────────────────────────────────────────────────────

    def _load_cache(self) -> None:
        """Carrega IOCs ativos em memória para checagens rápidas."""
        self._cache_ip     = {}
        self._cache_domain = {}
        self._cache_hash   = {}
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM ioc_list WHERE tenant_id=? AND active=1",
                (self.tenant_id,)
            ).fetchall()
        for r in rows:
            row = dict(r)
            t   = row["ioc_type"]
            v   = row["value"]
            if t == "ip":
                self._cache_ip[v] = row
            elif t == "domain":
                self._cache_domain[v] = row
            elif t == "hash":
                self._cache_hash[v] = row
        self._cache_loaded = True
        logger.debug("IOC cache loaded: %d IPs, %d domains, %d hashes",
                     len(self._cache_ip), len(self._cache_domain), len(self._cache_hash))

    def invalidate_cache(self) -> None:
        self._cache_loaded = False

    def _ensure_cache(self) -> None:
        if not self._cache_loaded:
            self._load_cache()

    # ── Check ─────────────────────────────────────────────────────────────────

    def check_ip(self, ip: str, event_id: str = "") -> Optional[dict]:
        """Verifica se um IP está na lista de IOCs. Retorna o hit ou None."""
        self._ensure_cache()
        normalized = _normalize(ip, "ip")
        hit = self._cache_ip.get(normalized)
        if hit:
            self._record_hit(hit["ioc_id"], normalized, event_id)
            return self._format_hit(hit, normalized)
        return None

    def check_domain(self, domain: str, event_id: str = "") -> Optional[dict]:
        """Verifica se um domínio está na lista de IOCs."""
        self._ensure_cache()
        normalized = _normalize(domain, "domain")
        hit = self._cache_domain.get(normalized)
        if not hit:
            # Tenta match por sufixo (subdomínio)
            parts = normalized.split(".")
            for i in range(1, len(parts)):
                parent = ".".join(parts[i:])
                hit = self._cache_domain.get(parent)
                if hit:
                    break
        if hit:
            self._record_hit(hit["ioc_id"], normalized, event_id)
            return self._format_hit(hit, normalized)
        return None

    def check_hash(self, file_hash: str, event_id: str = "") -> Optional[dict]:
        """Verifica se um hash de arquivo está na lista de IOCs."""
        self._ensure_cache()
        normalized = _normalize(file_hash, "hash")
        hit = self._cache_hash.get(normalized)
        if hit:
            self._record_hit(hit["ioc_id"], normalized, event_id)
            return self._format_hit(hit, normalized)
        return None

    def check_all(self, ip: str = "", domain: str = "",
                  file_hash: str = "", event_id: str = "") -> list[dict]:
        """Checa múltiplos valores e retorna lista de hits."""
        hits = []
        if ip:
            h = self.check_ip(ip, event_id)
            if h:
                hits.append(h)
        if domain:
            h = self.check_domain(domain, event_id)
            if h:
                hits.append(h)
        if file_hash:
            h = self.check_hash(file_hash, event_id)
            if h:
                hits.append(h)
        return hits

    def _format_hit(self, row: dict, matched_val: str) -> dict:
        return {
            "ioc_id":      row["ioc_id"],
            "type":        row["ioc_type"],
            "value":       row["value"],
            "matched":     matched_val,
            "threat_name": row["threat_name"],
            "confidence":  row["confidence"],
            "source":      row["source"],
            "tags":        json.loads(row.get("tags", "[]")),
            "notes":       row.get("notes", ""),
            "hit_count":   row.get("hit_count", 0) + 1,
        }

    def _record_hit(self, ioc_id: str, matched_val: str, event_id: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        try:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE ioc_list SET hit_count=hit_count+1, last_hit=? "
                    "WHERE ioc_id=?",
                    (now, ioc_id)
                )
                conn.execute(
                    "INSERT OR IGNORE INTO ioc_hits VALUES (?,?,?,?,?,?,?)",
                    (str(uuid.uuid4()), self.tenant_id, ioc_id,
                     event_id or None, matched_val, "{}", now)
                )
        except Exception as e:
            logger.debug("IOC hit record failed: %s", e)

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def add_ioc(self, value: str, ioc_type: str = "",
                threat_name: str = "", confidence: int = 80,
                source: str = "manual", tags: list = None,
                notes: str = "") -> dict:
        """Adiciona um IOC manualmente. Retorna o registro criado."""
        value = value.strip()
        if len(value) > 512:
            raise ValueError("IOC value: máximo 512 caracteres")
        if threat_name and len(threat_name) > 120:
            raise ValueError("threat_name: máximo 120 caracteres")
        if notes and len(notes) > 1000:
            raise ValueError("notes: máximo 1000 caracteres")
        if not ioc_type:
            ioc_type = _detect_ioc_type(value)
        if not ioc_type:
            raise ValueError(f"Tipo de IOC não reconhecido para: {value!r}")
        if ioc_type not in IOC_TYPES:
            raise ValueError(f"Tipo inválido: {ioc_type!r}. Use: {IOC_TYPES}")

        normalized = _normalize(value, ioc_type)
        now = datetime.now(timezone.utc).isoformat()
        ioc_id = str(uuid.uuid4())

        row = (
            ioc_id, self.tenant_id, ioc_type, normalized, value,
            threat_name, confidence, source,
            json.dumps(tags or []), notes, 1, now, now, 0, None
        )

        with self._conn() as conn:
            try:
                conn.execute(
                    "INSERT INTO ioc_list VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    row
                )
            except sqlite3.IntegrityError:
                # Atualiza se já existe
                conn.execute(
                    "UPDATE ioc_list SET threat_name=?, confidence=?, source=?, "
                    "tags=?, notes=?, active=1, updated_at=? "
                    "WHERE tenant_id=? AND ioc_type=? AND value=?",
                    (threat_name, confidence, source,
                     json.dumps(tags or []), notes, now,
                     self.tenant_id, ioc_type, normalized)
                )
                existing = conn.execute(
                    "SELECT * FROM ioc_list WHERE tenant_id=? AND ioc_type=? AND value=?",
                    (self.tenant_id, ioc_type, normalized)
                ).fetchone()
                self.invalidate_cache()
                return dict(existing)

        self.invalidate_cache()
        return {
            "ioc_id": ioc_id, "ioc_type": ioc_type, "value": normalized,
            "threat_name": threat_name, "confidence": confidence,
            "source": source, "created_at": now
        }

    def delete_ioc(self, ioc_id: str) -> bool:
        with self._conn() as conn:
            r = conn.execute(
                "DELETE FROM ioc_list WHERE ioc_id=? AND tenant_id=?",
                (ioc_id, self.tenant_id)
            )
        self.invalidate_cache()
        return r.rowcount > 0

    def toggle_ioc(self, ioc_id: str, active: bool) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as conn:
            r = conn.execute(
                "UPDATE ioc_list SET active=?, updated_at=? "
                "WHERE ioc_id=? AND tenant_id=?",
                (1 if active else 0, now, ioc_id, self.tenant_id)
            )
        self.invalidate_cache()
        return r.rowcount > 0

    # ── Import CSV ────────────────────────────────────────────────────────────

    def import_csv(self, csv_bytes: bytes,
                   default_threat: str = "Custom IOC",
                   default_confidence: int = 80) -> dict:
        """
        Importa IOCs de um CSV.

        Formatos suportados:
          1. Uma coluna: valor apenas (tipo detectado automaticamente)
          2. Duas colunas: valor,threat_name
          3. Formato completo: value,type,threat_name,confidence,tags,notes

        Retorna: {"imported": N, "skipped": N, "errors": [...]}
        """
        text = csv_bytes.decode("utf-8-sig", errors="replace")
        reader = csv.reader(io.StringIO(text))

        imported = 0
        skipped  = 0
        errors   = []

        for lineno, row in enumerate(reader, 1):
            if not row or not row[0].strip():
                skipped += 1
                continue
            raw_val = row[0].strip()
            if raw_val.lower() in ("value", "ioc", "indicator", "#"):
                skipped += 1  # header
                continue
            if raw_val.startswith("#"):
                skipped += 1  # comentário
                continue

            # Extrair campos opcionais
            ioc_type    = row[1].strip().lower() if len(row) > 1 else ""
            threat_name = row[2].strip()         if len(row) > 2 else default_threat
            confidence  = int(row[3].strip())    if len(row) > 3 and row[3].strip().isdigit() else default_confidence
            tags_raw    = row[4].strip()          if len(row) > 4 else ""
            notes       = row[5].strip()          if len(row) > 5 else ""
            tags = [t.strip() for t in tags_raw.split(",") if t.strip()] if tags_raw else []

            try:
                self.add_ioc(
                    value=raw_val,
                    ioc_type=ioc_type or "",
                    threat_name=threat_name or default_threat,
                    confidence=confidence,
                    source="csv_import",
                    tags=tags,
                    notes=notes,
                )
                imported += 1
            except ValueError as e:
                errors.append({"line": lineno, "value": raw_val, "error": str(e)})
                skipped += 1
            except Exception as e:
                errors.append({"line": lineno, "value": raw_val, "error": str(e)})
                skipped += 1

        self.invalidate_cache()
        logger.info("IOC import: %d imported, %d skipped, %d errors",
                    imported, skipped, len(errors))
        return {"imported": imported, "skipped": skipped, "errors": errors[:20]}

    # ── Export CSV ────────────────────────────────────────────────────────────

    def export_csv(self) -> bytes:
        """Exporta todos os IOCs ativos como CSV."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM ioc_list WHERE tenant_id=? ORDER BY ioc_type, value",
                (self.tenant_id,)
            ).fetchall()

        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["value", "type", "threat_name", "confidence",
                          "tags", "notes", "source", "active",
                          "hit_count", "created_at"])
        for r in rows:
            r = dict(r)
            tags = ",".join(json.loads(r.get("tags", "[]")))
            writer.writerow([
                r["value_raw"], r["ioc_type"], r["threat_name"],
                r["confidence"], tags, r.get("notes", ""),
                r["source"], r["active"], r["hit_count"], r["created_at"]
            ])
        return buf.getvalue().encode("utf-8")

    # ── List / Stats ──────────────────────────────────────────────────────────

    def list_iocs(self, ioc_type: str = "", active_only: bool = False,
                  limit: int = 500, offset: int = 0) -> list[dict]:
        where = ["tenant_id=?"]
        params: list = [self.tenant_id]
        if ioc_type:
            where.append("ioc_type=?")
            params.append(ioc_type)
        if active_only:
            where.append("active=1")
        params += [limit, offset]
        sql = (
            f"SELECT * FROM ioc_list WHERE {' AND '.join(where)} "
            f"ORDER BY updated_at DESC LIMIT ? OFFSET ?"
        )
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["tags"] = json.loads(d.get("tags", "[]"))
            result.append(d)
        return result

    def count_iocs(self) -> dict:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT ioc_type, active, COUNT(*) as n "
                "FROM ioc_list WHERE tenant_id=? "
                "GROUP BY ioc_type, active",
                (self.tenant_id,)
            ).fetchall()
        stats: dict = {"total": 0, "active": 0, "by_type": {}}
        for r in rows:
            t, active, n = r["ioc_type"], r["active"], r["n"]
            if t not in stats["by_type"]:
                stats["by_type"][t] = {"total": 0, "active": 0}
            stats["by_type"][t]["total"] += n
            stats["total"] += n
            if active:
                stats["by_type"][t]["active"] += n
                stats["active"] += n
        return stats

    def recent_hits(self, limit: int = 50) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT h.*, i.ioc_type, i.threat_name, i.confidence "
                "FROM ioc_hits h "
                "JOIN ioc_list i ON i.ioc_id = h.ioc_id "
                "WHERE h.tenant_id=? "
                "ORDER BY h.hit_at DESC LIMIT ?",
                (self.tenant_id, limit)
            ).fetchall()
        return [dict(r) for r in rows]


# ── Singleton por tenant ──────────────────────────────────────────────────────
_managers: dict[str, IOCManager] = {}


def get_ioc_manager(db_path: str = "netguard_events.db",
                    tenant_id: str = "default") -> IOCManager:
    key = f"{db_path}::{tenant_id}"
    if key not in _managers:
        _managers[key] = IOCManager(db_path=db_path, tenant_id=tenant_id)
    return _managers[key]
