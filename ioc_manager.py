"""
NetGuard IDS - IOC Manager
Manages custom indicators of compromise per tenant.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import logging
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("ids.ioc")

IOC_TYPES = {"ip", "domain", "hash", "url"}

_RE_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_RE_HASH_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
_RE_HASH_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
_RE_HASH_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_RE_URL = re.compile(r"^https?://", re.IGNORECASE)
_RE_DOMAIN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-.]{1,253}[a-zA-Z0-9]$")

DDL_IOCS = """
CREATE TABLE IF NOT EXISTS ioc_list (
    ioc_id      TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL DEFAULT 'default',
    ioc_type    TEXT NOT NULL,
    value       TEXT NOT NULL,
    value_raw   TEXT NOT NULL,
    threat_name TEXT NOT NULL DEFAULT '',
    confidence  INTEGER NOT NULL DEFAULT 80,
    source      TEXT NOT NULL DEFAULT 'manual',
    tags        TEXT NOT NULL DEFAULT '[]',
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


def _detect_ioc_type(value: str) -> Optional[str]:
    raw = str(value or "").strip()
    if not raw:
        return None
    if _RE_IPV4.match(raw):
        try:
            ipaddress.ip_address(raw)
            return "ip"
        except ValueError:
            pass
    if ":" in raw:
        try:
            ipaddress.ip_address(raw)
            return "ip"
        except ValueError:
            pass
    if _RE_HASH_MD5.match(raw) or _RE_HASH_SHA1.match(raw) or _RE_HASH_SHA256.match(raw):
        return "hash"
    if _RE_URL.match(raw):
        return "url"
    if "." in raw and _RE_DOMAIN.match(raw):
        return "domain"
    return None


def _normalize(value: str, ioc_type: str) -> str:
    normalized = str(value or "").strip().lower()
    if ioc_type == "domain":
        return normalized.rstrip(".")
    return normalized


class IOCManager:
    def __init__(self, db_path: str = "netguard_events.db", tenant_id: str = "default"):
        self.db_path = db_path
        self.tenant_id = tenant_id
        self._cache_ip: dict[str, dict] = {}
        self._cache_domain: dict[str, dict] = {}
        self._cache_hash: dict[str, dict] = {}
        self._cache_loaded = False
        self._init_db()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL").close()
        conn.execute("PRAGMA foreign_keys=ON").close()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(DDL_IOCS + DDL_IOC_HITS)

    def _detect_ioc_type(self, value: str) -> str:
        return _detect_ioc_type(value) or "unknown"

    def _serialize_ioc(self, row: dict | sqlite3.Row | None) -> Optional[dict]:
        if not row:
            return None
        data = dict(row)
        tags = data.get("tags", [])
        if isinstance(tags, str):
            try:
                tags = json.loads(tags or "[]")
            except (json.JSONDecodeError, ValueError):
                tags = []
        data["tags"] = tags
        data["id"] = data.get("ioc_id")
        data["enabled"] = int(data.get("active", 1))
        data["value"] = data.get("value_raw") or data.get("value", "")
        return data

    def _get_ioc_row(self, conn: sqlite3.Connection, ioc_id: str):
        return conn.execute(
            "SELECT * FROM ioc_list WHERE ioc_id=? AND tenant_id=?",
            (ioc_id, self.tenant_id),
        ).fetchone()

    def invalidate_cache(self) -> None:
        self._cache_loaded = False

    def _load_cache(self) -> None:
        self._cache_ip = {}
        self._cache_domain = {}
        self._cache_hash = {}
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM ioc_list WHERE tenant_id=? AND active=1",
                (self.tenant_id,),
            ).fetchall()
        for row in rows:
            item = dict(row)
            if item["ioc_type"] == "ip":
                self._cache_ip[item["value"]] = item
            elif item["ioc_type"] == "domain":
                self._cache_domain[item["value"]] = item
            elif item["ioc_type"] == "hash":
                self._cache_hash[item["value"]] = item
        self._cache_loaded = True

    def _ensure_cache(self) -> None:
        if not self._cache_loaded:
            self._load_cache()

    def _format_hit(self, row: dict, matched_val: str) -> dict:
        return {
            "ioc_id": row["ioc_id"],
            "id": row["ioc_id"],
            "type": row["ioc_type"],
            "value": row.get("value_raw") or row["value"],
            "matched": matched_val,
            "threat_name": row["threat_name"],
            "confidence": row["confidence"],
            "source": row["source"],
            "tags": json.loads(row.get("tags", "[]")) if isinstance(row.get("tags"), str) else row.get("tags", []),
            "notes": row.get("notes", ""),
            "hit_count": row.get("hit_count", 0) + 1,
        }

    def _record_hit(self, ioc_id: str, matched_val: str, event_id: str = "") -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as conn:
            conn.execute(
                "UPDATE ioc_list SET hit_count=hit_count+1, last_hit=? WHERE ioc_id=?",
                (now, ioc_id),
            )
            conn.execute(
                "INSERT OR IGNORE INTO ioc_hits VALUES (?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), self.tenant_id, ioc_id, event_id or None, matched_val, "{}", now),
            )
        self.invalidate_cache()

    def check_ip(self, ip: str, event_id: str = "") -> Optional[dict]:
        self._ensure_cache()
        normalized = _normalize(ip, "ip")
        hit = self._cache_ip.get(normalized)
        if not hit:
            return None
        self._record_hit(hit["ioc_id"], normalized, event_id)
        return self._format_hit(hit, normalized)

    def check_domain(self, domain: str, event_id: str = "") -> Optional[dict]:
        self._ensure_cache()
        normalized = _normalize(domain, "domain")
        hit = self._cache_domain.get(normalized)
        if not hit:
            parts = normalized.split(".")
            for index in range(1, len(parts)):
                parent = ".".join(parts[index:])
                hit = self._cache_domain.get(parent)
                if hit:
                    break
        if not hit:
            return None
        self._record_hit(hit["ioc_id"], normalized, event_id)
        return self._format_hit(hit, normalized)

    def check_hash(self, file_hash: str, event_id: str = "") -> Optional[dict]:
        self._ensure_cache()
        normalized = _normalize(file_hash, "hash")
        hit = self._cache_hash.get(normalized)
        if not hit:
            return None
        self._record_hit(hit["ioc_id"], normalized, event_id)
        return self._format_hit(hit, normalized)

    def check_all(self, ip: str = "", domain: str = "", file_hash: str = "", event_id: str = "") -> list[dict]:
        hits = []
        if ip:
            hit = self.check_ip(ip, event_id)
            if hit:
                hits.append(hit)
        if domain:
            hit = self.check_domain(domain, event_id)
            if hit:
                hits.append(hit)
        if file_hash:
            hit = self.check_hash(file_hash, event_id)
            if hit:
                hits.append(hit)
        return hits

    def add_ioc(
        self,
        value: str | dict,
        ioc_type: str = "",
        threat_name: str = "",
        confidence: int = 80,
        source: str = "manual",
        tags: list | None = None,
        notes: str = "",
    ) -> dict:
        if isinstance(value, dict):
            payload = dict(value)
            value = str(payload.get("value", "") or "")
            ioc_type = str(payload.get("ioc_type") or payload.get("type") or ioc_type or "")
            threat_name = str(payload.get("threat_name") or payload.get("description") or threat_name or "")
            confidence = int(payload.get("confidence", confidence))
            source = str(payload.get("source") or source)
            tags = payload.get("tags", tags)
            notes = str(payload.get("notes") or notes or "")

        value = str(value or "").strip()
        if len(value) > 512:
            raise ValueError("IOC value: max 512 chars")
        if threat_name and len(threat_name) > 120:
            raise ValueError("threat_name: max 120 chars")
        if notes and len(notes) > 1000:
            raise ValueError("notes: max 1000 chars")

        if not ioc_type:
            ioc_type = _detect_ioc_type(value) or ""
        if not ioc_type:
            raise ValueError(f"Tipo de IOC nao reconhecido para: {value!r}")
        if ioc_type not in IOC_TYPES:
            raise ValueError(f"Tipo invalido: {ioc_type!r}")

        normalized = _normalize(value, ioc_type)
        now = datetime.now(timezone.utc).isoformat()
        ioc_id = str(uuid.uuid4())

        with self._conn() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO ioc_list (
                        ioc_id, tenant_id, ioc_type, value, value_raw, threat_name,
                        confidence, source, tags, notes, active, created_at,
                        updated_at, hit_count, last_hit
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        ioc_id,
                        self.tenant_id,
                        ioc_type,
                        normalized,
                        value,
                        threat_name,
                        confidence,
                        source,
                        json.dumps(tags or []),
                        notes,
                        1,
                        now,
                        now,
                        0,
                        None,
                    ),
                )
                created = self._get_ioc_row(conn, ioc_id)
            except sqlite3.IntegrityError as exc:
                raise ValueError("IOC já existe") from exc

        self.invalidate_cache()
        return self._serialize_ioc(created) or {
            "ioc_id": ioc_id,
            "id": ioc_id,
            "ioc_type": ioc_type,
            "value": value,
            "enabled": 1,
        }

    def delete_ioc(self, ioc_id: str) -> bool:
        with self._conn() as conn:
            result = conn.execute(
                "DELETE FROM ioc_list WHERE ioc_id=? AND tenant_id=?",
                (ioc_id, self.tenant_id),
            )
        self.invalidate_cache()
        return result.rowcount > 0

    def toggle_ioc(self, ioc_id: str, active: Optional[bool] = None):
        toggle_mode = active is None
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as conn:
            current = self._get_ioc_row(conn, ioc_id)
            if not current:
                return None if toggle_mode else False
            if toggle_mode:
                active = not bool(current["active"])
            result = conn.execute(
                "UPDATE ioc_list SET active=?, updated_at=? WHERE ioc_id=? AND tenant_id=?",
                (1 if active else 0, now, ioc_id, self.tenant_id),
            )
            updated = self._get_ioc_row(conn, ioc_id) if result.rowcount else None
        self.invalidate_cache()
        if toggle_mode:
            return self._serialize_ioc(updated)
        return result.rowcount > 0

    def import_csv(
        self,
        csv_bytes: bytes | str,
        default_threat: str = "Custom IOC",
        default_confidence: int = 80,
    ) -> dict:
        text = csv_bytes if isinstance(csv_bytes, str) else csv_bytes.decode("utf-8-sig", errors="replace")
        reader = csv.reader(io.StringIO(text))

        imported = 0
        skipped = 0
        errors = []

        for lineno, row in enumerate(reader, 1):
            if not row or not row[0].strip():
                skipped += 1
                continue

            raw_value = row[0].strip()
            if raw_value.lower() in {"value", "ioc", "indicator", "#"} or raw_value.startswith("#"):
                skipped += 1
                continue

            second_col = row[1].strip() if len(row) > 1 else ""
            if second_col.lower() in IOC_TYPES:
                parsed_type = second_col.lower()
                threat = row[2].strip() if len(row) > 2 else default_threat
            else:
                parsed_type = ""
                threat = second_col or default_threat

            confidence = (
                int(row[3].strip())
                if len(row) > 3 and row[3].strip().isdigit()
                else default_confidence
            )
            tags_raw = row[4].strip() if len(row) > 4 else ""
            notes = row[5].strip() if len(row) > 5 else ""
            tags = [item.strip() for item in tags_raw.split(",") if item.strip()] if tags_raw else []

            try:
                self.add_ioc(
                    value=raw_value,
                    ioc_type=parsed_type,
                    threat_name=threat,
                    confidence=confidence,
                    source="csv_import",
                    tags=tags,
                    notes=notes,
                )
                imported += 1
            except ValueError as exc:
                skipped += 1
                errors.append({"line": lineno, "value": raw_value, "error": str(exc)})
            except Exception as exc:
                skipped += 1
                errors.append({"line": lineno, "value": raw_value, "error": str(exc)})

        self.invalidate_cache()
        return {"imported": imported, "skipped": skipped, "errors": errors[:20]}

    def export_csv(self) -> bytes:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM ioc_list WHERE tenant_id=? ORDER BY ioc_type, value",
                (self.tenant_id,),
            ).fetchall()

        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            ["value", "type", "threat_name", "confidence", "tags", "notes", "source", "active", "hit_count", "created_at"]
        )
        for row in rows:
            item = dict(row)
            tags = item.get("tags", "[]")
            if isinstance(tags, str):
                tags = json.loads(tags or "[]")
            writer.writerow(
                [
                    item["value_raw"],
                    item["ioc_type"],
                    item["threat_name"],
                    item["confidence"],
                    ",".join(tags),
                    item.get("notes", ""),
                    item["source"],
                    item["active"],
                    item["hit_count"],
                    item["created_at"],
                ]
            )
        return buf.getvalue().encode("utf-8")

    def list_iocs(
        self,
        ioc_type: str = "",
        active_only: bool = False,
        limit: int = 500,
        offset: int = 0,
        page: Optional[int] = None,
        per_page: Optional[int] = None,
    ):
        if per_page is not None:
            page = max(1, int(page or 1))
            limit = max(1, int(per_page))
            offset = (page - 1) * limit

        where = ["tenant_id=?"]
        params: list = [self.tenant_id]
        if ioc_type:
            where.append("ioc_type=?")
            params.append(ioc_type)
        if active_only:
            where.append("active=1")

        sql = (
            f"SELECT * FROM ioc_list WHERE {' AND '.join(where)} "
            "ORDER BY updated_at DESC LIMIT ? OFFSET ?"
        )

        with self._conn() as conn:
            rows = conn.execute(sql, params + [limit, offset]).fetchall()
            total = conn.execute(
                f"SELECT COUNT(*) FROM ioc_list WHERE {' AND '.join(where)}",
                params,
            ).fetchone()[0]

        items = [self._serialize_ioc(row) for row in rows]
        if per_page is not None:
            return {"items": items, "total": total, "page": page, "per_page": limit}
        return items

    def count_iocs(self) -> dict:
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT ioc_type, active, COUNT(*) AS n
                FROM ioc_list
                WHERE tenant_id=?
                GROUP BY ioc_type, active
                """,
                (self.tenant_id,),
            ).fetchall()

        stats: dict = {"total": 0, "active": 0, "by_type": {}}
        for row in rows:
            ioc_type = row["ioc_type"]
            active = row["active"]
            count = row["n"]
            stats["by_type"].setdefault(ioc_type, {"total": 0, "active": 0})
            stats["by_type"][ioc_type]["total"] += count
            stats["total"] += count
            if active:
                stats["by_type"][ioc_type]["active"] += count
                stats["active"] += count
        return stats

    def recent_hits(self, limit: int = 50) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT h.*, i.ioc_type, i.threat_name, i.confidence
                FROM ioc_hits h
                JOIN ioc_list i ON i.ioc_id = h.ioc_id
                WHERE h.tenant_id=?
                ORDER BY h.hit_at DESC
                LIMIT ?
                """,
                (self.tenant_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]


_managers: dict[str, IOCManager] = {}


def get_ioc_manager(db_path: str = "netguard_events.db", tenant_id: str = "default") -> IOCManager:
    key = f"{db_path}::{tenant_id}"
    if key not in _managers:
        _managers[key] = IOCManager(db_path=db_path, tenant_id=tenant_id)
    return _managers[key]
