"""
NetGuard IDS — Trial Token Engine
Gera links de demonstração com tempo limitado para clientes em potencial.
"""
from __future__ import annotations  # noqa: F401

import logging
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger("netguard.trial")

SCHEMA = """
CREATE TABLE IF NOT EXISTS trials (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    token        TEXT    NOT NULL UNIQUE,
    email        TEXT    NOT NULL,
    name         TEXT    NOT NULL DEFAULT '',
    company      TEXT    NOT NULL DEFAULT '',
    duration_h   INTEGER NOT NULL DEFAULT 72,
    created_at   TEXT    NOT NULL,
    expires_at   TEXT    NOT NULL,
    first_access TEXT,
    last_access  TEXT,
    access_count INTEGER NOT NULL DEFAULT 0,
    revoked      INTEGER NOT NULL DEFAULT 0,
    notes        TEXT    NOT NULL DEFAULT ''
);
"""

class TrialEngine:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock   = threading.Lock()
        self._init_db()

    @contextmanager
    def _db(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL").close()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self):
        with self._db() as c:
            c.executescript(SCHEMA)

    # ── Criar trial ───────────────────────────────────────────────
    def create_trial(self, email: str, name: str = "", company: str = "",
                     duration_h: int = 72, notes: str = "") -> dict:
        if not email or "@" not in email:
            raise ValueError("E-mail inválido")
        if len(email) > 254:
            raise ValueError("E-mail: máximo 254 caracteres")
        if name and len(name) > 120:
            raise ValueError("name: máximo 120 caracteres")
        if company and len(company) > 120:
            raise ValueError("company: máximo 120 caracteres")
        if notes and len(notes) > 1000:
            raise ValueError("notes: máximo 1000 caracteres")
        if not (1 <= duration_h <= 8760):   # 1h – 1 year
            raise ValueError("duration_h deve estar entre 1 e 8760 horas")

        token      = "ng_trial_" + secrets.token_urlsafe(24)
        now        = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=duration_h)

        with self._db() as c:
            c.execute(
                "INSERT INTO trials(token,email,name,company,duration_h,created_at,expires_at,notes) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (token, email.lower().strip(), name.strip(), company.strip(),
                 duration_h, _fmt(now), _fmt(expires_at), notes.strip())
            )
        logger.info("Trial criado | email=%s | company=%s | expires=%s | token=%s…",
                    email, company, _fmt(expires_at), token[:20])
        return self.get_trial(token)

    # ── Validar trial ─────────────────────────────────────────────
    def validate_trial(self, token: str) -> dict:
        """Retorna status do trial. Campos: valid, expired, revoked, trial (dict)."""
        trial = self.get_trial(token)
        if not trial:
            return {"valid": False, "expired": False, "revoked": False, "trial": None,
                    "reason": "token_not_found"}
        if trial["revoked"]:
            return {"valid": False, "expired": False, "revoked": True, "trial": trial,
                    "reason": "revoked"}
        now = datetime.now(timezone.utc)
        exp = _parse(trial["expires_at"])
        if now > exp:
            return {"valid": False, "expired": True, "revoked": False, "trial": trial,
                    "remaining_seconds": 0, "reason": "expired"}

        remaining = int((exp - now).total_seconds())
        self._record_access(token)
        return {
            "valid": True, "expired": False, "revoked": False,
            "trial": self.get_trial(token),
            "remaining_seconds": remaining,
            "remaining_h": round(remaining / 3600, 1),
            "reason": "ok",
        }

    def _record_access(self, token: str):
        now = _fmt(datetime.now(timezone.utc))
        with self._db() as c:
            c.execute(
                "UPDATE trials SET access_count=access_count+1, last_access=?, "
                "first_access=COALESCE(first_access,?) WHERE token=?",
                (now, now, token)
            )

    # ── CRUD ──────────────────────────────────────────────────────
    def get_trial(self, token: str) -> Optional[dict]:
        with self._db() as c:
            row = c.execute("SELECT * FROM trials WHERE token=?", (token,)).fetchone()
        return dict(row) if row else None

    def list_trials(self, include_expired: bool = True) -> list:
        with self._db() as c:
            rows = c.execute("SELECT * FROM trials ORDER BY id DESC").fetchall()
        trials = [dict(r) for r in rows]
        if not include_expired:
            now = datetime.now(timezone.utc)
            trials = [t for t in trials if _parse(t["expires_at"]) > now and not t["revoked"]]
        # Enriquece com campos computados
        now = datetime.now(timezone.utc)
        for t in trials:
            exp = _parse(t["expires_at"])
            t["expired"]         = now > exp
            t["remaining_h"]     = max(0, round((exp - now).total_seconds() / 3600, 1))
            t["status"]          = ("revoked" if t["revoked"] else
                                    "expired" if t["expired"] else "active")
        return trials

    def revoke_trial(self, token: str) -> bool:
        with self._db() as c:
            c.execute("UPDATE trials SET revoked=1 WHERE token=?", (token,))
        logger.info("Trial revogado | token=%s…", token[:20])
        return True

    def extend_trial(self, token: str, extra_hours: int = 24) -> dict:
        with self._db() as c:
            row = c.execute("SELECT expires_at FROM trials WHERE token=?", (token,)).fetchone()
            if not row:
                raise ValueError("Trial não encontrado")
            exp     = _parse(row["expires_at"])
            new_exp = max(exp, datetime.now(timezone.utc)) + timedelta(hours=extra_hours)
            c.execute("UPDATE trials SET expires_at=?, revoked=0 WHERE token=?",
                      (_fmt(new_exp), token))
        logger.info("Trial estendido +%dh | token=%s…", extra_hours, token[:20])
        return self.get_trial(token)

    def stats(self) -> dict:
        with self._db() as c:
            total   = c.execute("SELECT COUNT(*) FROM trials").fetchone()[0]
            active  = c.execute(
                "SELECT COUNT(*) FROM trials WHERE revoked=0 AND expires_at > ?",
                (_fmt(datetime.now(timezone.utc)),)
            ).fetchone()[0]
            expired = c.execute(
                "SELECT COUNT(*) FROM trials WHERE revoked=0 AND expires_at <= ?",
                (_fmt(datetime.now(timezone.utc)),)
            ).fetchone()[0]
        return {"total": total, "active": active, "expired": expired,
                "revoked": total - active - expired}


# ── Helpers ───────────────────────────────────────────────────────
def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def _parse(s: str) -> datetime:
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


# ── Singleton ─────────────────────────────────────────────────────
_engine: Optional[TrialEngine] = None
_engine_lock = threading.Lock()

def get_trial_engine(db_path: str) -> TrialEngine:
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = TrialEngine(db_path)
    return _engine
