"""
NetGuard IDS — Remote Remediation Engine
Kill process + Isolate host. Transforma alertas em ações.
"""
from __future__ import annotations  # noqa: F401

import json
import logging
import os
import platform
import shutil
import signal
import sqlite3
import subprocess
import threading
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("netguard.remediation")

# ── Schema ────────────────────────────────────────────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS remediation_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   TEXT    NOT NULL DEFAULT 'default',
    action      TEXT    NOT NULL,
    target      TEXT    NOT NULL,
    reason      TEXT    NOT NULL DEFAULT '',
    operator    TEXT    NOT NULL DEFAULT 'system',
    result      TEXT    NOT NULL DEFAULT 'ok',
    detail      TEXT    NOT NULL DEFAULT '',
    auto        INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE TABLE IF NOT EXISTS isolated_hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   TEXT    NOT NULL DEFAULT 'default',
    ip          TEXT    NOT NULL,
    reason      TEXT    NOT NULL DEFAULT '',
    rule_id     TEXT,
    isolated_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    expires_at  TEXT,
    active      INTEGER NOT NULL DEFAULT 1,
    UNIQUE(tenant_id, ip)
);
CREATE TABLE IF NOT EXISTS remediation_config (
    tenant_id       TEXT    PRIMARY KEY,
    auto_kill       INTEGER NOT NULL DEFAULT 0,
    auto_isolate    INTEGER NOT NULL DEFAULT 0,
    auto_min_sev    TEXT    NOT NULL DEFAULT 'critical',
    whitelist_ips   TEXT    NOT NULL DEFAULT '[]',
    whitelist_procs TEXT    NOT NULL DEFAULT '["System","svchost.exe","lsass.exe","csrss.exe","winlogon.exe","services.exe","smss.exe"]'
);
"""

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"
SEV_ORDER  = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Processos que nunca devem ser mortos
SAFE_PROCS = {
    "system", "svchost.exe", "lsass.exe", "csrss.exe",
    "winlogon.exe", "services.exe", "smss.exe", "wininit.exe",
    "explorer.exe", "python.exe", "python3", "python",
    "systemd", "init", "kernel", "kthreadd",
}


class RemediationEngine:
    def __init__(self, db_path: str, tenant_id: str = "default",
                 whitelist_ips: list = None):
        self.db_path   = db_path
        self.tenant_id = tenant_id
        self._lock     = threading.Lock()
        self._whitelist_ips = set(whitelist_ips or [])
        self._init_db()

    def _db(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        with self._db() as c:
            c.executescript(SCHEMA)
        # Garante config padrão
        with self._db() as c:
            c.execute(
                "INSERT OR IGNORE INTO remediation_config(tenant_id) VALUES(?)",
                (self.tenant_id,)
            )

    # ── Config ────────────────────────────────────────────────────
    def get_config(self) -> dict:
        with self._db() as c:
            row = c.execute(
                "SELECT * FROM remediation_config WHERE tenant_id=?",
                (self.tenant_id,)
            ).fetchone()
        if not row:
            return {"auto_kill": False, "auto_isolate": False,
                    "auto_min_sev": "critical", "whitelist_ips": [],
                    "whitelist_procs": list(SAFE_PROCS)}
        d = dict(row)
        d["whitelist_ips"]   = json.loads(d.get("whitelist_ips", "[]"))
        d["whitelist_procs"] = json.loads(d.get("whitelist_procs", "[]"))
        return d

    def update_config(self, data: dict) -> dict:
        cfg = self.get_config()
        if "auto_kill"    in data: cfg["auto_kill"]    = bool(data["auto_kill"])
        if "auto_isolate" in data: cfg["auto_isolate"] = bool(data["auto_isolate"])
        if "auto_min_sev" in data: cfg["auto_min_sev"] = data["auto_min_sev"]
        if "whitelist_ips"   in data: cfg["whitelist_ips"]   = list(data["whitelist_ips"])
        if "whitelist_procs" in data: cfg["whitelist_procs"] = list(data["whitelist_procs"])
        with self._db() as c:
            c.execute(
                "INSERT OR REPLACE INTO remediation_config "
                "(tenant_id,auto_kill,auto_isolate,auto_min_sev,whitelist_ips,whitelist_procs) "
                "VALUES(?,?,?,?,?,?)",
                (self.tenant_id,
                 1 if cfg["auto_kill"] else 0,
                 1 if cfg["auto_isolate"] else 0,
                 cfg["auto_min_sev"],
                 json.dumps(cfg["whitelist_ips"]),
                 json.dumps(cfg["whitelist_procs"]))
            )
        return self.get_config()

    # ── Kill Process ──────────────────────────────────────────────
    def kill_process(self, pid: int, reason: str = "", operator: str = "manual",
                     auto: bool = False) -> dict:
        pid = int(pid)
        proc_name = self._proc_name(pid)

        # Safety checks
        if proc_name and proc_name.lower() in SAFE_PROCS:
            return self._fail(f"Processo protegido: {proc_name}", "kill", str(pid),
                              reason, operator, auto)
        cfg = self.get_config()
        wl  = {p.lower() for p in cfg.get("whitelist_procs", [])}
        if proc_name and proc_name.lower() in wl:
            return self._fail(f"Processo na whitelist: {proc_name}", "kill", str(pid),
                              reason, operator, auto)

        try:
            if IS_WINDOWS:
                result = subprocess.run(
                    ["taskkill", "/PID", str(pid), "/F"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode != 0:
                    raise RuntimeError(result.stderr.strip() or "taskkill falhou")
                detail = f"taskkill /PID {pid} /F | {result.stdout.strip()}"
            else:
                os.kill(pid, signal.SIGKILL)
                detail = f"SIGKILL → PID {pid}"

            logger.warning("REMEDIATION | kill | pid=%d | proc=%s | op=%s | reason=%s",
                           pid, proc_name, operator, reason)
            return self._log("kill", str(pid), reason, operator, "ok",
                             f"{proc_name} | {detail}", auto)

        except ProcessLookupError:
            return self._fail(f"PID {pid} não encontrado (já encerrado?)", "kill",
                              str(pid), reason, operator, auto)
        except Exception as e:
            return self._fail(str(e), "kill", str(pid), reason, operator, auto)

    def _proc_name(self, pid: int) -> str:
        try:
            import psutil
            return psutil.Process(pid).name()
        except Exception:
            return ""

    # ── Isolate Host ──────────────────────────────────────────────
    def isolate_host(self, ip: str, reason: str = "", operator: str = "manual",
                     duration_minutes: int = 60, auto: bool = False) -> dict:
        ip = ip.strip()
        if not ip:
            return self._fail("IP inválido", "isolate", ip, reason, operator, auto)

        # Whitelist check
        if ip in self._whitelist_ips:
            return self._fail(f"IP na whitelist: {ip}", "isolate", ip,
                              reason, operator, auto)
        cfg = self.get_config()
        if ip in cfg.get("whitelist_ips", []):
            return self._fail(f"IP na whitelist: {ip}", "isolate", ip,
                              reason, operator, auto)

        # Aplica regra de firewall
        ok, detail = self._add_firewall_block(ip)
        if not ok:
            return self._fail(detail, "isolate", ip, reason, operator, auto)

        # Persiste no banco
        from datetime import timedelta
        expires = None
        if duration_minutes > 0:
            expires = datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)
            expires = expires.strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._db() as c:
            c.execute(
                "INSERT OR REPLACE INTO isolated_hosts"
                "(tenant_id,ip,reason,isolated_at,expires_at,active) VALUES(?,?,?,?,?,1)",
                (self.tenant_id, ip, reason,
                 datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), expires)
            )
        logger.warning("REMEDIATION | isolate | ip=%s | op=%s | dur=%dmin | reason=%s",
                       ip, operator, duration_minutes, reason)
        return self._log("isolate", ip, reason, operator, "ok", detail, auto)

    def unisolate_host(self, ip: str, operator: str = "manual") -> dict:
        ip = ip.strip()
        ok, detail = self._remove_firewall_block(ip)
        with self._db() as c:
            c.execute(
                "UPDATE isolated_hosts SET active=0 WHERE tenant_id=? AND ip=?",
                (self.tenant_id, ip)
            )
        logger.info("REMEDIATION | unisolate | ip=%s | op=%s", ip, operator)
        return self._log("unisolate", ip, "operator request", operator,
                         "ok" if ok else "warn", detail, False)

    def _add_firewall_block(self, ip: str):
        try:
            if IS_WINDOWS:
                name = f"NetGuard-Block-{ip}"
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name={name}", "dir=in",  "action=block", f"remoteip={ip}"],
                    capture_output=True, timeout=10, check=True
                )
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name={name}", "dir=out", "action=block", f"remoteip={ip}"],
                    capture_output=True, timeout=10, check=True
                )
                return True, f"netsh rule '{name}' criada (in+out)"
            elif IS_LINUX:
                if shutil.which("iptables"):
                    subprocess.run(["iptables", "-I", "INPUT",  "-s", ip, "-j", "DROP"],
                                   capture_output=True, timeout=10, check=True)
                    subprocess.run(["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"],
                                   capture_output=True, timeout=10, check=True)
                    return True, f"iptables DROP para {ip} (in+out)"
                elif shutil.which("ufw"):
                    subprocess.run(["ufw", "deny", "from", ip, "to", "any"],
                                   capture_output=True, timeout=10, check=True)
                    return True, f"ufw deny from {ip}"
                else:
                    return False, "nenhum firewall disponível (iptables/ufw)"
            else:
                return False, f"plataforma não suportada: {platform.system()}"
        except subprocess.CalledProcessError as e:
            return False, f"erro firewall: {e.stderr.decode()[:200] if e.stderr else str(e)}"
        except Exception as e:
            return False, str(e)

    def _remove_firewall_block(self, ip: str):
        try:
            if IS_WINDOWS:
                name = f"NetGuard-Block-{ip}"
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
                    capture_output=True, timeout=10
                )
                return True, f"regra '{name}' removida"
            elif IS_LINUX:
                if shutil.which("iptables"):
                    subprocess.run(["iptables", "-D", "INPUT",  "-s", ip, "-j", "DROP"],
                                   capture_output=True, timeout=10)
                    subprocess.run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
                                   capture_output=True, timeout=10)
                    return True, f"iptables DROP removido para {ip}"
                elif shutil.which("ufw"):
                    subprocess.run(["ufw", "delete", "deny", "from", ip, "to", "any"],
                                   capture_output=True, timeout=10)
                    return True, f"ufw rule removida para {ip}"
            return True, "nenhuma regra para remover"
        except Exception as e:
            return False, str(e)

    # ── Auto-remediation ──────────────────────────────────────────
    def auto_respond(self, event: dict) -> Optional[dict]:
        """
        Chamado pelo pipeline de detecção.
        Aplica kill/isolate automaticamente se configurado e severidade suficiente.
        """
        cfg = self.get_config()
        sev = event.get("severity", "info")
        min_sev = cfg.get("auto_min_sev", "critical")

        if SEV_ORDER.get(sev, 0) < SEV_ORDER.get(min_sev, 4):
            return None

        results = []
        reason = f"Auto-remediation | {event.get('threat','?')} | sev={sev}"

        if cfg.get("auto_isolate") and event.get("source_ip"):
            ip = event["source_ip"]
            r  = self.isolate_host(ip, reason=reason, operator="auto",
                                   duration_minutes=60, auto=True)
            results.append(r)
            logger.warning("AUTO-ISOLATE | ip=%s | sev=%s | threat=%s",
                           ip, sev, event.get("threat"))

        if cfg.get("auto_kill") and event.get("details", {}).get("pid"):
            pid = event["details"]["pid"]
            r   = self.kill_process(int(pid), reason=reason,
                                    operator="auto", auto=True)
            results.append(r)

        return results or None

    # ── Listas ────────────────────────────────────────────────────
    def isolated_hosts(self) -> list:
        with self._db() as c:
            rows = c.execute(
                "SELECT * FROM isolated_hosts WHERE tenant_id=? AND active=1 ORDER BY id DESC",
                (self.tenant_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def history(self, limit: int = 50) -> list:
        with self._db() as c:
            rows = c.execute(
                "SELECT * FROM remediation_log WHERE tenant_id=? ORDER BY id DESC LIMIT ?",
                (self.tenant_id, limit)
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Helpers ───────────────────────────────────────────────────
    def _log(self, action, target, reason, operator, result, detail, auto) -> dict:
        with self._db() as c:
            cur = c.execute(
                "INSERT INTO remediation_log"
                "(tenant_id,action,target,reason,operator,result,detail,auto) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (self.tenant_id, action, target, reason, operator,
                 result, detail, 1 if auto else 0)
            )
            lid = cur.lastrowid
        return {"ok": result == "ok", "action": action, "target": target,
                "result": result, "detail": detail, "id": lid}

    def _fail(self, msg, action, target, reason, operator, auto) -> dict:
        logger.warning("REMEDIATION BLOCKED | %s | %s | %s", action, target, msg)
        self._log(action, target, reason, operator, "blocked", msg, auto)
        return {"ok": False, "action": action, "target": target,
                "result": "blocked", "detail": msg}


# ── Singleton ─────────────────────────────────────────────────────
_engines: dict = {}
_lock = threading.Lock()

def get_remediation_engine(db_path: str, tenant_id: str = "default",
                           whitelist_ips: list = None) -> RemediationEngine:
    key = f"{db_path}::{tenant_id}"
    with _lock:
        if key not in _engines:
            _engines[key] = RemediationEngine(db_path, tenant_id, whitelist_ips)
    return _engines[key]
