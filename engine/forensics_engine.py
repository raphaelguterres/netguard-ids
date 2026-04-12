"""
NetGuard IDS — Forensics Snapshot Engine
Captura automaticamente evidências forenses quando alertas críticos são disparados.

Coleta:
  • Processos em execução (PID, nome, usuário, CPU, memória, cmdline)
  • Conexões de rede ativas (local/remoto, status, PID)
  • Arquivos abertos suspeitos
  • Variáveis de ambiente relevantes
  • Usuários logados
  • Últimos eventos do sistema (últimas entradas de log relevantes)
  • Hash de binários suspeitos
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import sqlite3
import subprocess
import sys  # noqa: F401
import threading
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("netguard.forensics")

# ── Schema ────────────────────────────────────────────────────────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS forensic_snapshots (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id     TEXT NOT NULL UNIQUE,
    trigger_type    TEXT NOT NULL DEFAULT 'manual',  -- manual, auto, alert
    trigger_event   TEXT NOT NULL DEFAULT '{}',
    severity        TEXT NOT NULL DEFAULT 'critical',
    captured_at     TEXT NOT NULL,
    hostname        TEXT NOT NULL DEFAULT '',
    os_info         TEXT NOT NULL DEFAULT '',
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    processes       TEXT NOT NULL DEFAULT '[]',      -- JSON
    connections     TEXT NOT NULL DEFAULT '[]',      -- JSON
    open_files      TEXT NOT NULL DEFAULT '[]',      -- JSON
    users_logged    TEXT NOT NULL DEFAULT '[]',      -- JSON
    environment     TEXT NOT NULL DEFAULT '{}',      -- JSON
    recent_logs     TEXT NOT NULL DEFAULT '[]',      -- JSON
    hash_artifacts  TEXT NOT NULL DEFAULT '[]',      -- JSON
    summary         TEXT NOT NULL DEFAULT '',
    notes           TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_forensic_tenant ON forensic_snapshots(tenant_id, captured_at);
"""

# Processos sempre suspeitos (keywords)
SUSPICIOUS_PROCESS_KEYWORDS = [
    "mimikatz", "procdump", "meterpreter", "cobalt", "empire", "psexec",
    "powershell", "cmd.exe", "wscript", "cscript", "regsvr32", "rundll32",
    "mshta", "certutil", "bitsadmin", "netsh", "schtasks", "at.exe",
    "whoami", "net.exe", "nltest", "wmic", "nc.exe", "ncat", "nmap",
]


class ForensicsEngine:
    def __init__(self, db_path: str):
        self.db_path   = db_path
        self._lock     = threading.Lock()
        self._os       = platform.system().lower()  # windows / linux / darwin
        self._init_db()

    def _db(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        with self._db() as c:
            c.executescript(SCHEMA)

    # ── Public API ────────────────────────────────────────────────────────────

    def capture(self, trigger_type: str = "manual",
                trigger_event: dict = None,
                severity: str = "critical",
                tenant_id: str = "default") -> dict:
        """Captura snapshot forense completo. Chamado em background thread."""
        import uuid
        snap_id = "SNAP-" + uuid.uuid4().hex[:8].upper()
        now     = _now()

        logger.info("Iniciando snapshot forense: %s [%s]", snap_id, trigger_type)

        hostname = platform.node()
        os_info  = f"{platform.system()} {platform.release()} {platform.machine()}"

        procs   = self._collect_processes()
        conns   = self._collect_connections()
        files   = self._collect_open_files()
        users   = self._collect_users()
        env     = self._collect_env()
        logs    = self._collect_recent_logs()
        hashes  = self._collect_artifact_hashes(procs)
        summary = self._build_summary(procs, conns, files)

        snap = {
            "snapshot_id":   snap_id,
            "trigger_type":  trigger_type,
            "trigger_event": json.dumps(trigger_event or {}),
            "severity":      severity,
            "captured_at":   now,
            "hostname":      hostname,
            "os_info":       os_info,
            "tenant_id":     tenant_id,
            "processes":     json.dumps(procs),
            "connections":   json.dumps(conns),
            "open_files":    json.dumps(files),
            "users_logged":  json.dumps(users),
            "environment":   json.dumps(env),
            "recent_logs":   json.dumps(logs),
            "hash_artifacts":json.dumps(hashes),
            "summary":       summary,
        }

        with self._db() as c:
            c.execute(
                "INSERT INTO forensic_snapshots("
                "snapshot_id,trigger_type,trigger_event,severity,captured_at,"
                "hostname,os_info,tenant_id,processes,connections,open_files,"
                "users_logged,environment,recent_logs,hash_artifacts,summary) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                tuple(snap[k] for k in [
                    "snapshot_id","trigger_type","trigger_event","severity","captured_at",
                    "hostname","os_info","tenant_id","processes","connections","open_files",
                    "users_logged","environment","recent_logs","hash_artifacts","summary",
                ]),
            )

        logger.info("Snapshot forense concluído: %s | procs=%d conns=%d",
                    snap_id, len(procs), len(conns))
        return self.get_snapshot(snap_id)

    def capture_async(self, trigger_type: str = "alert",
                      trigger_event: dict = None,
                      severity: str = "critical",
                      tenant_id: str = "default") -> str:
        """Dispara captura em background thread. Retorna snapshot_id previsto."""
        import uuid
        snap_id = "SNAP-" + uuid.uuid4().hex[:8].upper()

        def _run():
            try:
                self.capture(trigger_type, trigger_event, severity, tenant_id)
            except Exception as e:
                logger.error("Snapshot async error: %s", e)

        t = threading.Thread(target=_run, daemon=True, name=f"forensic-{snap_id}")
        t.start()
        return snap_id

    def get_snapshot(self, snapshot_id: str) -> Optional[dict]:
        with self._db() as c:
            row = c.execute("SELECT * FROM forensic_snapshots WHERE snapshot_id=?",
                            (snapshot_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        # Deserializar JSON fields
        for f in ("trigger_event","processes","connections","open_files",
                  "users_logged","environment","recent_logs","hash_artifacts"):
            try:
                d[f] = json.loads(d[f])
            except Exception:
                pass
        return d

    def list_snapshots(self, tenant_id: str = "default", limit: int = 50) -> list:
        with self._db() as c:
            rows = c.execute(
                "SELECT snapshot_id,trigger_type,severity,captured_at,hostname,"
                "os_info,summary,tenant_id FROM forensic_snapshots "
                "WHERE tenant_id=? ORDER BY captured_at DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_snapshot(self, snapshot_id: str) -> bool:
        with self._db() as c:
            c.execute("DELETE FROM forensic_snapshots WHERE snapshot_id=?", (snapshot_id,))
        return True

    def stats(self, tenant_id: str = "default") -> dict:
        with self._db() as c:
            total = c.execute("SELECT COUNT(*) FROM forensic_snapshots WHERE tenant_id=?",
                              (tenant_id,)).fetchone()[0]
            by_sev= c.execute(
                "SELECT severity, COUNT(*) FROM forensic_snapshots WHERE tenant_id=? GROUP BY severity",
                (tenant_id,),
            ).fetchall()
        return {
            "total": total,
            "by_severity": {r[0]: r[1] for r in by_sev},
        }

    # ── Collectors ───────────────────────────────────────────────────────────

    def _collect_processes(self) -> list:
        procs = []
        try:
            import psutil
            for p in psutil.process_iter(
                ["pid", "name", "username", "cpu_percent", "memory_percent",
                 "cmdline", "exe", "create_time", "status"]
            ):
                try:
                    info = p.info
                    name_lower = (info.get("name") or "").lower()
                    suspicious = any(kw in name_lower for kw in SUSPICIOUS_PROCESS_KEYWORDS)
                    procs.append({
                        "pid":        info.get("pid"),
                        "name":       info.get("name", ""),
                        "user":       info.get("username", ""),
                        "cpu":        round(info.get("cpu_percent") or 0, 2),
                        "mem":        round(info.get("memory_percent") or 0, 2),
                        "cmdline":    " ".join(info.get("cmdline") or [])[:512],
                        "exe":        info.get("exe") or "",
                        "status":     info.get("status", ""),
                        "suspicious": suspicious,
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            # Sort suspicious first
            procs.sort(key=lambda x: (-int(x["suspicious"]), -x["cpu"]))
            return procs[:200]
        except ImportError:
            return self._collect_processes_fallback()
        except Exception as e:
            logger.warning("Process collection error: %s", e)
            return []

    def _collect_processes_fallback(self) -> list:
        """Coleta via subprocess se psutil não disponível."""
        procs = []
        try:
            if self._os == "windows":
                out = subprocess.check_output(
                    ["tasklist", "/FO", "CSV", "/NH"], timeout=10,
                    stderr=subprocess.DEVNULL
                ).decode("cp850", errors="replace")
                for line in out.strip().splitlines():
                    parts = [p.strip('"') for p in line.split('","')]
                    if len(parts) >= 2:
                        procs.append({"name": parts[0], "pid": parts[1], "suspicious": False})
            else:
                out = subprocess.check_output(
                    ["ps", "aux"], timeout=10, stderr=subprocess.DEVNULL
                ).decode("utf-8", errors="replace")
                for line in out.strip().splitlines()[1:50]:
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        procs.append({
                            "user": parts[0], "pid": parts[1],
                            "cpu": parts[2], "mem": parts[3],
                            "name": parts[10][:100], "suspicious": False,
                        })
        except Exception as e:
            logger.debug("Process fallback error: %s", e)
        return procs

    def _collect_connections(self) -> list:
        conns = []
        try:
            import psutil
            for c in psutil.net_connections(kind="inet"):
                try:
                    laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                    raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                    conns.append({
                        "pid":    c.pid,
                        "laddr":  laddr,
                        "raddr":  raddr,
                        "status": c.status,
                        "family": str(c.family),
                    })
                except Exception:
                    pass
            return conns[:300]
        except ImportError:
            return self._collect_connections_fallback()
        except Exception as e:
            logger.warning("Connection collection error: %s", e)
            return []

    def _collect_connections_fallback(self) -> list:
        conns = []
        try:
            cmd = ["netstat", "-an"] if self._os == "windows" else ["ss", "-tunapl"]
            out = subprocess.check_output(cmd, timeout=10,
                                          stderr=subprocess.DEVNULL).decode("utf-8", errors="replace")
            for line in out.strip().splitlines()[1:100]:
                conns.append({"raw": line.strip()[:200]})
        except Exception:
            pass
        return conns

    def _collect_open_files(self) -> list:
        files = []
        try:
            import psutil
            suspicious_extensions = {".exe", ".dll", ".bat", ".ps1", ".vbs", ".js",
                                      ".hta", ".scr", ".pif", ".cmd", ".msi", ".doc",
                                      ".docm", ".xlsm", ".zip", ".7z", ".rar"}
            for p in psutil.process_iter(["pid", "name"]):
                try:
                    for f in p.open_files():
                        ext = os.path.splitext(f.path)[1].lower()
                        if ext in suspicious_extensions:
                            files.append({
                                "pid":  p.info["pid"],
                                "name": p.info["name"],
                                "path": f.path[:512],
                                "ext":  ext,
                            })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            return files[:100]
        except Exception:
            return []

    def _collect_users(self) -> list:
        users = []
        try:
            import psutil
            for u in psutil.users():
                users.append({
                    "name":     u.name,
                    "terminal": u.terminal or "",
                    "host":     u.host or "",
                    "started":  datetime.fromtimestamp(u.started, tz=timezone.utc).strftime("%H:%M:%S"),
                })
            return users
        except Exception:
            pass
        try:
            if self._os != "windows":
                out = subprocess.check_output(["who"], timeout=5,
                                              stderr=subprocess.DEVNULL).decode("utf-8", errors="replace")
                for line in out.strip().splitlines():
                    users.append({"raw": line.strip()})
        except Exception:
            pass
        return users

    def _collect_env(self) -> dict:
        """Coleta variáveis de ambiente relevantes (sem senhas/tokens)."""
        interesting = {"PATH", "COMPUTERNAME", "USERNAME", "USERDOMAIN", "OS",
                       "PROCESSOR_ARCHITECTURE", "SESSIONNAME", "LOGONSERVER",
                       "USERDNSDOMAIN", "SystemRoot", "TEMP", "TMP",
                       "HOME", "USER", "SHELL", "LANG", "HOSTNAME",
                       "PWD", "SUDO_USER"}
        sensitive   = {"PASSWORD", "SECRET", "TOKEN", "KEY", "PASS", "CREDENTIAL",
                       "AWS_", "AZURE_", "GCP_", "API_KEY", "PRIVATE"}

        env_out = {}
        for k, v in os.environ.items():
            if any(s in k.upper() for s in sensitive):
                env_out[k] = "***REDACTED***"
            elif k in interesting or k.upper() in interesting:
                env_out[k] = v[:256]
        return env_out

    def _collect_recent_logs(self) -> list:
        logs = []
        try:
            if self._os == "windows":
                # Windows Event Log via wevtutil
                out = subprocess.check_output(
                    ["wevtutil", "qe", "Security", "/c:20", "/rd:true", "/f:text"],
                    timeout=15, stderr=subprocess.DEVNULL
                ).decode("utf-8", errors="replace")
                for block in out.split("\r\n\r\n")[:10]:
                    if block.strip():
                        logs.append({"source": "Security", "raw": block.strip()[:500]})
            else:
                # Linux: journalctl or /var/log/auth.log
                try:
                    out = subprocess.check_output(
                        ["journalctl", "-n", "30", "--no-pager", "-p", "warning"],
                        timeout=10, stderr=subprocess.DEVNULL
                    ).decode("utf-8", errors="replace")
                    for line in out.strip().splitlines()[-20:]:
                        logs.append({"source": "journal", "raw": line.strip()[:300]})
                except Exception:
                    try:
                        with open("/var/log/auth.log") as f:
                            lines = f.readlines()[-20:]
                        for line in lines:
                            logs.append({"source": "auth.log", "raw": line.strip()[:300]})
                    except Exception:
                        pass
        except Exception as e:
            logger.debug("Log collection error: %s", e)
        return logs[:30]

    def _collect_artifact_hashes(self, procs: list) -> list:
        """Calcula hash MD5/SHA256 de executáveis de processos suspeitos."""
        hashes = []
        seen_paths = set()
        for p in procs:
            if not p.get("suspicious") or not p.get("exe"):
                continue
            exe = p["exe"]
            if exe in seen_paths or not os.path.isfile(exe):
                continue
            seen_paths.add(exe)
            try:
                md5  = hashlib.md5()
                sha2 = hashlib.sha256()
                with open(exe, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        md5.update(chunk)
                        sha2.update(chunk)
                hashes.append({
                    "path":   exe,
                    "md5":    md5.hexdigest(),
                    "sha256": sha2.hexdigest(),
                    "size":   os.path.getsize(exe),
                })
            except Exception:
                pass
            if len(hashes) >= 20:
                break
        return hashes

    def _build_summary(self, procs: list, conns: list, files: list) -> str:
        susp_procs = [p for p in procs if p.get("suspicious")]
        ext_conns  = [c for c in conns if c.get("raddr") and not c.get("raddr", "").startswith(
            ("127.", "10.", "192.168.", "172.", "[::1]", "0.0.0.0")
        )]
        parts = [
            f"{len(procs)} processos ({len(susp_procs)} suspeitos)",
            f"{len(conns)} conexões ({len(ext_conns)} externas)",
            f"{len(files)} arquivos suspeitos abertos",
        ]
        if susp_procs:
            names = ", ".join({p.get("name","?") for p in susp_procs[:5]})
            parts.append(f"Processos flagged: {names}")
        return " | ".join(parts)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Singleton ─────────────────────────────────────────────────────────────────

_forensics_instance: Optional[ForensicsEngine] = None
_forensics_lock = threading.Lock()


def get_forensics_engine(db_path: str) -> ForensicsEngine:
    global _forensics_instance
    with _forensics_lock:
        if _forensics_instance is None:
            _forensics_instance = ForensicsEngine(db_path)
    return _forensics_instance
