"""
NetGuard IDS — EDR Sentinel
Monitoramento contínuo de processos com scoring comportamental e auto-resposta.
Nível: EDR profissional (CrowdStrike-inspired) em Python puro.
"""
from __future__ import annotations  # noqa: F401

import json
import logging
import os
import platform
import re
import sqlite3
import subprocess
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Callable, Optional

logger = logging.getLogger("netguard.edr")

# ═══════════════════════════════════════════════════════════════════
# THREAT INTELLIGENCE — LOLBins, padrões suspeitos, paths maliciosos
# ═══════════════════════════════════════════════════════════════════

# Living-off-the-Land Binaries — legítimos mas abusados por atacantes
LOLBINS = {
    "powershell.exe", "powershell", "pwsh.exe", "pwsh",
    "cmd.exe", "cmd",
    "wscript.exe", "cscript.exe",
    "mshta.exe", "mshta",
    "regsvr32.exe", "regsvr32",
    "rundll32.exe", "rundll32",
    "certutil.exe", "certutil",
    "bitsadmin.exe", "bitsadmin",
    "wmic.exe", "wmic",
    "msiexec.exe",
    "installutil.exe",
    "regasm.exe", "regsvcs.exe",
    "odbcconf.exe",
    "ieexec.exe",
    "pcalua.exe",
    "scriptrunner.exe",
    "schtasks.exe",
    "at.exe",
    "net.exe", "net1.exe",
    "netsh.exe",
    "nltest.exe",
    "whoami.exe",
    "systeminfo.exe",
    "tasklist.exe", "taskkill.exe",
}

# Cmdline suspeita — padrões que indicam comportamento malicioso
SUSPICIOUS_CMDLINE_PATTERNS = [
    # PowerShell ofuscado
    (r"-enc\b|-encodedcommand",      40, "PowerShell encoded command"),
    (r"-w\s+hid|-windowstyle\s+hid", 35, "PowerShell hidden window"),
    (r"iex\s*\(|invoke-expression",  45, "PowerShell Invoke-Expression"),
    (r"downloadstring|webclient",     40, "PowerShell download"),
    (r"bypass",                       30, "ExecutionPolicy Bypass"),
    (r"frombase64string",             35, "Base64 decode execution"),
    # Shell injection
    (r"&&\s*(cmd|powershell|bash)",   35, "Chained shell execution"),
    (r"\|\s*(cmd|powershell|bash)",   30, "Piped shell execution"),
    # Recon
    (r"net\s+user\s+/domain",        25, "Domain user enumeration"),
    (r"net\s+group.*domain",         25, "Domain group enumeration"),
    (r"nltest.*dclist",               30, "DC enumeration"),
    (r"whoami\s*/priv",               20, "Privilege discovery"),
    # Lateral movement
    (r"psexec|paexec",               40, "PsExec lateral movement"),
    (r"wmiexec|smbexec",             45, "WMI/SMB lateral movement"),
    # Exfiltration
    (r"curl\s.*\|\s*(bash|sh|cmd)",  45, "Curl pipe execution"),
    (r"wget\s.*-o\s*/tmp",           35, "Wget to temp"),
    # Persistence
    (r"schtasks.*\/create",          30, "Scheduled task creation"),
    (r"reg\s+(add|import).*run",     35, "Registry run key"),
    (r"startup.*\.exe|\.bat|\.ps1",  30, "Startup folder persistence"),
    # Anti-forensics
    (r"vssadmin.*delete",            50, "VSS shadow copy deletion (ransomware)"),
    (r"wbadmin.*delete",             50, "Backup deletion"),
    (r"bcdedit.*recoveryenabled\s+no", 50, "Boot recovery disabled"),
    (r"cipher\s+/w",                 40, "Secure file wipe"),
]

# Parent-child suspeito — Office/browser spawnando shell
SUSPICIOUS_PARENT_CHILD = {
    # (parent_name, child_name): score_delta
    ("winword.exe",   "cmd.exe"):        60,
    ("winword.exe",   "powershell.exe"):  65,
    ("excel.exe",     "cmd.exe"):         60,
    ("excel.exe",     "powershell.exe"):  65,
    ("outlook.exe",   "cmd.exe"):         65,
    ("outlook.exe",   "powershell.exe"):  70,
    ("chrome.exe",    "powershell.exe"):  55,
    ("chrome.exe",    "cmd.exe"):         50,
    ("firefox.exe",   "powershell.exe"):  55,
    ("iexplore.exe",  "powershell.exe"):  65,
    ("acrobat.exe",   "cmd.exe"):         60,
    ("acrord32.exe",  "powershell.exe"):  65,
    ("winrar.exe",    "powershell.exe"):  40,
    ("7z.exe",        "powershell.exe"):  40,
    ("powershell.exe","powershell.exe"):  30,  # PS spawning PS
    ("cmd.exe",       "powershell.exe"):  25,
    ("mshta.exe",     "cmd.exe"):         55,
    ("wscript.exe",   "cmd.exe"):         50,
    ("cscript.exe",   "powershell.exe"):  50,
}

# Paths suspeitos onde malware frequentemente reside
SUSPICIOUS_PATHS = [
    (r"\\temp\\.*\.(exe|bat|ps1|vbs|js|hta)$",      25, "Executable in Temp"),
    (r"\\tmp\\.*\.(exe|bat|ps1|vbs|js|hta)$",        25, "Executable in /tmp"),
    (r"\\appdata\\local\\temp\\",                     15, "AppData Temp"),
    (r"\\users\\public\\",                            20, "Public folder"),
    (r"\\programdata\\.*\.(exe|bat|ps1)$",            20, "ProgramData executable"),
    (r"\\windows\\temp\\",                            25, "Windows Temp"),
    (r"\\recycle\.bin\\",                             40, "Recycle bin executable"),
    (r"\\downloads\\.*\.(exe|bat|ps1|vbs)$",          10, "Downloads executable"),
]

# Processos de sistema que nunca devem ter filhos suspeitos
PROTECTED_SYSTEM_PROCS = {
    "lsass.exe", "csrss.exe", "smss.exe", "services.exe",
    "winlogon.exe", "svchost.exe", "spoolsv.exe", "explorer.exe",
}

# Ações de resposta automática
ACTION_LOG   = "log"
ACTION_ALERT = "alert"
ACTION_BLOCK = "block_ip"
ACTION_KILL  = "kill_process"

SCORE_THRESHOLDS = {
    ACTION_LOG:   10,
    ACTION_ALERT: 30,
    ACTION_BLOCK: 55,
    ACTION_KILL:  75,
}

# ═══════════════════════════════════════════════════════════════════
# SCHEMA
# ═══════════════════════════════════════════════════════════════════
SCHEMA = """
CREATE TABLE IF NOT EXISTS edr_processes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    pid          INTEGER NOT NULL,
    ppid         INTEGER,
    name         TEXT,
    exe          TEXT,
    cmdline      TEXT,
    username     TEXT,
    score        INTEGER NOT NULL DEFAULT 0,
    findings     TEXT,
    status       TEXT    NOT NULL DEFAULT 'running',
    action_taken TEXT,
    seen_at      TEXT    NOT NULL,
    ended_at     TEXT
);

CREATE TABLE IF NOT EXISTS edr_actions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    pid          INTEGER,
    process_name TEXT,
    score        INTEGER,
    action       TEXT    NOT NULL,
    reason       TEXT,
    success      INTEGER NOT NULL DEFAULT 0,
    detail       TEXT,
    ts           TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_edr_proc_pid ON edr_processes(pid);
CREATE INDEX IF NOT EXISTS idx_edr_proc_seen ON edr_processes(seen_at);
"""


# ═══════════════════════════════════════════════════════════════════
# EDR SENTINEL ENGINE
# ═══════════════════════════════════════════════════════════════════
class EDRSentinel:
    def __init__(
        self,
        db_path: str,
        auto_kill: bool = False,
        auto_block: bool = True,
        kill_threshold: int = 80,
        block_threshold: int = 60,
        poll_interval: float = 2.0,
        event_callback: Optional[Callable] = None,
    ):
        self.db_path        = db_path
        self.auto_kill      = auto_kill
        self.auto_block     = auto_block
        self.kill_threshold = kill_threshold
        self.block_threshold= block_threshold
        self.poll_interval  = poll_interval
        self.event_callback = event_callback  # chamado a cada detecção

        self._lock          = threading.Lock()
        self._seen_pids: set[int] = set()
        self._running       = False
        self._thread: Optional[threading.Thread] = None
        self._blocked_ips: set[str] = set()

        self._init_db()

    def _db(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        with self._db() as c:
            c.executescript(SCHEMA)

    # ── Start / Stop ──────────────────────────────────────────────
    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="edr-sentinel"
        )
        self._thread.start()
        logger.info("EDR Sentinel iniciado | auto_kill=%s | auto_block=%s | interval=%.1fs",
                    self.auto_kill, self.auto_block, self.poll_interval)

    def stop(self):
        self._running = False

    # ── Main loop ─────────────────────────────────────────────────
    def _loop(self):
        while self._running:
            try:
                self._scan_processes()
            except Exception as e:
                logger.debug("EDR scan error: %s", e)
            time.sleep(self.poll_interval)

    def _scan_processes(self):
        try:
            import psutil
        except ImportError:
            return

        current_pids: set[int] = set()
        for proc in psutil.process_iter(
            ["pid", "ppid", "name", "exe", "cmdline", "username", "status"]
        ):
            try:
                info = proc.info
                pid  = info.get("pid", 0)
                if not pid:
                    continue
                current_pids.add(pid)

                # Só analisa processos novos
                if pid in self._seen_pids:
                    continue
                self._seen_pids.add(pid)

                score, findings = self._score_process(info, psutil)
                self._persist_process(info, score, findings)

                if score >= SCORE_THRESHOLDS[ACTION_ALERT]:
                    self._handle_threat(proc, info, score, findings, psutil)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
            except Exception as e:
                logger.debug("EDR proc error pid=%s: %s", proc.pid if proc else "?", e)

        # Marca processos encerrados
        ended = self._seen_pids - current_pids
        if ended:
            self._mark_ended(ended)
            self._seen_pids -= ended

    # ── Scoring ───────────────────────────────────────────────────
    def _score_process(self, info: dict, psutil) -> tuple[int, list]:
        score    = 0
        findings = []
        name     = (info.get("name") or "").lower()
        exe      = (info.get("exe") or "").lower()
        cmdline  = " ".join(info.get("cmdline") or []).lower()
        username = (info.get("username") or "").lower()

        # 1. LOLBin
        if name in LOLBINS:
            score += 15
            findings.append({"type": "lolbin", "msg": f"LOLBin: {name}", "score": 15})

        # 2. Cmdline suspeita
        for pattern, pts, label in SUSPICIOUS_CMDLINE_PATTERNS:
            if re.search(pattern, cmdline, re.IGNORECASE):
                score += pts
                findings.append({"type": "cmdline", "msg": label, "score": pts})

        # 3. Path suspeito
        for pattern, pts, label in SUSPICIOUS_PATHS:
            if re.search(pattern, exe, re.IGNORECASE):
                score += pts
                findings.append({"type": "path", "msg": label, "score": pts})

        # 4. Parent-child suspeito
        ppid = info.get("ppid")
        if ppid:
            try:
                import psutil as _ps
                parent = _ps.Process(ppid)
                parent_name = parent.name().lower()
                key = (parent_name, name)
                if key in SUSPICIOUS_PARENT_CHILD:
                    pts = SUSPICIOUS_PARENT_CHILD[key]
                    score += pts
                    findings.append({
                        "type": "parent_child",
                        "msg":  f"Suspeito: {parent_name} → {name}",
                        "score": pts,
                    })
            except Exception:
                pass

        # 5. SYSTEM sem motivo (processo de usuário rodando como SYSTEM)
        if "system" in username and name not in PROTECTED_SYSTEM_PROCS:
            score += 20
            findings.append({"type": "privilege", "msg": f"SYSTEM privilege: {name}", "score": 20})

        # 6. Sem exe no disco (fileless / hollowing)
        if not exe and name not in {"system", "idle", "[system process]", "registry"}:
            score += 25
            findings.append({"type": "fileless", "msg": "Processo sem executável no disco", "score": 25})

        # 7. Executável em path de rede (UNC)
        if exe.startswith("\\\\"):
            score += 35
            findings.append({"type": "unc_path", "msg": "Executável em path UNC (rede)", "score": 35})

        return min(score, 100), findings

    # ── Resposta automática ───────────────────────────────────────
    def _handle_threat(self, proc, info: dict, score: int, findings: list, psutil):
        name    = info.get("name") or "unknown"
        pid     = info.get("pid")
        reasons = "; ".join(f["msg"] for f in findings)

        # Notifica callback (integra com pipeline de eventos)
        if self.event_callback:
            try:
                sev = "critical" if score >= 75 else "high" if score >= 55 else "medium"
                self.event_callback({
                    "severity":   sev,
                    "threat":     f"[EDR] {name} (score={score})",
                    "event_type": "edr_detection",
                    "source_ip":  "127.0.0.1",
                    "hostname":   platform.node(),
                    "timestamp":  _now(),
                    "details": {
                        "pid":      pid,
                        "name":     name,
                        "exe":      info.get("exe"),
                        "cmdline":  " ".join(info.get("cmdline") or [])[:300],
                        "score":    score,
                        "findings": findings,
                        "description": f"Processo suspeito detectado: {reasons}",
                    },
                })
            except Exception:
                pass

        # Auto-kill
        if self.auto_kill and score >= self.kill_threshold:
            success, detail = self._kill_process(pid, proc, psutil)
            self._log_action(pid, name, score, ACTION_KILL, reasons, success, detail)
            logger.warning("EDR AUTO-KILL | pid=%d | name=%s | score=%d | %s", pid, name, score, reasons)
            return

        # Auto-block (bloqueia IPs de conexões abertas pelo processo)
        if self.auto_block and score >= self.block_threshold:
            blocked = self._block_process_connections(pid, psutil)
            detail  = f"Bloqueados {len(blocked)} IPs: {', '.join(blocked[:5])}"
            self._log_action(pid, name, score, ACTION_BLOCK, reasons, bool(blocked), detail)
            if blocked:
                logger.warning("EDR AUTO-BLOCK | pid=%d | name=%s | ips=%s", pid, name, blocked)
            return

        # Apenas alerta
        self._log_action(pid, name, score, ACTION_ALERT, reasons, True, "Alerta gerado")

    def _kill_process(self, pid: int, proc, psutil) -> tuple[bool, str]:
        try:
            import psutil as _ps
            p = _ps.Process(pid)
            p.kill()
            return True, f"PID {pid} encerrado"
        except Exception as e:
            return False, str(e)

    def _block_process_connections(self, pid: int, psutil) -> list[str]:
        blocked = []
        try:
            import psutil as _ps
            p    = _ps.Process(pid)
            conn = p.net_connections()
            for c in conn:
                if c.raddr and c.raddr.ip:
                    ip = c.raddr.ip
                    if ip not in self._blocked_ips and not ip.startswith("127."):
                        if self._block_ip_os(ip):
                            self._blocked_ips.add(ip)
                            blocked.append(ip)
        except Exception:
            pass
        return blocked

    def _block_ip_os(self, ip: str) -> bool:
        """Bloqueia IP via netsh (Windows) ou iptables (Linux)."""
        try:
            if platform.system() == "Windows":
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name=NetGuard-Block-{ip}", "dir=out", "action=block",
                     f"remoteip={ip}", "enable=yes"],
                    capture_output=True, timeout=5
                )
            else:
                subprocess.run(
                    ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
                    capture_output=True, timeout=5
                )
            return True
        except Exception:
            return False

    # ── Persistência ──────────────────────────────────────────────
    def _persist_process(self, info: dict, score: int, findings: list):
        try:
            with self._db() as c:
                c.execute(
                    "INSERT OR IGNORE INTO edr_processes"
                    "(pid,ppid,name,exe,cmdline,username,score,findings,seen_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        info.get("pid"), info.get("ppid"), info.get("name"),
                        info.get("exe"),
                        " ".join(info.get("cmdline") or [])[:500],
                        info.get("username"), score,
                        json.dumps(findings), _now(),
                    )
                )
        except Exception:
            pass

    def _mark_ended(self, pids: set):
        try:
            with self._db() as c:
                for pid in pids:
                    c.execute(
                        "UPDATE edr_processes SET status='ended', ended_at=? "
                        "WHERE pid=? AND status='running'",
                        (_now(), pid)
                    )
        except Exception:
            pass

    def _log_action(self, pid, name, score, action, reason, success, detail):
        try:
            with self._db() as c:
                c.execute(
                    "INSERT INTO edr_actions(pid,process_name,score,action,reason,success,detail,ts) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (pid, name, score, action, reason[:500], int(success), detail, _now())
                )
        except Exception:
            pass

    # ── API pública ───────────────────────────────────────────────
    def get_threats(self, min_score: int = 30, limit: int = 100) -> list:
        with self._db() as c:
            rows = c.execute(
                "SELECT * FROM edr_processes WHERE score>=? ORDER BY score DESC, seen_at DESC LIMIT ?",
                (min_score, limit)
            ).fetchall()
        return [_enrich_proc(dict(r)) for r in rows]

    def get_all_processes(self, limit: int = 200) -> list:
        with self._db() as c:
            rows = c.execute(
                "SELECT * FROM edr_processes ORDER BY seen_at DESC LIMIT ?",
                (limit,)
            ).fetchall()
        return [_enrich_proc(dict(r)) for r in rows]

    def get_actions(self, limit: int = 100) -> list:
        with self._db() as c:
            rows = c.execute(
                "SELECT * FROM edr_actions ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_live_processes(self) -> list:
        """Snapshot atual de todos os processos via psutil (sem DB)."""
        try:
            import psutil
            result = []
            for proc in psutil.process_iter(
                ["pid", "ppid", "name", "exe", "cmdline", "username",
                 "cpu_percent", "memory_percent", "status", "create_time"]
            ):
                try:
                    info = proc.info
                    score, findings = self._score_process(info, psutil)
                    result.append({
                        "pid":     info.get("pid"),
                        "ppid":    info.get("ppid"),
                        "name":    info.get("name"),
                        "exe":     info.get("exe"),
                        "cmdline": " ".join(info.get("cmdline") or [])[:200],
                        "user":    info.get("username"),
                        "cpu":     round(info.get("cpu_percent") or 0, 1),
                        "mem":     round(info.get("memory_percent") or 0, 1),
                        "status":  info.get("status"),
                        "score":   score,
                        "findings": findings,
                        "is_lolbin": (info.get("name") or "").lower() in LOLBINS,
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            return sorted(result, key=lambda x: x["score"], reverse=True)
        except ImportError:
            return []

    def kill_pid(self, pid: int) -> dict:
        try:
            import psutil
            p = psutil.Process(pid)
            name = p.name()
            p.kill()
            self._log_action(pid, name, 0, ACTION_KILL, "Manual via dashboard", True, "Encerrado manualmente")
            return {"ok": True, "msg": f"PID {pid} ({name}) encerrado"}
        except Exception as e:
            return {"ok": False, "msg": str(e)}

    def block_pid_connections(self, pid: int) -> dict:
        try:
            import psutil
            blocked = self._block_process_connections(pid, psutil)
            p       = psutil.Process(pid)
            self._log_action(pid, p.name(), 0, ACTION_BLOCK,
                             "Manual via dashboard", True, f"IPs: {blocked}")
            return {"ok": True, "blocked": blocked}
        except Exception as e:
            return {"ok": False, "msg": str(e)}

    def status(self) -> dict:
        with self._db() as c:
            total   = c.execute("SELECT COUNT(*) FROM edr_processes").fetchone()[0]
            threats = c.execute("SELECT COUNT(*) FROM edr_processes WHERE score>=30").fetchone()[0]
            actions = c.execute("SELECT COUNT(*) FROM edr_actions").fetchone()[0]
            kills   = c.execute("SELECT COUNT(*) FROM edr_actions WHERE action='kill_process'").fetchone()[0]
            blocks  = c.execute("SELECT COUNT(*) FROM edr_actions WHERE action='block_ip'").fetchone()[0]
        return {
            "running":        self._running,
            "auto_kill":      self.auto_kill,
            "auto_block":     self.auto_block,
            "kill_threshold": self.kill_threshold,
            "block_threshold":self.block_threshold,
            "poll_interval":  self.poll_interval,
            "pids_tracked":   len(self._seen_pids),
            "total_processes":total,
            "threats_found":  threats,
            "total_actions":  actions,
            "auto_kills":     kills,
            "auto_blocks":    blocks,
        }


# ── Helpers ───────────────────────────────────────────────────────
def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _enrich_proc(row: dict) -> dict:
    try:
        row["findings"] = json.loads(row.get("findings") or "[]")
    except Exception:
        row["findings"] = []
    sev = row.get("score", 0)
    row["severity"] = ("critical" if sev >= 75 else
                       "high"     if sev >= 55 else
                       "medium"   if sev >= 30 else
                       "low"      if sev >= 10 else "ok")
    return row


# ── Singleton ─────────────────────────────────────────────────────
_sentinel: Optional[EDRSentinel] = None
_sentinel_lock = threading.Lock()

def get_edr_sentinel(db_path: str, **kwargs) -> EDRSentinel:
    global _sentinel
    with _sentinel_lock:
        if _sentinel is None:
            _sentinel = EDRSentinel(db_path, **kwargs)
    return _sentinel
