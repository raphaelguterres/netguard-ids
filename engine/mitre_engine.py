"""
NetGuard IDS - MITRE ATT&CK engine.
Maps detections to MITRE ATT&CK and generates coverage data for the UI.
"""
from __future__ import annotations

import copy
import logging
import pathlib
import sqlite3
import threading
from collections import defaultdict
from datetime import datetime, timedelta, timezone

logger = logging.getLogger("netguard.mitre")

TACTICS = [
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0010", "Exfiltration"),
    ("TA0011", "Command and Control"),
    ("TA0040", "Impact"),
]
TACTIC_NAME_BY_ID = {tactic_id: tactic_name for tactic_id, tactic_name in TACTICS}

TECHNIQUES: list[dict] = [
    {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "TA0001",
     "keywords": ["sqli", "sql injection", "rce", "webshell", "exploit", "cve-", "path traversal", "lfi", "rfi", "log4j", "shellshock"]},
    {"id": "T1566", "name": "Phishing", "tactic": "TA0001",
     "keywords": ["phishing", "spear", "malicious link", "credential harvest"]},
    {"id": "T1078", "name": "Valid Accounts", "tactic": "TA0001",
     "keywords": ["brute force", "credential stuffing", "password spray", "invalid login", "failed login", "auth failure"]},
    {"id": "T1133", "name": "External Remote Services", "tactic": "TA0001",
     "keywords": ["rdp", "vpn", "ssh", "telnet", "citrix", "remote desktop", "external access"]},

    {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "TA0002",
     "keywords": ["powershell", "cmd.exe", "bash", "python", "wscript", "cscript", "mshta", "certutil", "bitsadmin", "encoded command", "executionpolicy bypass"]},
    {"id": "T1059.001", "name": "PowerShell", "tactic": "TA0002",
     "keywords": ["powershell", "invoke-expression", "iex", "downloadstring", "encodedcommand", "bypass", "hidden"]},
    {"id": "T1204", "name": "User Execution", "tactic": "TA0002",
     "keywords": ["macro", "office", "vba", "attachment", "user clicked", "executable"]},
    {"id": "T1569", "name": "System Services", "tactic": "TA0002",
     "keywords": ["sc.exe", "service create", "svchost", "service start"]},

    {"id": "T1543", "name": "Create or Modify System Process", "tactic": "TA0003",
     "keywords": ["new service", "service install", "svchost", "scheduled task", "at.exe", "schtasks"]},
    {"id": "T1547", "name": "Boot or Logon Autostart", "tactic": "TA0003",
     "keywords": ["registry run", "hkcu\\software\\microsoft\\windows\\currentversion\\run", "startup folder", "autorun"]},
    {"id": "T1136", "name": "Create Account", "tactic": "TA0003",
     "keywords": ["net user", "useradd", "adduser", "new account created", "account creation"]},

    {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "TA0004",
     "keywords": ["privilege escalation", "token impersonation", "uac bypass", "sudo exploit", "kernel exploit", "local privilege"]},
    {"id": "T1055", "name": "Process Injection", "tactic": "TA0004",
     "keywords": ["process injection", "dll injection", "reflective", "hollowing", "createremotethread", "writeprocessmemory"]},
    {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "TA0004",
     "keywords": ["uac", "bypass uac", "eventvwr", "fodhelper", "sdclt", "sudo -s", "su root"]},

    {"id": "T1562", "name": "Impair Defenses", "tactic": "TA0005",
     "keywords": ["disable firewall", "netsh advfirewall", "defender disable", "antivirus disabled", "security tools stopped", "ufw disable"]},
    {"id": "T1070", "name": "Indicator Removal", "tactic": "TA0005",
     "keywords": ["clear log", "wevtutil cl", "rm -rf /var/log", "del /f", "shred", "log cleared", "audit log deleted"]},
    {"id": "T1036", "name": "Masquerading", "tactic": "TA0005",
     "keywords": ["svchost.exe in wrong path", "renamed executable", "fake process", "double extension"]},
    {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "TA0005",
     "keywords": ["base64", "encoded payload", "obfuscated", "xor encoded", "packed binary", "eval(", "frombase64string"]},

    {"id": "T1110", "name": "Brute Force", "tactic": "TA0006",
     "keywords": ["brute force", "multiple failed", "login attempts", "password attack", "hydra", "medusa", "ncrack", "dictionary attack"]},
    {"id": "T1003", "name": "OS Credential Dumping", "tactic": "TA0006",
     "keywords": ["mimikatz", "lsass", "secretsdump", "hashdump", "credential dump", "sam database", "ntds.dit", "procdump lsass"]},
    {"id": "T1552", "name": "Unsecured Credentials", "tactic": "TA0006",
     "keywords": ["plaintext password", "credentials in file", "hardcoded password", "config file password", "env variable password"]},
    {"id": "T1056", "name": "Input Capture", "tactic": "TA0006",
     "keywords": ["keylogger", "keystroke", "input capture", "form grabbing"]},

    {"id": "T1046", "name": "Network Service Discovery", "tactic": "TA0007",
     "keywords": ["port scan", "nmap", "masscan", "shodan", "portscan", "network scan", "service scan", "syn scan"]},
    {"id": "T1082", "name": "System Information Discovery", "tactic": "TA0007",
     "keywords": ["systeminfo", "uname -a", "hostname", "whoami", "ipconfig", "ifconfig", "env |", "cat /etc/os-release"]},
    {"id": "T1083", "name": "File and Directory Discovery", "tactic": "TA0007",
     "keywords": ["dir /s", "find / -name", "ls -la /", "ls /etc", "directory listing", "directory traversal discovered"]},
    {"id": "T1018", "name": "Remote System Discovery", "tactic": "TA0007",
     "keywords": ["arp scan", "arp -a", "ping sweep", "netdiscover", "nbtscan", "net view"]},

    {"id": "T1021", "name": "Remote Services", "tactic": "TA0008",
     "keywords": ["psexec", "wmiexec", "lateral movement", "remote execute", "winrm", "smbexec", "pass the hash", "pass the ticket"]},
    {"id": "T1570", "name": "Lateral Tool Transfer", "tactic": "TA0008",
     "keywords": ["smb transfer", "file copy", "xcopy", "robocopy", "curl -o", "wget -O", "bitsadmin transfer"]},

    {"id": "T1114", "name": "Email Collection", "tactic": "TA0009",
     "keywords": ["email exfil", "mailbox access", "owa access", "exchange", "pst file", "email harvesting"]},
    {"id": "T1005", "name": "Data from Local System", "tactic": "TA0009",
     "keywords": ["sensitive file", "data collection", "clipboard", "screenshot capture", "document access"]},

    {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "TA0010",
     "keywords": ["data exfiltration", "large upload", "unusual upload", "outbound data", "exfil", "curl post large"]},
    {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "TA0010",
     "keywords": ["dns tunnel", "icmp tunnel", "dns exfil", "ftp exfil", "dnscat", "iodine"]},

    {"id": "T1071", "name": "Application Layer Protocol", "tactic": "TA0011",
     "keywords": ["c2", "command and control", "beacon", "c&c", "rat", "remote access trojan", "cobalt strike", "metasploit", "meterpreter"]},
    {"id": "T1095", "name": "Non-Application Layer Protocol", "tactic": "TA0011",
     "keywords": ["icmp c2", "raw socket", "custom protocol c2"]},
    {"id": "T1572", "name": "Protocol Tunneling", "tactic": "TA0011",
     "keywords": ["dns tunnel", "http tunnel", "ssh tunnel", "ngrok", "cloudflare tunnel", "tcp over http"]},
    {"id": "T1219", "name": "Remote Access Software", "tactic": "TA0011",
     "keywords": ["anydesk", "teamviewer", "ultraviewer", "rustdesk", "atera", "screenconnect", "remote utilities"]},
    {"id": "T1008", "name": "Fallback Channels", "tactic": "TA0011",
     "keywords": ["domain generation algorithm", "dga", "fast flux", "tor exit", "onion routing", "bulletproof"]},

    {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "TA0040",
     "keywords": ["ransomware", "encrypted files", "vssadmin delete", "wbadmin delete", "bcdedit", "ransom note", "your files are encrypted"]},
    {"id": "T1498", "name": "Network Denial of Service", "tactic": "TA0040",
     "keywords": ["ddos", "dos attack", "syn flood", "udp flood", "http flood", "amplification", "denial of service", "connection flood"]},
    {"id": "T1489", "name": "Service Stop", "tactic": "TA0040",
     "keywords": ["service stopped", "net stop", "systemctl stop", "kill -9", "service disabled", "av stopped", "backup deleted"]},
    {"id": "T1485", "name": "Data Destruction", "tactic": "TA0040",
     "keywords": ["rm -rf", "del /f /s", "wipe disk", "diskpart clean", "data destruction", "format c:", "dd if=/dev/zero"]},
]

_KEYWORD_INDEX: dict[str, list[dict]] = defaultdict(list)
for technique in TECHNIQUES:
    for keyword in technique["keywords"]:
        _KEYWORD_INDEX[keyword].append(technique)

SCHEMA = """
CREATE TABLE IF NOT EXISTS mitre_hits (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id     TEXT NOT NULL DEFAULT 'default',
    technique_id  TEXT NOT NULL,
    technique_name TEXT NOT NULL,
    tactic_id     TEXT NOT NULL,
    event_id      TEXT,
    threat_name   TEXT,
    severity      TEXT,
    source_ip     TEXT,
    ts            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_mitre_tenant ON mitre_hits(tenant_id, ts);
CREATE INDEX IF NOT EXISTS idx_mitre_tech ON mitre_hits(tenant_id, technique_id);
"""


def _heat_color(count: int, max_count: int) -> str:
    if count <= 0 or max_count <= 0:
        return ""
    ratio = count / max_count
    if ratio < 0.33:
        return "#d29922"
    if ratio < 0.66:
        return "#f0883e"
    return "#f85149"


class MitreEngine:
    def __init__(self, db_path: str, tenant_id: str = "default"):
        self.db_path = db_path
        self.tenant_id = tenant_id
        self._cache: dict[str, dict] = {}
        self._cache_lock = threading.Lock()
        self._schema_ready = False
        self._init_db()

    def _db(self, *, read_only: bool = False):
        timeout = 1.0 if read_only else 3.0
        if read_only:
            db_uri = f"{pathlib.Path(self.db_path).resolve().as_uri()}?mode=ro"
            conn = sqlite3.connect(db_uri, timeout=timeout, uri=True)
        else:
            conn = sqlite3.connect(self.db_path, timeout=timeout)
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout={int(timeout * 1000)}")
        if read_only:
            conn.execute("PRAGMA query_only=ON")
        return conn

    def _init_db(self):
        try:
            with self._db() as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.executescript(SCHEMA)
            self._schema_ready = True
        except sqlite3.OperationalError as exc:
            if self._is_locked_error(exc):
                logger.warning("MITRE init deferred due to locked database | tenant=%s", self.tenant_id)
                return
            raise

    @staticmethod
    def _is_missing_table_error(exc: Exception) -> bool:
        return "no such table" in str(exc).lower()

    @staticmethod
    def _is_locked_error(exc: Exception) -> bool:
        return "database is locked" in str(exc).lower()

    def _cache_get(self, key: str):
        with self._cache_lock:
            cached = self._cache.get(key)
            return copy.deepcopy(cached)

    def _cache_set(self, key: str, value):
        with self._cache_lock:
            self._cache[key] = copy.deepcopy(value)
        return value

    def _cache_clear(self):
        with self._cache_lock:
            self._cache.clear()

    def _empty_heat_map(self, days: int, *, degraded: bool = False) -> dict:
        payload = {
            "matrix": [
                {
                    "tactic_id": tactic_id,
                    "tactic_name": tactic_name,
                    "techniques": [
                        {"id": tech["id"], "name": tech["name"], "count": 0, "color": ""}
                        for tech in TECHNIQUES
                        if tech["tactic"] == tactic_id
                    ],
                }
                for tactic_id, tactic_name in TACTICS
            ],
            "top_techniques": [],
            "top10": [],
            "total_hits": 0,
            "days": days,
        }
        if degraded:
            payload["degraded"] = True
            payload["warning"] = "database_locked"
        return payload

    def _empty_stats(self, *, degraded: bool = False) -> dict:
        payload = {
            "total_hits": 0,
            "unique_techniques_hit": 0,
            "unique_tactics_hit": 0,
            "total_techniques": len(TECHNIQUES),
            "total_tactics": len(TACTICS),
            "coverage_pct": 0.0,
        }
        if degraded:
            payload["degraded"] = True
            payload["warning"] = "database_locked"
        return payload

    def _fallback_heat_map(self, days: int) -> dict:
        cached = self._cache_get(f"heat_map:{days}")
        if cached:
            cached["degraded"] = True
            cached["warning"] = "database_locked"
            return cached
        return self._empty_heat_map(days, degraded=True)

    def _fallback_stats(self) -> dict:
        cached = self._cache_get("stats")
        if cached:
            cached["degraded"] = True
            cached["warning"] = "database_locked"
            return cached
        return self._empty_stats(degraded=True)

    @staticmethod
    def map_event(text: str) -> list[dict]:
        low = (text or "").lower()
        matched: list[dict] = []
        seen: set[str] = set()
        for keyword, techniques in _KEYWORD_INDEX.items():
            if keyword in low:
                for technique in techniques:
                    technique_id = technique["id"]
                    if technique_id in seen:
                        continue
                    seen.add(technique_id)
                    matched.append(technique)
        return matched

    def record_hit(self, event: dict, techniques: list[dict]):
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        rows = [
            (
                self.tenant_id,
                technique["id"],
                technique["name"],
                technique["tactic"],
                event.get("event_id", ""),
                event.get("threat", ""),
                event.get("severity", ""),
                event.get("source_ip", ""),
                ts,
            )
            for technique in techniques
        ]
        if not rows:
            return
        try:
            with self._db() as conn:
                conn.executemany(
                    "INSERT INTO mitre_hits(tenant_id,technique_id,technique_name,tactic_id,"
                    "event_id,threat_name,severity,source_ip,ts) VALUES(?,?,?,?,?,?,?,?,?)",
                    rows,
                )
            self._cache_clear()
        except sqlite3.OperationalError as exc:
            if self._is_locked_error(exc):
                logger.warning("MITRE write skipped due to locked database | tenant=%s", self.tenant_id)
                return
            if self._is_missing_table_error(exc):
                logger.warning("MITRE write skipped because schema is not ready | tenant=%s", self.tenant_id)
                self._init_db()
                return
            raise

    def heat_map(self, days: int = 30) -> dict:
        since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            with self._db(read_only=True) as conn:
                rows = conn.execute(
                    "SELECT technique_id, technique_name, tactic_id, COUNT(*) AS cnt "
                    "FROM mitre_hits WHERE tenant_id=? AND ts>=? "
                    "GROUP BY technique_id ORDER BY cnt DESC",
                    (self.tenant_id, since),
                ).fetchall()
        except sqlite3.OperationalError as exc:
            if self._is_locked_error(exc):
                logger.warning("MITRE heatmap fallback due to locked database | tenant=%s", self.tenant_id)
                return self._fallback_heat_map(days)
            if self._is_missing_table_error(exc):
                logger.warning("MITRE heatmap fallback because schema is not ready | tenant=%s", self.tenant_id)
                return self._fallback_heat_map(days)
            raise

        counts = {
            row["technique_id"]: {
                "name": row["technique_name"],
                "tactic": row["tactic_id"],
                "count": row["cnt"],
            }
            for row in rows
        }
        max_count = max((item["count"] for item in counts.values()), default=0)

        matrix = []
        for tactic_id, tactic_name in TACTICS:
            techniques = []
            for technique in TECHNIQUES:
                if technique["tactic"] != tactic_id:
                    continue
                count = counts.get(technique["id"], {}).get("count", 0)
                techniques.append({
                    "id": technique["id"],
                    "name": technique["name"],
                    "count": count,
                    "color": _heat_color(count, max_count),
                })
            matrix.append({
                "tactic_id": tactic_id,
                "tactic_name": tactic_name,
                "techniques": techniques,
            })

        top_techniques = [
            {
                "id": technique_id,
                **info,
                "tactic_name": TACTIC_NAME_BY_ID.get(info["tactic"], info["tactic"]),
                "color": _heat_color(info["count"], max_count),
            }
            for technique_id, info in sorted(counts.items(), key=lambda item: -item[1]["count"])
        ][:10]

        payload = {
            "matrix": matrix,
            "top_techniques": top_techniques,
            "top10": top_techniques,
            "total_hits": sum(row["cnt"] for row in rows),
            "days": days,
        }
        return self._cache_set(f"heat_map:{days}", payload)

    def recent_hits(self, limit: int = 50) -> list[dict]:
        try:
            with self._db(read_only=True) as conn:
                rows = conn.execute(
                    "SELECT * FROM mitre_hits WHERE tenant_id=? ORDER BY id DESC LIMIT ?",
                    (self.tenant_id, limit),
                ).fetchall()
        except sqlite3.OperationalError as exc:
            if self._is_locked_error(exc):
                logger.warning("MITRE recent hits fallback due to locked database | tenant=%s", self.tenant_id)
                return []
            if self._is_missing_table_error(exc):
                logger.warning("MITRE recent hits fallback because schema is not ready | tenant=%s", self.tenant_id)
                return []
            raise
        return [dict(row) for row in rows]

    def technique_detail(self, technique_id: str, days: int = 30) -> dict:
        since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        technique = next((item for item in TECHNIQUES if item["id"] == technique_id), None)
        attack_url = f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
        try:
            with self._db(read_only=True) as conn:
                rows = conn.execute(
                    "SELECT * FROM mitre_hits WHERE tenant_id=? AND technique_id=? AND ts>=? "
                    "ORDER BY id DESC LIMIT 100",
                    (self.tenant_id, technique_id, since),
                ).fetchall()
        except sqlite3.OperationalError as exc:
            if self._is_locked_error(exc):
                logger.warning("MITRE technique detail fallback due to locked database | tenant=%s", self.tenant_id)
                rows = []
            elif self._is_missing_table_error(exc):
                logger.warning("MITRE technique detail fallback because schema is not ready | tenant=%s", self.tenant_id)
                rows = []
            else:
                raise

        payload = {
            "id": technique["id"] if technique else technique_id,
            "name": technique["name"] if technique else technique_id,
            "tactic": technique["tactic"] if technique else "",
            "tactic_name": TACTIC_NAME_BY_ID.get(technique["tactic"], technique["tactic"]) if technique else "",
            "keywords": technique.get("keywords", []) if technique else [],
            "description": technique.get("description", "") if technique else "",
            "url": attack_url,
            "technique": technique,
            "hits": [dict(row) for row in rows],
            "count": len(rows),
            "attack_url": attack_url,
        }
        return payload

    def navigator_layer(self, days: int = 30) -> dict:
        heat_map = self.heat_map(days)
        counts = {
            technique["id"]: technique["count"]
            for tactic in heat_map.get("matrix", [])
            for technique in tactic.get("techniques", [])
            if technique.get("count", 0) > 0
        }
        max_count = max(counts.values(), default=1)
        return {
            "name": "NetGuard IDS Coverage",
            "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": f"Techniques detected in the last {days} days",
            "techniques": [
                {
                    "techniqueID": technique_id,
                    "score": count,
                    "color": _heat_color(count, max_count),
                    "comment": f"{count} detections",
                    "enabled": True,
                }
                for technique_id, count in counts.items()
            ],
            "gradient": {
                "colors": ["#ffffcc", "#fd8d3c", "#bd0026"],
                "minValue": 0,
                "maxValue": max_count,
            },
            "legendItems": [
                {"label": "Detected (low)", "color": "#fd8d3c"},
                {"label": "Detected (high)", "color": "#bd0026"},
            ],
        }

    def stats(self) -> dict:
        try:
            with self._db(read_only=True) as conn:
                total_hits = conn.execute(
                    "SELECT COUNT(*) FROM mitre_hits WHERE tenant_id=?",
                    (self.tenant_id,),
                ).fetchone()[0]
                unique_techniques_hit = conn.execute(
                    "SELECT COUNT(DISTINCT technique_id) FROM mitre_hits WHERE tenant_id=?",
                    (self.tenant_id,),
                ).fetchone()[0]
                unique_tactics_hit = conn.execute(
                    "SELECT COUNT(DISTINCT tactic_id) FROM mitre_hits WHERE tenant_id=?",
                    (self.tenant_id,),
                ).fetchone()[0]
        except sqlite3.OperationalError as exc:
            if self._is_locked_error(exc):
                logger.warning("MITRE stats fallback due to locked database | tenant=%s", self.tenant_id)
                return self._fallback_