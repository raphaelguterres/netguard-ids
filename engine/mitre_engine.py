"""
NetGuard IDS — MITRE ATT&CK Engine
Mapeia detecções para o framework MITRE ATT&CK e gera heat maps de cobertura.
"""
from __future__ import annotations  # noqa: F401

import json  # noqa: F401
import logging
import sqlite3
import threading
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Optional  # noqa: F401

logger = logging.getLogger("netguard.mitre")

# ── ATT&CK Tactics (kill chain phases) ───────────────────────────
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

# ── Técnicas mapeadas (subset das mais relevantes para IDS de rede) ─
TECHNIQUES: list[dict] = [
    # ── Initial Access ─────────────────────────────────────────────
    {"id":"T1190","name":"Exploit Public-Facing Application","tactic":"TA0001",
     "keywords":["sqli","sql injection","rce","webshell","exploit","cve-","path traversal","lfi","rfi","log4j","shellshock"]},
    {"id":"T1566","name":"Phishing","tactic":"TA0001",
     "keywords":["phishing","spear","malicious link","credential harvest"]},
    {"id":"T1078","name":"Valid Accounts","tactic":"TA0001",
     "keywords":["brute force","credential stuffing","password spray","invalid login","failed login","auth failure"]},
    {"id":"T1133","name":"External Remote Services","tactic":"TA0001",
     "keywords":["rdp","vpn","ssh","telnet","citrix","remote desktop","external access"]},

    # ── Execution ──────────────────────────────────────────────────
    {"id":"T1059","name":"Command and Scripting Interpreter","tactic":"TA0002",
     "keywords":["powershell","cmd.exe","bash","python","wscript","cscript","mshta","certutil","bitsadmin","encoded command","executionpolicy bypass"]},
    {"id":"T1059.001","name":"PowerShell","tactic":"TA0002",
     "keywords":["powershell","invoke-expression","iex","downloadstring","encodedcommand","bypass","hidden"]},
    {"id":"T1204","name":"User Execution","tactic":"TA0002",
     "keywords":["macro","office","vba","attachment","user clicked","executable"]},
    {"id":"T1569","name":"System Services","tactic":"TA0002",
     "keywords":["sc.exe","service create","svchost","service start"]},

    # ── Persistence ────────────────────────────────────────────────
    {"id":"T1543","name":"Create or Modify System Process","tactic":"TA0003",
     "keywords":["new service","service install","svchost","scheduled task","at.exe","schtasks"]},
    {"id":"T1547","name":"Boot or Logon Autostart","tactic":"TA0003",
     "keywords":["registry run","hkcu\\software\\microsoft\\windows\\currentversion\\run","startup folder","autorun"]},
    {"id":"T1136","name":"Create Account","tactic":"TA0003",
     "keywords":["net user","useradd","adduser","new account created","account creation"]},

    # ── Privilege Escalation ───────────────────────────────────────
    {"id":"T1068","name":"Exploitation for Privilege Escalation","tactic":"TA0004",
     "keywords":["privilege escalation","token impersonation","uac bypass","sudo exploit","kernel exploit","local privilege"]},
    {"id":"T1055","name":"Process Injection","tactic":"TA0004",
     "keywords":["process injection","dll injection","reflective","hollowing","createremotethread","writeprocessmemory"]},
    {"id":"T1548","name":"Abuse Elevation Control Mechanism","tactic":"TA0004",
     "keywords":["uac","bypass uac","eventvwr","fodhelper","sdclt","sudo -s","su root"]},

    # ── Defense Evasion ────────────────────────────────────────────
    {"id":"T1562","name":"Impair Defenses","tactic":"TA0005",
     "keywords":["disable firewall","netsh advfirewall","defender disable","antivirus disabled","security tools stopped","ufw disable"]},
    {"id":"T1070","name":"Indicator Removal","tactic":"TA0005",
     "keywords":["clear log","wevtutil cl","rm -rf /var/log","del /f","shred","log cleared","audit log deleted"]},
    {"id":"T1036","name":"Masquerading","tactic":"TA0005",
     "keywords":["svchost.exe in wrong path","renamed executable","fake process","double extension"]},
    {"id":"T1027","name":"Obfuscated Files or Information","tactic":"TA0005",
     "keywords":["base64","encoded payload","obfuscated","xor encoded","packed binary","eval(","frombase64string"]},

    # ── Credential Access ──────────────────────────────────────────
    {"id":"T1110","name":"Brute Force","tactic":"TA0006",
     "keywords":["brute force","multiple failed","login attempts","password attack","hydra","medusa","ncrack","dictionary attack"]},
    {"id":"T1003","name":"OS Credential Dumping","tactic":"TA0006",
     "keywords":["mimikatz","lsass","secretsdump","hashdump","credential dump","sam database","ntds.dit","procdump lsass"]},
    {"id":"T1552","name":"Unsecured Credentials","tactic":"TA0006",
     "keywords":["plaintext password","credentials in file","hardcoded password","config file password","env variable password"]},
    {"id":"T1056","name":"Input Capture","tactic":"TA0006",
     "keywords":["keylogger","keystroke","input capture","form grabbing"]},

    # ── Discovery ──────────────────────────────────────────────────
    {"id":"T1046","name":"Network Service Discovery","tactic":"TA0007",
     "keywords":["port scan","nmap","masscan","shodan","portscan","network scan","service scan","syn scan"]},
    {"id":"T1082","name":"System Information Discovery","tactic":"TA0007",
     "keywords":["systeminfo","uname -a","hostname","whoami","ipconfig","ifconfig","env |","cat /etc/os-release"]},
    {"id":"T1083","name":"File and Directory Discovery","tactic":"TA0007",
     "keywords":["dir /s","find / -name","ls -la /","ls /etc","directory listing","directory traversal discovered"]},
    {"id":"T1018","name":"Remote System Discovery","tactic":"TA0007",
     "keywords":["arp scan","arp -a","ping sweep","netdiscover","nbtscan","net view"]},

    # ── Lateral Movement ───────────────────────────────────────────
    {"id":"T1021","name":"Remote Services","tactic":"TA0008",
     "keywords":["psexec","wmiexec","lateral movement","remote execute","winrm","smbexec","pass the hash","pass the ticket"]},
    {"id":"T1570","name":"Lateral Tool Transfer","tactic":"TA0008",
     "keywords":["smb transfer","file copy","xcopy","robocopy","curl -o","wget -O","bitsadmin transfer"]},

    # ── Collection ─────────────────────────────────────────────────
    {"id":"T1114","name":"Email Collection","tactic":"TA0009",
     "keywords":["email exfil","mailbox access","owa access","exchange","pst file","email harvesting"]},
    {"id":"T1005","name":"Data from Local System","tactic":"TA0009",
     "keywords":["sensitive file","data collection","clipboard","screenshot capture","document access"]},

    # ── Exfiltration ───────────────────────────────────────────────
    {"id":"T1041","name":"Exfiltration Over C2 Channel","tactic":"TA0010",
     "keywords":["data exfiltration","large upload","unusual upload","outbound data","exfil","curl post large"]},
    {"id":"T1048","name":"Exfiltration Over Alternative Protocol","tactic":"TA0010",
     "keywords":["dns tunnel","icmp tunnel","dns exfil","ftp exfil","dnscat","iodine"]},

    # ── Command and Control ────────────────────────────────────────
    {"id":"T1071","name":"Application Layer Protocol","tactic":"TA0011",
     "keywords":["c2","command and control","beacon","c&c","rat","remote access trojan","cobalt strike","metasploit","meterpreter"]},
    {"id":"T1095","name":"Non-Application Layer Protocol","tactic":"TA0011",
     "keywords":["icmp c2","raw socket","custom protocol c2"]},
    {"id":"T1572","name":"Protocol Tunneling","tactic":"TA0011",
     "keywords":["dns tunnel","http tunnel","ssh tunnel","ngrok","cloudflare tunnel","tcp over http"]},
    {"id":"T1219","name":"Remote Access Software","tactic":"TA0011",
     "keywords":["anydesk","teamviewer","ultraviewer","rustdesk","atera","screenconnect","remote utilities"]},
    {"id":"T1008","name":"Fallback Channels","tactic":"TA0011",
     "keywords":["domain generation algorithm","dga","fast flux","tor exit","onion routing","bulletproof"]},

    # ── Impact ─────────────────────────────────────────────────────
    {"id":"T1486","name":"Data Encrypted for Impact","tactic":"TA0040",
     "keywords":["ransomware","encrypted files","vssadmin delete","wbadmin delete","bcdedit","ransom note","your files are encrypted"]},
    {"id":"T1498","name":"Network Denial of Service","tactic":"TA0040",
     "keywords":["ddos","dos attack","syn flood","udp flood","http flood","amplification","denial of service","connection flood"]},
    {"id":"T1489","name":"Service Stop","tactic":"TA0040",
     "keywords":["service stopped","net stop","systemctl stop","kill -9","service disabled","av stopped","backup deleted"]},
    {"id":"T1485","name":"Data Destruction","tactic":"TA0040",
     "keywords":["rm -rf","del /f /s","wipe disk","diskpart clean","data destruction","format c:","dd if=/dev/zero"]},
]

# Índice keyword→técnica para lookup O(1)
_KEYWORD_INDEX: dict[str, list[dict]] = defaultdict(list)
for _t in TECHNIQUES:
    for _kw in _t["keywords"]:
        _KEYWORD_INDEX[_kw].append(_t)


# ── Schema ────────────────────────────────────────────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS mitre_hits (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   TEXT    NOT NULL DEFAULT 'default',
    technique_id TEXT   NOT NULL,
    technique_name TEXT NOT NULL,
    tactic_id   TEXT    NOT NULL,
    event_id    TEXT,
    threat_name TEXT,
    severity    TEXT,
    source_ip   TEXT,
    ts          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_mitre_tenant ON mitre_hits(tenant_id, ts);
CREATE INDEX IF NOT EXISTS idx_mitre_tech   ON mitre_hits(tenant_id, technique_id);
"""


class MitreEngine:
    def __init__(self, db_path: str, tenant_id: str = "default"):
        self.db_path   = db_path
        self.tenant_id = tenant_id
        self._lock     = threading.Lock()
        self._init_db()

    def _db(self):
        c = sqlite3.connect(self.db_path, timeout=10)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        return c

    def _init_db(self):
        with self._db() as c:
            c.executescript(SCHEMA)

    # ── Mapeamento ────────────────────────────────────────────────
    @staticmethod
    def map_event(text: str) -> list[dict]:
        """Retorna lista de técnicas ATT&CK identificadas no texto."""
        low = text.lower()
        matched, seen = [], set()
        for kw, techs in _KEYWORD_INDEX.items():
            if kw in low:
                for t in techs:
                    if t["id"] not in seen:
                        seen.add(t["id"])
                        matched.append(t)
        return matched

    def record_hit(self, event: dict, techniques: list[dict]):
        """Persiste hit de técnica ATT&CK para um evento."""
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        rows = [
            (self.tenant_id, t["id"], t["name"], t["tactic"],
             event.get("event_id",""), event.get("threat",""),
             event.get("severity",""), event.get("source_ip",""), ts)
            for t in techniques
        ]
        with self._db() as c:
            c.executemany(
                "INSERT INTO mitre_hits(tenant_id,technique_id,technique_name,tactic_id,"
                "event_id,threat_name,severity,source_ip,ts) VALUES(?,?,?,?,?,?,?,?,?)",
                rows
            )

    # ── Heat Map ──────────────────────────────────────────────────
    def heat_map(self, days: int = 30) -> dict:
        """Retorna contagem de hits por técnica para o heat map."""
        since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._db() as c:
            rows = c.execute(
                "SELECT technique_id, technique_name, tactic_id, COUNT(*) as cnt "
                "FROM mitre_hits WHERE tenant_id=? AND ts>=? "
                "GROUP BY technique_id ORDER BY cnt DESC",
                (self.tenant_id, since)
            ).fetchall()

        counts = {r["technique_id"]: {"name": r["technique_name"],
                                       "tactic": r["tactic_id"],
                                       "count": r["cnt"]}
                  for r in rows}

        # Monta estrutura completa (técnicas sem hits = count 0)
        matrix = []
        for tactic_id, tactic_name in TACTICS:
            techs = [t for t in TECHNIQUES if t["tactic"] == tactic_id]
            matrix.append({
                "tactic_id":   tactic_id,
                "tactic_name": tactic_name,
                "techniques":  [
                    {"id": t["id"], "name": t["name"],
                     "count": counts.get(t["id"], {}).get("count", 0)}
                    for t in techs
                ]
            })
        return {
            "matrix":    matrix,
            "top_techniques": [
                {"id": tid, **info}
                for tid, info in sorted(counts.items(), key=lambda x: -x[1]["count"])
            ][:10],
            "total_hits": sum(r["cnt"] for r in rows),
            "days":       days,
        }

    def recent_hits(self, limit: int = 50) -> list:
        with self._db() as c:
            rows = c.execute(
                "SELECT * FROM mitre_hits WHERE tenant_id=? ORDER BY id DESC LIMIT ?",
                (self.tenant_id, limit)
            ).fetchall()
        return [dict(r) for r in rows]

    def technique_detail(self, technique_id: str, days: int = 30) -> dict:
        since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._db() as c:
            hits = c.execute(
                "SELECT * FROM mitre_hits WHERE tenant_id=? AND technique_id=? AND ts>=? "
                "ORDER BY id DESC LIMIT 100",
                (self.tenant_id, technique_id, since)
            ).fetchall()
        tech = next((t for t in TECHNIQUES if t["id"] == technique_id), None)
        return {
            "technique": tech,
            "hits":      [dict(r) for r in hits],
            "count":     len(hits),
            "attack_url": f"https://attack.mitre.org/techniques/{technique_id.replace('.','/')}/"
        }

    def navigator_layer(self, days: int = 30) -> dict:
        """Exporta ATT&CK Navigator layer JSON compatível com mitre-attack/attack-navigator."""
        hm     = self.heat_map(days)
        counts = {t["id"]: t["count"]
                  for tac in hm["matrix"] for t in tac["techniques"] if t["count"] > 0}
        max_c  = max(counts.values(), default=1)

        return {
            "name":        "NetGuard IDS Coverage",
            "versions":    {"attack": "14", "navigator": "4.9", "layer": "4.5"},
            "domain":      "enterprise-attack",
            "description": f"Técnicas detectadas nos últimos {days} dias",
            "techniques":  [
                {
                    "techniqueID": tid,
                    "score":       cnt,
                    "color":       _heat_color(cnt, max_c),
                    "comment":     f"{cnt} detecções",
                    "enabled":     True,
                }
                for tid, cnt in counts.items()
            ],
            "gradient": {
                "colors": ["#ffffcc","#fd8d3c","#bd0026"],
                "minValue": 0,
                "maxValue": max_c,
            },
            "legendItems": [
                {"label": "Detectado (baixo)",  "color": "#fd8d3c"},
                {"label": "Detectado (alto)",   "color": "#bd0026"},
            ],
        }

    def stats(self) -> dict:
        with self._db() as c:
            total = c.execute(
                "SELECT COUNT(*) FROM mitre_hits WHERE tenant_id=?", (self.tenant_id,)
            ).fetchone()[0]
            unique_techs = c.execute(
                "SELECT COUNT(DISTINCT technique_id) FROM mitre_hits WHERE tenant_id=?",
                (self.tenant_id,)
            ).fetchone()[0]
            unique_tactics = c.execute(
                "SELECT COUNT(DISTINCT tactic_id) FROM mitre_hits WHERE tenant_id=?",
                (self.tenant_id,)
            ).fetchone()[0]
        total_techs  = len(TECHNIQUES)
        total_tactics = len(TACTICS)
        return {
            "total_hits":     total,
            "unique_techniques_hit": unique_techs,
            "unique_tactics_hit":   unique_tactics,
            "total_techniques": total_techs,
            "total_tactics":    total_tactics,
            "coverage_pct":   round(unique_techs / total_techs * 100, 1),
        }


def _heat_color(count: int, max_count: int) -> str:
    if count == 0 or max_count == 0:
        return ""
    ratio = count / max_count
    if ratio < 0.33:
        return "#d29922"
    elif ratio < 0.66:
        return "#f0883e"
    return "#f85149"


# ── Singleton ─────────────────────────────────────────────────────
_engines: dict[str, MitreEngine] = {}
_lock = threading.Lock()

def get_mitre_engine(db_path: str, tenant_id: str = "default") -> MitreEngine:
    key = f"{db_path}::{tenant_id}"
    with _lock:
        if key not in _engines:
            _engines[key] = MitreEngine(db_path, tenant_id)
    return _engines[key]
