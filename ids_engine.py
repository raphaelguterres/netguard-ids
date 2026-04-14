"""
NetGuard IDS Engine v3.0
Detecção contextual, janela deslizante, whitelist,
composite scoring, persistência SQLite, bloqueio de IP.
"""

import os, re, json, sqlite3, hashlib, logging, threading, subprocess, copy, time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional
from urllib.parse import unquote
from enum import Enum


# ── Enums ────────────────────────────────────────────────────────

class Severity(str, Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"

    @property
    def score(self) -> int:
        return {"low":1,"medium":2,"high":3,"critical":4}[self.value]


class DetectionMethod(str, Enum):
    SIGNATURE = "signature"
    THRESHOLD = "threshold"
    COMPOSITE = "composite"
    BLOCK     = "block"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_iso() -> str:
    return _utc_now().isoformat().replace("+00:00", "Z")


# ── Modelos ──────────────────────────────────────────────────────

@dataclass
class ThreatSignature:
    name:             str
    pattern:          str
    severity:         Severity
    description:      str
    mitre_tactic:     str  = ""
    mitre_technique:  str  = ""
    context_required: List[str] = field(default_factory=list)
    false_positive_rate: float  = 0.02
    _compiled: object = field(default=None, init=False, repr=False)

    def __post_init__(self):
        self._compiled = re.compile(self.pattern, re.IGNORECASE | re.DOTALL)

    def matches(self, text: str) -> bool:
        return bool(self._compiled.search(text))


@dataclass
class DetectionEvent:
    detection_id:    str
    timestamp:       str
    threat_name:     str
    severity:        str
    description:     str
    source_ip:       str
    log_entry:       str
    method:          str
    mitre_tactic:    str
    mitre_technique: str
    status:          str   = "active"
    analyst_note:    str   = ""
    confidence:      float = 1.0
    count:           int   = 1
    updated_at:      Optional[str] = None

    def to_dict(self) -> Dict:
        return asdict(self)


# ── Sliding window counter ────────────────────────────────────────

class SlidingWindowCounter:
    def __init__(self, window_seconds: int = 60):
        self.window = timedelta(seconds=window_seconds)
        self._data: Dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def add(self, key: str) -> int:
        now = _utc_now()
        with self._lock:
            dq = self._data[key]
            dq.append(now)
            cutoff = now - self.window
            while dq and dq[0] < cutoff:
                dq.popleft()
            return len(dq)

    def count(self, key: str) -> int:
        now = _utc_now()
        with self._lock:
            dq = self._data[key]
            cutoff = now - self.window
            while dq and dq[0] < cutoff:
                dq.popleft()
            return len(dq)

    def reset(self, key: str):
        with self._lock:
            self._data.pop(key, None)


# ── Bloqueio de IP (Windows Firewall / iptables) ─────────────────

class IPBlocker:
    """
    Bloqueia IPs no firewall do sistema operacional.
    Windows: netsh advfirewall
    Linux:   iptables
    """
    def __init__(self):
        self._blocked: Dict[str, str] = {}   # ip -> motivo
        self._lock = threading.Lock()
        import platform
        self.is_windows = platform.system() == "Windows"
        self.logger = logging.getLogger("ids.blocker")

    def block(self, ip: str, reason: str) -> bool:
        with self._lock:
            if ip in self._blocked:
                return True  # já bloqueado
        try:
            if self.is_windows:
                ok = self._block_windows(ip, reason)
            else:
                ok = self._block_linux(ip, reason)
            if ok:
                with self._lock:
                    self._blocked[ip] = reason
                self.logger.warning("IP BLOQUEADO | %s | %s", ip, reason)
            return ok
        except Exception as e:
            self.logger.error("Falha ao bloquear %s: %s", ip, e)
            return False

    def unblock(self, ip: str) -> bool:
        try:
            if self.is_windows:
                ok = self._unblock_windows(ip)
            else:
                ok = self._unblock_linux(ip)
            if ok:
                with self._lock:
                    self._blocked.pop(ip, None)
                self.logger.info("IP DESBLOQUEADO | %s", ip)
            return ok
        except Exception as e:
            self.logger.error("Falha ao desbloquear %s: %s", ip, e)
            return False

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._blocked

    def list_blocked(self) -> Dict[str, str]:
        with self._lock:
            return dict(self._blocked)

    def _block_windows(self, ip: str, reason: str) -> bool:
        rule = f"IDS_BLOCK_{ip.replace('.','_')}"
        cmd = ["netsh","advfirewall","firewall","add","rule",
               f"name={rule}","dir=in","action=block",
               f"remoteip={ip}","protocol=any","enable=yes",
               f"description=IDS: {reason}"]
        r = subprocess.run(cmd, capture_output=True, timeout=10)
        return r.returncode == 0

    def _unblock_windows(self, ip: str) -> bool:
        rule = f"IDS_BLOCK_{ip.replace('.','_')}"
        cmd = ["netsh","advfirewall","firewall","delete","rule",f"name={rule}"]
        r = subprocess.run(cmd, capture_output=True, timeout=10)
        return r.returncode == 0

    def _block_linux(self, ip: str, reason: str) -> bool:
        r = subprocess.run(
            ["iptables","-I","INPUT","-s",ip,"-j","DROP","-m","comment","--comment",f"IDS:{reason}"],
            capture_output=True, timeout=10
        )
        return r.returncode == 0

    def _unblock_linux(self, ip: str) -> bool:
        r = subprocess.run(
            ["iptables","-D","INPUT","-s",ip,"-j","DROP"],
            capture_output=True, timeout=10
        )
        return r.returncode == 0


# ── SQLite store ─────────────────────────────────────────────────

class DetectionStore:
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS detections (
        detection_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL,
        threat_name TEXT NOT NULL, severity TEXT NOT NULL,
        description TEXT, source_ip TEXT, log_entry TEXT,
        method TEXT, mitre_tactic TEXT, mitre_technique TEXT,
        status TEXT DEFAULT 'active', analyst_note TEXT DEFAULT '',
        confidence REAL DEFAULT 1.0, count INTEGER DEFAULT 1,
        updated_at TEXT
    );
    CREATE TABLE IF NOT EXISTS blocked_ips (
        ip TEXT PRIMARY KEY, reason TEXT, blocked_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_sev  ON detections(severity);
    CREATE INDEX IF NOT EXISTS idx_ip   ON detections(source_ip);
    CREATE INDEX IF NOT EXISTS idx_ts   ON detections(timestamp);
    CREATE INDEX IF NOT EXISTS idx_stat ON detections(status);
    """

    def __init__(self, db_path: str = "ids_detections.db"):
        self.db_path = db_path
        self._local  = threading.local()
        if db_path != ":memory:":
            db_dir = os.path.dirname(os.path.abspath(db_path))
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)
            conn = sqlite3.connect(db_path)
            conn.executescript(self.SCHEMA); conn.commit(); conn.close()

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            if self.db_path != ":memory:":
                conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(self.SCHEMA); conn.commit()
            self._local.conn = conn
        return self._local.conn

    def insert(self, e: DetectionEvent):
        self._conn().execute("""
            INSERT OR REPLACE INTO detections
            (detection_id,timestamp,threat_name,severity,description,
             source_ip,log_entry,method,mitre_tactic,mitre_technique,
             status,analyst_note,confidence,count,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (e.detection_id,e.timestamp,e.threat_name,e.severity,
              e.description,e.source_ip,e.log_entry,e.method,
              e.mitre_tactic,e.mitre_technique,e.status,e.analyst_note,
              e.confidence,e.count,e.updated_at))
        self._conn().commit()

    def update_status(self, did: str, status: str, note: str = "") -> bool:
        cur = self._conn().execute(
            "UPDATE detections SET status=?,analyst_note=?,updated_at=? WHERE detection_id=?",
            (status, note, _utc_iso(), did))
        self._conn().commit()
        return cur.rowcount > 0

    def query(self, severity=None, status=None, source_ip=None,
              limit=100, offset=0) -> List[Dict]:
        clauses, params = [], []
        if severity:  clauses.append("severity=?");  params.append(severity)
        if status:    clauses.append("status=?");    params.append(status)
        if source_ip: clauses.append("source_ip=?"); params.append(source_ip)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params += [limit, offset]
        rows = self._conn().execute(
            f"SELECT * FROM detections {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params).fetchall()
        return [dict(r) for r in rows]

    def statistics(self) -> Dict:
        c = self._conn()
        total   = c.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
        by_sev  = dict(c.execute("SELECT severity,COUNT(*) FROM detections GROUP BY severity").fetchall())
        by_thr  = dict(c.execute("SELECT threat_name,COUNT(*) FROM detections GROUP BY threat_name ORDER BY 2 DESC LIMIT 20").fetchall())
        by_stat = dict(c.execute("SELECT status,COUNT(*) FROM detections GROUP BY status").fetchall())
        top_ips = c.execute(
            "SELECT source_ip,COUNT(*) as c FROM detections WHERE source_ip IS NOT NULL "
            "GROUP BY source_ip ORDER BY c DESC LIMIT 10").fetchall()
        hourly = c.execute(
            "SELECT strftime('%Y-%m-%dT%H:00:00',timestamp) as hour,COUNT(*) as c "
            "FROM detections WHERE timestamp>=datetime('now','-24 hours') "
            "GROUP BY hour ORDER BY hour").fetchall()
        return {
            "total":total, "by_severity":by_sev, "by_threat":by_thr,
            "by_status":by_stat,
            "top_attacker_ips":[dict(r) for r in top_ips],
            "hourly_last_24h":[dict(r) for r in hourly],
            "critical":by_sev.get("critical",0), "high":by_sev.get("high",0),
            "medium":by_sev.get("medium",0),     "low":by_sev.get("low",0),
        }

    def count_total(self) -> int:
        return self._conn().execute("SELECT COUNT(*) FROM detections").fetchone()[0]

    def export_csv(self) -> str:
        rows = self._conn().execute(
            "SELECT detection_id,timestamp,threat_name,severity,source_ip,"
            "method,mitre_tactic,mitre_technique,status,confidence,count "
            "FROM detections ORDER BY timestamp DESC").fetchall()
        hdr = "detection_id,timestamp,threat_name,severity,source_ip,method,mitre_tactic,mitre_technique,status,confidence,count"
        return hdr + "\n" + "\n".join(",".join(str(v) for v in r) for r in rows)

    # ── Blocked IPs persistence ──
    def save_block(self, ip: str, reason: str):
        self._conn().execute(
            "INSERT OR REPLACE INTO blocked_ips(ip,reason,blocked_at) VALUES(?,?,?)",
            (ip, reason, _utc_iso()))
        self._conn().commit()

    def remove_block(self, ip: str):
        self._conn().execute("DELETE FROM blocked_ips WHERE ip=?", (ip,))
        self._conn().commit()

    def load_blocks(self) -> List[Dict]:
        rows = self._conn().execute("SELECT * FROM blocked_ips").fetchall()
        return [dict(r) for r in rows]


# ── Assinaturas ──────────────────────────────────────────────────

def build_signatures() -> List[ThreatSignature]:
    return [
        # SQL Injection
        ThreatSignature("SQL Injection — UNION-based",
            r"union\s+(?:all\s+)?select\s+(?:null|[\d]+|0x[0-9a-f]+)",
            Severity.HIGH, "UNION SELECT com valores null/numéricos",
            "TA0006","T1190", ["url","body","query_string"], 0.01),
        ThreatSignature("SQL Injection — Comment Terminator",
            r"'[\s]*(?:or|and)[\s]+[\w'\"]+[\s]*[=<>]|'[\s]*--(?:[\s&]|$)|';[\s]*--",
            Severity.HIGH, "Terminação de query com comentário SQL",
            "TA0006","T1190", [], 0.005),
        ThreatSignature("SQL Injection — Stacked Queries",
            r";\s*(?:drop|truncate|delete|insert|update|exec|execute)\s+",
            Severity.CRITICAL, "Stacked query: DDL/DML secundário",
            "TA0006","T1190", [], 0.005),

        # XSS
        ThreatSignature("XSS — Script Tag",
            r"<script[\s>][^<]*(?:alert|fetch|eval|document\.|window\.location)[^<]*</script>",
            Severity.HIGH, "Tag <script> com payload malicioso",
            "TA0001","T1189", [], 0.02),
        ThreatSignature("XSS — Event Handler",
            r"(?:onerror|onload|onclick|onmouseover)\s*=\s*['\"]?(?:alert|fetch|eval|document\.cookie)",
            Severity.HIGH, "Event handler HTML com exfiltração",
            "TA0001","T1189", [], 0.01),

        # Path Traversal
        ThreatSignature("Path Traversal",
            r"(?:\.\.[\\/]){2,}|(?:%2e%2e[\\/]){2,}|(?:\.\.%2f){2,}|(?:\.\.%5c){2,}",
            Severity.MEDIUM, "Travessia de diretório (2+ níveis)",
            "TA0005","T1083", ["url","path"], 0.02),

        # Command Injection
        ThreatSignature("Command Injection — Shell Redirect",
            r"(?:bash|sh|zsh|ksh)\s+(?:-[isc]\s+)?(?:>&|>|<)\s*(?:/dev/(?:tcp|udp)|&\d)",
            Severity.CRITICAL, "Redirecionamento de shell para socket",
            "TA0002","T1059.004", [], 0.001),
        ThreatSignature("Command Injection — Pipe to Shell",
            r"(?:curl|wget)\s+(?:-s\s+)?https?://[^\s]+\s*\|\s*(?:bash|sh|python|perl)",
            Severity.CRITICAL, "Download e execução via pipe",
            "TA0002","T1059", [], 0.005),

        # Port Scanning
        ThreatSignature("Port Scanning — Tool",
            r"(?:nmap|masscan|zmap|unicornscan)\s+(?:-[psSAFXU]|\d{1,5})",
            Severity.MEDIUM, "Ferramenta de port scanning detectada",
            "TA0043","T1046", [], 0.05),
        ThreatSignature("Port Scanning — TCP Flags",
            r"(?:SYN_RECV|RST,ACK|FIN,URG,PSH).*?(?:SRC|src)=[\d.]+.*?(?:DPT|dpt)=\d+",
            Severity.MEDIUM, "Flags TCP anômalos (scan)",
            "TA0043","T1046", [], 0.08),

        # Privilege Escalation
        ThreatSignature("Privilege Escalation — Root Shell",
            r"sudo\s+(?:-u\s+root\s+)?(?:/bin/bash|/bin/sh|bash|sh)\b|su\s+-\s*(?:root)?\b",
            Severity.CRITICAL, "Shell root interativo via sudo/su",
            "TA0004","T1548.003", [], 0.04),
        ThreatSignature("Privilege Escalation — SUID",
            r"chmod\s+(?:[0-9]*[46][0-9]*\s+|[ug]\+s\s+)(?:/bin/|/usr/bin/)",
            Severity.HIGH, "Modificação de SUID em binários do sistema",
            "TA0004","T1548.001", [], 0.02),

        # Reverse Shell
        ThreatSignature("Reverse Shell — Netcat",
            r"nc(?:at)?\s+(?:-[enlvp]+\s+)*[\d.]+\s+\d{2,5}\s*(?:-e\s+/bin/(?:bash|sh))?",
            Severity.CRITICAL, "Netcat com conexão de saída",
            "TA0011","T1071", [], 0.01),
        ThreatSignature("Reverse Shell — Python",
            r"python[23]?\s+-c\s+['\"]import\s+socket",
            Severity.CRITICAL, "Python one-liner de reverse shell",
            "TA0011","T1059.006", [], 0.005),

        # DDoS
        ThreatSignature("DDoS — Flood",
            r"(?:syn\s+flood|udp\s+flood|http\s+flood|rate\s+exceeded|bandwidth\s+exceeded).*?\d{3,}",
            Severity.CRITICAL, "Log de flood com métrica numérica",
            "TA0040","T1498", [], 0.03),

        # Credential Dumping
        ThreatSignature("Credential Dumping — /etc/shadow",
            r"(?:cat|less|more|head|tail|strings)\s+/etc/shadow",
            Severity.CRITICAL, "Leitura de hashes de senha do sistema",
            "TA0006","T1003.008", [], 0.001),

        # Persistence
        ThreatSignature("Persistence — Crontab",
            r"crontab\s+-[el].*?(?:wget|curl|bash|/dev/tcp|nc\s)",
            Severity.HIGH, "Crontab editado com comandos de rede/shell",
            "TA0003","T1053.003", [], 0.01),

        # Conexão suspeita (para monitor de rede)
        ThreatSignature("Suspicious Network Connection",
            r"SUSPICIOUS CONNECTION.*?DPT=(?:4444|4445|1234|31337|9999|6666|6667)",
            Severity.HIGH, "Conexão ativa em porta clássica de reverse shell",
            "TA0011","T1095", [], 0.02),

        # Processo suspeito
        ThreatSignature("Suspicious Process",
            r"Suspicious process (?:running|detected):\s*(?:nc|ncat|mimikatz|meterpreter|cobaltstrike|psexec|lazagne|rubeus|bloodhound)",
            Severity.CRITICAL, "Ferramenta de hacking em execução",
            "TA0002","T1588", [], 0.005),

        # Windows Events
        ThreatSignature("Windows — Account Created",
            r"New user account created:",
            Severity.MEDIUM, "Nova conta de usuário criada no sistema",
            "TA0003","T1136.001", ["syslog"], 0.15),
        ThreatSignature("Windows — Admin Group",
            r"(?:User added to Administrators|Member added to privileged) group:",
            Severity.HIGH, "Usuário adicionado ao grupo Administradores",
            "TA0004","T1098", ["syslog","command"], 0.05),
        ThreatSignature("Windows — New Service",
            r"New service installed:",
            Severity.HIGH, "Novo serviço instalado (possível persistence)",
            "TA0003","T1543.003", ["command"], 0.10),
    ]


# ── Engine principal ──────────────────────────────────────────────

class IDSEngine:
    THRESHOLDS = {
        "ssh_failures":    {"window":60,  "limit":5,  "severity":Severity.HIGH},
        "http_errors_4xx": {"window":30,  "limit":20, "severity":Severity.MEDIUM},
        "req_rate":        {"window":60,  "limit":100,"severity":Severity.HIGH},
    }

    # IPs que disparam bloqueio automático (apenas CRITICAL com alta confiança)
    AUTO_BLOCK_SEVERITY  = Severity.CRITICAL
    AUTO_BLOCK_CONFIDENCE = 0.90

    def __init__(self, db_path="ids_detections.db",
                 whitelist_ips=None, whitelist_uas=None,
                 auto_block=False):
        self.signatures = build_signatures()
        self.store      = DetectionStore(db_path)
        self.blocker    = IPBlocker()
        self.auto_block = auto_block
        self.logger     = logging.getLogger("ids.engine")

        self.whitelist_ips = set(whitelist_ips or ["127.0.0.1","::1"])
        self.whitelist_uas = set(whitelist_uas or
            ["prometheus","grafana","zabbix","nagios","uptime-kuma"])

        self._ssh_counter  = SlidingWindowCounter(60)
        self._http_counter = SlidingWindowCounter(30)
        self._req_counter  = SlidingWindowCounter(60)
        self._stats_cache = None
        self._stats_cache_at = 0.0
        self._stats_cache_ttl = 8.0
        self._stats_cache_lock = threading.Lock()

        # Restaura bloqueios persistidos
        for b in self.store.load_blocks():
            self.blocker._blocked[b["ip"]] = b["reason"]

    # ── API pública ──────────────────────────────────────────────

    def analyze(self, log_entry: str, source_ip: str = None,
                context: Dict = None) -> List[DetectionEvent]:
        context = context or {}
        if self._is_whitelisted(source_ip, context.get("user_agent","")):
            return []

        events: List[DetectionEvent] = []
        events += self._signature_scan(log_entry, source_ip, context)
        events += self._threshold_check(log_entry, source_ip, context)

        if len(events) >= 2:
            events = self._composite_boost(events)

        for ev in events:
            self.store.insert(ev)
            self.logger.warning("DETECTION | %s | %s | %s | ip=%s",
                ev.severity.upper(), ev.threat_name, ev.method, ev.source_ip)
            # Auto-bloqueio
            if (self.auto_block
                    and ev.severity == self.AUTO_BLOCK_SEVERITY.value
                    and ev.confidence >= self.AUTO_BLOCK_CONFIDENCE
                    and ev.source_ip and ev.source_ip != "unknown"
                    and not self._is_whitelisted(ev.source_ip, "")):
                if self.blocker.block(ev.source_ip, ev.threat_name):
                    self.store.save_block(ev.source_ip, ev.threat_name)

        if events:
            self._invalidate_statistics_cache()
        return events

    def block_ip(self, ip: str, reason: str = "Manual") -> bool:
        ok = self.blocker.block(ip, reason)
        if ok:
            self.store.save_block(ip, reason)
            self._invalidate_statistics_cache()
        return ok

    def unblock_ip(self, ip: str) -> bool:
        ok = self.blocker.unblock(ip)
        if ok:
            self.store.remove_block(ip)
            self._invalidate_statistics_cache()
        return ok

    def update_status(self, did: str, status: str, note: str = "") -> bool:
        ok = self.store.update_status(did, status, note)
        if ok:
            self._invalidate_statistics_cache()
        return ok

    def get_detections(self, **kwargs) -> List[Dict]:
        return self.store.query(**kwargs)

    def get_statistics(self) -> Dict:
        now = time.time()
        with self._stats_cache_lock:
            if self._stats_cache is not None and (now - self._stats_cache_at) < self._stats_cache_ttl:
                return copy.deepcopy(self._stats_cache)

        s = self.store.statistics()
        s["blocked_ips"] = self.blocker.list_blocked()
        s["auto_block"]  = self.auto_block

        with self._stats_cache_lock:
            self._stats_cache = copy.deepcopy(s)
            self._stats_cache_at = now
        return s

    def _invalidate_statistics_cache(self):
        with self._stats_cache_lock:
            self._stats_cache = None
            self._stats_cache_at = 0.0

    def export(self, fmt="json") -> str:
        if fmt == "csv":
            return self.store.export_csv()
        return json.dumps(self.store.query(limit=10000), indent=2, default=str)

    # ── Internals ────────────────────────────────────────────────

    def _is_whitelisted(self, ip, ua):
        if ip and ip in self.whitelist_ips: return True
        return any(w in ua.lower() for w in self.whitelist_uas)

    def _signature_scan(self, log_entry, source_ip, context):
        events, field = [], context.get("field","")
        decoded = unquote(log_entry)
        for sig in self.signatures:
            if sig.context_required and field not in sig.context_required:
                continue
            if sig.matches(decoded):
                events.append(DetectionEvent(
                    detection_id=self._gen_id(log_entry, sig.name),
                    timestamp=_utc_iso(),
                    threat_name=sig.name, severity=sig.severity.value,
                    description=sig.description,
                    source_ip=source_ip or "unknown",
                    log_entry=log_entry[:500],
                    method=DetectionMethod.SIGNATURE.value,
                    mitre_tactic=sig.mitre_tactic,
                    mitre_technique=sig.mitre_technique,
                    confidence=round(1.0-sig.false_positive_rate, 3),
                ))
        return events

    def _threshold_check(self, log_entry, source_ip, context):
        events = []
        if not source_ip: return events
        ssh_pat = re.compile(
            r"(?:failed password|invalid user|authentication failure).*?from\s+[\d.]+",
            re.IGNORECASE)
        if ssh_pat.search(log_entry):
            count = self._ssh_counter.add(source_ip)
            cfg   = self.THRESHOLDS["ssh_failures"]
            if count == cfg["limit"]:
                events.append(self._make_thresh("ssh_failures", source_ip, count, cfg["severity"]))
        return events

    def _make_thresh(self, etype, ip, count, severity):
        labels = {
            "ssh_failures":    ("Brute Force SSH",   "TA0006","T1110.001"),
            "http_errors_4xx": ("HTTP Enumeration",  "TA0043","T1595"),
            "req_rate":        ("HTTP Flood / DoS",  "TA0040","T1498.002"),
        }
        name, tac, tech = labels.get(etype, (etype,"",""))
        cfg = self.THRESHOLDS[etype]
        return DetectionEvent(
            detection_id=self._gen_id(ip, etype),
            timestamp=_utc_iso(),
            threat_name=name, severity=severity.value,
            description=f"{count} eventos em {cfg['window']}s (limiar: {cfg['limit']})",
            source_ip=ip, log_entry=f"[THRESHOLD] {etype} count={count}",
            method=DetectionMethod.THRESHOLD.value,
            mitre_tactic=tac, mitre_technique=tech,
            confidence=0.92, count=count,
        )

    def _composite_boost(self, events):
        order = ["low","medium","high","critical"]
        worst = max(events, key=lambda e: order.index(e.severity))
        if worst.severity != "critical":
            worst.severity    = "critical"
            worst.description += " [COMPOSITE: múltiplas técnicas simultâneas]"
            worst.confidence  = min(worst.confidence+0.05, 1.0)
        return events

    @staticmethod
    def _gen_id(text, salt):
        return hashlib.sha256(
            f"{salt}:{text}:{_utc_iso()}".encode()
        ).hexdigest()[:12]


# ── Log parsers ───────────────────────────────────────────────────

class LogProcessor:
    _SYSLOG_RE   = re.compile(r'(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?):\s+(.*)')
    _APACHE_RE   = re.compile(r'(\S+)\s+-\s+(\S+)\s+\[(.+?)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+|-)')
    _FIREWALL_RE = re.compile(r'SRC=(\S+)\s+DST=(\S+).*?PROTO=(\S+).*?DPT=(\d+)')

    @classmethod
    def parse_syslog(cls, line):
        m = cls._SYSLOG_RE.match(line)
        if m: return {"timestamp":m.group(1),"hostname":m.group(2),
                      "service":m.group(3),"message":m.group(4),"field":"syslog","raw":line}
        return {"field":"syslog","raw":line,"message":line}

    @classmethod
    def parse_apache(cls, line):
        m = cls._APACHE_RE.match(line)
        if m: return {"source_ip":m.group(1),"timestamp":m.group(3),
                      "method":m.group(4),"url":m.group(5),
                      "status_code":int(m.group(6)),"field":"url","raw":line}
        return {"field":"url","raw":line}

    @classmethod
    def parse_firewall(cls, line):
        m = cls._FIREWALL_RE.search(line)
        if m: return {"source_ip":m.group(1),"dest_ip":m.group(2),
                      "protocol":m.group(3),"dest_port":int(m.group(4)),
                      "field":"firewall","raw":line}
        return {"field":"firewall","raw":line}

    @classmethod
    def detect_format(cls, line):
        if re.match(r'\w{3}\s+\d+\s+\d+:\d+:\d+', line): return "syslog"
        if re.search(r'SRC=[\d.]+ DST=', line):           return "firewall"
        if re.match(r'[\d.]+ - .+\[.+\] "[A-Z]+ ', line): return "apache"
        return "raw"

    @classmethod
    def parse_auto(cls, line):
        fmt = cls.detect_format(line)
        return {"syslog":cls.parse_syslog,"firewall":cls.parse_firewall,
                "apache":cls.parse_apache}.get(fmt, lambda l:{"field":"raw","raw":l,"message":l})(line)
