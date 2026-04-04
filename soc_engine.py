"""
NetGuard SOC Engine v1.0
Motor de detecção SIEM/XDR — arquivo único, sem dependências internas.
12 regras SOC baseadas em comportamento, alinhadas ao MITRE ATT&CK.
"""

import re, uuid, time, json, logging, threading, queue, sqlite3, socket, statistics
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict  # noqa: F401
from pathlib import Path  # noqa: F401
from typing import List, Dict, Optional, Callable  # noqa: F401

logger = logging.getLogger("netguard.soc")

# ── Severity ─────────────────────────────────────────────────────
class Sev:
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

# ── Event Model ───────────────────────────────────────────────────
@dataclass
class SOCEvent:
    event_type: str
    severity:   str
    source:     str
    details:    dict
    rule_id:    str  = ""
    rule_name:  str  = ""
    mitre_tactic: str = ""
    mitre_tech:   str = ""
    tags:       list = field(default_factory=list)
    raw:        str  = ""
    event_id:   str  = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:  str  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    host_id:    str  = field(default_factory=lambda: socket.gethostname())

    def to_dict(self):
        return {
            "event_id":     self.event_id,
            "timestamp":    self.timestamp,
            "host_id":      self.host_id,
            "event_type":   self.event_type,
            "severity":     self.severity,
            "source":       self.source,
            "rule_id":      self.rule_id,
            "rule_name":    self.rule_name,
            "mitre":        {"tactic": self.mitre_tactic, "technique": self.mitre_tech},
            "details":      self.details,
            "tags":         self.tags,
            "raw":          self.raw[:300] if self.raw else "",
        }

def mkevent(etype, sev, src, details, rid="", rname="", tactic="", tech="", tags=None, raw=""):
    return SOCEvent(
        event_type=etype, severity=sev, source=src, details=details,
        rule_id=rid, rule_name=rname, mitre_tactic=tactic, mitre_tech=tech,
        tags=tags or [], raw=raw[:300] if raw else "",
    )

# ── Storage ───────────────────────────────────────────────────────
class SOCStorage:
    def __init__(self, db_path):
        self.db = str(db_path)
        self._lock = threading.Lock()
        self._init()

    def _init(self):
        with sqlite3.connect(self.db) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS soc_events (
                    event_id   TEXT PRIMARY KEY,
                    timestamp  TEXT NOT NULL,
                    host_id    TEXT,
                    event_type TEXT,
                    severity   TEXT,
                    source     TEXT,
                    rule_id    TEXT,
                    rule_name  TEXT,
                    mitre_tactic TEXT,
                    mitre_tech TEXT,
                    details    TEXT,
                    tags       TEXT,
                    raw        TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_sev  ON soc_events(severity);
                CREATE INDEX IF NOT EXISTS idx_type ON soc_events(event_type);
                CREATE INDEX IF NOT EXISTS idx_ts   ON soc_events(timestamp DESC);
                CREATE TABLE IF NOT EXISTS soc_baseline (
                    host_id TEXT, btype TEXT, value TEXT,
                    first_seen TEXT, last_seen TEXT, count INTEGER DEFAULT 1,
                    PRIMARY KEY(host_id, btype, value)
                );
            """)

    def _migrate(self, real_hostname: str):
        """Corrige dados legados no banco: host_id='new' → hostname real."""
        if not real_hostname or real_hostname.lower() in ("new","localhost",""):
            return
        try:
            with sqlite3.connect(self.db) as conn:
                fixed = conn.execute(
                    "UPDATE soc_events SET host_id=? WHERE host_id='new' OR host_id='' OR host_id IS NULL",
                    (real_hostname,)
                ).rowcount
                conn.execute(
                    "UPDATE soc_baseline SET host_id=? WHERE host_id='new' OR host_id=''",
                    (real_hostname,)
                )
                conn.commit()
                if fixed:
                    import logging
                    logging.getLogger("netguard.soc").info(
                        "DB migration: %d eventos corrigidos host_id='new'→'%s'", fixed, real_hostname
                    )
        except Exception as e:
            pass


    def save(self, event: SOCEvent):
        with self._lock:
            try:
                with sqlite3.connect(self.db) as conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO soc_events
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """, (
                        event.event_id, event.timestamp, event.host_id,
                        event.event_type, event.severity, event.source,
                        event.rule_id, event.rule_name,
                        event.mitre_tactic, event.mitre_tech,
                        json.dumps(event.details),
                        json.dumps(event.tags),
                        event.raw[:300] if event.raw else "",
                    ))
            except Exception as e:
                logger.error("SOC save error: %s", e)

    def save_batch(self, events):
        for e in events:
            self.save(e)

    def query(self, limit=100, severity=None, event_type=None, since=None, offset=0):
        sql = "SELECT * FROM soc_events WHERE 1=1"
        params = []
        if severity:   sql += " AND severity=?";    params.append(severity.upper())
        if event_type: sql += " AND event_type=?";  params.append(event_type)
        if since:      sql += " AND timestamp>=?";  params.append(since)
        sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        try:
            with sqlite3.connect(self.db) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(sql, params).fetchall()
                result = []
                for r in rows:
                    d = dict(r)
                    for f in ('details', 'tags'):
                        try: d[f] = json.loads(d[f] or '{}')
                        except: pass
                    d['mitre'] = {'tactic': d.pop('mitre_tactic',''), 'technique': d.pop('mitre_tech','')}
                    result.append(d)
                return result
        except Exception as e:
            logger.error("SOC query error: %s", e)
            return []

    def stats(self):
        try:
            with sqlite3.connect(self.db) as conn:
                conn.row_factory = sqlite3.Row
                total = conn.execute("SELECT COUNT(*) FROM soc_events").fetchone()[0]
                by_sev = {r['severity']: r['c'] for r in conn.execute(
                    "SELECT severity, COUNT(*) as c FROM soc_events GROUP BY severity")}
                by_type = {r['event_type']: r['c'] for r in conn.execute(
                    "SELECT event_type, COUNT(*) as c FROM soc_events GROUP BY event_type ORDER BY c DESC LIMIT 10")}
                since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
                last24 = conn.execute("SELECT COUNT(*) FROM soc_events WHERE timestamp>=?", (since,)).fetchone()[0]
                return {"total": total, "by_severity": by_sev, "by_type": by_type, "last_24h": last24}
        except:
            return {}

    def get_baseline(self, host_id, btype):
        try:
            with sqlite3.connect(self.db) as conn:
                rows = conn.execute(
                    "SELECT value FROM soc_baseline WHERE host_id=? AND btype=?",
                    (host_id, btype)).fetchall()
                return {r[0] for r in rows}
        except: return set()

    def update_baseline(self, host_id, btype, value):
        now = datetime.now(timezone.utc).isoformat()
        try:
            with sqlite3.connect(self.db) as conn:
                conn.execute("""
                    INSERT INTO soc_baseline(host_id,btype,value,first_seen,last_seen,count)
                    VALUES(?,?,?,?,?,1)
                    ON CONFLICT(host_id,btype,value)
                    DO UPDATE SET last_seen=?,count=count+1
                """, (host_id, btype, str(value), now, now, now))
        except: pass

    def update_baseline_batch(self, host_id, btype, values):
        for v in values:
            self.update_baseline(host_id, btype, str(v))

# ── KNOWN processes baseline ──────────────────────────────────────
KNOWN_PROCS = {
    "system","smss.exe","csrss.exe","wininit.exe","winlogon.exe","services.exe",
    "lsass.exe","svchost.exe","dwm.exe","explorer.exe","taskhostw.exe","sihost.exe",
    "ctfmon.exe","fontdrvhost.exe","spoolsv.exe","searchindexer.exe","conhost.exe",
    "dllhost.exe","rundll32.exe","cmd.exe","powershell.exe","taskmgr.exe",
    "runtimebroker.exe","applicationframehost.exe","shellexperiencehost.exe",
    "startmenuexperiencehost.exe","securityhealthsystray.exe","msmpeng.exe",
    "brave.exe","chrome.exe","msedge.exe","firefox.exe","msedgewebview2.exe",
    "python.exe","python3.exe","python3.13.exe","node.exe","code.exe","git.exe",
    "discord.exe","steam.exe","steamwebhelper.exe","gameoverlayui.exe",
    "whatsapp.exe","whatsapp.root.exe","slack.exe","zoom.exe","claude.exe",
    "widgets.exe","protonvpn.exe","audiodg.exe","wmiprvse.exe","wbemcons.exe",
    "spoolsv.exe","lsm.exe","wlanext.exe","dashost.exe","smartscreen.exe",
    "registry","smss.exe","wermgr.exe","msiexec.exe","winstore.app.exe",
    "securityhealthservice.exe","nissrv.exe","mssense.exe","mpdefendercoreservice.exe",
    "mpdefendercoreserv.exe","protonvpnclient.exe","protonvpn_service.exe",
    "openconsole.exe","regedit.exe","mmc.exe","eventvwr.exe",
    "netguard","netguard.exe","lsass.exe","wuauclt.exe",
}

COMMON_PORTS = {
    22,25,53,80,110,143,443,465,587,993,995,3306,5432,6379,
    8080,8443,8888,135,137,138,139,445,1433,3389,5985,5986,
    1024,3000,4000,5000,5001,8000,8001,9000,27015,27016,27017,
    27036,27037,49152,49153,49154,49155,6040,6463,6600,7680,
}

PRIVATE_PFX = ("192.168.","10.","172.16.","172.17.","172.18.","172.19.",
               "172.20.","172.21.","172.22.","172.23.","172.24.","172.25.",
               "172.26.","172.27.","172.28.","172.29.","172.30.","172.31.",
               "127.","0.0.0.0","::1","169.254.")

def is_private(ip): return any(ip.startswith(p) for p in PRIVATE_PFX)

# ── Web patterns ──────────────────────────────────────────────────
SQLI_RE = re.compile(
    r"(?:union[\s/\*]+select|'\s*or\s*'?\d|or\s+\d+=\d+|'\s*=\s*'|1\s*=\s*1"
    r"|drop\s+table|exec\s*\(|xp_cmdshell|sleep\s*\(|benchmark\s*\(|waitfor\s+delay"
    r"|into\s+(?:outfile|dumpfile)|select\s+.*from\s+|insert\s+into|delete\s+from)",
    re.IGNORECASE)

XSS_RE = re.compile(
    r"(?:<script[^>]*>|javascript\s*:|vbscript\s*:|on\w+\s*=|eval\s*\("
    r"|document\.cookie|<iframe|<svg[^>]+onload|<img[^>]+onerror)",
    re.IGNORECASE)

SUSP_UA = ["sqlmap","nikto","nmap","masscan","curl/","python-requests",
           "dirbuster","gobuster","wfuzz","hydra","burpsuite","nuclei",
           "acunetix","w3af","havij","wget/","libwww-perl","zgrab"]


# ── Main Engine ───────────────────────────────────────────────────
class SOCEngine:
    def __init__(self, db_path, alert_callback=None, host_id: str = ""):
        if host_id and host_id.lower() not in ("new", "localhost", ""):
            self.host_id = host_id
        else:
            try:
                import subprocess
                hn = subprocess.check_output("hostname", shell=True, text=True).strip()
                self.host_id = hn if hn and hn.lower() not in ("new","localhost","") else "netguard-host"
            except Exception:
                hn = socket.gethostname()
                self.host_id = hn if hn and hn.lower() not in ("new","localhost","") else "netguard-host"
        self.storage  = SOCStorage(db_path)
        self.callback = alert_callback
        self._q       = queue.Queue(maxsize=500)
        self._running = False

        # State for behavioral rules
        self._cpu_high: Dict[int, float] = {}
        self._conn_times = defaultdict(lambda: deque(maxlen=200))
        self._proc_ips   = defaultdict(lambda: deque(maxlen=200))
        self._known_listen: set = set()
        self._known_proc_ports = defaultdict(set)
        self._proc_counts: list = []
        self._port_counts: list = []
        self._conn_counts: list = []
        # Deduplication: processes/ports already alerted this session
        self._alerted_procs:  set = set()
        self._alerted_ports:  set = set()
        self._alerted_ips:    set = set()
        self._cycles:         int = 0

        logger.info("SOC Engine iniciado | host=%s | db=%s", self.host_id, db_path)

    def start(self):
        self._running = True
        threading.Thread(target=self._worker, daemon=True, name="soc-worker").start()

    def stop(self):
        self._running = False

    def enqueue(self, snapshot: dict):
        try: self._q.put_nowait(snapshot)
        except queue.Full: pass

    def _worker(self):
        while self._running:
            try:
                snap = self._q.get(timeout=1.0)
                evts = self.analyze(snap.get("processes",[]), snap.get("ports",[]), snap.get("connections",[]))
                self._q.task_done()
            except queue.Empty: continue
            except Exception as e: logger.error("SOC worker: %s", e)

    def analyze(self, processes=None, ports=None, connections=None):
        events = []
        now    = time.time()
        p = processes or []
        pt = ports or []
        cn = connections or []

        bl_procs = self.storage.get_baseline(self.host_id, "procs")
        bl_ports = self.storage.get_baseline(self.host_id, "ports")
        bl_ips   = self.storage.get_baseline(self.host_id, "ips")

        ext_proc_names = {
            c.get("process","").lower() for c in cn
            if c.get("dst_ip") and not is_private(c.get("dst_ip",""))
        }

        # ── R1: Unknown process ───────────────────────────────────
        # Only fires ONCE per session per process (deduplication)
        for proc in p:
            name = (proc.get("name") or "").lower()
            if not name or name == "memcompression": continue
            if name in KNOWN_PROCS or name in bl_procs: continue
            if name in self._alerted_procs: continue
            # Unknown — alert once then add to session + baseline
            events.append(mkevent(
                "process_unknown", Sev.MEDIUM, "soc.process",
                {"process": name, "pid": proc.get("pid"), "exe": (proc.get("exe") or "")[:100]},
                "R1", "Processo Desconhecido", "execution", "T1204",
                ["process","unknown"], f"Unknown: {name}"))
            self._alerted_procs.add(name)
            self.storage.update_baseline(self.host_id, "procs", name)

        # ── R2: High CPU ──────────────────────────────────────────
        for proc in p:
            pid = proc.get("pid", 0)
            cpu = float(proc.get("cpu") or 0)
            name = (proc.get("name") or "").lower()
            if cpu > 80:
                if pid not in self._cpu_high:
                    self._cpu_high[pid] = now
                elif now - self._cpu_high[pid] >= 30:
                    dur = int(now - self._cpu_high[pid])
                    events.append(mkevent(
                        "process_high_cpu", Sev.HIGH, "soc.process",
                        {"process": name, "pid": pid, "cpu": cpu, "duration_sec": dur},
                        "R2", "CPU Alta Contínua", "execution", "T1496",
                        ["process","cpu"], f"{name} {cpu}% for {dur}s"))
                    self._cpu_high[pid] = now + 300
            else:
                self._cpu_high.pop(pid, None)

        # ── R3: Processo abrindo porta não-padrão em well-known range (1-1023)
        # Portas dinâmicas Windows (49152+) estão em COMMON_PORTS — nunca alertam
        for port_info in pt:
            port = int(port_info.get("port") or 0)
            proc = (port_info.get("process") or "").lower()
            proto = port_info.get("proto","tcp")
            if not port or not proc: continue
            if port in COMMON_PORTS: continue
            # Só alerta em well-known range (1-1023) — exceto os já comuns
            if port >= 1024: continue
            key = f"r3:{proc}:{port}"
            if key in self._alerted_ports: continue
            events.append(mkevent(
                "port_opened", Sev.HIGH, "soc.network",
                {"process": proc, "port": port, "proto": proto},
                "R3", "Processo Abrindo Porta Well-Known Incomum", "persistence", "T1205",
                ["network","port"], f"{proc} opened {proto}/{port}"))
            self._alerted_ports.add(key)
            self._known_proc_ports[proc].add(port)

        # ── R4: Connection spike ──────────────────────────────────
        ip_conn_count = defaultdict(int)
        for conn in cn:
            dst = conn.get("dst_ip","")
            if dst and not is_private(dst):
                self._conn_times[dst].append(now)
                recent = [t for t in self._conn_times[dst] if now - t <= 10]
                if len(recent) >= 50:
                    events.append(mkevent(
                        "network_spike", Sev.HIGH, "soc.network",
                        {"dst_ip": dst, "count": len(recent), "window_sec": 10, "process": conn.get("process","")},
                        "R4", "Spike de Conexões", "reconnaissance", "T1046",
                        ["network","spike"], f"{len(recent)} conns to {dst} in 10s"))
                    self._conn_times[dst].clear()

        # ── R5: Many unique IPs ───────────────────────────────────
        for conn in cn:
            dst = conn.get("dst_ip","")
            proc = conn.get("process","").lower()
            if dst and proc and not is_private(dst):
                self._proc_ips[proc].append((now, dst))
                recent_ips = {ip for t,ip in self._proc_ips[proc] if now-t <= 30}
                if len(recent_ips) >= 20:
                    events.append(mkevent(
                        "network_scan", Sev.HIGH, "soc.network",
                        {"process": proc, "unique_ips": len(recent_ips), "sample": list(recent_ips)[:5]},
                        "R5", "Múltiplos IPs — Bot/Worm", "discovery", "T1046",
                        ["network","scan"], f"{proc} → {len(recent_ips)} IPs in 30s"))
                    self._proc_ips[proc].clear()

        # ── R6: Unknown process with external connection ──────────
        for proc in p:
            name = (proc.get("name") or "").lower()
            if not name: continue
            if name in ext_proc_names and name not in KNOWN_PROCS and name not in bl_procs:
                events.append(mkevent(
                    "process_external_conn", Sev.MEDIUM, "soc.process",
                    {"process": name, "pid": proc.get("pid")},
                    "R6", "Processo Desconhecido com Conexão Externa", "command_and_control", "T1071",
                    ["process","network"], f"{name} making external connection"))

        # ── R7: New LISTEN port ───────────────────────────────────
        for port_info in pt:
            port = int(port_info.get("port") or 0)
            proto = port_info.get("proto","tcp")
            key = f"{proto}/{port}"
            if not port or port in COMMON_PORTS: continue
            if key in self._known_listen or key in bl_ports: continue
            if key in self._alerted_ports: continue
            events.append(mkevent(
                "port_new_listen", Sev.MEDIUM, "soc.network",
                {"port": port, "proto": proto, "process": port_info.get("process","")},
                "R7", "Nova Porta em LISTEN", "persistence", "T1205",
                ["network","listen"], f"New LISTEN: {key}"))
            self._known_listen.add(key)
            self._alerted_ports.add(key)
            self.storage.update_baseline(self.host_id, "ports", key)

        # ── R8: New external IP ───────────────────────────────────
        seen_ips = set()
        for conn in cn:
            ip = conn.get("dst_ip","")
            if not ip or is_private(ip): continue
            if ip in bl_ips or ip in seen_ips or ip in self._alerted_ips: continue
            events.append(mkevent(
                "ip_new_external", Sev.LOW, "soc.network",
                {"ip": ip, "process": conn.get("process","")},
                "R8", "Novo IP Externo", "reconnaissance", "T1590",
                ["network","ip"], f"New IP: {ip}"))
            seen_ips.add(ip)
            self._alerted_ips.add(ip)
            self.storage.update_baseline(self.host_id, "ips", ip)

        # ── R9: Behavior deviation ────────────────────────────────
        if len(self._proc_counts) >= 10:
            for hist, cur, metric in [
                (self._proc_counts, len(p), "processos"),
                (self._port_counts, len(pt), "portas"),
                (self._conn_counts, len(cn), "conexoes"),
            ]:
                if len(hist) >= 5:
                    mean  = statistics.mean(hist)
                    stdev = statistics.stdev(hist) if len(hist) > 1 else 0
                    if stdev > 0 and abs(cur - mean) / stdev > 2.5:
                        events.append(mkevent(
                            "behavior_deviation", Sev.MEDIUM, "soc.behavior",
                            {"metric": metric, "current": cur, "mean": round(mean,1), "stdev": round(stdev,1)},
                            "R9", "Desvio de Comportamento", "discovery", "T1082",
                            ["behavior","anomaly"], f"Deviation: {metric} {cur} vs avg {mean:.0f}"))
                        break

        self._proc_counts = (self._proc_counts + [len(p)])[-50:]
        self._port_counts = (self._port_counts + [len(pt)])[-50:]
        self._conn_counts = (self._conn_counts + [len(cn)])[-50:]

        # Save and alert
        if events:
            self.storage.save_batch(events)
            for e in events:
                if e.severity in (Sev.HIGH, Sev.CRITICAL):
                    self._alert(e)
            logger.info("SOC | %d events | host=%s", len(events), self.host_id)

        # Update proc baseline
        self.storage.update_baseline_batch(self.host_id, "procs", [(p.get("name") or "").lower() for p in p if p.get("name")])

        # Every 10 cycles, clear session dedup so new processes are still caught
        self._cycles += 1
        if self._cycles % 10 == 0:
            self._alerted_ips.clear()
            logger.debug("SOC: cleared session IP dedup at cycle %d", self._cycles)

        return events

    def analyze_web(self, payload="", source_ip="", user_agent=""):
        events = []
        if not payload and not user_agent:
            return events

        if payload:
            decoded = self._decode(payload)
            m = SQLI_RE.search(decoded)
            if m:
                events.append(mkevent("web_sqli", Sev.HIGH, "soc.web",
                    {"match": m.group(0)[:60], "source_ip": source_ip, "payload": payload[:150]},
                    "R10", "SQL Injection", "initial_access", "T1190", ["web","sqli"], payload[:200]))
            m = XSS_RE.search(decoded)
            if m:
                events.append(mkevent("web_xss", Sev.HIGH, "soc.web",
                    {"match": m.group(0)[:60], "source_ip": source_ip},
                    "R11", "XSS Detectado", "initial_access", "T1190", ["web","xss"], payload[:200]))

        if user_agent:
            ua = user_agent.lower()
            for sus in SUSP_UA:
                if sus in ua:
                    events.append(mkevent("web_suspicious_ua", Sev.MEDIUM, "soc.web",
                        {"user_agent": user_agent[:150], "matched": sus, "source_ip": source_ip},
                        "R12", "User-Agent Suspeito", "reconnaissance", "T1595", ["web","ua"], user_agent[:150]))
                    break

        if events:
            self.storage.save_batch(events)
            for e in events:
                if e.severity in (Sev.HIGH, Sev.CRITICAL): self._alert(e)
        return events

    def _alert(self, event):
        if self.callback:
            try: self.callback(event)
            except: pass

    @staticmethod
    def _decode(text):
        import urllib.parse
        r = text
        for _ in range(3):
            try:
                d = urllib.parse.unquote(r)
                if d == r: break
                r = d
            except: break
        for enc, dec in [("&#60;","<"),("&#62;",">"),("&lt;","<"),("&gt;",">"),("&amp;","&")]:
            r = r.replace(enc, dec)
        return r

    def get_events(self, **kw): return self.storage.query(**kw)
    def get_stats(self):
        return {"engine": {"active": True, "rules": 12}, "storage": self.storage.stats(), "host_id": self.host_id}
