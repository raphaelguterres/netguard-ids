"""
NetGuard — Web Detection Rules
Pack completo de regras de detecção web.
"""

import re
import logging
import statistics
from typing import List, Optional
from models.event_model import make_event, Severity, EventType

logger = logging.getLogger("netguard.rules.web")

# ── SQL Injection ─────────────────────────────────────────────────
SQLI_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"(?:union[\s/\*]+select)",
    r"(?:'\s*(?:or|and)\s*'?\d|'\s*(?:or|and)\s*'\w)",
    r"(?:or|and)\s+\d+=\d+",
    r"(?:select\s+(?:null|@@|user\(|version\(|load_file|0x|char\().*\s+from\s+)",
    r"(?:insert\s+into|drop\s+table|delete\s+from|update\s+\w+\s+set)",
    r"(?:exec(?:ute)?\s*\(|xp_cmdshell)",
    r"(?:sleep\s*\(\d+\)|benchmark\s*\(|waitfor\s+delay)",
    r"(?:into\s+(?:outfile|dumpfile))",
    r"(?:'\s*;\s*--|#\s*$|/\*.*\*/)",
    r"(?:1\s*=\s*1|'\s*=\s*'|1\s*=\s*'1)",
    r"(?:char\s*\(\d+\)|0x[0-9a-f]{4,})",
]]

# ── XSS ──────────────────────────────────────────────────────────
XSS_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"<script[^>]*>",
    r"javascript\s*:",
    r"vbscript\s*:",
    r"on(?:load|error|click|mouse\w+|key\w+|focus|blur)\s*=",
    r"eval\s*\(",
    r"document\.(?:cookie|write|location)",
    r"window\.(?:location|open)",
    r"<iframe[^>]*>",
    r"<img[^>]+onerror",
    r"<svg[^>]+onload",
    r"&#(?:x[0-9a-f]+|\d+);",
    r"expression\s*\(",
    r"data:text/html",
]]

# ── Path Traversal ────────────────────────────────────────────────
PATH_TRAVERSAL_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e[/%5c]",
    r"(?:etc/passwd|etc/shadow|win\.ini|boot\.ini)",
    r"(?:/proc/self|/etc/hosts)",
    r"(?:c:\\windows|c:\\users|c:\\boot)",
]]

# ── User-Agents suspeitos ─────────────────────────────────────────
SUSPICIOUS_UA = [
    "sqlmap","nikto","nmap","masscan","dirbuster","gobuster",
    "wfuzz","hydra","burpsuite","nuclei","acunetix","w3af",
    "havij","pangolin","jsql","zgrab","curl/","python-requests",
    "go-http-client","libwww-perl","lwp-request","wget/",
    "scanner","exploit","vulnerability","pentest",
]

# ── Payloads suspeitos (RCE, SSRF, XXE etc.) ─────────────────────
SUSPICIOUS_PAYLOAD_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    # RCE
    r"(?:;|\||\`|\$\()\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh)",
    r"(?:system|passthru|exec|shell_exec|popen)\s*\(",
    r"\$\{jndi:",                       # Log4Shell
    r"(?:<%|%>|<%=)",                   # JSP injection
    # SSRF
    r"(?:file|dict|gopher|ldap|ftp)://",
    r"169\.254\.169\.254",              # AWS metadata
    r"metadata\.google\.internal",
    # XXE
    r"<!ENTITY\s+\w+\s+(?:SYSTEM|PUBLIC)",
    r"file:///etc/",
    # SSTI
    r"\{\{.*\}\}",
    r"\$\{.*\}",
    r"#\{.*\}",
]]


class WebRules:
    def __init__(self, repository=None):
        self.repo = repository
        self._behavior_history = {"procs": [], "ports": [], "conns": []}

    @staticmethod
    def _decode(text: str) -> str:
        import urllib.parse
        result = text
        for _ in range(3):
            try:
                d = urllib.parse.unquote(result)
                if d == result: break
                result = d
            except: break
        for enc, dec in [("&#60;","<"),("&#62;",">"),("&lt;","<"),
                         ("&gt;",">"),("&amp;","&"),("&quot;",'"')]:
            result = result.replace(enc, dec)
        return result

    # ── W-R1: SQL Injection ───────────────────────────────────────
    def detect_sqli(self, payload: str, source_ip: str = "",
                    context: str = "") -> Optional[object]:
        decoded = self._decode(payload)
        for p in SQLI_PATTERNS:
            m = p.search(decoded)
            if m:
                return make_event(
                    event_type      = EventType.WEB_SQLI,
                    severity        = Severity.HIGH,
                    source          = "agent.web",
                    details         = {"match": m.group(0)[:80], "source_ip": source_ip,
                                       "payload": payload[:200], "context": context},
                    rule_id         = "W-R1",
                    rule_name       = "SQL Injection Detectado",
                    mitre_tactic    = "initial_access",
                    mitre_technique = "T1190",
                    tags            = ["web","sqli","injection"],
                )
        return None

    # ── W-R2: XSS ─────────────────────────────────────────────────
    def detect_xss(self, payload: str, source_ip: str = "") -> Optional[object]:
        decoded = self._decode(payload)
        for p in XSS_PATTERNS:
            m = p.search(decoded)
            if m:
                return make_event(
                    event_type      = EventType.WEB_XSS,
                    severity        = Severity.HIGH,
                    source          = "agent.web",
                    details         = {"match": m.group(0)[:80], "source_ip": source_ip,
                                       "payload": payload[:200]},
                    rule_id         = "W-R2",
                    rule_name       = "XSS Detectado",
                    mitre_tactic    = "initial_access",
                    mitre_technique = "T1190",
                    tags            = ["web","xss","injection"],
                )
        return None

    # ── W-R3: Path Traversal ──────────────────────────────────────
    def detect_path_traversal(self, path: str, source_ip: str = "") -> Optional[object]:
        decoded = self._decode(path)
        for p in PATH_TRAVERSAL_PATTERNS:
            m = p.search(decoded)
            if m:
                return make_event(
                    event_type      = "web_path_traversal",
                    severity        = Severity.HIGH,
                    source          = "agent.web",
                    details         = {"match": m.group(0)[:80], "path": path[:200],
                                       "source_ip": source_ip},
                    rule_id         = "W-R3",
                    rule_name       = "Path Traversal Detectado",
                    mitre_tactic    = "initial_access",
                    mitre_technique = "T1190",
                    tags            = ["web","traversal","lfi"],
                )
        return None

    # ── W-R4: User-Agent suspeito ─────────────────────────────────
    def detect_suspicious_ua(self, ua: str, source_ip: str = "") -> Optional[object]:
        ua_lower = ua.lower()
        for sus in SUSPICIOUS_UA:
            if sus.lower() in ua_lower:
                return make_event(
                    event_type      = EventType.WEB_SUSPICIOUS_UA,
                    severity        = Severity.MEDIUM,
                    source          = "agent.web",
                    details         = {"user_agent": ua[:200], "matched": sus,
                                       "source_ip": source_ip},
                    rule_id         = "W-R4",
                    rule_name       = "User-Agent Suspeito",
                    mitre_tactic    = "reconnaissance",
                    mitre_technique = "T1595",
                    tags            = ["web","scanner","ua"],
                )
        return None

    # ── W-R5: Payload suspeito (RCE/SSRF/XXE/SSTI) ───────────────
    def detect_suspicious_payload(self, payload: str,
                                  source_ip: str = "") -> Optional[object]:
        decoded = self._decode(payload)
        for p in SUSPICIOUS_PAYLOAD_PATTERNS:
            m = p.search(decoded)
            if m:
                # Classify type
                pat = p.pattern.lower()
                if "jndi" in pat:                       rtype, tech = "Log4Shell",  "T1190"
                elif "169.254" in pat or "ssrf" in pat: rtype, tech = "SSRF",       "T1190"
                elif "entity" in pat or "file://" in pat: rtype, tech = "XXE",      "T1190"
                elif "{{" in pat or "${" in pat:        rtype, tech = "SSTI",       "T1190"
                else:                                   rtype, tech = "RCE",        "T1059"
                return make_event(
                    event_type      = "web_payload_suspicious",
                    severity        = Severity.CRITICAL if rtype in ("Log4Shell","RCE") else Severity.HIGH,
                    source          = "agent.web",
                    details         = {"attack_type": rtype, "match": m.group(0)[:80],
                                       "payload": payload[:200], "source_ip": source_ip},
                    rule_id         = "W-R5",
                    rule_name       = f"Payload Suspeito — {rtype}",
                    mitre_tactic    = "initial_access",
                    mitre_technique = tech,
                    tags            = ["web","rce","injection", rtype.lower()],
                )
        return None

    # ── W-R6: Desvio de comportamento ────────────────────────────
    def detect_behavior_deviation(self, proc_count: int, port_count: int,
                                  conn_count: int, host_id: str) -> Optional[object]:
        h = self._behavior_history
        if len(h["procs"]) < 8:
            h["procs"].append(proc_count)
            h["ports"].append(port_count)
            h["conns"].append(conn_count)
            return None

        deviations = []
        for vals, cur, label in [
            (h["procs"], proc_count, "processos"),
            (h["ports"], port_count, "portas"),
            (h["conns"], conn_count, "conexões"),
        ]:
            if len(vals) < 2: continue
            mean  = statistics.mean(vals)
            stdev = statistics.stdev(vals)
            if stdev == 0: continue
            if abs(cur - mean) / stdev > 2.5:
                deviations.append(f"{label}: {cur} (média {mean:.0f})")

        h["procs"] = (h["procs"] + [proc_count])[-50:]
        h["ports"] = (h["ports"] + [port_count])[-50:]
        h["conns"] = (h["conns"] + [conn_count])[-50:]

        if not deviations:
            return None
        return make_event(
            event_type      = EventType.BEHAVIOR_DEVIATION,
            severity        = Severity.MEDIUM,
            source          = "agent.behavior",
            details         = {"deviations": deviations, "processes": proc_count,
                               "ports": port_count, "connections": conn_count},
            rule_id         = "B-R1",
            rule_name       = "Desvio de Comportamento do Sistema",
            mitre_tactic    = "discovery",
            mitre_technique = "T1082",
            tags            = ["behavior","anomaly","baseline"],
        )

    def analyze_payload(self, payload: str, source_ip: str = "",
                        user_agent: str = "", path: str = "") -> List:
        events = []
        if payload:
            for fn in [self.detect_sqli, self.detect_xss,
                       self.detect_suspicious_payload]:
                e = fn(payload, source_ip)
                if e: events.append(e)
        if path:
            e = self.detect_path_traversal(path, source_ip)
            if e: events.append(e)
        if user_agent:
            e = self.detect_suspicious_ua(user_agent, source_ip)
            if e: events.append(e)
        return events
