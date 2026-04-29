"""
NetGuard Detection Engine — rule-based pattern detection on the
canonical event schema.

Inputs: a list of `Event`s (or plain dicts that match the schema).
Outputs: a list of `Alert`s. Each alert carries:

    rule_id, severity, confidence, mitre_tactic, mitre_technique,
    title, evidence, host_id, timestamp, event_ids

The engine is *stateless and pure* — same events in, same alerts out.
That makes it trivial to test and replay.

Rule registry is open: callers can add new rules with `register_rule()`.
The built-in rule pack covers the spec:

  - powershell -enc / encoded command
  - cmd spawning powershell (anomalous parent/child)
  - certutil download/decode
  - mshta http(s) / javascript / vbscript
  - rundll32 url / javascript payload
  - regsvr32 Squiblydoo (scrobj.dll, /i:http)
  - persistence indicators (Run keys, scheduled tasks, services)
  - suspicious outbound (network event with rare port + shell process)
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Iterable, Sequence

from storage.repository import Alert, Event

from . import mitre_mapper

logger = logging.getLogger("netguard.detection")

# ── Severity ladder ──────────────────────────────────────────────────

SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _sev_norm(sev: str) -> str:
    s = (sev or "low").lower().strip()
    return s if s in SEV_ORDER else "low"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ── Rule model ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    confidence: int
    mitre_technique: str
    description: str
    matcher: Callable[[Event], tuple[bool, str]]
    """matcher(event) -> (matched, evidence_snippet)"""


def _coerce_event(ev: Event | dict) -> Event:
    """
    Accept either the Event dataclass (canonical) or a plain dict whose
    keys match the canonical schema. Missing fields get sensible
    defaults so rules don't have to defensively `.get(...)` everything.
    """
    if isinstance(ev, Event):
        return ev
    if not isinstance(ev, dict):
        raise TypeError(f"event must be Event or dict, got {type(ev).__name__}")
    return Event(
        event_id=ev.get("event_id") or str(uuid.uuid4()),
        host_id=ev.get("host_id") or "",
        timestamp=ev.get("timestamp") or _utc_now_iso(),
        event_type=ev.get("event_type") or "",
        severity=_sev_norm(ev.get("severity") or "low"),
        confidence=int(ev.get("confidence") or 0),
        process_name=ev.get("process_name") or "",
        pid=ev.get("pid"),
        ppid=ev.get("ppid"),
        command_line=ev.get("command_line") or "",
        user=ev.get("user") or ev.get("username") or "",
        src_ip=ev.get("src_ip") or "",
        dst_ip=ev.get("dst_ip") or "",
        dst_port=ev.get("dst_port"),
        mitre_tactic=ev.get("mitre_tactic") or "",
        mitre_technique=ev.get("mitre_technique") or "",
        evidence=ev.get("evidence") or "",
        raw=ev.get("raw") or {},
    )


# ── Built-in rules ───────────────────────────────────────────────────


# Patterns are compiled once at module load. The first match wins; the
# matcher returns the matched substring as evidence for the alert UI.

_RX_PS_ENCODED = re.compile(
    r"(?i)\bpowershell(?:\.exe)?\b.*?\s-(?:e|en|enc|encod\w*)\s+[A-Za-z0-9+/=]{16,}",
)
_RX_PS_DOWNLOAD = re.compile(
    r"(?i)\bpowershell(?:\.exe)?\b.*?(?:DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|iwr|iex)",
)
_RX_CERTUTIL = re.compile(
    r"(?i)\bcertutil(?:\.exe)?\b.*?(?:-urlcache|-decode|-encode|-split|-f\s+https?:)",
)
_RX_MSHTA = re.compile(
    r"(?i)\bmshta(?:\.exe)?\b.*?(?:https?:|javascript:|vbscript:)",
)
_RX_RUNDLL32 = re.compile(
    r"(?i)\brundll32(?:\.exe)?\b.*?(?:javascript:|https?:|\.dll,\w+\s+http)",
)
_RX_REGSVR32 = re.compile(
    r"(?i)\bregsvr32(?:\.exe)?\b.*?(?:/i:https?:|/i:\\\\|scrobj\.dll)",
)
_RX_SCHTASKS = re.compile(
    r"(?i)\bschtasks(?:\.exe)?\b.*?\s/(?:create|change)\b",
)
_RX_SVC_CREATE = re.compile(
    r"(?i)\bnew-service\b|\bsc(?:\.exe)?\s+create\b",
)
_RX_REG_RUN = re.compile(
    r"(?i)\breg(?:\.exe)?\s+add\b.*?(?:\\Run|\\RunOnce|\\Image File Execution Options)",
)
_RX_BITSADMIN = re.compile(
    r"(?i)\b(?:bitsadmin|curl|wget)(?:\.exe)?\b.*?https?://",
)
_RX_LSASS_DUMP = re.compile(
    r"(?i)(?:procdump.*?lsass|comsvcs\.dll.*?MiniDump|sekurlsa::logonpasswords|mimikatz)",
)
_RX_AMSI_BYPASS = re.compile(
    r"(?i)(?:System\.Management\.Automation\.AmsiUtils|amsiInitFailed|reflection\.assembly]::load)",
)


_SHELL_PROCS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
                "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}
_OFFICE_PROCS = {"winword.exe", "excel.exe", "outlook.exe",
                 "powerpnt.exe", "acrord32.exe"}


def _match_ps_encoded(ev: Event) -> tuple[bool, str]:
    if ev.event_type not in {"process_execution", "script_execution"}:
        return False, ""
    m = _RX_PS_ENCODED.search(ev.command_line or "")
    return (True, m.group(0)[:200]) if m else (False, "")


def _match_ps_download(ev: Event) -> tuple[bool, str]:
    if ev.event_type not in {"process_execution", "script_execution"}:
        return False, ""
    m = _RX_PS_DOWNLOAD.search(ev.command_line or "")
    return (True, m.group(0)[:200]) if m else (False, "")


def _match_certutil(ev: Event) -> tuple[bool, str]:
    if ev.event_type not in {"process_execution", "script_execution"}:
        return False, ""
    m = _RX_CERTUTIL.search(ev.command_line or "")
    return (True, m.group(0)[:200]) if m else (False, "")


def _match_mshta(ev: Event) -> tuple[bool, str]:
    m = _RX_MSHTA.search(ev.command_line or "")
    return (True, m.group(0)[:200]) if m else (False, "")


def _match_rundll32(ev: Event) -> tuple[bool, str]:
    m = _RX_RUNDLL32.search(ev.command_line or "")
    return (True, m.group(0)[:200]) if m else (False, "")


def _match_regsvr32(ev: Event) -> tuple[bool, str]:
    m = _RX_REGSVR32.search(ev.command_line or "")
    return (True, m.group(0)[:200]) if m else (False, "")


def _match_schtasks(ev: Event) -> tuple[bool, str]:
    m = _RX_SCHTASKS.search(ev.command_line or "")
    return (True, m.group(0)[:200]) if m else (False, "")


def _match_service_create(ev: Event) -> tuple[bool, str]:
    m = _RX_SVC_CREATE.search(ev.command_line or "")
    return (True, m.group(0)[:200]) if m else (False, "")


def _match_reg_run(ev: Event) -> tuple[bool, str]:
    m = _RX_REG_RUN.search(ev.command_line or "")
    return (True, m.group(0)[:200]) if m else (False, "")


def _match_bitsadmin_curl(ev: Event) -> tuple[bool, str]:
    m = _RX_BITSADMIN.search(ev.command_line or "")
    return (True, m.group(0)[:200]) if m else (False, "")


def _match_office_spawn_shell(ev: Event) -> tuple[bool, str]:
    """Office process spawning a shell — classic macro execution."""
    proc = (ev.process_name or "").lower()
    parent = (ev.raw.get("parent_process") or "").lower() if ev.raw else ""
    if proc in _SHELL_PROCS and parent in _OFFICE_PROCS:
        return True, f"{parent} -> {proc}"
    return False, ""


def _match_lsass_dump(ev: Event) -> tuple[bool, str]:
    m = _RX_LSASS_DUMP.search(ev.command_line or "")
    return (True, m.group(0)[:200]) if m else (False, "")


def _match_amsi_bypass(ev: Event) -> tuple[bool, str]:
    m = _RX_AMSI_BYPASS.search(ev.command_line or "")
    return (True, m.group(0)[:200]) if m else (False, "")


def _match_rare_outbound_port(ev: Event) -> tuple[bool, str]:
    """
    Outbound network connection on a high non-standard port from a
    shell-like process — a low-confidence but useful indicator.
    """
    if ev.event_type != "network_connection":
        return False, ""
    if not ev.dst_port or ev.dst_port < 1024:
        return False, ""
    common = {1080, 1443, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000}
    if ev.dst_port in common:
        return False, ""
    proc = (ev.process_name or "").lower()
    if proc not in _SHELL_PROCS:
        return False, ""
    return True, f"{proc} -> {ev.dst_ip}:{ev.dst_port}"


_BUILTIN_RULES: list[Rule] = [
    Rule(
        rule_id="NG-EXEC-PS-ENC-001",
        title="PowerShell -EncodedCommand execution",
        severity="high",
        confidence=92,
        mitre_technique="T1027.010",
        description="PowerShell invoked with an encoded command — common obfuscation for download/execute payloads.",
        matcher=_match_ps_encoded,
    ),
    Rule(
        rule_id="NG-EXEC-PS-DL-001",
        title="PowerShell remote download / Invoke-Expression",
        severity="high",
        confidence=88,
        mitre_technique="T1059.001",
        description="PowerShell using DownloadString/IWR/iex — indicator of remote payload execution.",
        matcher=_match_ps_download,
    ),
    Rule(
        rule_id="NG-LOLBIN-CERTUTIL-001",
        title="certutil abuse (download/decode)",
        severity="high",
        confidence=90,
        mitre_technique="T1105",
        description="certutil used outside cert workflows — known LOLBin for staging payloads.",
        matcher=_match_certutil,
    ),
    Rule(
        rule_id="NG-LOLBIN-MSHTA-001",
        title="mshta executing remote / inline script",
        severity="high",
        confidence=88,
        mitre_technique="T1218.005",
        description="mshta proxy-executing http(s) / javascript / vbscript content.",
        matcher=_match_mshta,
    ),
    Rule(
        rule_id="NG-LOLBIN-RUNDLL32-001",
        title="rundll32 with remote payload",
        severity="high",
        confidence=85,
        mitre_technique="T1218.011",
        description="rundll32 invoked with javascript: scheme or http URL — abnormal usage.",
        matcher=_match_rundll32,
    ),
    Rule(
        rule_id="NG-LOLBIN-REGSVR32-001",
        title="regsvr32 Squiblydoo",
        severity="high",
        confidence=92,
        mitre_technique="T1218.010",
        description="regsvr32 with /i:http or scrobj.dll — Squiblydoo signed-binary proxy execution.",
        matcher=_match_regsvr32,
    ),
    Rule(
        rule_id="NG-PERSIST-SCHTASKS-001",
        title="Scheduled task created/modified",
        severity="medium",
        confidence=75,
        mitre_technique="T1053.005",
        description="schtasks /create or /change — common persistence mechanism.",
        matcher=_match_schtasks,
    ),
    Rule(
        rule_id="NG-PERSIST-SERVICE-001",
        title="New Windows service",
        severity="medium",
        confidence=70,
        mitre_technique="T1543.003",
        description="sc.exe create or New-Service — service persistence.",
        matcher=_match_service_create,
    ),
    Rule(
        rule_id="NG-PERSIST-REG-RUN-001",
        title="Registry Run / RunOnce / IFEO write",
        severity="high",
        confidence=85,
        mitre_technique="T1547.001",
        description="reg add to autorun / IFEO keys.",
        matcher=_match_reg_run,
    ),
    Rule(
        rule_id="NG-INGRESS-LOLBIN-001",
        title="Ingress tool transfer via bitsadmin/curl/wget",
        severity="medium",
        confidence=70,
        mitre_technique="T1105",
        description="bitsadmin/curl/wget downloading from http(s) URL.",
        matcher=_match_bitsadmin_curl,
    ),
    Rule(
        rule_id="NG-EXEC-OFFICE-SHELL-001",
        title="Office spawning shell process",
        severity="critical",
        confidence=90,
        mitre_technique="T1059",
        description="Word/Excel/Outlook spawning cmd/powershell/mshta — macro/exploit execution.",
        matcher=_match_office_spawn_shell,
    ),
    Rule(
        rule_id="NG-CRED-LSASS-001",
        title="LSASS credential dump indicator",
        severity="critical",
        confidence=95,
        mitre_technique="T1003.001",
        description="procdump/comsvcs/mimikatz/sekurlsa pattern in command line.",
        matcher=_match_lsass_dump,
    ),
    Rule(
        rule_id="NG-EVASION-AMSI-001",
        title="AMSI bypass attempt",
        severity="high",
        confidence=85,
        mitre_technique="T1562.001",
        description="AmsiUtils reflection / amsiInitFailed pattern — defense evasion.",
        matcher=_match_amsi_bypass,
    ),
    Rule(
        rule_id="NG-NET-RARE-PORT-001",
        title="Outbound connection from shell on uncommon port",
        severity="medium",
        confidence=55,
        mitre_technique="T1071",
        description="Shell process making outbound connection to a non-standard port.",
        matcher=_match_rare_outbound_port,
    ),
]


# ── Engine ───────────────────────────────────────────────────────────


class DetectionEngine:
    """
    Stateless, thread-safe rule evaluator.

    Usage:
        engine = DetectionEngine()
        alerts = engine.evaluate(events)

    Add custom rules:
        engine.register_rule(my_rule)
    """

    def __init__(self, rules: Sequence[Rule] | None = None):
        self.rules: list[Rule] = list(rules if rules is not None else _BUILTIN_RULES)

    def register_rule(self, rule: Rule) -> None:
        """Append a rule. Caller is responsible for unique rule_id."""
        if any(r.rule_id == rule.rule_id for r in self.rules):
            raise ValueError(f"duplicate rule_id: {rule.rule_id}")
        self.rules.append(rule)

    def evaluate(self, events: Iterable[Event | dict]) -> list[Alert]:
        out: list[Alert] = []
        for raw in events:
            ev = _coerce_event(raw)
            for rule in self.rules:
                try:
                    matched, evidence = rule.matcher(ev)
                except Exception:
                    logger.exception("rule %s crashed on event %s",
                                     rule.rule_id, ev.event_id)
                    continue
                if not matched:
                    continue
                out.append(self._build_alert(rule, ev, evidence))
        return out

    def evaluate_one(self, event: Event | dict) -> list[Alert]:
        return self.evaluate([event])

    # ── helpers ──

    def _build_alert(self, rule: Rule, ev: Event, evidence: str) -> Alert:
        tactic = mitre_mapper.tactic_for(rule.mitre_technique)
        return Alert(
            alert_id=_stable_alert_id(rule.rule_id, ev.host_id, ev.event_id),
            host_id=ev.host_id,
            rule_id=rule.rule_id,
            severity=rule.severity,
            confidence=int(rule.confidence),
            timestamp=ev.timestamp or _utc_now_iso(),
            title=rule.title,
            evidence=evidence or rule.description,
            mitre_tactic=tactic,
            mitre_technique=rule.mitre_technique,
            event_ids=[ev.event_id],
            status="open",
        )


# ── Convenience module-level functions ──────────────────────────────

def _stable_alert_id(rule_id: str, host_id: str, event_id: str) -> str:
    seed = f"netguard:detection:{rule_id}:{host_id}:{event_id}"
    return str(uuid.uuid5(uuid.NAMESPACE_URL, seed))


_default_engine = DetectionEngine()


def evaluate(events: Iterable[Event | dict]) -> list[Alert]:
    """Module-level shortcut using the default engine."""
    return _default_engine.evaluate(events)


def builtin_rules() -> list[Rule]:
    return list(_BUILTIN_RULES)
