"""
NetGuard — Process Detection Rules
Pack completo de regras de detecção de processos.
Alinhado ao MITRE ATT&CK.
"""

import re
import time
import logging
from datetime import datetime, timezone
from collections import defaultdict  # noqa: F401
from typing import Optional
from models.event_model import make_event, Severity, EventType

logger = logging.getLogger("netguard.rules.process")

# ── Baseline de processos legítimos ──────────────────────────────
KNOWN_PROCESSES = {
    "system","smss.exe","csrss.exe","wininit.exe","winlogon.exe",
    "services.exe","lsass.exe","svchost.exe","dwm.exe","explorer.exe",
    "taskhostw.exe","sihost.exe","ctfmon.exe","fontdrvhost.exe",
    "spoolsv.exe","searchindexer.exe","conhost.exe","dllhost.exe",
    "rundll32.exe","cmd.exe","powershell.exe","taskmgr.exe",
    "runtimebroker.exe","applicationframehost.exe","shellexperiencehost.exe",
    "startmenuexperiencehost.exe","securityhealthsystray.exe","msmpeng.exe",
    "brave.exe","chrome.exe","msedge.exe","firefox.exe","msedgewebview2.exe",
    "python.exe","python3.exe","node.exe","code.exe","git.exe",
    "discord.exe","steam.exe","steamwebhelper.exe","whatsapp.exe",
    "slack.exe","zoom.exe","claude.exe","widgets.exe","protonvpn.exe",
    "audiodg.exe","wmiprvse.exe","netguard.exe","searchhost.exe",
    "searchprotocolhost.exe","searchfilterhost.exe","backgroundtaskhost.exe",
    "registry","memcompression","smartscreen.exe","msiexec.exe",
    "wuauclt.exe","tiworker.exe","trustedinstaller.exe","dashost.exe",
    "wlanext.exe","lsm.exe","wermgr.exe","sppsvc.exe","securityhealthservice.exe",
}

# Processos que NUNCA deveriam executar powershell ou cmd
PROC_NO_SHELL = {
    "winword.exe","excel.exe","outlook.exe","powerpnt.exe",
    "acrord32.exe","foxit reader.exe","notepad++.exe",
}

# Pastas suspeitas para execução de binários
SUSPICIOUS_PATHS = [
    r"\\temp\\", r"\\tmp\\", r"\\appdata\\local\\temp\\",
    r"\\downloads\\", r"\\desktop\\",
    r"\\recycle", r"\\$recycle",
    r"\\public\\", r"\\users\\public\\",
]

# Horário de trabalho "normal" (06h–22h)
WORK_HOUR_START = 6
WORK_HOUR_END   = 22

# Padrões de PowerShell suspeito
POWERSHELL_SUSPICIOUS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"-enc\s+[A-Za-z0-9+/]{20,}",          # encoded command
        r"-encodedcommand\s+",
        r"iex\s*\(",                             # Invoke-Expression
        r"invoke-expression",
        r"downloadstring\s*\(",                  # download cradle
        r"downloadfile\s*\(",
        r"net\.webclient",
        r"bitstransfer",
        r"\bbypass\b",                           # -ExecutionPolicy Bypass
        r"hidden.*-command",
        r"-nop\b.*-w\s+hidden",
        r"frombase64string",
        r"\[system\.convert\]",
        r"invoke-mimikatz",
        r"invoke-shellcode",
        r"powercat",
        r"amsibypass",
    ]
]


class ProcessRules:
    def __init__(self, repository=None):
        self.repo = repository
        self._cpu_high_start: dict = {}          # pid → ts quando CPU ficou alta
        self._proc_first_seen: dict = {}         # name → first seen ts
        self._alerted_procs: set   = set()       # dedup session

    # ── R1: Processo desconhecido ─────────────────────────────────
    def detect_unknown_process(self, proc: dict, baseline: set) -> Optional[object]:
        name = (proc.get("name") or "").lower()
        if not name or name in KNOWN_PROCESSES or name in baseline:
            return None
        if name in self._alerted_procs:
            return None
        self._alerted_procs.add(name)
        return make_event(
            event_type      = EventType.PROCESS_UNKNOWN,
            severity        = Severity.MEDIUM,
            source          = "agent.process",
            details         = {"process": name, "pid": proc.get("pid"),
                               "exe": (proc.get("exe") or "")[:120]},
            rule_id         = "P-R1",
            rule_name       = "Processo Desconhecido",
            mitre_tactic    = "execution",
            mitre_technique = "T1204",
            tags            = ["process", "unknown", "baseline"],
        )

    # ── R2: CPU alta contínua ─────────────────────────────────────
    def detect_high_cpu(self, proc: dict, threshold: float = 80.0, duration: int = 30) -> Optional[object]:
        pid  = proc.get("pid", 0)
        cpu  = float(proc.get("cpu") or 0)
        name = (proc.get("name") or "").lower()
        now  = time.time()
        if cpu > threshold:
            if pid not in self._cpu_high_start:
                self._cpu_high_start[pid] = now
            elif now - self._cpu_high_start[pid] >= duration:
                dur = int(now - self._cpu_high_start[pid])
                self._cpu_high_start[pid] = now + 300  # cooldown
                sev = Severity.CRITICAL if cpu >= 95 else Severity.HIGH
                return make_event(
                    event_type      = EventType.PROCESS_HIGH_CPU,
                    severity        = sev,
                    source          = "agent.process",
                    details         = {"process": name, "pid": pid,
                                       "cpu_usage": round(cpu, 1), "duration_sec": dur},
                    rule_id         = "P-R2",
                    rule_name       = "CPU Alta Contínua",
                    mitre_tactic    = "execution",
                    mitre_technique = "T1496",
                    tags            = ["process", "cpu", "performance"],
                )
        else:
            self._cpu_high_start.pop(pid, None)
        return None

    # ── R3: Execução fora do horário normal ───────────────────────
    def detect_off_hours_process(self, proc: dict, baseline: set) -> Optional[object]:
        name = (proc.get("name") or "").lower()
        if not name or name in KNOWN_PROCESSES or name in baseline:
            return None
        hour = datetime.now(timezone.utc).hour
        if WORK_HOUR_START <= hour <= WORK_HOUR_END:
            return None  # dentro do horário
        key = f"offhours:{name}"
        if key in self._alerted_procs:
            return None
        self._alerted_procs.add(key)
        return make_event(
            event_type      = "process_off_hours",
            severity        = Severity.MEDIUM,
            source          = "agent.process",
            details         = {"process": name, "pid": proc.get("pid"),
                               "hour_utc": hour, "exe": (proc.get("exe") or "")[:100]},
            rule_id         = "P-R3",
            rule_name       = "Processo Fora do Horário Normal",
            mitre_tactic    = "persistence",
            mitre_technique = "T1053",
            tags            = ["process", "schedule", "anomaly"],
        )

    # ── R4: PowerShell suspeito ───────────────────────────────────
    def detect_suspicious_powershell(self, proc: dict, cmdline: str = "") -> Optional[object]:
        name = (proc.get("name") or "").lower()
        if "powershell" not in name and "pwsh" not in name:
            return None
        if not cmdline:
            return None
        for pattern in POWERSHELL_SUSPICIOUS:
            m = pattern.search(cmdline)
            if m:
                return make_event(
                    event_type      = "powershell_suspicious",
                    severity        = Severity.HIGH,
                    source          = "agent.process",
                    details         = {"process": name, "pid": proc.get("pid"),
                                       "match": m.group(0)[:80],
                                       "cmdline": cmdline[:200]},
                    rule_id         = "P-R4",
                    rule_name       = "PowerShell Suspeito",
                    mitre_tactic    = "execution",
                    mitre_technique = "T1059.001",
                    tags            = ["process", "powershell", "lolbas"],
                )
        return None

    # ── R5: Binário executado em pasta suspeita ───────────────────
    def detect_suspicious_path(self, proc: dict) -> Optional[object]:
        exe  = (proc.get("exe") or "").lower().replace("\\", "/")
        name = (proc.get("name") or "").lower()
        if not exe or not name:
            return None
        for path in SUSPICIOUS_PATHS:
            if path in exe:
                key = f"susppath:{name}:{path}"
                if key in self._alerted_procs:
                    return None
                self._alerted_procs.add(key)
                return make_event(
                    event_type      = "process_suspicious_path",
                    severity        = Severity.HIGH,
                    source          = "agent.process",
                    details         = {"process": name, "pid": proc.get("pid"),
                                       "exe": exe[:150], "suspicious_path": path},
                    rule_id         = "P-R5",
                    rule_name       = "Binário Executado em Pasta Suspeita",
                    mitre_tactic    = "defense_evasion",
                    mitre_technique = "T1036.005",
                    tags            = ["process", "path", "evasion"],
                )
        return None

    # ── R6: Processo do sistema executando shell ──────────────────
    def detect_shell_from_office(self, proc: dict, parent_name: str = "") -> Optional[object]:
        parent = parent_name.lower()
        child  = (proc.get("name") or "").lower()
        if parent not in PROC_NO_SHELL:
            return None
        if child not in ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"):
            return None
        key = f"shelloffice:{parent}:{child}"
        if key in self._alerted_procs:
            return None
        self._alerted_procs.add(key)
        return make_event(
            event_type      = "shell_spawned_from_office",
            severity        = Severity.CRITICAL,
            source          = "agent.process",
            details         = {"parent": parent, "child": child,
                               "pid": proc.get("pid")},
            rule_id         = "P-R6",
            rule_name       = "Shell Iniciado por Aplicativo Office/PDF",
            mitre_tactic    = "execution",
            mitre_technique = "T1566.001",
            tags            = ["process", "office", "shell", "phishing"],
        )

    def analyze(self, processes: list, connections: list,
                host_id: str, baseline: set) -> list:
        """Roda todas as regras de processo."""
        events = []
        ext_proc_names = {
            c.get("process","").lower() for c in connections
            if c.get("dst_ip","") and not c.get("dst_ip","").startswith(
                ("127.","192.168.","10.","172."))
        }

        for proc in processes:
            name = (proc.get("name") or "").lower()
            if not name:
                continue

            e = self.detect_unknown_process(proc, baseline)
            if e: events.append(e)

            e = self.detect_high_cpu(proc)
            if e: events.append(e)

            e = self.detect_suspicious_path(proc)
            if e: events.append(e)

            cmdline = proc.get("cmdline","")
            if cmdline:
                e = self.detect_suspicious_powershell(proc, cmdline)
                if e: events.append(e)

            if name in ext_proc_names and name not in KNOWN_PROCESSES:
                e = make_event(
                    event_type      = EventType.PROCESS_EXTERNAL_CONN,
                    severity        = Severity.MEDIUM,
                    source          = "agent.process",
                    details         = {"process": name, "pid": proc.get("pid")},
                    rule_id         = "P-R7",
                    rule_name       = "Processo Desconhecido com Conexão Externa",
                    mitre_tactic    = "command_and_control",
                    mitre_technique = "T1071",
                    tags            = ["process", "network", "c2"],
                )
                events.append(e)

        return events
