"""
MITRE ATT&CK technique → tactic mapper.

Detection rules emit the technique ID they match (e.g. T1027.010).
The dashboard / SIEM queries / threat-hunter reports want the parent
*tactic* too. This module provides a one-shot lookup, plus helpers for
URL building and pretty-printing.

Coverage is intentionally a curated subset relevant to NetGuard's
endpoint detections — not the full ATT&CK matrix. Adding entries is
safe; missing entries fall back to "Unknown" without crashing.

Source: ATT&CK v15 (latest as of writing). Sub-techniques inherit the
parent's tactic if not explicitly listed.
"""

from __future__ import annotations

from typing import Iterable

# Canonical tactic short names (we use Title Case for display).
TACTICS = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
)


# Technique → primary tactic. Many techniques map to multiple tactics in
# the real matrix; we pick the one most useful for the alert UI.
_TECH_TO_TACTIC: dict[str, str] = {
    # Initial Access
    "T1566": "Initial Access",          # Phishing
    "T1190": "Initial Access",          # Exploit Public-Facing App
    "T1078": "Defense Evasion",         # Valid Accounts (also IA, PE, Persist)

    # Execution
    "T1059": "Execution",               # Command and Scripting Interpreter
    "T1059.001": "Execution",           # PowerShell
    "T1059.003": "Execution",           # Windows cmd
    "T1059.005": "Execution",           # VBA / macros
    "T1059.006": "Execution",           # Python
    "T1047":     "Execution",           # WMI
    "T1053":     "Persistence",         # Scheduled Task — also Persist
    "T1053.005": "Persistence",         # schtasks
    "T1129":     "Execution",           # Shared Modules

    # Persistence
    "T1547":     "Persistence",         # Boot or Logon Autostart
    "T1547.001": "Persistence",         # Registry Run keys
    "T1543":     "Persistence",         # Create or Modify System Process
    "T1543.003": "Persistence",         # Windows Service
    "T1546":     "Persistence",         # Event Triggered Execution
    "T1546.012": "Persistence",         # IFEO

    # Privilege Escalation
    "T1068":     "Privilege Escalation",
    "T1134":     "Privilege Escalation",
    "T1055":     "Privilege Escalation",  # also Defense Evasion

    # Defense Evasion
    "T1027":     "Defense Evasion",     # Obfuscated Files
    "T1027.010": "Defense Evasion",     # Command Obfuscation
    "T1140":     "Defense Evasion",     # Deobfuscate
    "T1218":     "Defense Evasion",     # Signed Binary Proxy Exec
    "T1218.005": "Defense Evasion",     # Mshta
    "T1218.010": "Defense Evasion",     # Regsvr32
    "T1218.011": "Defense Evasion",     # Rundll32
    "T1562":     "Defense Evasion",     # Impair Defenses
    "T1562.001": "Defense Evasion",     # Disable security tools

    # Credential Access
    "T1003":     "Credential Access",   # OS Cred Dump
    "T1003.001": "Credential Access",   # LSASS
    "T1110":     "Credential Access",   # Brute Force
    "T1555":     "Credential Access",

    # Discovery
    "T1082":     "Discovery",           # System Info
    "T1083":     "Discovery",           # File/Dir Discovery
    "T1057":     "Discovery",           # Process Discovery

    # Lateral Movement
    "T1021":     "Lateral Movement",
    "T1021.001": "Lateral Movement",    # RDP
    "T1021.002": "Lateral Movement",    # SMB

    # Collection
    "T1005":     "Collection",          # Local System

    # Command and Control
    "T1071":     "Command and Control",
    "T1071.001": "Command and Control", # Web Protocols
    "T1105":     "Command and Control", # Ingress Tool Transfer
    "T1572":     "Command and Control", # Protocol Tunneling
    "T1090":     "Command and Control", # Proxy

    # Exfiltration
    "T1041":     "Exfiltration",
    "T1567":     "Exfiltration",        # Web Service exfil

    # Impact
    "T1486":     "Impact",              # Data Encrypted for Impact (ransomware)
    "T1490":     "Impact",              # Inhibit System Recovery
    "T1489":     "Impact",              # Service Stop
}


def tactic_for(technique: str) -> str:
    """
    Resolve a technique ID (with or without sub-technique) to its tactic.

    Returns "Unknown" if the technique isn't in the curated map.
    Sub-technique fallback: T1059.001 → falls back to T1059 if the
    sub-technique isn't explicitly listed.
    """
    if not technique:
        return "Unknown"
    t = technique.strip().upper()
    if t in _TECH_TO_TACTIC:
        return _TECH_TO_TACTIC[t]
    # Sub-technique fallback to parent.
    if "." in t:
        parent = t.split(".", 1)[0]
        if parent in _TECH_TO_TACTIC:
            return _TECH_TO_TACTIC[parent]
    return "Unknown"


def attack_url(technique: str) -> str:
    """Canonical attack.mitre.org URL for the technique."""
    if not technique:
        return ""
    t = technique.strip().upper()
    if "." in t:
        parent, sub = t.split(".", 1)
        return f"https://attack.mitre.org/techniques/{parent}/{sub}/"
    return f"https://attack.mitre.org/techniques/{t}/"


def normalize(technique: str) -> str:
    """Strip whitespace, uppercase, validate basic shape."""
    if not technique:
        return ""
    t = technique.strip().upper()
    # Accept "T1059", "T1059.001", "T1059/001". Reject anything else.
    parts = t.replace("/", ".").split(".")
    if not parts[0].startswith("T") or not parts[0][1:].isdigit():
        return ""
    if len(parts) == 2 and not parts[1].isdigit():
        return parts[0]
    return ".".join(parts)


def expand_tactics(techniques: Iterable[str]) -> dict[str, list[str]]:
    """
    Group techniques by tactic. Useful for dashboard heatmap.

    Example:
        expand_tactics(["T1059.001", "T1547.001", "T1027"])
        -> {"Execution": ["T1059.001"],
            "Persistence": ["T1547.001"],
            "Defense Evasion": ["T1027"]}
    """
    out: dict[str, list[str]] = {}
    for t in techniques:
        norm = normalize(t)
        if not norm:
            continue
        tac = tactic_for(norm)
        out.setdefault(tac, []).append(norm)
    return out


def known_techniques() -> list[str]:
    """List of every technique ID we have an explicit mapping for."""
    return sorted(_TECH_TO_TACTIC.keys())
