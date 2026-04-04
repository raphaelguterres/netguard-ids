"""
NetGuard — Event Model
Estrutura normalizada de evento seguindo padrão SIEM/XDR.
Compatível com MITRE ATT&CK, ECS (Elastic Common Schema) e OCSF.
"""

import uuid
import socket
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any  # noqa: F401
from enum import Enum


class Severity(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def score(self) -> int:
        return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]

    def __lt__(self, other): return self.score <  other.score
    def __le__(self, other): return self.score <= other.score
    def __gt__(self, other): return self.score >  other.score
    def __ge__(self, other): return self.score >= other.score


class EventType(str, Enum):
    # Process
    PROCESS_STARTED       = "process_started"
    PROCESS_ANOMALY       = "process_anomaly"
    PROCESS_HIGH_CPU      = "process_high_cpu"
    PROCESS_UNKNOWN       = "process_unknown"
    PROCESS_EXTERNAL_CONN = "process_external_conn"

    # Network
    PORT_OPENED           = "port_opened"
    PORT_NEW_LISTEN       = "port_new_listen"
    CONNECTION_OUTBOUND   = "connection_outbound"
    NETWORK_SPIKE         = "network_spike"
    NETWORK_SCAN          = "network_scan"
    NETWORK_BEACONING     = "network_beaconing"
    IP_NEW_EXTERNAL       = "ip_new_external"

    # Web
    WEB_ATTACK_DETECTED   = "web_attack_detected"
    WEB_SQLI              = "web_sqli"
    WEB_XSS               = "web_xss"
    WEB_SUSPICIOUS_UA     = "web_suspicious_ua"

    # Behavior
    BEHAVIOR_DEVIATION    = "behavior_deviation"
    BEHAVIOR_BASELINE     = "behavior_baseline"

    # System
    SYSTEM_ALERT          = "system_alert"


@dataclass
class MitreInfo:
    tactic:    str = ""
    technique: str = ""
    subtechnique: str = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v}


@dataclass
class SecurityEvent:
    """
    Evento de segurança normalizado.
    Estrutura compatível com SIEM/XDR.
    """
    event_type:  str
    severity:    str
    source:      str
    details:     Dict[str, Any]

    # Auto-populated
    event_id:    str            = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:   str            = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    host_id:     str            = field(default_factory=lambda: socket.gethostname())
    rule_id:     str            = ""
    rule_name:   str            = ""
    mitre:       MitreInfo      = field(default_factory=MitreInfo)
    tags:        list           = field(default_factory=list)
    raw:         str            = ""
    acknowledged: bool          = False

    def to_dict(self) -> dict:
        d = asdict(self)
        d['mitre'] = self.mitre.to_dict()
        return d

    @property
    def severity_score(self) -> int:
        return Severity(self.severity).score if self.severity in Severity._value2member_map_ else 0

    def __repr__(self):
        return (f"SecurityEvent(type={self.event_type}, sev={self.severity}, "
                f"src={self.source}, host={self.host_id})")


def make_event(
    event_type: str,
    severity:   str,
    source:     str,
    details:    dict,
    rule_id:    str = "",
    rule_name:  str = "",
    mitre_tactic:     str = "",
    mitre_technique:  str = "",
    tags:       list = None,
    raw:        str = "",
) -> SecurityEvent:
    """Factory para criar eventos normalizados."""
    return SecurityEvent(
        event_type = event_type,
        severity   = severity,
        source     = source,
        details    = details,
        rule_id    = rule_id,
        rule_name  = rule_name,
        mitre      = MitreInfo(tactic=mitre_tactic, technique=mitre_technique),
        tags       = tags or [],
        raw        = raw[:500] if raw else "",
    )
