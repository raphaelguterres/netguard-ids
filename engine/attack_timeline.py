from __future__ import annotations  # noqa: F401

from collections import defaultdict
from typing import Any, Dict, List
import hashlib

from models.attack_timeline_model import AttackTimeline, TimelineStep


EVENT_PHASE_MAP = {

    # RECONNAISSANCE
    "port_scan_suspected": "Reconnaissance",
    "port_scan": "Reconnaissance",
    "network_scan": "Reconnaissance",
    "recon": "Reconnaissance",

    # PROCESS
    "process_unknown": "Execution",
    "process_external_conn": "Command and Control",
    "process_high_cpu": "Impact",

    # PORTS
    "port_new_listen": "Persistence",

    # NETWORK
    "ip_new_external": "Command and Control",

    # BRUTE / AUTH
    "multiple_failed_logins": "Initial Access",
    "brute_force_detected": "Initial Access",

    # POWERSHELL / EXEC
    "powershell_encoded_command": "Execution",
    "suspicious_process_execution": "Execution",
    "suspicious_powershell": "Execution",
    "suspicious_bash": "Execution",
    "encoded_command_execution": "Defense Evasion",
    "office_spawned_interpreter": "Execution",
    "rare_process_execution": "Execution",
    "unusual_parent_child": "Execution",

    # MOVEMENT
    "lateral_movement_detected": "Lateral Movement",

    # DATA
    "large_outbound_transfer": "Exfiltration",
    "unusual_outbound_port": "Command and Control",
    "rare_outbound_destination": "Command and Control",
    "beaconing_pattern_detected": "Command and Control",

    # MALWARE
    "malware_detected": "Impact",
    "persistence_indicator_detected": "Persistence",
    "brute_force_auth_pattern": "Credential Access",
    "auth_failure_then_success": "Credential Access",
    "login_outside_baseline": "Initial Access",
    "execution_persistence_chain": "Persistence",
    "credential_to_execution_chain": "Execution",
    "execution_to_external_beaconing": "Command and Control",
    "office_script_external_persistence_chain": "Persistence",

}

SEVERITY_SCORE = {
    "info": 2,
    "low": 8,
    "medium": 18,
    "high": 30,
    "critical": 45,
}


class AttackTimelineEngine:
    def __init__(self) -> None:
        pass

    def map_phase(self, event_type: str) -> str:
        return EVENT_PHASE_MAP.get(event_type, "Unknown")

    def score_timeline(self, events: List[Dict[str, Any]]) -> int:
        total = 0
        unique_phases = set()

        for event in events:
            sev = (event.get("severity") or "info").lower()
            total += SEVERITY_SCORE.get(sev, 2)
            unique_phases.add(self.map_phase(event.get("event_type", "")))

        total += max(0, (len(unique_phases) - 1) * 5)
        return min(total, 100)

    def build_attack_id(self, host_id: str, events: List[Dict[str, Any]]) -> str:
        seed = host_id + "|" + "|".join(
            f"{e.get('timestamp','')}-{e.get('event_type','')}" for e in events[:10]
        )
        digest = hashlib.md5(seed.encode()).hexdigest()[:10]
        return f"atk-{digest}"

    def group_events(self, events: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for event in events:
            host_id = event.get("host_id", "unknown-host")
            grouped[host_id].append(event)

        for host_id in grouped:
            grouped[host_id].sort(key=lambda x: x.get("timestamp", ""))

        return grouped

    def build_timelines(self, events: List[Dict[str, Any]]) -> List[AttackTimeline]:
        grouped = self.group_events(events)
        timelines: List[AttackTimeline] = []

        for host_id, host_events in grouped.items():
            attack_id = self.build_attack_id(host_id, host_events)
            risk_score = self.score_timeline(host_events)

            steps = []
            for event in host_events:
                steps.append(
                    TimelineStep(
                        timestamp=event.get("timestamp", ""),
                        phase=self.map_phase(event.get("event_type", "")),
                        event_type=event.get("event_type", ""),
                        severity=event.get("severity", "info"),
                        message=event.get("message", ""),
                        source=event.get("source", "netguard"),
                        metadata=event.get("metadata", {}) or {},
                    )
                )

            timelines.append(
                AttackTimeline(
                    attack_id=attack_id,
                    host_id=host_id,
                    risk_score=risk_score,
                    steps=steps,
                )
            )

        timelines.sort(key=lambda t: t.risk_score, reverse=True)
        return timelines
