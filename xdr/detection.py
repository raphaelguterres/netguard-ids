"""Behavior-based detection rules for NetGuard XDR."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from .schema import DetectionRecord, EndpointEvent
from .severity import max_severity

SUSPICIOUS_POWERSHELL = (
    "-enc",
    "-encodedcommand",
    "downloadstring",
    "invoke-expression",
    "iex(",
    " bypass ",
    "frombase64string",
)

SUSPICIOUS_BASH = (
    "curl ",
    "wget ",
    "| sh",
    "| bash",
    "base64 -d",
    "chmod +x",
    "/tmp/",
)

PERSISTENCE_METHODS = {
    "registry_run_key",
    "scheduled_task",
    "startup_folder",
    "cron",
    "systemd",
    "launch_agent",
}

OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe"}
SCRIPT_CHILDREN = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "bash", "sh"}


class BehaviorDetectionEngine:
    """Stateful behavior engine tuned for lightweight endpoint telemetry."""

    def __init__(self):
        self._lock = threading.RLock()
        self._baseline_processes: dict[str, defaultdict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._auth_failures: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))

    def process(self, event: EndpointEvent) -> list[DetectionRecord]:
        findings: list[DetectionRecord] = []
        command = (event.command_line or "").lower()
        process = (event.process_name or "").lower()
        parent = (event.parent_process or "").lower()

        if process in {"powershell.exe", "pwsh.exe"} and any(token in command for token in SUSPICIOUS_POWERSHELL):
            findings.append(
                DetectionRecord(
                    rule_id="NG-EDR-001",
                    rule_name="Suspicious PowerShell execution",
                    severity="high",
                    summary="PowerShell command line contains attacker tradecraft indicators.",
                    confidence=0.9,
                    tags=["powershell", "script", "execution"],
                    details={"command_line": event.command_line},
                )
            )

        if process in {"bash", "sh"} and any(token in command for token in SUSPICIOUS_BASH):
            findings.append(
                DetectionRecord(
                    rule_id="NG-EDR-002",
                    rule_name="Suspicious Bash execution",
                    severity="high",
                    summary="Shell command matches download-and-execute behavior.",
                    confidence=0.88,
                    tags=["bash", "script", "download_execute"],
                    details={"command_line": event.command_line},
                )
            )

        if event.event_type == "authentication" and event.auth_result == "failure":
            if self._track_auth_failures(event):
                findings.append(
                    DetectionRecord(
                        rule_id="NG-EDR-003",
                        rule_name="Brute force authentication pattern",
                        severity="high",
                        summary="Repeated authentication failures were observed from the same source.",
                        confidence=0.82,
                        tags=["authentication", "bruteforce"],
                        details={"username": event.username, "source_ip": event.auth_source_ip},
                    )
                )

        if event.event_type == "persistence_indicator":
            method = (event.persistence_method or "").lower()
            severity = "high" if method in PERSISTENCE_METHODS else "medium"
            findings.append(
                DetectionRecord(
                    rule_id="NG-EDR-004",
                    rule_name="Persistence mechanism observed",
                    severity=severity,
                    summary="A persistence indicator was reported on the endpoint.",
                    confidence=0.86,
                    tags=["persistence", method or "unknown"],
                    details={"method": event.persistence_method, "target": event.persistence_target},
                )
            )

        if event.event_type == "process_execution" and parent in OFFICE_PARENTS and process in SCRIPT_CHILDREN:
            findings.append(
                DetectionRecord(
                    rule_id="NG-EDR-005",
                    rule_name="Suspicious process tree",
                    severity="high",
                    summary="Office or document reader spawned a scripting engine.",
                    confidence=0.91,
                    tags=["process_tree", "execution"],
                    details={"parent_process": event.parent_process, "process_name": event.process_name},
                )
            )

        if event.event_type == "network_connection" and event.network_direction == "outbound":
            if event.network_dst_port in {4444, 1337, 8081, 9001}:
                findings.append(
                    DetectionRecord(
                        rule_id="NG-EDR-006",
                        rule_name="Suspicious outbound connection",
                        severity="medium",
                        summary="Connection metadata matches an uncommon egress pattern.",
                        confidence=0.68,
                        tags=["network", "egress"],
                        details={"dst_ip": event.network_dst_ip, "dst_port": event.network_dst_port},
                    )
                )

        anomaly = self._baseline_anomaly(event)
        if anomaly:
            findings.append(anomaly)

        if findings and event.severity:
            elevated = max_severity(event.severity, *(item.severity for item in findings))
            for finding in findings:
                finding.severity = max_severity(finding.severity, elevated)
        return findings

    def _baseline_anomaly(self, event: EndpointEvent) -> DetectionRecord | None:
        if event.event_type != "process_execution" or not event.process_name:
            return None
        host_bucket = self._baseline_processes[event.host_id]
        process = event.process_name.lower()
        with self._lock:
            host_bucket[process] += 1
            count = host_bucket[process]
            known = len(host_bucket)
        if count == 1 and known >= 5:
            return DetectionRecord(
                rule_id="NG-EDR-007",
                rule_name="Process anomaly compared to host baseline",
                severity="medium",
                summary="Process execution deviates from the observed local baseline.",
                confidence=0.62,
                tags=["baseline", "process_anomaly"],
                details={"process_name": event.process_name, "baseline_size": known},
            )
        return None

    def _track_auth_failures(self, event: EndpointEvent) -> bool:
        key = f"{event.host_id}:{event.username}:{event.auth_source_ip}"
        now = time.time()
        with self._lock:
            bucket = self._auth_failures[key]
            bucket.append(now)
            cutoff = now - 120
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            return len(bucket) >= 5
