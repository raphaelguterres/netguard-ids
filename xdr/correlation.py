"""Correlation of weak endpoint signals into higher-confidence alerts."""

from __future__ import annotations

import threading
from collections import defaultdict, deque
from dataclasses import dataclass

from .schema import CorrelationRecord, DetectionRecord, EndpointEvent
from .severity import normalize_severity
from .detections.base import parse_event_timestamp
from .severity import max_severity


@dataclass(slots=True)
class _SignalRecord:
    timestamp: float
    detection: DetectionRecord


class WeakSignalCorrelationEngine:
    def __init__(self):
        self._lock = threading.RLock()
        self._signals: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))

    def process(self, event: EndpointEvent, detections: list[DetectionRecord]) -> list[CorrelationRecord]:
        correlations: list[CorrelationRecord] = []
        now = parse_event_timestamp(event.timestamp).timestamp()
        host = event.host_id
        with self._lock:
            bucket = self._signals[host]
            for detection in detections:
                bucket.append(_SignalRecord(timestamp=parse_event_timestamp(detection.timestamp).timestamp(), detection=detection))
            self._prune(bucket, now)
            recent = [item.detection for item in bucket]

        suspicious_scripts = [item for item in recent if self._has_any_tag(item, {"script_abuse", "encoded_command"})]
        persistence = [item for item in recent if self._has_any_tag(item, {"persistence"})]
        brute_force = [item for item in recent if self._has_any_tag(item, {"auth_abuse", "bruteforce"})]
        external = [item for item in recent if self._has_any_tag(item, {"external_connection", "beaconing", "c2_suspected"})]
        office_spawn = [item for item in recent if item.alert_type == "office_spawned_interpreter"]
        powershell = [item for item in recent if item.alert_type == "suspicious_powershell"]
        beaconing = [item for item in recent if self._has_any_tag(item, {"beaconing", "c2_suspected"})]

        if len(suspicious_scripts) >= 3:
            correlations.append(
                CorrelationRecord(
                    rule_id="NG-XDR-COR-001",
                    rule_name="Repeated suspicious script execution",
                    alert_type="suspicious_script_burst",
                    host_id=host,
                    technique="T1059",
                    tactic="execution",
                    severity="critical",
                    summary="Multiple suspicious script executions were observed in a short period.",
                    confidence=0.94,
                    signal_count=len(suspicious_scripts),
                    timestamp=event.timestamp,
                    tags=["correlation", "script_burst"],
                    details={"host_id": host},
                    related_events=self._merge_related_events(suspicious_scripts),
                )
            )

        if suspicious_scripts and persistence:
            correlations.append(
                CorrelationRecord(
                    rule_id="NG-XDR-COR-002",
                    rule_name="Execution plus persistence chain",
                    alert_type="execution_persistence_chain",
                    host_id=host,
                    technique="T1059 -> T1547",
                    tactic="persistence",
                    severity="critical",
                    summary="Suspicious scripting activity was followed by persistence indicators.",
                    confidence=0.97,
                    signal_count=len(suspicious_scripts) + len(persistence),
                    timestamp=event.timestamp,
                    tags=["correlation", "persistence_chain"],
                    details={"host_id": host, "sequence": ["execution", "persistence"]},
                    related_events=self._merge_related_events(suspicious_scripts + persistence),
                )
            )

        if brute_force and suspicious_scripts:
            correlations.append(
                CorrelationRecord(
                    rule_id="NG-XDR-COR-003",
                    rule_name="Auth abuse followed by script activity",
                    alert_type="credential_to_execution_chain",
                    host_id=host,
                    technique="T1110 -> T1059",
                    tactic="credential_access",
                    severity=max_severity("high", event.severity),
                    summary="Authentication abuse and suspicious scripting occurred on the same host.",
                    confidence=0.84,
                    signal_count=len(brute_force) + len(suspicious_scripts),
                    timestamp=event.timestamp,
                    tags=["correlation", "credential_to_execution"],
                    details={"host_id": host},
                    related_events=self._merge_related_events(brute_force + suspicious_scripts),
                )
            )

        if beaconing and suspicious_scripts:
            correlations.append(
                CorrelationRecord(
                    rule_id="NG-XDR-COR-004",
                    rule_name="Suspicious execution with outbound beaconing",
                    alert_type="execution_to_external_beaconing",
                    host_id=host,
                    technique="T1059 -> T1071",
                    tactic="command_and_control",
                    severity="critical",
                    summary="Script abuse coincided with repeated beacon-like outbound traffic on the same host.",
                    confidence=0.89,
                    signal_count=len(beaconing) + len(suspicious_scripts),
                    timestamp=event.timestamp,
                    tags=["correlation", "execution_to_c2"],
                    details={"host_id": host},
                    related_events=self._merge_related_events(beaconing + suspicious_scripts),
                )
            )

        if office_spawn and powershell and external and persistence:
            correlations.append(
                CorrelationRecord(
                    rule_id="NG-XDR-COR-005",
                    rule_name="Office to script to network to persistence chain",
                    alert_type="office_script_external_persistence_chain",
                    host_id=host,
                    technique="T1204.002 -> T1059.001 -> T1071 -> T1547",
                    tactic="persistence",
                    severity="critical",
                    summary="An EDR-style host chain was observed: document parent, suspicious PowerShell, external connection, then persistence.",
                    confidence=0.98,
                    signal_count=len(office_spawn) + len(powershell) + len(external) + len(persistence),
                    timestamp=event.timestamp,
                    tags=["correlation", "execution_chain", "process_tree", "external_connection", "persistence_chain"],
                    details={
                        "host_id": host,
                        "sequence": ["office_spawned_interpreter", "suspicious_powershell", "external_connection", "persistence_indicator_detected"],
                    },
                    related_events=self._merge_related_events(office_spawn + powershell + external + persistence, limit=8),
                )
            )

        return self._dedupe(correlations)

    @staticmethod
    def _prune(bucket: deque, now: float) -> None:
        cutoff = now - (20 * 60)
        while bucket and bucket[0].timestamp < cutoff:
            bucket.popleft()

    @staticmethod
    def _has_any_tag(record: DetectionRecord, candidates: set[str]) -> bool:
        return any(tag in candidates for tag in (record.tags or []))

    @staticmethod
    def _merge_related_events(records: list[DetectionRecord], *, limit: int = 6) -> list[dict]:
        merged: list[dict] = []
        seen = set()
        for record in records:
            for item in record.related_events or []:
                key = (item.get("event_id"), item.get("timestamp"), item.get("event_type"))
                if key in seen:
                    continue
                seen.add(key)
                merged.append(dict(item))
                if len(merged) >= limit:
                    return merged
        return merged

    @staticmethod
    def _dedupe(correlations: list[CorrelationRecord]) -> list[CorrelationRecord]:
        deduped: list[CorrelationRecord] = []
        seen = set()
        for record in correlations:
            key = (
                record.rule_id,
                record.host_id,
                normalize_severity(record.severity),
                tuple(sorted(record.tags or [])),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(record)
        return deduped
