"""Correlation of weak endpoint signals into higher-confidence alerts."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from .schema import CorrelationRecord, DetectionRecord, EndpointEvent
from .severity import max_severity


class WeakSignalCorrelationEngine:
    def __init__(self):
        self._lock = threading.RLock()
        self._signals: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))

    def process(self, event: EndpointEvent, detections: list[DetectionRecord]) -> list[CorrelationRecord]:
        correlations: list[CorrelationRecord] = []
        now = time.time()
        host = event.host_id
        with self._lock:
            bucket = self._signals[host]
            for detection in detections:
                bucket.append((now, detection))
            self._prune(bucket, now)
            recent = [item for _, item in bucket]

        suspicious_scripts = [item for item in recent if self._has_any_tag(item, {"script_abuse", "encoded_command"})]
        persistence = [item for item in recent if self._has_any_tag(item, {"persistence"})]
        brute_force = [item for item in recent if self._has_any_tag(item, {"auth_abuse", "bruteforce"})]
        beaconing = [item for item in recent if self._has_any_tag(item, {"beaconing", "c2_suspected"})]

        if len(suspicious_scripts) >= 3:
            correlations.append(
                CorrelationRecord(
                    rule_id="NG-XDR-COR-001",
                    rule_name="Repeated suspicious script execution",
                    severity="critical",
                    summary="Multiple suspicious script executions were observed in a short period.",
                    confidence=0.94,
                    signal_count=len(suspicious_scripts),
                    tags=["correlation", "script_burst"],
                    details={"host_id": host},
                )
            )

        if suspicious_scripts and persistence:
            correlations.append(
                CorrelationRecord(
                    rule_id="NG-XDR-COR-002",
                    rule_name="Execution plus persistence chain",
                    severity="critical",
                    summary="Suspicious scripting activity was followed by persistence indicators.",
                    confidence=0.97,
                    signal_count=len(suspicious_scripts) + len(persistence),
                    tags=["correlation", "persistence_chain"],
                    details={"host_id": host},
                )
            )

        if brute_force and suspicious_scripts:
            correlations.append(
                CorrelationRecord(
                    rule_id="NG-XDR-COR-003",
                    rule_name="Auth abuse followed by script activity",
                    severity=max_severity("high", event.severity),
                    summary="Authentication abuse and suspicious scripting occurred on the same host.",
                    confidence=0.84,
                    signal_count=len(brute_force) + len(suspicious_scripts),
                    tags=["correlation", "credential_to_execution"],
                    details={"host_id": host},
                )
            )

        if beaconing and suspicious_scripts:
            correlations.append(
                CorrelationRecord(
                    rule_id="NG-XDR-COR-004",
                    rule_name="Suspicious execution with outbound beaconing",
                    severity="critical",
                    summary="Script abuse coincided with repeated beacon-like outbound traffic on the same host.",
                    confidence=0.89,
                    signal_count=len(beaconing) + len(suspicious_scripts),
                    tags=["correlation", "execution_to_c2"],
                    details={"host_id": host},
                )
            )

        return correlations

    @staticmethod
    def _prune(bucket: deque, now: float) -> None:
        cutoff = now - (20 * 60)
        while bucket and bucket[0][0] < cutoff:
            bucket.popleft()

    @staticmethod
    def _has_any_tag(record: DetectionRecord, candidates: set[str]) -> bool:
        return any(tag in candidates for tag in (record.tags or []))
