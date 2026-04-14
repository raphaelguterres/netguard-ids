"""Behavior-based detection engine orchestration for NetGuard XDR."""

from __future__ import annotations

import json
import threading

from .detections import (
    DEFAULT_RULES,
    BehavioralBaselineAdapter,
    DetectionContext,
    HostBehaviorStore,
)
from .schema import DetectionRecord, EndpointEvent
from .severity import max_severity


class BehaviorDetectionEngine:
    """Stateful, explainable detection engine built from modular rules."""

    def __init__(self, *, rules=None, baseline_adapter: BehavioralBaselineAdapter | None = None):
        self._lock = threading.RLock()
        self._rules = tuple(rules or DEFAULT_RULES)
        self._store = HostBehaviorStore()
        self._baseline_adapter = baseline_adapter or BehavioralBaselineAdapter()

    @property
    def rules(self):
        return self._rules

    def process(self, event: EndpointEvent) -> list[DetectionRecord]:
        with self._lock:
            profile = self._store.observe(event)
            baseline_signals = self._baseline_adapter.assess(event, profile)

        context = DetectionContext(
            event=event,
            profile=profile,
            baseline_signals=baseline_signals,
        )
        findings: list[DetectionRecord] = []
        for rule in self._rules:
            if not rule.applies_to(event):
                continue
            findings.extend(rule.evaluate(context))

        ml_signal = baseline_signals.get("ml_behavior_deviation")
        if ml_signal:
            findings.append(
                DetectionRecord(
                    rule_id="NG-EDR-013",
                    rule_name="ML baseline behavior deviation",
                    severity=ml_signal.get("severity", "medium"),
                    summary=ml_signal.get("description", "ML baseline detected a behavior deviation."),
                    confidence=0.74,
                    tags=["baseline", "ml_baseline", "behavior_deviation"],
                    details=ml_signal.get("details", {}),
                    related_events=[context.current_ref()],
                    recommended_action="investigate_baseline_deviation",
                )
            )

        if findings and event.severity:
            elevated = max_severity(event.severity, *(item.severity for item in findings))
            for finding in findings:
                finding.severity = max_severity(finding.severity, elevated)

        return self._dedupe(findings)

    @staticmethod
    def _dedupe(findings: list[DetectionRecord]) -> list[DetectionRecord]:
        deduped: list[DetectionRecord] = []
        seen = set()
        for finding in findings:
            key = (
                finding.rule_id,
                finding.summary,
                tuple(sorted(finding.tags)),
                json.dumps(finding.details or {}, sort_keys=True, default=str),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)
        return deduped
