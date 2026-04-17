"""Persistence-oriented endpoint detections."""

from __future__ import annotations

from .base import DetectionContext, DetectionRule

PERSISTENCE_METHODS = {
    "registry_run_key": "high",
    "scheduled_task": "high",
    "startup_folder": "medium",
    "cron": "high",
    "systemd": "high",
    "launch_agent": "high",
    "service": "high",
}

PERSISTENCE_TECHNIQUES = {
    "registry_run_key": "T1547.001",
    "scheduled_task": "T1053.005",
    "startup_folder": "T1547.001",
    "cron": "T1053.003",
    "systemd": "T1543.002",
    "launch_agent": "T1543.001",
    "service": "T1543.003",
}


class PersistenceIndicatorRule(DetectionRule):
    rule_id = "NG-EDR-004"
    rule_name = "Persistence mechanism observed"
    alert_type = "persistence_indicator_detected"
    supported_event_types = ("persistence_indicator",)
    recommended_action = "review_persistence_artifact"
    base_tags = ("persistence", "endpoint_modification")
    mitre_tactic = "persistence"

    def evaluate(self, context: DetectionContext):
        method = (context.event.persistence_method or "").lower()
        severity = PERSISTENCE_METHODS.get(method, "medium")
        technique = PERSISTENCE_TECHNIQUES.get(method, "T1547")
        target = context.event.persistence_target or ""
        if "run" in target.lower() or "startup" in target.lower():
            severity = "high"
            technique = "T1547.001"
        return [
            self.detection(
                severity=severity,
                confidence=0.86,
                description="A persistence indicator was reported on the endpoint.",
                context=context,
                tags=[method or "unknown_persistence"],
                details={"method": context.event.persistence_method, "target": context.event.persistence_target},
                technique=technique,
            )
        ]
