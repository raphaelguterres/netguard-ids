"""NetGuard EDR/XDR pipeline orchestration."""

from __future__ import annotations

import threading
from collections import defaultdict, deque
from typing import Any

from .correlation import WeakSignalCorrelationEngine
from .detection import BehaviorDetectionEngine
from .response import ResponseEngine
from .schema import PipelineOutcome, parse_endpoint_events
from .severity import clamp_risk, risk_level, severity_weight


class XDRPipeline:
    def __init__(
        self,
        detection_engine: BehaviorDetectionEngine | None = None,
        correlation_engine: WeakSignalCorrelationEngine | None = None,
        response_engine: ResponseEngine | None = None,
    ):
        self.detection_engine = detection_engine or BehaviorDetectionEngine()
        self.correlation_engine = correlation_engine or WeakSignalCorrelationEngine()
        self.response_engine = response_engine or ResponseEngine()
        self._risk_lock = threading.RLock()
        self._history_lock = threading.RLock()
        self._host_risk_scores: dict[str, int] = defaultdict(int)
        self._host_recent_activity: dict[str, deque] = defaultdict(lambda: deque(maxlen=80))

    def process_payload(self, payload: dict[str, Any] | list[Any]) -> list[PipelineOutcome]:
        events = parse_endpoint_events(payload)
        return [self.process_event(event) for event in events]

    def process_event(self, event) -> PipelineOutcome:
        detections = self.detection_engine.process(event)
        correlations = self.correlation_engine.process(event, detections)
        actions = self.response_engine.plan(event, detections, correlations)
        risk_delta = max(1, severity_weight(event.severity) // 3)
        risk_delta += sum(max(1, int(severity_weight(item.severity) * max(item.confidence, 0.5))) for item in detections)
        risk_delta += sum(max(1, int(severity_weight(item.severity) * max(item.confidence, 0.5))) for item in correlations)
        if any("execution_chain" in (item.tags or []) for item in correlations):
            risk_delta += 12
        host_risk = self._update_host_risk(event.host_id, risk_delta)
        outcome = PipelineOutcome(
            event=event,
            detections=detections,
            correlations=correlations,
            actions=actions,
            host_risk_score=host_risk,
        )
        self._record_outcome(outcome)
        return outcome

    def current_host_risk(self, host_id: str) -> dict[str, Any]:
        with self._risk_lock:
            score = clamp_risk(self._host_risk_scores.get(host_id, 0))
        return {"host_id": host_id, "risk_score": score, "risk_level": risk_level(score)}

    def _update_host_risk(self, host_id: str, delta: int) -> int:
        with self._risk_lock:
            baseline = max(0, self._host_risk_scores.get(host_id, 0) - 2)
            self._host_risk_scores[host_id] = clamp_risk(baseline + delta)
            return self._host_risk_scores[host_id]

    def _record_outcome(self, outcome: PipelineOutcome) -> None:
        with self._history_lock:
            self._host_recent_activity[outcome.event.host_id].appendleft(outcome.to_dict())

    def recent_host_activity(self, host_id: str, *, limit: int = 25) -> list[dict[str, Any]]:
        with self._history_lock:
            return list(self._host_recent_activity.get(host_id, ()))[:limit]
