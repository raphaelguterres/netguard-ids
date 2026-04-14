"""Base abstractions for explainable XDR detection rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from ..schema import DetectionRecord, EndpointEvent
from ..severity import normalize_severity


def parse_event_timestamp(raw: str) -> datetime:
    value = (raw or "").strip()
    if not value:
        return datetime.now(timezone.utc)
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        dt = datetime.fromisoformat(value)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def canonical_command(command_line: str) -> str:
    return " ".join((command_line or "").strip().lower().split())[:256]


def related_event_ref(event: EndpointEvent) -> dict[str, Any]:
    return {
        "event_id": event.event_id,
        "timestamp": event.timestamp,
        "event_type": event.event_type,
        "host_id": event.host_id,
        "process_name": event.process_name,
        "username": event.username,
        "source": event.source,
    }


@dataclass(slots=True)
class DetectionContext:
    event: EndpointEvent
    profile: Any
    baseline_signals: dict[str, Any] = field(default_factory=dict)

    @property
    def event_time(self) -> datetime:
        return parse_event_timestamp(self.event.timestamp)

    def current_ref(self) -> dict[str, Any]:
        return related_event_ref(self.event)

    def recent_related(
        self,
        predicate: Callable[[dict[str, Any]], bool] | None = None,
        *,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        return self.profile.recent_related_events(predicate=predicate, limit=limit)


class DetectionRule(ABC):
    rule_id: str = ""
    rule_name: str = ""
    supported_event_types: tuple[str, ...] = ()
    recommended_action: str = "investigate"
    base_tags: tuple[str, ...] = ()

    def applies_to(self, event: EndpointEvent) -> bool:
        if not self.supported_event_types:
            return True
        return event.event_type in self.supported_event_types

    @abstractmethod
    def evaluate(self, context: DetectionContext) -> list[DetectionRecord]:
        raise NotImplementedError

    def detection(
        self,
        *,
        severity: str,
        confidence: float,
        description: str,
        context: DetectionContext,
        tags: list[str] | tuple[str, ...] = (),
        details: dict[str, Any] | None = None,
        related_events: list[dict[str, Any]] | None = None,
        recommended_action: str | None = None,
    ) -> DetectionRecord:
        merged_tags = list(dict.fromkeys([*self.base_tags, *tags]))
        merged_details = dict(details or {})
        return DetectionRecord(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=normalize_severity(severity, default="medium"),
            summary=description,
            confidence=round(float(confidence), 2),
            tags=merged_tags,
            details=merged_details,
            related_events=related_events or [context.current_ref()],
            recommended_action=recommended_action or self.recommended_action,
        )
