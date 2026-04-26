"""Load and evaluate simple Sigma-like YAML rules."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from xdr.schema import DetectionRecord

logger = logging.getLogger("netguard.yaml_rules")

DEFAULT_RULES_DIR = Path(__file__).resolve().parent / "yaml"
_SUPPORTED_OPERATORS = {
    "equals",
    "contains",
    "contains_any",
    "startswith",
    "endswith",
    "regex",
    "in",
    "gte",
    "lte",
    "gt",
    "lt",
}


class YamlRuleValidationError(ValueError):
    """Raised when a YAML rule is malformed."""


@dataclass(slots=True)
class YamlRuleCondition:
    field: str
    operator: str
    value: Any


@dataclass(slots=True)
class YamlRuleAggregation:
    count: int
    within_seconds: int
    group_by: str = ""
    distinct_field: str = ""
    event_type: str = ""


@dataclass(slots=True)
class YamlDetectionRule:
    rule_id: str
    title: str
    description: str
    severity: str
    event_types: tuple[str, ...]
    all_conditions: tuple[YamlRuleCondition, ...] = ()
    any_conditions: tuple[YamlRuleCondition, ...] = ()
    aggregation: YamlRuleAggregation | None = None
    tactic: str = ""
    technique: str = ""
    tags: tuple[str, ...] = ()
    recommended_action: str = "investigate"
    source_path: str = ""
    alert_type: str = ""

    def matches_current_event(self, context: Any) -> bool:
        if self.event_types and context.event.event_type not in self.event_types:
            return False
        current = _event_to_mapping(context)
        if self.all_conditions and not all(
            _match_condition(condition, current)
            for condition in self.all_conditions
        ):
            return False
        if self.any_conditions and not any(
            _match_condition(condition, current)
            for condition in self.any_conditions
        ):
            return False
        if self.aggregation and not _match_aggregation(self.aggregation, context, current):
            return False
        return True

    def build_detection(self, context: Any) -> DetectionRecord:
        related_events = context.recent_related(limit=10)
        details = {
            "description": self.description,
            "source_rule": self.source_path,
            "yaml_rule": True,
            "aggregation": (
                {
                    "count": self.aggregation.count,
                    "within_seconds": self.aggregation.within_seconds,
                    "group_by": self.aggregation.group_by,
                    "distinct_field": self.aggregation.distinct_field,
                }
                if self.aggregation
                else {}
            ),
        }
        details["matched_conditions"] = {
            "all": [condition.field for condition in self.all_conditions],
            "any": [condition.field for condition in self.any_conditions],
        }
        return DetectionRecord(
            rule_id=self.rule_id,
            rule_name=self.title,
            alert_type=self.alert_type or self.rule_id.lower().replace("-", "_"),
            host_id=context.event.host_id,
            process_name=context.event.process_name,
            parent_process=context.event.parent_process,
            cmdline=context.event.command_line,
            technique=self.technique,
            tactic=self.tactic,
            severity=self.severity,
            summary=self.description,
            confidence=0.8 if self.aggregation else 0.72,
            timestamp=context.event.timestamp,
            tags=list(dict.fromkeys(["yaml_rule", *self.tags])),
            details=details,
            related_events=related_events or [context.current_ref()],
            recommended_action=self.recommended_action,
        )


@dataclass(slots=True)
class YamlRuleRegistry:
    rules: tuple[YamlDetectionRule, ...] = field(default_factory=tuple)

    def evaluate(self, context: DetectionContext) -> list[DetectionRecord]:
        detections: list[DetectionRecord] = []
        for rule in self.rules:
            if rule.matches_current_event(context):
                detections.append(rule.build_detection(context))
        return detections


def load_yaml_rules(directory: str | Path | None = None) -> YamlRuleRegistry:
    rules_dir = Path(directory or DEFAULT_RULES_DIR)
    if not rules_dir.exists():
        return YamlRuleRegistry()
    loaded_rules: list[YamlDetectionRule] = []
    for path in sorted(rules_dir.glob("*.y*ml")):
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            loaded_rules.append(_parse_rule(payload, source_path=str(path)))
        except Exception as exc:
            logger.warning("Skipping invalid YAML rule %s: %s", path, exc)
    return YamlRuleRegistry(rules=tuple(loaded_rules))


def _parse_rule(payload: dict[str, Any], *, source_path: str) -> YamlDetectionRule:
    if not isinstance(payload, dict):
        raise YamlRuleValidationError(f"{source_path}: rule body must be an object")

    rule_id = str(payload.get("id") or "").strip()
    title = str(payload.get("title") or "").strip()
    description = str(payload.get("description") or "").strip()
    severity = str(payload.get("severity") or "medium").strip().lower()
    if not rule_id or not title:
        raise YamlRuleValidationError(f"{source_path}: id and title are required")

    detection = payload.get("detection") or {}
    if not isinstance(detection, dict):
        raise YamlRuleValidationError(f"{source_path}: detection must be an object")

    event_types = tuple(
        str(item).strip().lower()
        for item in (payload.get("event_types") or detection.get("event_types") or [])
        if str(item).strip()
    )
    all_conditions = tuple(
        _parse_condition(item, source_path=source_path)
        for item in detection.get("all", [])
    )
    any_conditions = tuple(
        _parse_condition(item, source_path=source_path)
        for item in detection.get("any", [])
    )
    if not all_conditions and not any_conditions:
        raise YamlRuleValidationError(
            f"{source_path}: detection requires at least one condition",
        )

    aggregation = None
    raw_aggregation = detection.get("aggregation") or {}
    if raw_aggregation:
        if not isinstance(raw_aggregation, dict):
            raise YamlRuleValidationError(f"{source_path}: aggregation must be an object")
        aggregation = YamlRuleAggregation(
            count=max(1, int(raw_aggregation.get("count") or 1)),
            within_seconds=max(1, int(raw_aggregation.get("within_seconds") or 300)),
            group_by=str(raw_aggregation.get("group_by") or "").strip(),
            distinct_field=str(raw_aggregation.get("distinct_field") or "").strip(),
            event_type=str(raw_aggregation.get("event_type") or "").strip().lower(),
        )

    mitre = payload.get("mitre") or {}
    if mitre and not isinstance(mitre, dict):
        raise YamlRuleValidationError(f"{source_path}: mitre must be an object")

    return YamlDetectionRule(
        rule_id=rule_id,
        title=title,
        description=description or title,
        severity=severity,
        event_types=event_types,
        all_conditions=all_conditions,
        any_conditions=any_conditions,
        aggregation=aggregation,
        tactic=str(mitre.get("tactic") or "").strip(),
        technique=str(mitre.get("technique") or "").strip(),
        tags=tuple(str(item).strip().lower() for item in (payload.get("tags") or []) if str(item).strip()),
        recommended_action=str(payload.get("recommended_action") or "investigate").strip(),
        source_path=source_path,
        alert_type=str(payload.get("alert_type") or "").strip().lower(),
    )


def _parse_condition(payload: dict[str, Any], *, source_path: str) -> YamlRuleCondition:
    if not isinstance(payload, dict):
        raise YamlRuleValidationError(f"{source_path}: condition entries must be objects")
    field = str(payload.get("field") or "").strip()
    operator = str(payload.get("operator") or "").strip().lower()
    if not field or operator not in _SUPPORTED_OPERATORS:
        raise YamlRuleValidationError(
            f"{source_path}: invalid condition ({field or 'missing field'} / {operator})",
        )
    return YamlRuleCondition(field=field, operator=operator, value=payload.get("value"))


def _event_to_mapping(context: Any) -> dict[str, Any]:
    event = context.event.to_dict()
    event["details"] = dict(context.event.details or {})
    event["auth_result"] = context.event.auth_result
    event["auth_source_ip"] = context.event.auth_source_ip
    event["network_dst_ip"] = context.event.network_dst_ip
    event["network_dst_port"] = context.event.network_dst_port
    return event


def _resolve_field(field_name: str, payload: dict[str, Any]) -> Any:
    current: Any = payload
    for part in str(field_name).split("."):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _match_condition(condition: YamlRuleCondition, payload: dict[str, Any]) -> bool:
    actual = _resolve_field(condition.field, payload)
    operator = condition.operator
    expected = condition.value
    if operator == "equals":
        return str(actual).lower() == str(expected).lower()
    if operator == "contains":
        return str(expected).lower() in str(actual or "").lower()
    if operator == "contains_any":
        values = expected if isinstance(expected, list) else [expected]
        actual_text = str(actual or "").lower()
        return any(str(item).lower() in actual_text for item in values)
    if operator == "startswith":
        return str(actual or "").lower().startswith(str(expected).lower())
    if operator == "endswith":
        return str(actual or "").lower().endswith(str(expected).lower())
    if operator == "regex":
        return bool(re.search(str(expected), str(actual or ""), flags=re.IGNORECASE))
    if operator == "in":
        values = [str(item).lower() for item in (expected or [])]
        return str(actual).lower() in values
    try:
        actual_num = float(actual)
        expected_num = float(expected)
    except (TypeError, ValueError):
        return False
    if operator == "gte":
        return actual_num >= expected_num
    if operator == "lte":
        return actual_num <= expected_num
    if operator == "gt":
        return actual_num > expected_num
    if operator == "lt":
        return actual_num < expected_num
    return False


def _match_aggregation(
    aggregation: YamlRuleAggregation,
    context: Any,
    current_payload: dict[str, Any],
) -> bool:
    reference_time = context.event_time.timestamp()
    window_events = context.recent_related(
        predicate=lambda item: (
            not aggregation.event_type
            or str(item.get("event_type") or "").strip().lower() == aggregation.event_type
        ),
        limit=120,
    )
    candidates: list[dict[str, Any]] = []
    group_value = _resolve_field(aggregation.group_by, current_payload) if aggregation.group_by else None
    for item in [context.current_ref(), *window_events]:
        timestamp_raw = str(item.get("timestamp") or "")
        try:
            if timestamp_raw == context.event.timestamp:
                parsed = context.event_time
            else:
                event_ts = timestamp_raw.replace("Z", "+00:00")
                parsed = datetime.fromisoformat(event_ts)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
        except Exception:
            parsed = context.event_time
        if reference_time - parsed.timestamp() > aggregation.within_seconds:
            continue
        if aggregation.group_by:
            if str(_resolve_field(aggregation.group_by, item) or "") != str(group_value or ""):
                continue
        candidates.append(item)

    if aggregation.distinct_field:
        distinct_values = {
            json.dumps(
                _resolve_field(aggregation.distinct_field, item) or "",
                sort_keys=True,
                default=str,
            )
            for item in candidates
        }
        return len(distinct_values) >= aggregation.count
    return len(candidates) >= aggregation.count
