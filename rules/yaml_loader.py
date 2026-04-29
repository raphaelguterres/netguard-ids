"""Load and evaluate simple Sigma-like YAML rules."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from fnmatch import fnmatch
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
    "regex_any",
    "in",
    "not_equals",
    "not_contains",
    "exists",
    "startswith_any",
    "endswith_any",
    "gte",
    "lte",
    "gt",
    "lt",
}
_SEVERITY_ALIASES = {
    "informational": "low",
    "info": "low",
    "low": "low",
    "medium": "medium",
    "moderate": "medium",
    "high": "high",
    "critical": "critical",
    "crit": "critical",
}
_SIGMA_CONTROL_KEYS = {
    "aggregation",
    "all",
    "any",
    "condition",
    "event_types",
    "timeframe",
}
_SIGMA_FIELD_ALIASES = {
    "commandline": "command_line",
    "currentdirectory": "details.current_directory",
    "destinationhostname": "details.destination_hostname",
    "destinationip": "network_dst_ip",
    "destinationport": "network_dst_port",
    "eventid": "details.event_id",
    "image": "process_name",
    "imagename": "process_name",
    "integritylevel": "details.integrity_level",
    "logonsourceip": "auth_source_ip",
    "originalfilename": "details.original_file_name",
    "parentcommandline": "details.parent_command_line",
    "parentimage": "parent_process",
    "processcommandline": "command_line",
    "processid": "pid",
    "processname": "process_name",
    "sourceip": "auth_source_ip",
    "sourceport": "details.source_port",
    "targetusername": "username",
    "user": "username",
    "username": "username",
}
_LOGSOURCE_CATEGORY_EVENT_TYPES = {
    "authentication": ("authentication",),
    "auth": ("authentication",),
    "network_connection": ("network_connection",),
    "network": ("network_connection",),
    "process_creation": ("process_execution",),
    "process": ("process_execution",),
    "registry_event": ("persistence_indicator",),
    "script": ("script_execution",),
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
    metadata: dict[str, Any] = field(default_factory=dict)

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
        if self.metadata:
            details["metadata"] = dict(self.metadata)
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

    def evaluate(self, context: Any) -> list[DetectionRecord]:
        detections: list[DetectionRecord] = []
        for rule in self.rules:
            if rule.matches_current_event(context):
                detections.append(rule.build_detection(context))
        return detections


@dataclass(slots=True)
class YamlRuleLoadError:
    source_path: str
    error: str


@dataclass(slots=True)
class YamlRuleLoadReport:
    registry: YamlRuleRegistry
    total_files: int = 0
    loaded_files: int = 0
    skipped_files: int = 0
    errors: tuple[YamlRuleLoadError, ...] = ()


def load_yaml_rules(directory: str | Path | None = None) -> YamlRuleRegistry:
    return load_yaml_rule_report(directory).registry


def load_yaml_rule_report(directory: str | Path | None = None) -> YamlRuleLoadReport:
    rules_dir = Path(directory or DEFAULT_RULES_DIR)
    if not rules_dir.exists():
        return YamlRuleLoadReport(registry=YamlRuleRegistry())
    loaded_rules: list[YamlDetectionRule] = []
    errors: list[YamlRuleLoadError] = []
    rule_files = sorted(rules_dir.glob("*.y*ml"))
    for path in rule_files:
        display_path = _safe_source_path(path)
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            loaded_rules.append(_parse_rule(payload, source_path=display_path))
        except Exception as exc:
            logger.warning("Skipping invalid YAML rule %s: %s", path, exc)
            errors.append(YamlRuleLoadError(source_path=display_path, error=str(exc)))
    return YamlRuleLoadReport(
        registry=YamlRuleRegistry(rules=tuple(loaded_rules)),
        total_files=len(rule_files),
        loaded_files=len(loaded_rules),
        skipped_files=len(errors),
        errors=tuple(errors),
    )


def _safe_source_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve())).replace("\\", "/")
    except Exception:
        return path.name


def _parse_rule(payload: dict[str, Any], *, source_path: str) -> YamlDetectionRule:
    if not isinstance(payload, dict):
        raise YamlRuleValidationError(f"{source_path}: rule body must be an object")

    rule_id = str(payload.get("id") or "").strip()
    title = str(payload.get("title") or payload.get("name") or "").strip()
    description = str(payload.get("description") or "").strip()
    severity = _normalize_severity(payload.get("severity") or payload.get("level") or "medium")
    if not rule_id or not title:
        raise YamlRuleValidationError(f"{source_path}: id and title are required")

    detection = payload.get("detection") or {}
    if not isinstance(detection, dict):
        raise YamlRuleValidationError(f"{source_path}: detection must be an object")

    raw_event_types = payload.get("event_types") or detection.get("event_types")
    event_types = (
        tuple(
            str(item).strip().lower()
            for item in _as_list(raw_event_types)
            if str(item).strip()
        )
        if raw_event_types
        else _event_types_from_logsource(payload.get("logsource") or {})
    )

    sigma_all_conditions, sigma_any_conditions = _parse_sigma_detection(
        detection,
        source_path=source_path,
    )
    all_conditions = tuple(
        _parse_condition(item, source_path=source_path)
        for item in _as_list(detection.get("all"))
    ) + sigma_all_conditions
    any_conditions = tuple(
        _parse_condition(item, source_path=source_path)
        for item in _as_list(detection.get("any"))
    ) + sigma_any_conditions
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
        tags=tuple(str(item).strip().lower() for item in _as_list(payload.get("tags")) if str(item).strip()),
        recommended_action=str(payload.get("recommended_action") or "investigate").strip(),
        source_path=source_path,
        alert_type=str(payload.get("alert_type") or "").strip().lower(),
        metadata=_rule_metadata(payload),
    )


def _as_list(value: Any) -> list[Any]:
    if value in (None, ""):
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _normalize_severity(value: Any) -> str:
    raw = str(value or "medium").strip().lower().replace("-", "_").replace(" ", "_")
    return _SEVERITY_ALIASES.get(raw, "medium")


def _event_types_from_logsource(logsource: Any) -> tuple[str, ...]:
    if not isinstance(logsource, dict):
        return ()
    candidates = [
        str(logsource.get("category") or "").strip().lower(),
        str(logsource.get("service") or "").strip().lower(),
        str(logsource.get("product") or "").strip().lower(),
    ]
    event_types: list[str] = []
    for candidate in candidates:
        event_types.extend(_LOGSOURCE_CATEGORY_EVENT_TYPES.get(candidate, ()))
    return tuple(dict.fromkeys(event_types))


def _rule_metadata(payload: dict[str, Any]) -> dict[str, Any]:
    metadata = {
        "author": payload.get("author"),
        "status": payload.get("status"),
        "references": _as_list(payload.get("references")),
        "falsepositives": _as_list(payload.get("falsepositives")),
        "logsource": payload.get("logsource") if isinstance(payload.get("logsource"), dict) else {},
    }
    return {
        key: value
        for key, value in metadata.items()
        if value not in (None, "", [], {})
    }


def _parse_sigma_detection(
    detection: dict[str, Any],
    *,
    source_path: str,
) -> tuple[tuple[YamlRuleCondition, ...], tuple[YamlRuleCondition, ...]]:
    selections = {
        str(name).strip().lower(): body
        for name, body in detection.items()
        if str(name).strip().lower() not in _SIGMA_CONTROL_KEYS and isinstance(body, dict)
    }
    if not selections:
        return (), ()

    condition = str(detection.get("condition") or "").strip()
    if not condition and len(selections) == 1:
        condition = next(iter(selections))
    if not condition:
        return (), ()

    condition_lower = condition.lower().strip()
    if " not " in f" {condition_lower} ":
        raise YamlRuleValidationError(
            f"{source_path}: Sigma 'not' conditions are not supported by this loader",
        )

    if condition_lower.startswith("1 of "):
        refs = _selection_refs_from_pattern(condition_lower.removeprefix("1 of ").strip(), selections)
        return (), tuple(_flatten_any_selection_conditions(refs, selections, source_path=source_path))

    if condition_lower.startswith("all of "):
        refs = _selection_refs_from_pattern(condition_lower.removeprefix("all of ").strip(), selections)
        return tuple(_flatten_selection_conditions(refs, selections, source_path=source_path)), ()

    has_and = " and " in f" {condition_lower} "
    has_or = " or " in f" {condition_lower} "
    if has_and and has_or:
        raise YamlRuleValidationError(
            f"{source_path}: mixed Sigma and/or conditions are not supported",
        )

    refs = _selection_refs_from_expression(condition_lower, selections)
    if has_or:
        return (), tuple(_flatten_any_selection_conditions(refs, selections, source_path=source_path))
    return tuple(_flatten_selection_conditions(refs, selections, source_path=source_path)), ()


def _selection_refs_from_pattern(pattern: str, selections: dict[str, Any]) -> tuple[str, ...]:
    refs = [
        name
        for name in selections
        if fnmatch(name.lower(), pattern.lower())
    ]
    if not refs and pattern in selections:
        refs = [pattern]
    return tuple(dict.fromkeys(refs))


def _selection_refs_from_expression(expression: str, selections: dict[str, Any]) -> tuple[str, ...]:
    tokens = [
        token
        for token in re.split(r"[\s()]+", expression)
        if token and token not in {"and", "or"}
    ]
    refs: list[str] = []
    for token in tokens:
        if "*" in token:
            refs.extend(_selection_refs_from_pattern(token, selections))
        elif token in selections:
            refs.append(token)
        else:
            raise YamlRuleValidationError(f"unknown Sigma selection: {token}")
    return tuple(dict.fromkeys(refs))


def _flatten_selection_conditions(
    refs: tuple[str, ...],
    selections: dict[str, Any],
    *,
    source_path: str,
) -> list[YamlRuleCondition]:
    conditions: list[YamlRuleCondition] = []
    for ref in refs:
        selection = selections.get(ref)
        if not isinstance(selection, dict):
            raise YamlRuleValidationError(f"{source_path}: Sigma selection {ref} must be an object")
        conditions.extend(_conditions_from_sigma_selection(selection, source_path=source_path))
    return conditions


def _flatten_any_selection_conditions(
    refs: tuple[str, ...],
    selections: dict[str, Any],
    *,
    source_path: str,
) -> list[YamlRuleCondition]:
    conditions: list[YamlRuleCondition] = []
    for ref in refs:
        selection = selections.get(ref)
        if not isinstance(selection, dict):
            raise YamlRuleValidationError(f"{source_path}: Sigma selection {ref} must be an object")
        parsed = _conditions_from_sigma_selection(selection, source_path=source_path)
        if len(parsed) != 1:
            raise YamlRuleValidationError(
                f"{source_path}: Sigma OR/1-of selection {ref} must contain exactly one field",
            )
        conditions.extend(parsed)
    return conditions


def _conditions_from_sigma_selection(
    selection: dict[str, Any],
    *,
    source_path: str,
) -> list[YamlRuleCondition]:
    conditions: list[YamlRuleCondition] = []
    for raw_field, expected in selection.items():
        field, modifiers = _split_sigma_field(raw_field)
        if not field:
            raise YamlRuleValidationError(f"{source_path}: Sigma selection contains an empty field name")
        operator = _operator_from_sigma_modifiers(modifiers, expected)
        values = _as_list(expected)
        if "all" in modifiers and isinstance(expected, list):
            for value in values:
                conditions.append(YamlRuleCondition(field=field, operator=operator, value=value))
            continue
        if isinstance(expected, dict):
            raise YamlRuleValidationError(
                f"{source_path}: nested Sigma field values are not supported for {raw_field}",
            )
        conditions.append(
            YamlRuleCondition(
                field=field,
                operator=_operator_for_multi_value(operator, expected),
                value=expected,
            )
        )
    return conditions


def _split_sigma_field(raw_field: Any) -> tuple[str, set[str]]:
    parts = [str(part).strip() for part in str(raw_field).split("|") if str(part).strip()]
    if not parts:
        return "", set()
    alias_key = re.sub(r"[^a-z0-9]", "", parts[0].lower())
    field = _SIGMA_FIELD_ALIASES.get(alias_key, parts[0].strip())
    modifiers = {part.lower() for part in parts[1:]}
    return field, modifiers


def _operator_from_sigma_modifiers(modifiers: set[str], expected: Any) -> str:
    if "exists" in modifiers:
        return "exists"
    if "contains" in modifiers:
        return "contains"
    if "startswith" in modifiers:
        return "startswith"
    if "endswith" in modifiers:
        return "endswith"
    if "re" in modifiers or "regex" in modifiers:
        return "regex"
    return "in" if isinstance(expected, list) else "equals"


def _operator_for_multi_value(operator: str, expected: Any) -> str:
    if not isinstance(expected, list):
        return operator
    if operator == "contains":
        return "contains_any"
    if operator == "startswith":
        return "startswith_any"
    if operator == "endswith":
        return "endswith_any"
    if operator == "regex":
        return "regex_any"
    if operator == "equals":
        return "in"
    return operator


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
    if operator == "not_equals":
        return str(actual).lower() != str(expected).lower()
    if operator == "contains":
        return str(expected).lower() in str(actual or "").lower()
    if operator == "not_contains":
        return str(expected).lower() not in str(actual or "").lower()
    if operator == "contains_any":
        values = expected if isinstance(expected, list) else [expected]
        actual_text = str(actual or "").lower()
        return any(str(item).lower() in actual_text for item in values)
    if operator == "startswith":
        return str(actual or "").lower().startswith(str(expected).lower())
    if operator == "startswith_any":
        values = expected if isinstance(expected, list) else [expected]
        actual_text = str(actual or "").lower()
        return any(actual_text.startswith(str(item).lower()) for item in values)
    if operator == "endswith":
        return str(actual or "").lower().endswith(str(expected).lower())
    if operator == "endswith_any":
        values = expected if isinstance(expected, list) else [expected]
        actual_text = str(actual or "").lower()
        return any(actual_text.endswith(str(item).lower()) for item in values)
    if operator == "regex":
        try:
            return bool(re.search(str(expected), str(actual or ""), flags=re.IGNORECASE))
        except re.error:
            return False
    if operator == "regex_any":
        values = expected if isinstance(expected, list) else [expected]
        try:
            return any(
                re.search(str(item), str(actual or ""), flags=re.IGNORECASE)
                for item in values
            )
        except re.error:
            return False
    if operator == "in":
        values = [str(item).lower() for item in _as_list(expected)]
        return str(actual).lower() in values
    if operator == "exists":
        exists = actual not in (None, "", [], {})
        return exists if bool(expected) else not exists
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
