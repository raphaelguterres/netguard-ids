"""
NetGuard — Event Engine
Orquestrador principal do pipeline de detecção.

Pipeline:
    raw_event
      → normalize_event
      → validate_event
      → enrich_event
      → run_rules
      → classify_severity
      → generate_alerts
      → persist_if_needed
      → return results
"""

import socket
import logging
import traceback  # noqa: F401
from datetime import datetime, timezone
from typing import Optional, Callable, Any
from dataclasses import dataclass, field  # noqa: F401

from engine.rule_executor import RuleRegistry, ExecutionResult, Alert
from engine.severity_classifier import classify_severity, is_high_priority
from engine.baseline_engine import BaselineEngine, get_default_baseline

logger = logging.getLogger("netguard.event_engine")

REQUIRED_FIELDS = {"event_type", "source", "details"}

SOURCE_ALIASES: dict = {
    "process":  "agent.process",
    "network":  "agent.network",
    "web":      "agent.web",
    "packet":   "agent.packet",
    "ids":      "agent.ids",
    "sigma":    "agent.sigma",
    "owasp":    "agent.owasp",
    "soc":      "agent.soc",
    "behavior": "agent.behavior",
}


@dataclass
class PipelineResult:
    event:          dict
    alerts:         list
    valid:          bool
    errors:         list
    rules_executed: int  = 0
    rules_failed:   int  = 0
    persisted:      bool = False

    @property
    def has_alerts(self) -> bool:
        return len(self.alerts) > 0

    @property
    def highest_severity(self) -> str:
        if not self.alerts:
            return "LOW"
        order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        return max(self.alerts, key=lambda a: order.get(a.get("severity","LOW"), 0)).get("severity","LOW")


# ── Step 1: Normalize ─────────────────────────────────────────────
def normalize_event(raw: dict) -> dict:
    event = dict(raw)

    # timestamp
    ts = event.get("timestamp")
    if not ts or not _is_valid_timestamp(ts):
        event["timestamp"] = datetime.now(timezone.utc).isoformat()
    elif isinstance(ts, datetime):
        event["timestamp"] = ts.isoformat()

    # host_id
    if not event.get("host_id"):
        event["host_id"] = socket.gethostname()

    # source
    src = str(event.get("source", "")).lower().strip()
    event["source"] = SOURCE_ALIASES.get(src, src or "agent.unknown")

    # details
    if not isinstance(event.get("details"), dict):
        raw_details = event.get("details")
        event["details"] = {"raw": str(raw_details)} if raw_details else {}

    # event_type
    if event.get("event_type"):
        event["event_type"] = (
            str(event["event_type"]).lower().strip()
            .replace(" ", "_").replace("-", "_")
        )

    # severity
    sev = event.get("severity")
    if sev and isinstance(sev, str):
        event["severity"] = sev.upper().strip()
    else:
        event["severity"] = None

    # tags
    if not isinstance(event.get("tags"), list):
        event["tags"] = []

    return event


# ── Step 2: Validate ──────────────────────────────────────────────
def validate_event(event: dict) -> tuple:
    errors = []

    for f in REQUIRED_FIELDS:
        if not event.get(f):
            errors.append(f"Campo obrigatório ausente: {f}")

    if event.get("details") is not None and not isinstance(event["details"], dict):
        errors.append("details deve ser um dict")

    if not event.get("event_type", "").strip():
        errors.append("event_type não pode ser vazio")

    if not event.get("source", "").strip():
        errors.append("source não pode ser vazio")

    sev = event.get("severity")
    if sev and sev not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        errors.append(f"severity inválida: {sev}")

    return len(errors) == 0, errors


# ── Step 3: Enrich ────────────────────────────────────────────────
def enrich_event(event: dict, baseline: Optional[BaselineEngine] = None, extra: Optional[dict] = None) -> dict:
    event = dict(event)

    # Classify severity if missing
    if not event.get("severity"):
        event["severity"] = classify_severity(
            event_type=event.get("event_type", ""),
            details=event.get("details"),
        )

    # Baseline flags
    if baseline:
        details = event.get("details", {})
        flags   = {}
        proc = details.get("process_name") or details.get("process")
        if proc:
            flags["is_new_process"] = not baseline.is_known_process(proc)
        ip = details.get("source_ip") or details.get("ip") or details.get("dst_ip")
        if ip:
            flags["is_new_ip"] = not baseline.is_known_ip(ip)
        port = details.get("port")
        if port:
            flags["is_new_port"] = not baseline.is_known_port(port)
        if flags:
            event["details"] = {**details, **flags}

    # Auto tags
    auto_tags = _infer_tags(event.get("event_type", ""))
    existing  = set(event.get("tags", []))
    event["tags"] = list(existing | auto_tags)

    if extra and isinstance(extra, dict):
        event.update(extra)

    return event


# ── Step 4: Run rules ─────────────────────────────────────────────
def run_rules(event: dict, registry: RuleRegistry, tags: Optional[list] = None) -> ExecutionResult:
    return registry.execute(event, tags=tags)


# ── Step 5: Classify alert severities ────────────────────────────
def classify_alert_severities(alerts: list, event: dict) -> list:
    valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    for alert in alerts:
        if not alert.severity or alert.severity not in valid:
            alert.severity = classify_severity(
                event_type=alert.event_type or event.get("event_type", ""),
                rule_name=alert.rule_name,
                details=alert.details,
                current=alert.severity,
            )
    return alerts


# ── Step 6: Generate alerts ───────────────────────────────────────
def generate_alerts(alerts: list, event: dict) -> list:
    result = []
    for alert in alerts:
        d = alert.to_dict()
        if not d.get("host_id"):
            d["host_id"] = event.get("host_id", "")
        if not d.get("timestamp"):
            d["timestamp"] = event.get("timestamp", datetime.now(timezone.utc).isoformat())
        result.append(d)
    return result


# ── Step 7: Persist ───────────────────────────────────────────────
def persist_if_needed(event: dict, alerts: list, store: Optional[Any] = None) -> bool:
    if not store:
        return False
    try:
        if hasattr(store, "save"):
            store.save(event)
        if hasattr(store, "save_alerts"):
            store.save_alerts(alerts)
        return True
    except Exception as e:
        logger.error("Persist error: %s", e)
        return False


# ── Main orchestrator ─────────────────────────────────────────────
class EventEngine:
    """
    Orquestrador principal do pipeline de detecção NetGuard.

    Uso:
        engine = EventEngine()
        engine.registry.register(rule_unknown_process)
        result = engine.process(raw_event)
        for alert in result.alerts:
            print(alert["severity"], alert["rule_name"])
    """

    def __init__(
        self,
        host_id:        str      = "",
        baseline:       Optional[BaselineEngine] = None,
        store:          Optional[Any] = None,
        alert_callback: Optional[Callable] = None,
    ):
        self.host_id  = host_id or socket.gethostname()
        self.baseline = baseline or get_default_baseline(self.host_id)
        self.store    = store
        self.callback = alert_callback
        self.registry = RuleRegistry()

        self._processed    = 0
        self._total_alerts = 0
        self._total_errors = 0

        logger.info("EventEngine iniciado | host=%s", self.host_id)

    def process(
        self,
        raw_event:    dict,
        enrich_extra: Optional[dict] = None,
        rule_tags:    Optional[list] = None,
        skip_persist: bool = False,
    ) -> PipelineResult:
        self._processed += 1
        pipeline_errors: list = []

        try:
            event = normalize_event(raw_event)

            valid, val_errors = validate_event(event)
            if not valid:
                pipeline_errors.extend(val_errors)

            event = enrich_event(event=event, baseline=self.baseline, extra=enrich_extra)

            exec_result = run_rules(event, self.registry, tags=rule_tags)

            classified  = classify_alert_severities(exec_result.alerts, event)
            alert_dicts = generate_alerts(classified, event)

            persisted = False
            if not skip_persist:
                persisted = persist_if_needed(event, alert_dicts, self.store)

            for alert in alert_dicts:
                if is_high_priority(alert.get("severity", "LOW")):
                    self._fire_callback(alert)

            self._total_alerts += len(alert_dicts)
            if exec_result.rules_failed:
                self._total_errors += exec_result.rules_failed

            return PipelineResult(
                event          = event,
                alerts         = alert_dicts,
                valid          = valid,
                errors         = pipeline_errors + [e["error"] for e in exec_result.errors],
                rules_executed = exec_result.rules_executed,
                rules_failed   = exec_result.rules_failed,
                persisted      = persisted,
            )

        except Exception as exc:
            logger.error("Pipeline error: %s", exc)
            self._total_errors += 1
            return PipelineResult(
                event=raw_event, alerts=[], valid=False, errors=[str(exc)]
            )

    def process_batch(self, events: list, **kwargs) -> list:
        return [self.process(e, **kwargs) for e in events]

    def stats(self) -> dict:
        return {
            "processed":      self._processed,
            "total_alerts":   self._total_alerts,
            "total_errors":   self._total_errors,
            "rules_active":   self.registry.active_count,
            "rules_total":    self.registry.count,
            "baseline_sizes": self.baseline.get_baseline_size(),
            "host_id":        self.host_id,
        }

    def _fire_callback(self, alert: dict) -> None:
        if self.callback:
            try:
                self.callback(alert)
            except Exception as e:
                logger.error("Alert callback error: %s", e)


# ── Helpers ───────────────────────────────────────────────────────
def _is_valid_timestamp(ts) -> bool:
    if not isinstance(ts, str):
        return False
    try:
        datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return True
    except (ValueError, AttributeError):
        return False


def _infer_tags(event_type: str) -> set:
    et = event_type.lower()
    tags = set()
    if "process"  in et:                          tags.add("process")
    if any(k in et for k in ("network","conn","ip","port","scan")): tags.add("network")
    if any(k in et for k in ("web","sqli","xss","ua")):             tags.add("web")
    if any(k in et for k in ("behavior","deviation")):              tags.add("behavior")
    if any(k in et for k in ("cpu","mem")):                         tags.add("performance")
    return tags
