"""
Ingestion pipeline: validates an agent payload, normalises it into
canonical `Event` objects, persists, runs detection + correlation +
risk, and returns the alerts to the agent.

Design notes:

- The pipeline is deliberately *synchronous*. For very high throughput
  swap `IngestionPipeline.process()` for an async/worker variant; the
  agent doesn't care because it gets back the same envelope.

- The agent envelope can come in two shapes:

  1. **Spec shape** (the "/api/events" canonical schema):
        {
          "host_id": "...", "hostname": "...", "agent_version": "...",
          "events": [ { event schema fields ... }, ... ]
        }

  2. **Legacy shape** (what /api/agent/events already accepts):
        {
          "host_id": "...", "display_name": "...", "platform": "...",
          "agent_version": "...", "metadata": {...},
          "events": [ { collector schema ... }, ... ]
        }

  `_normalize_event()` handles both — fields are translated by name
  and `raw` carries everything through.

- Events with missing `event_id` get a deterministic UUID5 derived from
  (host_id, timestamp, event_type, command_line/dst_ip) so retries are
  idempotent at the storage layer.

- A "batch_too_large" cap (500) mirrors the existing app.py contract.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from engine.detection_engine import DetectionEngine
from engine.soc_correlator import SocCorrelator
from engine.soc_risk_scorer import score_alerts
from storage.repository import Alert, Event, Host, Repository

logger = logging.getLogger("netguard.server.ingestion")

MAX_EVENTS_PER_BATCH = 500


# ── Errors ────────────────────────────────────────────────────────────


class IngestionError(Exception):
    """Base class for ingestion-time client errors (HTTP 400-class)."""
    code = "ingestion_error"
    status = 400


class ValidationError(IngestionError):
    code = "schema_invalid"


class PayloadTooLarge(IngestionError):
    code = "batch_too_large"
    status = 413


# ── Result ────────────────────────────────────────────────────────────


@dataclass
class IngestionResult:
    host_id: str
    accepted_events: int
    new_events: int
    alerts: list[Alert] = field(default_factory=list)
    correlation_alerts: list[Alert] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "LOW"

    def to_dict(self) -> dict:
        return {
            "ok": True,
            "host_id": self.host_id,
            "accepted_events": self.accepted_events,
            "new_events": self.new_events,
            "alerts": [a.to_dict() for a in self.alerts],
            "correlation_alerts": [a.to_dict() for a in self.correlation_alerts],
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
        }


# ── Pipeline ──────────────────────────────────────────────────────────


class IngestionPipeline:
    def __init__(
        self,
        repo: Repository,
        *,
        detection: DetectionEngine | None = None,
        correlator: SocCorrelator | None = None,
        correlate_lookback_s: int = 300,
    ):
        self.repo = repo
        self.detection = detection or DetectionEngine()
        self.correlator = correlator or SocCorrelator()
        self.correlate_lookback_s = int(correlate_lookback_s)

    def process(self, payload: dict) -> IngestionResult:
        host_id, hostname, platform_, agent_version, raw_events = self._unpack(payload)

        # 1. normalise
        events = [self._normalize_event(host_id, e) for e in raw_events]

        # 2. persist
        new_count = 0
        for ev in events:
            if self.repo.insert_event(ev):
                new_count += 1

        # 3. detection
        alerts = self.detection.evaluate(events)

        # 4. persist alerts (idempotent on alert_id)
        for a in alerts:
            self.repo.insert_alert(a)

        # 5. correlation across alerts in the look-back window for this host
        since_iso = self._lookback_iso()
        host_alerts_window = self.repo.list_alerts(
            host_id=host_id, since_iso=since_iso, limit=500,
        )
        # Include the just-detected ones (might not have been queried yet).
        merged = {a.alert_id: a for a in host_alerts_window}
        for a in alerts:
            merged.setdefault(a.alert_id, a)
        corr_alerts = self.correlator.correlate(list(merged.values()))
        for a in corr_alerts:
            self.repo.insert_alert(a)

        # 6. risk scoring (over the same window for this host)
        all_alerts = list(merged.values()) + corr_alerts
        score, level = score_alerts(all_alerts)
        self.repo.upsert_host(Host(
            host_id=host_id,
            hostname=hostname,
            platform=platform_,
            agent_version=agent_version,
            last_seen=self._now_iso(),
            first_seen=self._now_iso(),
            risk_score=score,
            risk_level=level,
        ))
        self.repo.update_host_risk(host_id, score, level)

        return IngestionResult(
            host_id=host_id,
            accepted_events=len(events),
            new_events=new_count,
            alerts=alerts,
            correlation_alerts=corr_alerts,
            risk_score=score,
            risk_level=level,
        )

    # ── helpers ──

    def _unpack(self, payload: Any) -> tuple[str, str, str, str, list[dict]]:
        if not isinstance(payload, dict):
            raise ValidationError("payload must be a JSON object")

        host_id = (payload.get("host_id") or "").strip()
        if not host_id:
            raise ValidationError("host_id is required")

        events = payload.get("events")
        if events is None:
            events = []
        if not isinstance(events, list):
            raise ValidationError("events must be a list")
        if len(events) > MAX_EVENTS_PER_BATCH:
            raise PayloadTooLarge(
                f"batch contains {len(events)} events (max {MAX_EVENTS_PER_BATCH})"
            )

        # Hostname can come from top-level or metadata or display_name.
        hostname = (
            payload.get("hostname")
            or payload.get("display_name")
            or (payload.get("metadata") or {}).get("hostname")
            or ""
        )
        platform_ = payload.get("platform") or (payload.get("metadata") or {}).get("platform_version") or ""
        agent_version = payload.get("agent_version") or ""
        return host_id, str(hostname), str(platform_), str(agent_version), events

    def _normalize_event(self, host_id: str, raw: Any) -> Event:
        if not isinstance(raw, dict):
            raise ValidationError("each event must be a JSON object")

        # Permissively read both schemas (spec + legacy collector).
        details = raw.get("details") or {}
        if not isinstance(details, dict):
            details = {}
        evidence = (
            raw.get("evidence")
            or details.get("evidence")
            or details.get("summary")
            or ""
        )

        event_id = raw.get("event_id") or self._derive_event_id(host_id, raw)
        timestamp = raw.get("timestamp") or self._now_iso()
        event_type = raw.get("event_type") or "process_execution"
        severity = (raw.get("severity") or "low").lower().strip() or "low"
        confidence = raw.get("confidence")
        if confidence is None:
            confidence = details.get("confidence")
        try:
            confidence = int(confidence) if confidence is not None else 0
        except (TypeError, ValueError):
            confidence = 0

        return Event(
            event_id=event_id,
            host_id=host_id,
            timestamp=str(timestamp),
            event_type=str(event_type),
            severity=severity,
            confidence=confidence,
            process_name=str(raw.get("process_name") or ""),
            pid=_safe_int(raw.get("pid")),
            ppid=_safe_int(raw.get("ppid")),
            command_line=str(raw.get("command_line") or ""),
            user=str(raw.get("user") or raw.get("username") or ""),
            src_ip=str(raw.get("src_ip") or details.get("src_ip") or ""),
            dst_ip=str(raw.get("dst_ip") or raw.get("network_dst_ip") or ""),
            dst_port=_safe_int(raw.get("dst_port") or raw.get("network_dst_port")),
            mitre_tactic=str(raw.get("mitre_tactic") or details.get("mitre_tactic") or ""),
            mitre_technique=str(raw.get("mitre_technique") or details.get("mitre_technique") or ""),
            evidence=str(evidence),
            raw=dict(raw),  # keep untouched copy for the dashboard
        )

    def _derive_event_id(self, host_id: str, raw: dict) -> str:
        """
        Deterministic UUID5 — same input → same id, so client retries
        after a timeout don't double-insert.
        """
        seed = "|".join([
            host_id,
            str(raw.get("timestamp") or ""),
            str(raw.get("event_type") or ""),
            str(raw.get("command_line") or "")[:256],
            str(raw.get("dst_ip") or "") + ":" + str(raw.get("dst_port") or ""),
        ])
        digest = hashlib.sha1(seed.encode("utf-8")).hexdigest()
        # Produce a UUID-shaped string from the SHA-1 digest.
        return str(uuid.UUID(digest[:32]))

    def _lookback_iso(self) -> str:
        from datetime import timedelta
        ts = datetime.now(timezone.utc) - timedelta(seconds=self.correlate_lookback_s)
        return ts.isoformat().replace("+00:00", "Z")

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_int(v: Any) -> int | None:
    if v is None or v == "":
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
