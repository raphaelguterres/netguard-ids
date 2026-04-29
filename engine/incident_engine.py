"""NetGuard incident engine backed by a repository abstraction."""

from __future__ import annotations

import logging
import threading
from typing import Optional

from storage.incident_repository import IncidentRepository

logger = logging.getLogger("netguard.incident")

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class IncidentEngine:
    def __init__(self, db_path: str, tenant_id: str = "default"):
        self.db_path = db_path
        self.tenant_id = tenant_id
        self._lock = threading.Lock()
        self._repo = IncidentRepository(db_path=db_path, tenant_id=tenant_id)

    def open_incident(
        self,
        title: str,
        severity: str = "medium",
        source: str = "edr",
        source_ip: str = None,
        host_id: str = None,
        summary: str = "",
        event_ids: list | None = None,
        tags: list | None = None,
        mitre_tactic: str = None,
        mitre_tech: str = None,
        status: str = "open",
        assigned_to: str = None,
        actor: str = "system",
        initial_comment: str = "",
    ) -> dict:
        incident = self._repo.create_incident(
            title=title,
            severity=severity,
            status=status,
            source=source,
            source_ip=source_ip,
            host_id=host_id,
            summary=summary,
            event_ids=event_ids or [],
            tags=tags or [],
            assigned_to=assigned_to,
            mitre_tactic=mitre_tactic,
            mitre_tech=mitre_tech,
            actor=actor,
            detail=f"Incident created by {source}: {title}",
        )
        if initial_comment:
            incident = self.add_note(
                int(incident["id"]),
                initial_comment,
                actor=actor,
            )
        logger.warning(
            "INCIDENT OPENED | tenant=%s | id=%s | sev=%s | %s",
            self.tenant_id,
            incident.get("id"),
            severity,
            title,
        )
        return incident

    def update_status(
        self,
        iid: int,
        status: str,
        actor: str = "analyst",
        note: str = "",
    ) -> dict:
        allowed = {"open", "investigating", "contained", "resolved", "false_positive"}
        if status not in allowed:
            raise ValueError(f"Status invalido: {status}")
        return self._repo.update_status(
            iid,
            status=status,
            actor=actor,
            note=note,
        ) or {}

    def update_severity(
        self,
        iid: int,
        severity: str,
        actor: str = "analyst",
        note: str = "",
    ) -> dict:
        if severity not in SEV_ORDER:
            raise ValueError(f"Severidade invalida: {severity}")
        return self._repo.update_severity(
            iid,
            severity=severity,
            actor=actor,
            note=note,
        ) or {}

    def assign(self, iid: int, assignee: str, actor: str = "analyst") -> dict:
        return self._repo.assign(iid, assignee=assignee, actor=actor) or {}

    def add_note(self, iid: int, note: str, actor: str = "analyst") -> dict:
        return self._repo.add_comment(iid, comment=note, actor=actor) or {}

    def add_comment(self, iid: int, comment: str, actor: str = "analyst") -> dict:
        return self.add_note(iid, comment, actor=actor)

    def get_incident(self, iid: int) -> Optional[dict]:
        return self._repo.get_incident(iid)

    def list_incidents(
        self,
        status: str = None,
        severity: str = None,
        host_id: str = None,
        limit: int = 50,
    ) -> list:
        return self._repo.list_incidents(
            status=status,
            severity=severity,
            host_id=host_id,
            limit=limit,
        )

    def get_timeline(self, iid: int) -> list:
        return self._repo.get_timeline(iid)

    def stats(self) -> dict:
        return self._repo.stats()

    def find_open_incident_by_event_id(self, event_id: str) -> Optional[dict]:
        return self._repo.find_open_incident_by_event_id(event_id)

    def ingest_edr_alert(self, alert: dict) -> Optional[dict]:
        score = alert.get("score", 0)
        if score < 30:
            return None

        severity = (
            "critical"
            if score >= 75
            else "high"
            if score >= 55
            else "medium"
            if score >= 30
            else "low"
        )
        host = alert.get("host_id") or alert.get("hostname", "unknown")
        process_name = alert.get("process_name", "?")
        title = f"[EDR] Processo suspeito: {process_name} em {host}"
        findings = alert.get("findings", [])
        summary = "; ".join(
            item.get("reason", "")
            for item in findings
            if item.get("reason")
        )

        existing = self._repo.find_recent_open_incident(
            host_id=host,
            source="edr",
            within_minutes=30,
        )
        if existing:
            iid = int(existing["id"])
            self.add_note(
                iid,
                f"Novo alerta EDR agrupado: {process_name} (score={score})",
                actor="edr",
            )
            if SEV_ORDER.get(severity, 0) > SEV_ORDER.get(existing.get("severity"), 0):
                self.update_severity(
                    iid,
                    severity,
                    actor="edr",
                    note=f"Severity escalated after grouped alert score={score}",
                )
            return self.get_incident(iid)

        return self.open_incident(
            title=title,
            severity=severity,
            source="edr",
            source_ip=alert.get("source_ip"),
            host_id=host,
            summary=summary,
            tags=["edr", process_name],
            actor="edr",
        )


_engines: dict[str, IncidentEngine] = {}
_engines_lock = threading.Lock()


def get_incident_engine(db_path: str, tenant_id: str = "default") -> IncidentEngine:
    key = f"{db_path}::{tenant_id}"
    with _engines_lock:
        if key not in _engines:
            _engines[key] = IncidentEngine(db_path, tenant_id)
    return _engines[key]
