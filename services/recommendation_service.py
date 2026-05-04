from __future__ import annotations

from typing import Any
from urllib.parse import quote


ACTIVE_INCIDENT_STATUSES = {"open", "in_progress", "investigating"}
SAFE_ROUTE_PREFIXES = ("/soc", "/soc-preview", "/admin/inbox")
FORBIDDEN_ROUTE_MARKERS = (
    "/api/",
    "/delete",
    "/reset",
    "/rotate",
    "/revoke",
    "/disable",
    "/actions",
    "/status",
)
SEVERITY_WEIGHT = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def _text(value: Any, default: str = "") -> str:
    value = "" if value is None else str(value)
    value = value.strip()
    return value or default


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_route(route: str, fallback: str = "/soc") -> str:
    normalized = _text(route, fallback)
    lowered = normalized.lower()
    if not normalized.startswith(SAFE_ROUTE_PREFIXES):
        return fallback
    if any(marker in lowered for marker in FORBIDDEN_ROUTE_MARKERS):
        return fallback
    return normalized


def _active_critical_incidents(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        item
        for item in incidents
        if _text(item.get("status"), "open").lower() in ACTIVE_INCIDENT_STATUSES
        and _text(item.get("severity"), "low").lower() == "critical"
    ]


def _critical_hosts(hosts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    critical = []
    for host in hosts:
        risk_score = _int(host.get("risk_score"))
        severity = _text(host.get("highest_severity") or host.get("risk_level"), "info").lower()
        if risk_score >= 80 or severity == "critical":
            critical.append(host)
    critical.sort(
        key=lambda item: (
            _int(item.get("risk_score")),
            SEVERITY_WEIGHT.get(_text(item.get("highest_severity"), "info").lower(), 0),
            _int(item.get("active_alerts")),
            _text(item.get("host_name") or item.get("host_id")),
        ),
        reverse=True,
    )
    return critical


def _offline_agents(hosts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        host
        for host in hosts
        if bool(host.get("agent_enrolled"))
        and _text(host.get("status"), "unknown").lower() in {"offline", "stale", "missing"}
    ]


def _host_route(host: dict[str, Any]) -> str:
    host_key = _text(host.get("host_name") or host.get("host_id"), "unknown-host")
    return _safe_route(f"/soc/hosts/{quote(host_key, safe='')}")


def get_recommended_route(context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the next safe read/investigation route for the SOC operator."""
    context = context or {}
    overview = context.get("overview") or {}
    hosts = list(context.get("hosts") or overview.get("host_risks") or [])
    incidents = list(context.get("incidents") or [])
    alerts = list(context.get("alerts") or overview.get("recent_detections") or [])
    events_24h = _int(overview.get("events_24h"))

    critical_incidents = _active_critical_incidents(incidents)
    if critical_incidents:
        return {
            "route": "/soc/incidents",
            "reason": f"{len(critical_incidents)} critical incident(s) are still open and need analyst review.",
            "priority": "critical",
            "label": "Review critical incidents",
            "auto_redirect": True,
        }

    risky_hosts = _critical_hosts(hosts)
    if risky_hosts:
        host = risky_hosts[0]
        host_name = _text(host.get("host_name") or host.get("host_id"), "Unknown host")
        risk_score = _int(host.get("risk_score"))
        return {
            "route": _host_route(host),
            "reason": f"{host_name} is the highest-risk host at {risk_score}/100.",
            "priority": "high",
            "label": "Investigate critical host",
            "auto_redirect": True,
        }

    offline = _offline_agents(hosts)
    if offline:
        return {
            "route": "/soc/hosts",
            "reason": f"{len(offline)} enrolled agent(s) have no recent heartbeat.",
            "priority": "medium",
            "label": "Review agent health",
            "auto_redirect": False,
        }

    if not hosts or events_24h <= 0:
        return {
            "route": "/soc/hosts",
            "reason": "Waiting for endpoint telemetry. Connect an agent to start monitoring.",
            "priority": "info",
            "label": "Connect an agent",
            "auto_redirect": False,
        }

    if alerts:
        return {
            "route": "/admin/inbox",
            "reason": f"{len(alerts)} recent signal(s) are ready for risk-first triage.",
            "priority": "medium",
            "label": "Open operator inbox",
            "auto_redirect": False,
        }

    return {
        "route": "/soc",
        "reason": "No critical activity detected. Continue monitoring posture and recent telemetry.",
        "priority": "low",
        "label": "Review overview",
        "auto_redirect": False,
    }
