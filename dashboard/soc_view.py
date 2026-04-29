"""
SOC dashboard view (CrowdStrike / Splunk-style dark UI).

This is a self-contained Flask blueprint that pulls data straight from
the storage `Repository` — it does not depend on the legacy app.py
HTTP API. Mount it next to the existing dashboard:

    from dashboard.soc_view import build_soc_blueprint
    app.register_blueprint(build_soc_blueprint(repo, key="dev_view_token"))

Routes:

    GET  /soc                  HTML dashboard page
    GET  /soc/api/overview     JSON: summary, counts, top techniques, hosts
    GET  /soc/api/rules        JSON: detection rule catalog and YAML health
    GET  /soc/api/host/<id>    JSON: host detail + recent alerts/events

`?token=` query param OR `X-Soc-View-Token` header is required if a
token is configured. The dashboard itself authenticates the human
operator via the existing dashboard login.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from storage.repository import Repository
from xdr.rule_catalog import build_detection_rule_catalog

from . import templates_html  # provides the embedded HTML template

logger = logging.getLogger("netguard.dashboard.soc")

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _hours_ago_iso(hours: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat().replace("+00:00", "Z")


def agent_liveness_from_last_seen(
    last_seen: str,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Classify endpoint liveness from heartbeat/ingest freshness."""

    observed = _parse_iso(last_seen)
    if observed is None:
        return {
            "agent_status": "offline",
            "last_seen_age_seconds": None,
            "last_seen_age_label": "never seen",
        }

    reference = now or datetime.now(timezone.utc)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)
    age_seconds = max(0, int((reference - observed).total_seconds()))
    if age_seconds <= 300:
        status = "online"
    elif age_seconds <= 1800:
        status = "stale"
    else:
        status = "offline"
    return {
        "agent_status": status,
        "last_seen_age_seconds": age_seconds,
        "last_seen_age_label": _age_label(age_seconds),
    }


def build_soc_blueprint(
    repo: Repository,
    *,
    view_token: str | None = None,
    url_prefix: str = "/soc",
    require_session_decorator=None,
    require_role_decorator=None,
) -> Any:
    from flask import Blueprint, abort, jsonify, request, Response  # lazy

    bp = Blueprint("netguard_soc", __name__, url_prefix=url_prefix)
    expected_token = (view_token or os.environ.get("NETGUARD_SOC_VIEW_TOKEN") or "").strip()

    def _identity(view):
        return view

    def _protect(view):
        wrapped = (require_session_decorator or _identity)(view)
        if require_role_decorator is not None:
            wrapped = require_role_decorator("viewer", "analyst", "admin")(wrapped)
        return wrapped

    def _check_token():
        if not expected_token:
            return
        provided = (
            request.args.get("token")
            or request.headers.get("X-Soc-View-Token")
            or ""
        ).strip()
        if provided != expected_token:
            abort(403)

    @bp.route("", methods=["GET"])
    @bp.route("/", methods=["GET"])
    @_protect
    def index():
        _check_token()
        # Pass `?token=` through to the AJAX endpoints if set.
        return Response(
            templates_html.SOC_DASHBOARD_HTML.replace(
                "__VIEW_TOKEN__",
                request.args.get("token") or "",
            ),
            mimetype="text/html",
        )

    @bp.route("/api/overview", methods=["GET"])
    @_protect
    def api_overview():
        _check_token()
        since = _hours_ago_iso(24)
        hosts = repo.list_hosts(limit=200)
        host_rows = [_host_row(host) for host in hosts]
        status_counts = {
            "online": sum(1 for item in host_rows if item["agent_status"] == "online"),
            "stale": sum(1 for item in host_rows if item["agent_status"] == "stale"),
            "offline": sum(1 for item in host_rows if item["agent_status"] == "offline"),
        }
        sev_counts = _normalize_severity_counts(
            repo.alert_counts_by_severity(since_iso=since),
        )
        top_tech = repo.top_mitre_techniques(since_iso=since, limit=10)

        # Mini timeline: alert counts per hour (last 24h)
        alerts = repo.list_alerts(since_iso=since, limit=2000)
        timeline = _bucket_per_hour(alerts)
        recent_alerts = repo.list_alerts(limit=12)
        recent_events = repo.list_events(limit=12)

        return jsonify({
            "ok": True,
            "as_of": _now_iso(),
            "summary": {
                "host_count": len(hosts),
                "alert_count_24h": sum(sev_counts.values()),
                "critical_24h": sev_counts.get("critical", 0),
                "high_24h": sev_counts.get("high", 0),
                "online_hosts": status_counts["online"],
                "stale_hosts": status_counts["stale"],
                "offline_hosts": status_counts["offline"],
                "avg_risk": _avg([h.risk_score for h in hosts]),
                "max_risk": max([h.risk_score for h in hosts], default=0),
            },
            "agent_status_counts": status_counts,
            "severity_counts": sev_counts,
            "severity_distribution": _severity_distribution(sev_counts),
            "top_techniques": [
                {"technique": t, "count": c} for t, c in top_tech
            ],
            "hosts": sorted(
                host_rows,
                key=lambda x: x["risk_score"], reverse=True,
            ),
            "timeline_24h": timeline,
            "recent_alerts": [_alert_row(item) for item in recent_alerts],
            "recent_events": [_event_row(item) for item in recent_events],
        })

    @bp.route("/api/rules", methods=["GET"])
    @_protect
    def api_rules():
        _check_token()
        source_filter = str(request.args.get("source") or "").strip().lower()
        catalog = build_detection_rule_catalog()
        if source_filter in {"builtin", "yaml"}:
            catalog["rules"] = [
                item for item in catalog["rules"]
                if item.get("source") == source_filter
            ]
        catalog["summary"]["returned_rules"] = len(catalog["rules"])
        return jsonify({"ok": True, **catalog})

    @bp.route("/api/host/<host_id>", methods=["GET"])
    @_protect
    def api_host(host_id: str):
        _check_token()
        host = repo.get_host(host_id)
        if host is None:
            return jsonify({"ok": False, "error": "host_not_found"}), 404
        recent_alerts = repo.list_alerts(host_id=host_id, limit=100)
        recent_events = repo.list_events(host_id=host_id, limit=100)
        return jsonify({
            "ok": True,
            "host": _host_row(host),
            "alerts": [a.to_dict() for a in recent_alerts],
            "events": [e.to_dict() for e in recent_events],
        })

    return bp


# ── helpers ──────────────────────────────────────────────────────────


def _avg(xs: list[int]) -> float:
    if not xs:
        return 0.0
    return round(sum(xs) / len(xs), 1)


def _parse_iso(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _age_label(age_seconds: int) -> str:
    if age_seconds < 60:
        return f"{age_seconds}s ago"
    if age_seconds < 3600:
        return f"{age_seconds // 60}m ago"
    if age_seconds < 86400:
        return f"{age_seconds // 3600}h ago"
    return f"{age_seconds // 86400}d ago"


def _host_row(host) -> dict[str, Any]:
    row = host.to_dict()
    row.update(agent_liveness_from_last_seen(str(row.get("last_seen") or "")))
    return row


def _normalize_severity(value: Any) -> str:
    severity = str(value or "").strip().lower()
    return severity if severity in _SEVERITY_ORDER else "info"


def _normalize_severity_counts(counts: dict[str, int]) -> dict[str, int]:
    normalized = {severity: 0 for severity in _SEVERITY_ORDER}
    for severity, count in (counts or {}).items():
        normalized[_normalize_severity(severity)] += int(count or 0)
    return normalized


def _severity_distribution(counts: dict[str, int]) -> list[dict[str, Any]]:
    total = sum(int(count or 0) for count in counts.values())
    return [
        {
            "severity": severity,
            "count": int(counts.get(severity, 0) or 0),
            "percentage": round((int(counts.get(severity, 0) or 0) / total) * 100, 1) if total else 0.0,
        }
        for severity in _SEVERITY_ORDER
    ]


def _alert_row(alert) -> dict[str, Any]:
    row = alert.to_dict()
    row["severity"] = _normalize_severity(row.get("severity"))
    return row


def _event_row(event) -> dict[str, Any]:
    row = event.to_dict()
    row["severity"] = _normalize_severity(row.get("severity"))
    return row


def _bucket_per_hour(alerts) -> list[dict]:
    """
    Aggregate alert counts into 24 hourly buckets aligned to the current
    hour. Returns oldest → newest.
    """
    buckets: dict[str, int] = {}
    for a in alerts:
        ts = (a.timestamp or "")[:13]  # 'YYYY-MM-DDTHH'
        if ts:
            buckets[ts] = buckets.get(ts, 0) + 1

    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    out = []
    for h in range(23, -1, -1):
        t = now - timedelta(hours=h)
        key = t.isoformat()[:13]
        out.append({
            "hour": key + ":00Z",
            "count": buckets.get(key, 0),
        })
    return out
