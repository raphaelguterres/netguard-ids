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

from . import templates_html  # provides the embedded HTML template

logger = logging.getLogger("netguard.dashboard.soc")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _hours_ago_iso(hours: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat().replace("+00:00", "Z")


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
        sev_counts = repo.alert_counts_by_severity(since_iso=since)
        top_tech = repo.top_mitre_techniques(since_iso=since, limit=10)

        # Mini timeline: alert counts per hour (last 24h)
        alerts = repo.list_alerts(since_iso=since, limit=2000)
        timeline = _bucket_per_hour(alerts)

        return jsonify({
            "ok": True,
            "as_of": _now_iso(),
            "summary": {
                "host_count": len(hosts),
                "alert_count_24h": sum(sev_counts.values()),
                "critical_24h": sev_counts.get("critical", 0),
                "high_24h": sev_counts.get("high", 0),
                "avg_risk": _avg([h.risk_score for h in hosts]),
                "max_risk": max([h.risk_score for h in hosts], default=0),
            },
            "severity_counts": sev_counts,
            "top_techniques": [
                {"technique": t, "count": c} for t, c in top_tech
            ],
            "hosts": sorted(
                [h.to_dict() for h in hosts],
                key=lambda x: x["risk_score"], reverse=True,
            ),
            "timeline_24h": timeline,
        })

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
            "host": host.to_dict(),
            "alerts": [a.to_dict() for a in recent_alerts],
            "events": [e.to_dict() for e in recent_events],
        })

    return bp


# ── helpers ──────────────────────────────────────────────────────────


def _avg(xs: list[int]) -> float:
    if not xs:
        return 0.0
    return round(sum(xs) / len(xs), 1)


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
