from __future__ import annotations

from typing import Any, Callable

from flask import Blueprint, jsonify, render_template, request


def create_soc_blueprint(
    *,
    require_session_decorator: Callable[[Callable[..., Any]], Callable[..., Any]],
    require_role_decorator: Callable[..., Callable[[Callable[..., Any]], Callable[..., Any]]],
    csrf_protect_decorator: Callable[[Callable[..., Any]], Callable[..., Any]],
    build_soc_preview_context: Callable[..., dict],
    build_soc_incidents_context: Callable[..., dict],
    build_soc_host_detail_context: Callable[..., dict | None],
    get_playbook_engine: Callable[[], Any],
    playbook_available: bool,
    current_request_tenant_id: Callable[[], str],
    logger: Any,
):
    bp = Blueprint("soc_views", __name__)

    @bp.route("/soc")
    @bp.route("/soc-preview")
    @require_session_decorator
    def soc_preview_overview():
        return render_template("soc/overview.html", **build_soc_preview_context())

    @bp.route("/soc/hosts")
    @bp.route("/soc-preview/hosts")
    @require_session_decorator
    def soc_preview_hosts():
        return render_template("soc/hosts.html", **build_soc_preview_context())

    @bp.route("/soc/alerts")
    @bp.route("/soc-preview/alerts")
    @require_session_decorator
    def soc_preview_alerts():
        return render_template("soc/alerts.html", **build_soc_preview_context())

    @bp.route("/soc/incidents")
    @bp.route("/soc-preview/incidents")
    @require_session_decorator
    def soc_preview_incidents():
        return render_template("soc/incidents.html", **build_soc_incidents_context())

    @bp.route("/soc/incidents/<incident_id>/status", methods=["POST"])
    @bp.route("/soc-preview/incidents/<incident_id>/status", methods=["POST"])
    @require_session_decorator
    @require_role_decorator("analyst", "admin")
    @csrf_protect_decorator
    def soc_incident_status_update(incident_id):
        if not playbook_available:
            return jsonify({"ok": False, "error": "playbook_engine_unavailable"}), 503

        payload = request.get_json(silent=True) if request.is_json else (request.form or {})
        status = str((payload or {}).get("status") or "").strip().lower()
        note = str((payload or {}).get("notes") or "").strip()
        if status not in {"open", "in_progress", "contained", "resolved", "false_positive"}:
            return jsonify({"ok": False, "error": "invalid_status"}), 400

        engine = get_playbook_engine()
        if not engine.get_incident(incident_id):
            return jsonify({"ok": False, "error": "incident_not_found"}), 404

        ok = engine.update_incident_status(incident_id, status, notes=note)
        if not ok:
            return jsonify({"ok": False, "error": "incident_not_found"}), 404

        incident = engine.get_incident(incident_id)
        logger.info(
            "SOC incident status updated | incident=%s | status=%s | tenant=%s",
            incident_id,
            status,
            current_request_tenant_id(),
        )
        return jsonify({"ok": True, "incident": incident})

    @bp.route("/soc/hosts/<host_id>")
    @bp.route("/soc-preview/hosts/<host_id>")
    @require_session_decorator
    def soc_preview_host_detail(host_id):
        base_context = build_soc_preview_context()
        context = build_soc_host_detail_context(host_id, context=base_context)
        if not context:
            context = {
                **base_context,
                "selected_host": {
                    "host_name": host_id,
                    "risk_score": 0,
                    "risk_level": "low",
                    "highest_severity": "low",
                    "last_seen": "unknown",
                    "active_alerts": 0,
                    "operating_system": "Unknown",
                    "status": "offline",
                },
                "host_alerts": [],
                "host_events": [],
                "host_incidents": [],
                "host_lineage": [],
                "host_metadata": [
                    ("Tenant", base_context["tenant_name"]),
                    ("Operating System", "Unknown"),
                    ("Status", "Offline"),
                    ("Sensor", "NetGuard Agent / XDR Pipeline"),
                ],
            }
        return render_template("soc/host_detail.html", **context)

    return bp
