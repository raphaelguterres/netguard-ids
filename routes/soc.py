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
    get_action_repository: Callable[[], Any],
    get_host_registry: Callable[[str | None], Any],
    get_playbook_engine: Callable[[], Any],
    playbook_available: bool,
    current_request_tenant_id: Callable[[], str],
    logger: Any,
):
    bp = Blueprint("soc_views", __name__)
    safe_action_types = {"ping", "collect_diagnostics", "flush_buffer"}

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
                    "host_id": host_id,
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
                "host_response_actions": [],
                "host_response_action_stats": {"pending": 0, "leased": 0, "terminal": 0},
                "safe_response_actions": sorted(safe_action_types),
                "host_metadata": [
                    ("Tenant", base_context["tenant_name"]),
                    ("Operating System", "Unknown"),
                    ("Status", "Offline"),
                    ("Sensor", "NetGuard Agent / XDR Pipeline"),
                ],
            }
        return render_template("soc/host_detail.html", **context)

    @bp.route("/soc/hosts/<host_id>/actions", methods=["POST"])
    @bp.route("/soc-preview/hosts/<host_id>/actions", methods=["POST"])
    @require_session_decorator
    @require_role_decorator("analyst", "admin")
    @csrf_protect_decorator
    def soc_queue_host_action(host_id):
        payload = request.get_json(silent=True) if request.is_json else (request.form or {})
        action_type = str((payload or {}).get("action_type") or "").strip().lower()
        reason = str((payload or {}).get("reason") or "Queued from SOC host workspace").strip()
        if action_type not in safe_action_types:
            return jsonify({
                "ok": False,
                "error": "unsupported_action_type",
                "allowed": sorted(safe_action_types),
            }), 400

        tenant_id = current_request_tenant_id()
        host = get_host_registry(tenant_id).get_host(host_id, tenant_id=tenant_id)
        if not host:
            return jsonify({"ok": False, "error": "host_not_enrolled"}), 404

        action = get_action_repository().create_action(
            tenant_id=tenant_id,
            host_id=host_id,
            action_type=action_type,
            payload={},
            requested_by=f"soc:{tenant_id}",
            reason=reason[:500],
            ttl_seconds=3600,
            max_attempts=3,
        )
        logger.info(
            "SOC response action queued | tenant=%s | host=%s | action=%s | action_id=%s",
            tenant_id,
            host_id,
            action_type,
            action.get("action_id"),
        )
        return jsonify({"ok": True, "action": action}), 201

    @bp.route("/soc/hosts/<host_id>/actions/<action_id>/cancel", methods=["POST"])
    @bp.route("/soc-preview/hosts/<host_id>/actions/<action_id>/cancel", methods=["POST"])
    @require_session_decorator
    @require_role_decorator("analyst", "admin")
    @csrf_protect_decorator
    def soc_cancel_host_action(host_id, action_id):
        payload = request.get_json(silent=True) if request.is_json else (request.form or {})
        reason = str((payload or {}).get("reason") or "Cancelled from SOC host workspace").strip()
        tenant_id = current_request_tenant_id()
        repository = get_action_repository()
        action = repository.get_action(str(action_id or ""), tenant_id=tenant_id)
        if not action or str(action.get("host_id") or "") != str(host_id):
            return jsonify({"ok": False, "error": "action_not_found"}), 404
        if action.get("status") in {"succeeded", "failed", "refused", "expired", "cancelled"}:
            return jsonify({"ok": False, "error": "action_not_cancellable"}), 409

        cancelled = repository.cancel_action(
            tenant_id=tenant_id,
            action_id=str(action_id),
            result={"cancelled_by": f"soc:{tenant_id}", "reason": reason[:500]},
        )
        if not cancelled:
            return jsonify({"ok": False, "error": "action_not_cancellable"}), 409
        logger.info(
            "SOC response action cancelled | tenant=%s | host=%s | action_id=%s",
            tenant_id,
            host_id,
            action_id,
        )
        return jsonify({"ok": True, "action": cancelled})

    return bp
