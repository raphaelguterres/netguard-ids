from __future__ import annotations

from typing import Any, Callable

from flask import Blueprint, jsonify, request


def _sanitize_list(
    value: Any,
    sanitize_text: Callable[..., str],
    *,
    max_len: int,
    max_items: int,
) -> list[str]:
    if not isinstance(value, list):
        return []
    cleaned: list[str] = []
    seen: set[str] = set()
    for item in value:
        text = sanitize_text(str(item or ""), max_len=max_len)
        if not text or text in seen:
            continue
        cleaned.append(text)
        seen.add(text)
        if len(cleaned) >= max_items:
            break
    return cleaned


def build_incident_api_handlers(
    *,
    incident_available: bool,
    get_incidents: Callable[[], Any],
    get_tenant_event_repo: Callable[[], Any],
    sanitize_text: Callable[..., str],
    valid_status: set[str],
    valid_severity: set[str],
    safe_limit: Callable[..., int],
    audit_fn: Callable[..., None],
):
    def incidents_create():
        if not incident_available:
            return jsonify({"error": "Incident Engine indisponivel"}), 503
        data = request.get_json(force=True) or {}
        event_id = sanitize_text(str(data.get("event_id") or ""), max_len=128)
        event_ids = _sanitize_list(
            data.get("event_ids"),
            sanitize_text,
            max_len=128,
            max_items=50,
        )
        tenant_repo = get_tenant_event_repo()
        event_record = tenant_repo.get_event(event_id) if event_id else None
        if event_id and not event_record:
            return jsonify({"error": "Evento nao encontrado"}), 404
        if event_id and event_id not in event_ids:
            event_ids = [event_id, *event_ids]

        eng = get_incidents()
        for candidate_event_id in event_ids:
            existing = eng.find_open_incident_by_event_id(candidate_event_id)
            if not existing:
                continue
            comment = sanitize_text(str(data.get("comment") or ""), max_len=2000)
            if comment:
                existing = eng.add_note(
                    int(existing["id"]),
                    f"Duplicate create request grouped: {comment}",
                    actor="analyst",
                ) or existing
            audit_fn(
                "INCIDENT_DEDUPLICATED",
                ip=request.remote_addr or "-",
                detail=f"iid={existing.get('id')} event_id={candidate_event_id}",
            )
            return jsonify({
                "ok": True,
                "deduplicated": True,
                "incident": existing,
            })

        details = (event_record or {}).get("details") or {}
        if not isinstance(details, dict):
            details = {}
        title = sanitize_text(
            str(
                data.get("title")
                or (event_record or {}).get("rule_name")
                or (event_record or {}).get("event_type")
                or "Manual incident"
            ),
            max_len=240,
        )
        if not title:
            return jsonify({"error": "title obrigatorio"}), 400

        severity = sanitize_text(
            str(data.get("severity") or (event_record or {}).get("severity") or "medium"),
            max_len=16,
        ).lower()
        if severity not in valid_severity:
            return jsonify({"error": f"severity invalido: {severity}"}), 400

        incident = eng.open_incident(
            title=title,
            severity=severity,
            source=sanitize_text(
                str(data.get("source") or (event_record or {}).get("source") or "manual"),
                max_len=64,
            ),
            source_ip=sanitize_text(
                str(data.get("source_ip") or details.get("source_ip") or ""),
                max_len=128,
            ),
            host_id=sanitize_text(
                str(data.get("host_id") or (event_record or {}).get("host_id") or ""),
                max_len=128,
            ),
            summary=sanitize_text(
                str(data.get("summary") or details.get("summary") or details.get("description") or ""),
                max_len=2000,
            ),
            event_ids=event_ids,
            tags=_sanitize_list(
                data.get("tags"),
                sanitize_text,
                max_len=64,
                max_items=25,
            ),
            mitre_tactic=sanitize_text(
                str(data.get("mitre_tactic") or details.get("tactic") or ""),
                max_len=120,
            ),
            mitre_tech=sanitize_text(
                str(data.get("mitre_tech") or details.get("technique") or ""),
                max_len=120,
            ),
            actor="analyst",
            initial_comment=sanitize_text(str(data.get("comment") or ""), max_len=2000),
        )
        audit_fn(
            "INCIDENT_CREATED",
            ip=request.remote_addr or "-",
            detail=f"iid={incident.get('id')} host={incident.get('host_id','')}",
        )
        return jsonify({"ok": True, "incident": incident}), 201

    def incidents_list():
        if not incident_available:
            return jsonify({"error": "Incident Engine indisponível"}), 503
        status = request.args.get("status", "")
        severity = request.args.get("severity", "")
        host_id = sanitize_text(str(request.args.get("host_id") or ""), max_len=128)
        limit = safe_limit(request.args.get("limit", 50))

        if status and status not in valid_status:
            return jsonify({"error": f"status inválido: {status}"}), 400
        if severity and severity not in valid_severity:
            return jsonify({"error": f"severity inválido: {severity}"}), 400

        eng = get_incidents()
        return jsonify({
            "incidents": eng.list_incidents(
                status=status or None,
                severity=severity or None,
                host_id=host_id or None,
                limit=limit,
            ),
            "stats": eng.stats(),
        })

    def incidents_get(iid: int):
        if not incident_available:
            return jsonify({"error": "Incident Engine indisponível"}), 503
        if iid < 1:
            return jsonify({"error": "ID inválido"}), 400
        inc = get_incidents().get_incident(iid)
        if not inc:
            return jsonify({"error": "Incidente não encontrado"}), 404
        timeline = get_incidents().get_timeline(iid)
        return jsonify({"incident": inc, "timeline": timeline})

    def incidents_update_status(iid: int):
        if not incident_available:
            return jsonify({"error": "Incident Engine indisponível"}), 503
        if iid < 1:
            return jsonify({"error": "ID inválido"}), 400
        data = request.get_json(force=True) or {}
        status = sanitize_text(str(data.get("status", "")), max_len=30)
        note = sanitize_text(str(data.get("note", "")), max_len=2000)
        if status not in valid_status:
            return jsonify({"error": f"status inválido: {status}"}), 400
        try:
            inc = get_incidents().update_status(iid, status, actor="analyst", note=note)
            audit_fn("INCIDENT_STATUS", ip=request.remote_addr or "-", detail=f"iid={iid} status={status}")
            return jsonify({"ok": True, "incident": inc})
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    def incidents_update_severity(iid: int):
        if not incident_available:
            return jsonify({"error": "Incident Engine indisponivel"}), 503
        if iid < 1:
            return jsonify({"error": "ID invalido"}), 400
        data = request.get_json(force=True) or {}
        severity = sanitize_text(str(data.get("severity", "")), max_len=16).lower()
        note = sanitize_text(str(data.get("note", "")), max_len=2000)
        if severity not in valid_severity:
            return jsonify({"error": f"severity invalido: {severity}"}), 400
        try:
            inc = get_incidents().update_severity(iid, severity, actor="analyst", note=note)
            audit_fn("INCIDENT_SEVERITY", ip=request.remote_addr or "-", detail=f"iid={iid} severity={severity}")
            return jsonify({"ok": True, "incident": inc})
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    def incidents_add_note(iid: int):
        if not incident_available:
            return jsonify({"error": "Incident Engine indisponível"}), 503
        if iid < 1:
            return jsonify({"error": "ID inválido"}), 400
        data = request.get_json(force=True) or {}
        note = sanitize_text(str(data.get("note", "")), max_len=2000)
        if not note:
            return jsonify({"error": "Nota vazia"}), 400
        inc = get_incidents().add_note(iid, note, actor="analyst")
        return jsonify({"ok": True, "incident": inc})

    def incidents_add_comment(iid: int):
        return incidents_add_note(iid)

    def incidents_assign(iid: int):
        if not incident_available:
            return jsonify({"error": "Incident Engine indisponível"}), 503
        if iid < 1:
            return jsonify({"error": "ID inválido"}), 400
        data = request.get_json(force=True) or {}
        assignee = sanitize_text(str(data.get("assignee", "")), max_len=120)
        inc = get_incidents().assign(iid, assignee)
        audit_fn("INCIDENT_ASSIGN", ip=request.remote_addr or "-", detail=f"iid={iid} assignee={assignee}")
        return jsonify({"ok": True, "incident": inc})

    return {
        "create": incidents_create,
        "list": incidents_list,
        "get": incidents_get,
        "update_status": incidents_update_status,
        "update_severity": incidents_update_severity,
        "add_note": incidents_add_note,
        "add_comment": incidents_add_comment,
        "assign": incidents_assign,
    }


def create_incident_api_blueprint(
    *,
    auth_decorator: Callable[[Callable[..., Any]], Callable[..., Any]],
    require_session_decorator: Callable[[Callable[..., Any]], Callable[..., Any]],
    require_role_decorator: Callable[..., Callable[[Callable[..., Any]], Callable[..., Any]]],
    csrf_protect_decorator: Callable[[Callable[..., Any]], Callable[..., Any]],
    limiter_obj: Any,
    incident_available: bool,
    get_incidents: Callable[[], Any],
    get_tenant_event_repo: Callable[[], Any],
    sanitize_text: Callable[..., str],
    valid_status: set[str],
    valid_severity: set[str],
    safe_limit: Callable[..., int],
    audit_fn: Callable[..., None],
):
    handlers = build_incident_api_handlers(
        incident_available=incident_available,
        get_incidents=get_incidents,
        get_tenant_event_repo=get_tenant_event_repo,
        sanitize_text=sanitize_text,
        valid_status=valid_status,
        valid_severity=valid_severity,
        safe_limit=safe_limit,
        audit_fn=audit_fn,
    )
    bp = Blueprint("incident_api", __name__)
    bp.add_url_rule(
        "/api/incidents",
        view_func=auth_decorator(
            require_session_decorator(
                require_role_decorator("analyst", "admin")(
                    csrf_protect_decorator(handlers["create"])
                )
            )
        ),
        methods=["POST"],
    )
    bp.add_url_rule(
        "/api/incidents",
        view_func=auth_decorator(
            require_session_decorator(
                require_role_decorator("analyst", "admin")(handlers["list"])
            )
        ),
        methods=["GET"],
        endpoint="incidents_list",
    )
    bp.add_url_rule(
        "/api/incidents/<int:iid>",
        view_func=auth_decorator(
            require_session_decorator(
                require_role_decorator("analyst", "admin")(handlers["get"])
            )
        ),
        methods=["GET"],
        endpoint="incidents_get",
    )
    bp.add_url_rule(
        "/api/incidents/<int:iid>/status",
        view_func=auth_decorator(
            require_session_decorator(
                require_role_decorator("analyst", "admin")(
                    csrf_protect_decorator(handlers["update_status"])
                )
            )
        ),
        methods=["PATCH"],
        endpoint="incidents_update_status",
    )
    bp.add_url_rule(
        "/api/incidents/<int:iid>/severity",
        view_func=auth_decorator(
            require_session_decorator(
                require_role_decorator("analyst", "admin")(
                    csrf_protect_decorator(handlers["update_severity"])
                )
            )
        ),
        methods=["PATCH"],
        endpoint="incidents_update_severity",
    )
    note_view = auth_decorator(
        require_session_decorator(
            require_role_decorator("analyst", "admin")(
                csrf_protect_decorator(
                    limiter_obj.limit("30 per minute")(handlers["add_note"])
                )
            )
        )
    )
    comment_view = auth_decorator(
        require_session_decorator(
            require_role_decorator("analyst", "admin")(
                csrf_protect_decorator(
                    limiter_obj.limit("30 per minute")(handlers["add_comment"])
                )
            )
        )
    )
    bp.add_url_rule(
        "/api/incidents/<int:iid>/note",
        view_func=note_view,
        methods=["POST"],
        endpoint="incidents_add_note",
    )
    bp.add_url_rule(
        "/api/incidents/<int:iid>/comments",
        view_func=comment_view,
        methods=["POST"],
        endpoint="incidents_add_comment",
    )
    bp.add_url_rule(
        "/api/incidents/<int:iid>/assign",
        view_func=auth_decorator(
            require_session_decorator(
                require_role_decorator("analyst", "admin")(
                    csrf_protect_decorator(handlers["assign"])
                )
            )
        ),
        methods=["POST"],
        endpoint="incidents_assign",
    )
    return bp
