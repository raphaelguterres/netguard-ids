from __future__ import annotations

from typing import Any, Callable

from flask import Blueprint, jsonify, request


def create_agent_api_blueprint(
    *,
    auth_decorator: Callable[[Callable[..., Any]], Callable[..., Any]],
    agent_auth_context_cls,
    audit_fn: Callable[..., None],
    authenticate_agent_request: Callable[..., Any],
    ensure_agent_writer: Callable[[Any], None],
    get_agent_service: Callable[[], Any],
    sanitize_text: Callable[..., str],
    set_request_tenant_context: Callable[[str, str], None],
    agent_snapshot_summary: Callable[[dict], dict],
    normalize_agent_event_payload: Callable[[dict, str, str], dict],
    process_xdr_ingest_payload: Callable[[dict], dict],
    resolve_tenant_with_role: Callable[[], tuple[str, str]],
    detection_engine: Any,
    de_available: bool,
    ml_available: bool,
    ml_baseline: Any,
    risk_available: bool,
    risk_engine: Any,
    request_ctx: Any,
    logger: Any,
):
    bp = Blueprint("agent_api", __name__)

    @bp.route("/api/agent/register", methods=["POST"])
    def agent_register():
        """Registers a host and returns a one-time API key for the professional agent."""
        try:
            auth_ctx = authenticate_agent_request(
                allow_agent_key=False,
                require_management=True,
            )
            data = request.get_json(force=True) or {}
            host_id = sanitize_text(str(data.get("host_id") or ""), max_len=128)
            if not host_id:
                return jsonify({"error": "host_id obrigatorio"}), 400
            tenant_override = sanitize_text(str(data.get("tenant_id") or ""), max_len=128)
            host, api_key = get_agent_service().register_host(
                auth_ctx=auth_ctx,
                host_id=host_id,
                display_name=sanitize_text(str(data.get("display_name") or host_id), max_len=128),
                platform=sanitize_text(str(data.get("platform") or ""), max_len=64).lower(),
                agent_version=sanitize_text(str(data.get("agent_version") or ""), max_len=64),
                metadata=data.get("metadata") if isinstance(data.get("metadata"), dict) else {},
                tags=data.get("tags") if isinstance(data.get("tags"), list) else [],
                tenant_id=tenant_override or None,
            )
            set_request_tenant_context(str(host.get("tenant_id") or auth_ctx.tenant_id), "analyst")
            audit_fn(
                "AGENT_REGISTERED",
                actor=host_id,
                ip=request.remote_addr or "-",
                detail=f"tenant={host.get('tenant_id')} prefix={api_key[:16]}",
            )
            return jsonify({"ok": True, "host": host, "api_key": api_key}), 201
        except PermissionError as exc:
            if str(exc) == "unauthorized":
                return jsonify({"error": "Unauthorized"}), 401
            return jsonify({"error": "Permissao insuficiente"}), 403
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @bp.route("/api/agent/heartbeat", methods=["POST"])
    def agent_heartbeat():
        """Heartbeat endpoint protected by host API key or tenant/admin token."""
        try:
            auth_ctx = authenticate_agent_request()
            ensure_agent_writer(auth_ctx)
            data = request.get_json(force=True) or {}
            host_id = sanitize_text(str(data.get("host_id") or auth_ctx.host_id or ""), max_len=128)
            if not host_id:
                return jsonify({"error": "host_id obrigatorio"}), 400
            platform_name = sanitize_text(str(data.get("platform") or ""), max_len=64).lower()
            # F-AGENT-1 (T16): admin pode pinar tenant via body; tenant/agent ignoram.
            tenant_override = sanitize_text(str(data.get("tenant_id") or ""), max_len=128)
            host = get_agent_service().record_heartbeat(
                auth_ctx=auth_ctx,
                host_id=host_id,
                display_name=sanitize_text(str(data.get("display_name") or ""), max_len=128),
                platform=platform_name,
                agent_version=sanitize_text(str(data.get("agent_version") or ""), max_len=64),
                source_ip=request.remote_addr or "",
                metadata={
                    "snapshot_summary": agent_snapshot_summary(data),
                    **(data.get("metadata") if isinstance(data.get("metadata"), dict) else {}),
                },
                tenant_id=tenant_override or None,
            )
            set_request_tenant_context(str(host.get("tenant_id") or auth_ctx.tenant_id), "analyst")
            return jsonify({"ok": True, "host": host})
        except PermissionError as exc:
            if str(exc) == "unauthorized":
                return jsonify({"error": "Unauthorized"}), 401
            return jsonify({"error": "Permissao insuficiente"}), 403
        except Exception as exc:
            logger.error("Agent heartbeat error: %s", exc)
            return jsonify({"error": str(exc)}), 400

    @bp.route("/api/agent/events", methods=["POST"])
    def agent_events_ingest():
        """Structured endpoint events from the modular agent transport."""
        try:
            auth_ctx = authenticate_agent_request()
            ensure_agent_writer(auth_ctx)
            data = request.get_json(force=True) or {}
            host_id = sanitize_text(str(data.get("host_id") or auth_ctx.host_id or ""), max_len=128)
            if not host_id:
                return jsonify({"error": "host_id obrigatorio"}), 400
            platform_name = sanitize_text(str(data.get("platform") or ""), max_len=64).lower()
            # F-AGENT-1 (T16): admin pode pinar tenant via body; tenant/agent ignoram.
            tenant_override = sanitize_text(str(data.get("tenant_id") or ""), max_len=128)
            host = get_agent_service().record_heartbeat(
                auth_ctx=auth_ctx,
                host_id=host_id,
                display_name=sanitize_text(str(data.get("display_name") or ""), max_len=128),
                platform=platform_name,
                agent_version=sanitize_text(str(data.get("agent_version") or ""), max_len=64),
                source_ip=request.remote_addr or "",
                metadata={
                    "snapshot_summary": agent_snapshot_summary(data),
                    **(data.get("metadata") if isinstance(data.get("metadata"), dict) else {}),
                },
                mark_event=True,
                tenant_id=tenant_override or None,
            )
            set_request_tenant_context(str(host.get("tenant_id") or auth_ctx.tenant_id), "analyst")
            payload = normalize_agent_event_payload(data, host_id, platform_name)
            result = process_xdr_ingest_payload(payload)
            result["host"] = host
            return jsonify(result)
        except PermissionError as exc:
            if str(exc) == "unauthorized":
                return jsonify({"error": "Unauthorized"}), 401
            return jsonify({"error": "Permissao insuficiente"}), 403
        except ValueError as exc:
            if str(exc) == "batch_too_large":
                return jsonify({"error": "batch_too_large", "max_events": 500}), 400
            return jsonify({"error": "invalid_event", "detail": str(exc)}), 400
        except RuntimeError:
            return jsonify({
                "error": "xdr_ingest_failed",
                "request_id": getattr(request_ctx, "request_id", ""),
            }), 500
        except Exception as exc:
            logger.error("Agent events ingest error: %s", exc)
            return jsonify({"error": str(exc)}), 400

    @bp.route("/api/agent/push-legacy-shadow", methods=["POST"])
    @auth_decorator
    def agent_push_v2():
        """Compatibility path for legacy snapshot agents with host registry updates."""
        try:
            data = request.get_json(force=True) or {}
            host_id = data.get("host_id", "unknown")
            procs = data.get("processes", [])
            conns = data.get("connections", [])
            ports = data.get("ports", [])

            tenant_id, tenant_role = resolve_tenant_with_role()
            auth_ctx = agent_auth_context_cls(
                tenant_id=tenant_id,
                role=tenant_role,
                auth_type="admin" if tenant_role == "admin" else "tenant",
            )
            ensure_agent_writer(auth_ctx)
            host = get_agent_service().record_heartbeat(
                auth_ctx=auth_ctx,
                host_id=sanitize_text(str(host_id), max_len=128) or "unknown",
                display_name=sanitize_text(str(host_id), max_len=128) or "unknown",
                platform=sanitize_text(str(data.get("platform") or ""), max_len=64).lower(),
                agent_version=sanitize_text(str(data.get("agent_v") or ""), max_len=64),
                source_ip=request.remote_addr or "",
                metadata={"snapshot_summary": agent_snapshot_summary(data)},
            )

            if de_available and detection_engine:
                try:
                    events = detection_engine.analyze(
                        processes=procs,
                        ports=ports,
                        connections=conns,
                    )
                    if events and risk_available and risk_engine:
                        for item in events:
                            event_data = item.to_dict() if hasattr(item, "to_dict") else dict(item)
                            event_data["host_id"] = host_id
                            risk_engine.ingest_event(event_data)
                except Exception:
                    pass

            if ml_available and ml_baseline:
                try:
                    ml_baseline.add_sample(
                        {"processes": procs, "connections": conns, "ports": ports}
                    )
                except Exception:
                    pass

            return jsonify(
                {
                    "status": "ok",
                    "host_id": host_id,
                    "host": host,
                    "processes": len(procs),
                    "connections": len(conns),
                    "ports": len(ports),
                }
            )
        except PermissionError as exc:
            if str(exc) == "unauthorized":
                return jsonify({"error": "Unauthorized"}), 401
            return jsonify({"error": "Permissao insuficiente"}), 403
        except Exception as exc:
            logger.error("Legacy agent shadow ingest error: %s", exc)
            return jsonify({"error": str(exc)}), 400

    return bp

