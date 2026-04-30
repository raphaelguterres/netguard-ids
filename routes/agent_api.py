from __future__ import annotations

import os
from typing import Any, Callable

from flask import Blueprint, jsonify, request

from server.response_policy import verify_response_policy


def create_agent_api_blueprint(
    *,
    auth_decorator: Callable[[Callable[..., Any]], Callable[..., Any]],
    agent_auth_context_cls,
    audit_fn: Callable[..., None],
    authenticate_agent_request: Callable[..., Any],
    ensure_agent_writer: Callable[[Any], None],
    get_action_repository: Callable[[], Any],
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
    safe_action_types = {"ping", "collect_diagnostics", "flush_buffer"}
    guarded_action_types = {"isolate_host", "kill_process", "block_ip", "delete_file"}
    valid_action_types = safe_action_types | guarded_action_types

    def _extract_enrollment_token(data: dict | None = None) -> str:
        explicit = (
            request.headers.get("X-NetGuard-Enrollment-Token", "").strip()
            or request.headers.get("X-Enrollment-Token", "").strip()
        )
        if explicit:
            return explicit
        auth_header = request.headers.get("Authorization", "").strip()
        if auth_header.lower().startswith("enrollment "):
            return auth_header[11:].strip()
        if isinstance(data, dict):
            return str(data.get("enrollment_token") or "").strip()
        return ""

    def _effective_action_tenant(auth_ctx, data: dict | None = None) -> str:
        data = data or {}
        tenant_override = sanitize_text(str(data.get("tenant_id") or ""), max_len=128)
        if auth_ctx.auth_type == "admin" and tenant_override:
            return tenant_override
        return str(auth_ctx.tenant_id or "default")

    def _verify_guarded_action_policy(
        auth_ctx,
        data: dict,
        *,
        tenant_id: str,
        host_id: str,
        action_type: str,
    ) -> str:
        if action_type not in guarded_action_types:
            return ""
        if auth_ctx.auth_type != "admin" and str(getattr(auth_ctx, "role", "")).lower() != "admin":
            return "destructive_action_requires_admin"
        ok, reason = verify_response_policy(
            os.environ.get("NETGUARD_RESPONSE_POLICY_SECRET", ""),
            tenant_id=tenant_id,
            host_id=host_id,
            action_type=action_type,
            nonce=data.get("policy_nonce"),
            expires_at=data.get("policy_expires_at"),
            signature=data.get("policy_signature"),
        )
        return "" if ok else reason

    @bp.route("/api/agent/register", methods=["POST"])
    def agent_register():
        """Registers a host and returns a one-time API key for the professional agent."""
        try:
            data = request.get_json(force=True) or {}
            enrollment_token = _extract_enrollment_token(data)
            if enrollment_token:
                auth_ctx = get_agent_service().verify_enrollment_token(enrollment_token)
                if not auth_ctx:
                    return jsonify({"error": "invalid_enrollment_token"}), 403
            else:
                auth_ctx = authenticate_agent_request(
                    allow_agent_key=False,
                    require_management=True,
                )
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

    @bp.route("/api/agent/enrollment-token", methods=["POST"])
    def agent_create_enrollment_token():
        """Creates a short-lived token for unattended host enrollment."""
        try:
            auth_ctx = authenticate_agent_request(
                allow_agent_key=False,
                require_management=True,
            )
            data = request.get_json(silent=True) or {}
            tenant_override = sanitize_text(str(data.get("tenant_id") or ""), max_len=128)
            record, token = get_agent_service().create_enrollment_token(
                auth_ctx=auth_ctx,
                tenant_id=tenant_override or None,
                expires_in_seconds=int(data.get("expires_in_seconds") or 3600),
                max_uses=int(data.get("max_uses") or 1),
            )
            set_request_tenant_context(str(record.get("tenant_id") or auth_ctx.tenant_id), "analyst")
            audit_fn(
                "AGENT_ENROLLMENT_TOKEN_CREATED",
                actor=str(record.get("created_by") or auth_ctx.auth_type),
                ip=request.remote_addr or "-",
                detail=(
                    f"tenant={record.get('tenant_id')} prefix={record.get('token_prefix')} "
                    f"max_uses={record.get('max_uses')}"
                ),
            )
            return jsonify({
                "ok": True,
                "token": token,
                "enrollment": record,
                "warning": "token exibido uma unica vez; armazene apenas em canal seguro",
            }), 201
        except PermissionError as exc:
            if str(exc) == "unauthorized":
                return jsonify({"error": "Unauthorized"}), 401
            return jsonify({"error": "Permissao insuficiente"}), 403
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @bp.route("/api/agent/enrollment-token/revoke", methods=["POST"])
    def agent_revoke_enrollment_token():
        """Revokes an unused enrollment token by its raw one-time value."""
        try:
            auth_ctx = authenticate_agent_request(
                allow_agent_key=False,
                require_management=True,
            )
            data = request.get_json(silent=True) or {}
            token = str(data.get("token") or "").strip()
            if not token:
                return jsonify({"error": "token obrigatorio"}), 400
            ok = get_agent_service().revoke_enrollment_token(auth_ctx=auth_ctx, token=token)
            if not ok:
                return jsonify({"error": "enrollment_token_nao_encontrado"}), 404
            audit_fn(
                "AGENT_ENROLLMENT_TOKEN_REVOKED",
                actor=auth_ctx.auth_type,
                ip=request.remote_addr or "-",
                detail=f"tenant={auth_ctx.tenant_id}",
            )
            return jsonify({"ok": True})
        except PermissionError as exc:
            if str(exc) == "unauthorized":
                return jsonify({"error": "Unauthorized"}), 401
            return jsonify({"error": "Permissao insuficiente"}), 403

    @bp.route("/api/agent/hosts/<path:host_id>/revoke", methods=["POST"])
    def agent_revoke_host_key(host_id: str):
        """Revokes a host API key without deleting host telemetry/history."""
        try:
            auth_ctx = authenticate_agent_request(
                allow_agent_key=False,
                require_management=True,
            )
            data = request.get_json(silent=True) or {}
            safe_host_id = sanitize_text(str(host_id or ""), max_len=128)
            if not safe_host_id:
                return jsonify({"error": "host_id obrigatorio"}), 400
            tenant_override = sanitize_text(str(data.get("tenant_id") or ""), max_len=128)
            host = get_agent_service().revoke_host_api_key(
                auth_ctx=auth_ctx,
                host_id=safe_host_id,
                tenant_id=tenant_override or None,
            )
            set_request_tenant_context(str(host.get("tenant_id") or auth_ctx.tenant_id), "analyst")
            audit_fn(
                "AGENT_KEY_REVOKED",
                actor=safe_host_id,
                ip=request.remote_addr or "-",
                detail=f"tenant={host.get('tenant_id')}",
            )
            return jsonify({"ok": True, "host": host})
        except PermissionError as exc:
            if str(exc) == "unauthorized":
                return jsonify({"error": "Unauthorized"}), 401
            return jsonify({"error": "Permissao insuficiente"}), 403
        except LookupError:
            return jsonify({"error": "host_nao_encontrado"}), 404

    @bp.route("/api/agent/hosts/<path:host_id>/rotate-key", methods=["POST"])
    def agent_rotate_host_key(host_id: str):
        """Rotates a host API key and returns the new secret once."""
        try:
            auth_ctx = authenticate_agent_request(
                allow_agent_key=False,
                require_management=True,
            )
            data = request.get_json(silent=True) or {}
            safe_host_id = sanitize_text(str(host_id or ""), max_len=128)
            if not safe_host_id:
                return jsonify({"error": "host_id obrigatorio"}), 400
            tenant_override = sanitize_text(str(data.get("tenant_id") or ""), max_len=128)
            host, api_key = get_agent_service().rotate_host_api_key(
                auth_ctx=auth_ctx,
                host_id=safe_host_id,
                tenant_id=tenant_override or None,
            )
            set_request_tenant_context(str(host.get("tenant_id") or auth_ctx.tenant_id), "analyst")
            audit_fn(
                "AGENT_KEY_ROTATED",
                actor=safe_host_id,
                ip=request.remote_addr or "-",
                detail=f"tenant={host.get('tenant_id')} prefix={api_key[:16]}",
            )
            return jsonify({
                "ok": True,
                "host": host,
                "api_key": api_key,
                "warning": "api_key exibida uma unica vez; atualize o credential store do endpoint",
            })
        except PermissionError as exc:
            if str(exc) == "unauthorized":
                return jsonify({"error": "Unauthorized"}), 401
            return jsonify({"error": "Permissao insuficiente"}), 403
        except LookupError:
            return jsonify({"error": "host_nao_encontrado"}), 404

    @bp.route("/api/agent/hosts/<path:host_id>/actions", methods=["POST"])
    def agent_queue_host_action(host_id: str):
        """Queues a response action for a specific enrolled host."""
        try:
            auth_ctx = authenticate_agent_request(
                allow_agent_key=False,
                require_management=True,
            )
            data = request.get_json(silent=True) or {}
            safe_host_id = sanitize_text(str(host_id or ""), max_len=128)
            if not safe_host_id:
                return jsonify({"error": "host_id obrigatorio"}), 400
            action_type = sanitize_text(str(data.get("action_type") or ""), max_len=64).lower()
            if action_type not in valid_action_types:
                return jsonify({
                    "error": "invalid_action_type",
                    "allowed": sorted(valid_action_types),
                }), 400
            if not auth_ctx.can_queue_response_actions:
                return jsonify({"error": "insufficient_scope", "scope": "response:queue"}), 403
            payload = data.get("payload") if isinstance(data.get("payload"), dict) else {}
            tenant_id = _effective_action_tenant(auth_ctx, data)
            host = get_agent_service().host_repo.get_host(safe_host_id, tenant_id=tenant_id)
            if not host:
                return jsonify({"error": "host_nao_encontrado"}), 404
            guarded_policy_error = _verify_guarded_action_policy(
                auth_ctx,
                data,
                tenant_id=tenant_id,
                host_id=safe_host_id,
                action_type=action_type,
            )
            if guarded_policy_error:
                audit_fn(
                    "AGENT_DESTRUCTIVE_ACTION_BLOCKED",
                    actor=safe_host_id,
                    ip=request.remote_addr or "-",
                    detail=f"tenant={tenant_id} action={action_type} reason={guarded_policy_error}",
                )
                return jsonify({
                    "error": guarded_policy_error,
                    "message": "destructive response actions require admin and signed policy approval",
                }), 403
            if action_type in guarded_action_types:
                payload = {
                    **payload,
                    "policy": {
                        "tenant_id": tenant_id,
                        "host_id": safe_host_id,
                        "action_type": action_type,
                        "nonce": str(data.get("policy_nonce") or "").strip(),
                        "expires_at": int(data.get("policy_expires_at")),
                        "signature": str(data.get("policy_signature") or "").strip().lower(),
                    },
                }
            action = get_action_repository().create_action(
                tenant_id=tenant_id,
                host_id=safe_host_id,
                action_type=action_type,
                payload=payload,
                requested_by=f"{auth_ctx.auth_type}:{auth_ctx.tenant_id}",
                reason=sanitize_text(str(data.get("reason") or ""), max_len=500),
                ttl_seconds=int(data.get("ttl_seconds") or 3600),
                max_attempts=int(data.get("max_attempts") or 3),
            )
            set_request_tenant_context(tenant_id, "analyst")
            audit_fn(
                "AGENT_ACTION_QUEUED",
                actor=safe_host_id,
                ip=request.remote_addr or "-",
                detail=f"tenant={tenant_id} action={action_type} id={action.get('action_id')}",
            )
            return jsonify({"ok": True, "action": action}), 201
        except PermissionError as exc:
            if str(exc) == "unauthorized":
                return jsonify({"error": "Unauthorized"}), 401
            return jsonify({"error": "Permissao insuficiente"}), 403
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @bp.route("/api/agent/hosts/<path:host_id>/actions", methods=["GET"])
    def agent_list_host_actions(host_id: str):
        """Lists queued/executed response actions for host triage."""
        try:
            auth_ctx = authenticate_agent_request(
                allow_agent_key=False,
                require_management=True,
            )
            data = {
                "tenant_id": request.args.get("tenant_id", ""),
            }
            tenant_id = _effective_action_tenant(auth_ctx, data)
            safe_host_id = sanitize_text(str(host_id or ""), max_len=128)
            status = sanitize_text(str(request.args.get("status") or ""), max_len=32).lower()
            actions = get_action_repository().list_actions(
                tenant_id=tenant_id,
                host_id=safe_host_id,
                status=status or None,
                limit=int(request.args.get("limit") or 100),
            )
            set_request_tenant_context(tenant_id, "analyst")
            return jsonify({"ok": True, "actions": actions, "total": len(actions)})
        except PermissionError as exc:
            if str(exc) == "unauthorized":
                return jsonify({"error": "Unauthorized"}), 401
            return jsonify({"error": "Permissao insuficiente"}), 403
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @bp.route("/api/agent/actions/<path:action_id>/cancel", methods=["POST"])
    def agent_cancel_action(action_id: str):
        """Cancels a pending/leased response action before agent completion."""
        try:
            auth_ctx = authenticate_agent_request(
                allow_agent_key=False,
                require_management=True,
            )
            data = request.get_json(silent=True) or {}
            tenant_id = _effective_action_tenant(auth_ctx, data)
            safe_action_id = sanitize_text(str(action_id or ""), max_len=128)
            reason = sanitize_text(str(data.get("reason") or ""), max_len=500)
            action = get_action_repository().cancel_action(
                tenant_id=tenant_id,
                action_id=safe_action_id,
                result={
                    "cancelled_by": f"{auth_ctx.auth_type}:{auth_ctx.tenant_id}",
                    "reason": reason,
                },
            )
            if not action:
                return jsonify({"error": "action_nao_encontrada_ou_terminal"}), 404
            set_request_tenant_context(tenant_id, "analyst")
            audit_fn(
                "AGENT_ACTION_CANCELLED",
                actor=safe_action_id,
                ip=request.remote_addr or "-",
                detail=f"tenant={tenant_id} status={action.get('status')}",
            )
            return jsonify({"ok": True, "action": action})
        except PermissionError as exc:
            if str(exc) == "unauthorized":
                return jsonify({"error": "Unauthorized"}), 401
            return jsonify({"error": "Permissao insuficiente"}), 403
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @bp.route("/api/agent/actions", methods=["GET"])
    def agent_poll_actions():
        """Agent polling endpoint. Only authenticated host keys can lease work."""
        try:
            auth_ctx = authenticate_agent_request()
            if auth_ctx.auth_type != "agent" or not auth_ctx.host_id:
                return jsonify({"error": "agent_key_required"}), 403
            actions = get_action_repository().lease_actions(
                tenant_id=str(auth_ctx.tenant_id or "default"),
                host_id=str(auth_ctx.host_id),
                limit=int(request.args.get("limit") or 10),
                lease_seconds=int(request.args.get("lease_seconds") or 120),
            )
            set_request_tenant_context(str(auth_ctx.tenant_id or "default"), "agent")
            return jsonify({"ok": True, "actions": actions, "total": len(actions)})
        except PermissionError as exc:
            if str(exc) == "unauthorized":
                return jsonify({"error": "Unauthorized"}), 401
            return jsonify({"error": "Permissao insuficiente"}), 403
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @bp.route("/api/agent/actions/<path:action_id>/ack", methods=["POST"])
    def agent_ack_action(action_id: str):
        """Agent ACK endpoint for completed/refused/failed response actions."""
        try:
            auth_ctx = authenticate_agent_request()
            if auth_ctx.auth_type != "agent" or not auth_ctx.host_id:
                return jsonify({"error": "agent_key_required"}), 403
            data = request.get_json(silent=True) or {}
            status = sanitize_text(str(data.get("status") or ""), max_len=32).lower()
            result = data.get("result") if isinstance(data.get("result"), dict) else {}
            action = get_action_repository().ack_action(
                tenant_id=str(auth_ctx.tenant_id or "default"),
                host_id=str(auth_ctx.host_id),
                action_id=sanitize_text(str(action_id or ""), max_len=128),
                status=status,
                result=result,
            )
            if not action:
                return jsonify({"error": "action_nao_encontrada"}), 404
            audit_fn(
                "AGENT_ACTION_ACKED",
                actor=str(auth_ctx.host_id),
                ip=request.remote_addr or "-",
                detail=f"tenant={auth_ctx.tenant_id} action={action_id} status={status}",
            )
            return jsonify({"ok": True, "action": action})
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
