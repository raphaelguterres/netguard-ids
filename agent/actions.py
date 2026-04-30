"""Server-to-agent response action polling and safe execution."""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlencode, urlsplit, urlunsplit

from agent.sender import EventSender

logger = logging.getLogger("netguard.agent.actions")

SAFE_ACTION_TYPES = {"ping", "collect_diagnostics", "flush_buffer"}
GUARDED_ACTION_TYPES = {"isolate_host", "kill_process", "block_ip", "delete_file"}
POLICY_MAX_TTL_SECONDS = 300
MIN_POLICY_SECRET_LENGTH = 32
MIN_POLICY_NONCE_LENGTH = 16


@dataclass(slots=True)
class ActionExecutionResult:
    status: str
    result: dict[str, Any]


def derive_actions_url(server_url: str) -> str:
    parts = urlsplit(server_url)
    path = parts.path.rstrip("/")
    for suffix in ("/api/events", "/api/agent/events"):
        if path.endswith(suffix):
            path = path[: -len(suffix)] + "/api/agent/actions"
            return urlunsplit((parts.scheme, parts.netloc, path, "", ""))
    if path.endswith("/api"):
        path += "/agent/actions"
    else:
        path += "/api/agent/actions"
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def _canonical_response_policy_message(
    *,
    tenant_id: str,
    host_id: str,
    action_type: str,
    nonce: str,
    expires_at: int | str,
) -> bytes:
    return "\n".join(
        [
            "netguard-response-action-v1",
            str(tenant_id or "").strip(),
            str(host_id or "").strip(),
            str(action_type or "").strip().lower(),
            str(nonce or "").strip(),
            str(int(expires_at)),
        ]
    ).encode("utf-8")


def _sign_response_policy(
    secret: str,
    *,
    tenant_id: str,
    host_id: str,
    action_type: str,
    nonce: str,
    expires_at: int | str,
) -> str:
    return hmac.new(
        secret.encode("utf-8"),
        _canonical_response_policy_message(
            tenant_id=tenant_id,
            host_id=host_id,
            action_type=action_type,
            nonce=nonce,
            expires_at=expires_at,
        ),
        hashlib.sha256,
    ).hexdigest()


class AgentActionClient:
    """HTTP client for polling and ACKing server-side action leases."""

    def __init__(self, sender: EventSender, actions_url: str | None = None):
        self.sender = sender
        self.actions_url = actions_url or derive_actions_url(sender.server_url)

    def poll(self, *, limit: int = 10, lease_seconds: int = 120) -> list[dict]:
        if self.sender._session is None:
            return []
        query = urlencode({
            "limit": max(1, min(int(limit), 50)),
            "lease_seconds": max(30, min(int(lease_seconds), 600)),
        })
        url = f"{self.actions_url}?{query}"
        try:
            resp = self.sender._session.get(
                url,
                headers=self.sender._headers(),
                timeout=self.sender.timeout,
                verify=self.sender.verify_tls,
            )
        except Exception as exc:
            logger.debug("action poll failed: %s", exc)
            return []
        if resp.status_code != 200:
            logger.debug("action poll rejected status=%s body=%s", resp.status_code, resp.text[:200])
            return []
        data = resp.json() if resp.content else {}
        actions = data.get("actions") if isinstance(data, dict) else []
        return [item for item in actions if isinstance(item, dict)]

    def ack(self, action_id: str, *, status: str, result: dict[str, Any]) -> bool:
        if self.sender._session is None or not action_id:
            return False
        url = f"{self.actions_url}/{action_id}/ack"
        try:
            resp = self.sender._session.post(
                url,
                json={"status": status, "result": result},
                headers=self.sender._headers(),
                timeout=self.sender.timeout,
                verify=self.sender.verify_tls,
            )
        except Exception as exc:
            logger.debug("action ack failed action=%s: %s", action_id, exc)
            return False
        if resp.status_code not in (200, 201, 202):
            logger.warning("action ack rejected action=%s status=%s", action_id, resp.status_code)
            return False
        return True


class AgentActionExecutor:
    """Executes a conservative allowlist of response actions.

    Destructive actions are intentionally refused unless a future signed
    policy enables them. This prevents the response channel from becoming
    an arbitrary remote shell.
    """

    def __init__(
        self,
        *,
        host_id: str,
        host_facts: dict[str, Any],
        sender: EventSender,
        allow_destructive: bool = False,
        response_policy_secret: str = "",
        diagnostics_provider: Callable[[], dict[str, Any]] | None = None,
    ):
        self.host_id = host_id
        self.host_facts = host_facts
        self.sender = sender
        self.allow_destructive = bool(allow_destructive)
        self.response_policy_secret = str(response_policy_secret or "")
        self.diagnostics_provider = diagnostics_provider

    def execute(self, action: dict[str, Any]) -> ActionExecutionResult:
        action_type = str(action.get("action_type") or "").strip().lower()
        payload = action.get("payload") if isinstance(action.get("payload"), dict) else {}
        try:
            if action_type == "ping":
                return ActionExecutionResult("succeeded", {"message": "pong"})
            if action_type == "collect_diagnostics":
                return ActionExecutionResult("succeeded", self._collect_diagnostics())
            if action_type == "flush_buffer":
                drained = self.sender.drain_once(max_batches=int(payload.get("max_batches") or 20))
                return ActionExecutionResult("succeeded", {"drained_batches": drained})
            if action_type in GUARDED_ACTION_TYPES:
                return self._handle_guarded_action(action_type, action)
            return ActionExecutionResult("failed", {"error": "unsupported_action_type"})
        except Exception as exc:
            logger.exception("action execution failed action_type=%s", action_type)
            return ActionExecutionResult("failed", {"error": exc.__class__.__name__})

    def _collect_diagnostics(self) -> dict[str, Any]:
        diagnostics = {
            "host_id": self.host_id,
            "hostname": self.host_facts.get("hostname", ""),
            "platform": self.host_facts.get("platform", ""),
            "platform_version": self.host_facts.get("platform_version", ""),
            "agent_user": self.host_facts.get("user", ""),
            "buffer_pending": self.sender.buffer.size(),
            "buffer_path": str(self.sender.buffer.db_path),
            "server_url": _redact_url(self.sender.server_url),
            "transport": {
                "server_url": _redact_url(self.sender.server_url),
                "verify_tls": self.sender.verify_tls,
                "timeout_seconds": self.sender.timeout,
                "max_retries": self.sender.max_retries,
                "backoff_factor": self.sender.backoff_factor,
            },
            "generated_at": int(time.time()),
        }
        if self.diagnostics_provider:
            try:
                extra = self.diagnostics_provider()
                if isinstance(extra, dict):
                    diagnostics.update(extra)
            except Exception as exc:
                logger.warning("diagnostics provider failed: %s", exc)
                diagnostics["diagnostics_provider_error"] = exc.__class__.__name__
        return diagnostics

    def _handle_guarded_action(self, action_type: str, action: dict[str, Any]) -> ActionExecutionResult:
        if not self.allow_destructive:
            return ActionExecutionResult(
                "refused",
                {
                    "error": "destructive_actions_disabled",
                    "action_type": action_type,
                    "message": "Enable signed policy support before allowing destructive response.",
                },
            )

        policy_ok, reason = self._verify_guarded_policy(action_type, action)
        if not policy_ok:
            return ActionExecutionResult(
                "refused",
                {
                    "error": reason,
                    "action_type": action_type,
                    "message": "Guarded response action rejected by endpoint policy verifier.",
                },
            )

        return ActionExecutionResult(
            "failed",
            {
                "error": "destructive_action_not_implemented",
                "action_type": action_type,
                "policy_verified": True,
            },
        )

    def _verify_guarded_policy(
        self,
        action_type: str,
        action: dict[str, Any],
    ) -> tuple[bool, str]:
        secret = self.response_policy_secret
        if not secret or len(secret) < MIN_POLICY_SECRET_LENGTH:
            return False, "destructive_actions_disabled"

        payload = action.get("payload") if isinstance(action.get("payload"), dict) else {}
        policy = payload.get("policy") if isinstance(payload.get("policy"), dict) else {}
        if not policy:
            return False, "missing_response_policy"

        action_host_id = str(action.get("host_id") or self.host_id or "").strip()
        policy_host_id = str(policy.get("host_id") or "").strip()
        if not policy_host_id or policy_host_id != action_host_id:
            return False, "policy_host_mismatch"
        if self.host_id and policy_host_id != self.host_id:
            return False, "policy_local_host_mismatch"

        action_tenant_id = str(action.get("tenant_id") or "").strip()
        policy_tenant_id = str(policy.get("tenant_id") or "").strip()
        if action_tenant_id and policy_tenant_id != action_tenant_id:
            return False, "policy_tenant_mismatch"

        policy_action_type = str(policy.get("action_type") or "").strip().lower()
        if policy_action_type != action_type:
            return False, "policy_action_mismatch"

        nonce = str(policy.get("nonce") or "").strip()
        signature = str(policy.get("signature") or "").strip().lower()
        if len(nonce) < MIN_POLICY_NONCE_LENGTH:
            return False, "invalid_policy_nonce"
        if not signature:
            return False, "missing_policy_signature"

        try:
            expires_at = int(policy.get("expires_at"))
        except (TypeError, ValueError):
            return False, "invalid_policy_expiry"

        now = int(time.time())
        if expires_at <= now:
            return False, "policy_expired"
        if expires_at > now + POLICY_MAX_TTL_SECONDS:
            return False, "policy_expiry_too_far"

        expected = _sign_response_policy(
            secret,
            tenant_id=policy_tenant_id,
            host_id=policy_host_id,
            action_type=policy_action_type,
            nonce=nonce,
            expires_at=expires_at,
        )
        if not hmac.compare_digest(expected, signature):
            return False, "invalid_policy_signature"
        return True, "ok"


def _redact_url(value: str) -> str:
    """Remove query/fragment/userinfo before echoing endpoint URLs in ACKs."""
    try:
        parts = urlsplit(value or "")
    except ValueError:
        return ""
    safe_netloc = parts.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parts.scheme, safe_netloc, parts.path, "", ""))
