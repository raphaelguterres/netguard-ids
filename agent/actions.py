"""Server-to-agent response action polling and safe execution."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

from agent.sender import EventSender

logger = logging.getLogger("netguard.agent.actions")

SAFE_ACTION_TYPES = {"ping", "collect_diagnostics", "flush_buffer"}
GUARDED_ACTION_TYPES = {"isolate_host", "kill_process", "block_ip", "delete_file"}


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
    ):
        self.host_id = host_id
        self.host_facts = host_facts
        self.sender = sender
        self.allow_destructive = bool(allow_destructive)

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
                return self._guarded_refusal(action_type)
            return ActionExecutionResult("failed", {"error": "unsupported_action_type"})
        except Exception as exc:
            logger.exception("action execution failed action_type=%s", action_type)
            return ActionExecutionResult("failed", {"error": exc.__class__.__name__})

    def _collect_diagnostics(self) -> dict[str, Any]:
        return {
            "host_id": self.host_id,
            "hostname": self.host_facts.get("hostname", ""),
            "platform": self.host_facts.get("platform", ""),
            "agent_user": self.host_facts.get("user", ""),
            "buffer_pending": self.sender.buffer.size(),
            "server_url": self.sender.server_url,
        }

    def _guarded_refusal(self, action_type: str) -> ActionExecutionResult:
        if self.allow_destructive:
            return ActionExecutionResult(
                "failed",
                {
                    "error": "destructive_action_not_implemented",
                    "action_type": action_type,
                },
            )
        return ActionExecutionResult(
            "refused",
            {
                "error": "destructive_actions_disabled",
                "action_type": action_type,
                "message": "Enable signed policy support before allowing destructive response.",
            },
        )
