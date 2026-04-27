"""Agent enrollment and heartbeat service."""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from typing import Any

from security import hash_token, role_level

logger = logging.getLogger("netguard.agent_service")

_AGENT_KEY_PREFIX = "nga_"


def generate_agent_api_key() -> str:
    return _AGENT_KEY_PREFIX + secrets.token_urlsafe(32)


@dataclass(slots=True)
class AgentAuthContext:
    tenant_id: str
    role: str
    auth_type: str
    host_id: str = ""

    @property
    def can_manage_hosts(self) -> bool:
        return self.auth_type == "admin" or role_level(self.role) >= role_level("analyst")

    @property
    def can_push_events(self) -> bool:
        return self.auth_type in {"admin", "tenant", "agent"}


class AgentService:
    """Business rules for agent registration, enrollment and heartbeats."""

    def __init__(self, host_repo, tenant_repo):
        self.host_repo = host_repo
        self.tenant_repo = tenant_repo

    def register_host(
        self,
        *,
        auth_ctx: AgentAuthContext,
        host_id: str,
        display_name: str = "",
        platform: str = "",
        agent_version: str = "",
        metadata: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        tenant_id: str | None = None,
    ) -> tuple[dict, str]:
        if not auth_ctx.can_manage_hosts:
            raise PermissionError("host enrollment requires analyst or admin role")

        effective_tenant_id = (
            tenant_id if auth_ctx.auth_type == "admin" and tenant_id else auth_ctx.tenant_id
        )
        tenant = self.tenant_repo.get_tenant_by_id(effective_tenant_id)
        if tenant:
            max_hosts = int(tenant.get("max_hosts") or 0)
            existing = self.host_repo.get_host(host_id, tenant_id=effective_tenant_id)
            if max_hosts > 0 and existing is None:
                enrolled = self.host_repo.count_hosts(tenant_id=effective_tenant_id)
                if enrolled >= max_hosts:
                    raise ValueError(
                        f"tenant host quota exceeded ({enrolled}/{max_hosts})",
                    )

        api_key = generate_agent_api_key()
        host = self.host_repo.register_host(
            tenant_id=effective_tenant_id,
            host_id=host_id,
            display_name=display_name or host_id,
            platform=platform,
            agent_version=agent_version,
            metadata=metadata or {},
            tags=tags or [],
            enrollment_method="api_token",
            api_key_hash=hash_token(api_key),
            api_key_prefix=api_key[:16],
        )
        return host, api_key

    def rotate_host_api_key(
        self,
        *,
        auth_ctx: AgentAuthContext,
        host_id: str,
        tenant_id: str | None = None,
    ) -> tuple[dict, str]:
        if not auth_ctx.can_manage_hosts:
            raise PermissionError("host key rotation requires analyst or admin role")
        effective_tenant_id = (
            tenant_id if auth_ctx.auth_type == "admin" and tenant_id else auth_ctx.tenant_id
        )
        api_key = generate_agent_api_key()
        ok = self.host_repo.rotate_api_key(
            host_id,
            tenant_id=effective_tenant_id,
            api_key_hash=hash_token(api_key),
            api_key_prefix=api_key[:16],
        )
        if not ok:
            raise LookupError("host not found")
        host = self.host_repo.get_host(host_id, tenant_id=effective_tenant_id) or {}
        return host, api_key

    def verify_agent_key(self, api_key: str) -> dict | None:
        if not api_key:
            return None
        return self.host_repo.verify_api_key(hash_token(api_key))

    def record_heartbeat(
        self,
        *,
        auth_ctx: AgentAuthContext,
        host_id: str,
        display_name: str = "",
        platform: str = "",
        agent_version: str = "",
        source_ip: str = "",
        metadata: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        mark_event: bool = False,
        tenant_id: str | None = None,
    ) -> dict:
        # F-AGENT-1 (T16): se a chamada vem sob auth admin e o body traz
        # tenant_id, esse valor pina o host no tenant correto. Sem esse
        # override, /api/agent/events sob admin grudava o host em
        # tenant_id="admin" (bucket de órfãos invisível em qualquer drilldown).
        # Mesma regra que register_host já aplicava: somente admin pode
        # escolher tenant via body — tenant/agent ficam presos ao seu próprio.
        if auth_ctx.auth_type == "agent" and auth_ctx.host_id and auth_ctx.host_id != host_id:
            raise PermissionError("agent key cannot write for another host")
        effective_tenant_id = (
            tenant_id if auth_ctx.auth_type == "admin" and tenant_id else auth_ctx.tenant_id
        )
        return self.host_repo.touch_host(
            host_id,
            tenant_id=effective_tenant_id,
            display_name=display_name,
            platform=platform,
            agent_version=agent_version,
            source_ip=source_ip,
            metadata=metadata or {},
            tags=tags or [],
            mark_event=mark_event,
        )

    def host_inventory(self, *, tenant_id: str, limit: int = 200) -> list[dict]:
        return self.host_repo.list_hosts(tenant_id=tenant_id, limit=limit)
