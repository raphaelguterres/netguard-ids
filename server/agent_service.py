"""Agent enrollment and heartbeat service."""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from security import hash_token, role_level, token_has_scope

logger = logging.getLogger("netguard.agent_service")

_AGENT_KEY_PREFIX = "nga_"
_ENROLLMENT_TOKEN_PREFIX = "nge_"


def generate_agent_api_key() -> str:
    return _AGENT_KEY_PREFIX + secrets.token_urlsafe(32)


def generate_enrollment_token() -> str:
    return _ENROLLMENT_TOKEN_PREFIX + secrets.token_urlsafe(32)


@dataclass(slots=True)
class AgentAuthContext:
    tenant_id: str
    role: str
    auth_type: str
    host_id: str = ""
    scopes: tuple[str, ...] | None = None

    def has_scope(self, scope: str) -> bool:
        if self.auth_type == "admin":
            return True
        return token_has_scope(self.scopes if self.scopes is not None else "", scope, role=self.role)

    @property
    def can_manage_hosts(self) -> bool:
        return (
            self.auth_type == "admin"
            or (
                role_level(self.role) >= role_level("analyst")
                and self.has_scope("hosts:manage")
            )
        )

    @property
    def can_push_events(self) -> bool:
        return self.auth_type in {"admin", "agent"} or (
            self.auth_type == "tenant" and self.has_scope("events:write")
        )

    @property
    def can_queue_response_actions(self) -> bool:
        return (
            self.auth_type == "admin"
            or (
                role_level(self.role) >= role_level("analyst")
                and self.has_scope("response:queue")
            )
        )


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
            enrollment_method=(
                "enrollment_token" if auth_ctx.auth_type == "enrollment" else "api_token"
            ),
            api_key_hash=hash_token(api_key),
            api_key_prefix=api_key[:16],
        )
        return host, api_key

    def create_enrollment_token(
        self,
        *,
        auth_ctx: AgentAuthContext,
        tenant_id: str | None = None,
        expires_in_seconds: int = 3600,
        max_uses: int = 1,
    ) -> tuple[dict, str]:
        if not auth_ctx.can_manage_hosts:
            raise PermissionError("agent enrollment token creation requires analyst or admin role")
        effective_tenant_id = (
            tenant_id if auth_ctx.auth_type == "admin" and tenant_id else auth_ctx.tenant_id
        )
        ttl = min(max(int(expires_in_seconds or 3600), 300), 7 * 24 * 3600)
        uses = min(max(int(max_uses or 1), 1), 1000)
        token = generate_enrollment_token()
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)
        record = self.host_repo.create_enrollment_token(
            token_hash=hash_token(token),
            token_prefix=token[:16],
            tenant_id=effective_tenant_id,
            created_by=f"{auth_ctx.auth_type}:{auth_ctx.tenant_id}",
            expires_at=expires_at.isoformat().replace("+00:00", "Z"),
            max_uses=uses,
        )
        return record, token

    def verify_enrollment_token(self, token: str) -> AgentAuthContext | None:
        if not token:
            return None
        record = self.host_repo.consume_enrollment_token(hash_token(token))
        if not record:
            return None
        return AgentAuthContext(
            tenant_id=str(record.get("tenant_id") or "default"),
            role="analyst",
            auth_type="enrollment",
            scopes=("hosts:manage",),
        )

    def revoke_enrollment_token(
        self,
        *,
        auth_ctx: AgentAuthContext,
        token: str,
    ) -> bool:
        if not auth_ctx.can_manage_hosts:
            raise PermissionError("agent enrollment token revocation requires analyst or admin role")
        if not token:
            return False
        token_hash = hash_token(token)
        record = self.host_repo.get_enrollment_token(token_hash=token_hash)
        if (
            record
            and auth_ctx.auth_type != "admin"
            and str(record.get("tenant_id") or "") != auth_ctx.tenant_id
        ):
            raise PermissionError("cannot revoke enrollment token from another tenant")
        return self.host_repo.revoke_enrollment_token(token_hash)

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

    def revoke_host_api_key(
        self,
        *,
        auth_ctx: AgentAuthContext,
        host_id: str,
        tenant_id: str | None = None,
    ) -> dict:
        if not auth_ctx.can_manage_hosts:
            raise PermissionError("host key revocation requires analyst or admin role")
        effective_tenant_id = (
            tenant_id if auth_ctx.auth_type == "admin" and tenant_id else auth_ctx.tenant_id
        )
        ok = self.host_repo.revoke_host_key(host_id, tenant_id=effective_tenant_id)
        if not ok:
            raise LookupError("host not found")
        return self.host_repo.get_host(host_id, tenant_id=effective_tenant_id) or {}

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
