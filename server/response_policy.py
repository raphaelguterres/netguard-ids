"""Signed policy helpers for high-risk endpoint response actions."""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Any

POLICY_MAX_TTL_SECONDS = 300
MIN_POLICY_SECRET_LENGTH = 32
MIN_NONCE_LENGTH = 16


def canonical_response_policy_message(
    *,
    tenant_id: str,
    host_id: str,
    action_type: str,
    nonce: str,
    expires_at: int | str,
) -> bytes:
    """Build a stable HMAC message for destructive action approvals."""
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


def sign_response_policy(
    secret: str,
    *,
    tenant_id: str,
    host_id: str,
    action_type: str,
    nonce: str,
    expires_at: int | str,
) -> str:
    if not secret or len(secret) < MIN_POLICY_SECRET_LENGTH:
        raise ValueError("policy_secret_not_configured")
    return hmac.new(
        secret.encode("utf-8"),
        canonical_response_policy_message(
            tenant_id=tenant_id,
            host_id=host_id,
            action_type=action_type,
            nonce=nonce,
            expires_at=expires_at,
        ),
        hashlib.sha256,
    ).hexdigest()


def verify_response_policy(
    secret: str,
    *,
    tenant_id: str,
    host_id: str,
    action_type: str,
    nonce: Any,
    expires_at: Any,
    signature: Any,
    now: float | None = None,
) -> tuple[bool, str]:
    """Verify a short-lived destructive action policy approval.

    This intentionally validates only an approval envelope. It does not mean
    the endpoint agent must execute the action; agent-side policy remains a
    separate fail-closed control.
    """
    if not secret or len(secret) < MIN_POLICY_SECRET_LENGTH:
        return False, "destructive_actions_disabled"

    nonce_text = str(nonce or "").strip()
    signature_text = str(signature or "").strip().lower()
    if len(nonce_text) < MIN_NONCE_LENGTH:
        return False, "invalid_policy_nonce"
    if not signature_text:
        return False, "missing_policy_signature"

    try:
        expires_int = int(expires_at)
    except (TypeError, ValueError):
        return False, "invalid_policy_expiry"

    now_int = int(now if now is not None else time.time())
    if expires_int <= now_int:
        return False, "policy_expired"
    if expires_int > now_int + POLICY_MAX_TTL_SECONDS:
        return False, "policy_expiry_too_far"

    try:
        expected = sign_response_policy(
            secret,
            tenant_id=tenant_id,
            host_id=host_id,
            action_type=action_type,
            nonce=nonce_text,
            expires_at=expires_int,
        )
    except ValueError as exc:
        return False, str(exc)

    if not hmac.compare_digest(expected, signature_text):
        return False, "invalid_policy_signature"
    return True, "ok"
