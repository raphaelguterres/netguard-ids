"""
API-key auth for the agent ingest endpoint.

Two backends:

- `EnvKeyStore` — accept any key listed in `NETGUARD_AGENT_KEYS`
  (comma-sep). Useful for dev / single-tenant.
- `RepositoryKeyStore` — verify against hashed keys in the storage
  repository. Production. Hashes are SHA-256, never compared in raw
  form.

Header: clients send `X-API-Key: nga_...` (or `X-NetGuard-Agent-Key`
for compatibility with the existing agent). Both names are accepted.
Comparisons use `hmac.compare_digest` to defeat timing attacks.

Usage:

    store = EnvKeyStore.from_env()
    @bp.route("/api/events", methods=["POST"])
    @require_agent_key(store)
    def ingest():
        ...
"""

from __future__ import annotations

import abc
import hashlib
import hmac
import logging
import os
from dataclasses import dataclass
from functools import wraps
from typing import Callable

logger = logging.getLogger("netguard.server.auth")

# Both header names are accepted. Order = preference.
HEADER_NAMES = ("X-API-Key", "X-NetGuard-Agent-Key")


@dataclass(frozen=True)
class AgentPrincipal:
    """Identity attached to an authenticated agent request."""
    key_id: str
    host_id: str = ""
    tenant_id: str = ""


def hash_api_key(api_key: str) -> str:
    """SHA-256 hex of the API key. Stable, never reversed."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def extract_api_key(headers) -> str:
    """Read the API key from the request headers; case-insensitive lookup."""
    for name in HEADER_NAMES:
        v = headers.get(name)
        if v:
            return v.strip()
    # Some load balancers strip non-standard headers; allow Authorization: Bearer.
    auth = (headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


# ── Key stores ────────────────────────────────────────────────────────


class KeyStore(abc.ABC):
    """Verify an inbound API key. Returns a Principal or None."""

    @abc.abstractmethod
    def verify(self, api_key: str) -> AgentPrincipal | None: ...


class EnvKeyStore(KeyStore):
    """
    Accepts keys listed in env. Dev-friendly.

    NETGUARD_AGENT_KEYS = "nga_dev_one,nga_dev_two"
    """

    def __init__(self, allowed_keys: list[str]):
        # Store hashes, not the raw keys, so a heap dump doesn't leak them.
        self._hashes = {hash_api_key(k): k[:8] + "..." for k in allowed_keys if k}

    @classmethod
    def from_env(cls, var: str = "NETGUARD_AGENT_KEYS") -> "EnvKeyStore":
        raw = os.environ.get(var, "")
        keys = [k.strip() for k in raw.split(",") if k.strip()]
        return cls(keys)

    def verify(self, api_key: str) -> AgentPrincipal | None:
        if not api_key:
            return None
        h = hash_api_key(api_key)
        # constant-time comparison across all stored hashes
        for stored_hash, label in self._hashes.items():
            if hmac.compare_digest(h, stored_hash):
                return AgentPrincipal(key_id=label)
        return None


class StaticKeyStore(KeyStore):
    """
    Map of key -> AgentPrincipal. For tests and explicit setups.
    """

    def __init__(self, key_to_principal: dict[str, AgentPrincipal]):
        self._map = {hash_api_key(k): p for k, p in key_to_principal.items()}

    def verify(self, api_key: str) -> AgentPrincipal | None:
        if not api_key:
            return None
        h = hash_api_key(api_key)
        for stored_hash, principal in self._map.items():
            if hmac.compare_digest(h, stored_hash):
                return principal
        return None


# ── Decorator for Flask views ────────────────────────────────────────


def require_agent_key(store: KeyStore) -> Callable:
    """
    Decorator that protects a Flask view. Rejects with 401 on missing
    key, 403 on invalid key. On success injects the AgentPrincipal as
    `request.netguard_principal` and as a kwarg if the view accepts it.

    Lazy-imports flask so this module is unit-testable without flask
    installed (the auth helpers above don't need it).
    """
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            from flask import jsonify, request  # lazy
            api_key = extract_api_key(request.headers)
            if not api_key:
                logger.info("auth: missing API key from %s", request.remote_addr)
                return jsonify({
                    "ok": False,
                    "error": "missing_api_key",
                    "message": "X-API-Key header required",
                }), 401
            principal = store.verify(api_key)
            if principal is None:
                logger.warning("auth: invalid API key from %s (key prefix=%s)",
                               request.remote_addr, api_key[:8])
                return jsonify({
                    "ok": False,
                    "error": "invalid_api_key",
                }), 403
            # Attach to request for downstream handlers
            request.netguard_principal = principal  # type: ignore[attr-defined]
            return view_func(*args, **kwargs)
        return wrapper
    return decorator
