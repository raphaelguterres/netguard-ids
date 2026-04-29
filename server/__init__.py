"""Server-side services for NetGuard.

The package surface is intentionally import-light: callers that only
need `server.auth` or `server.api` should not pay the import cost of
legacy agent-service dependencies at package import time.
"""

from __future__ import annotations

from importlib import import_module

__all__ = [
    # legacy
    "AgentAuthContext",
    "AgentService",
    "generate_agent_api_key",
    # auth
    "AgentPrincipal",
    "EnvKeyStore",
    "KeyStore",
    "StaticKeyStore",
    "extract_api_key",
    "hash_api_key",
    "require_agent_key",
    # ingestion
    "IngestionError",
    "IngestionPipeline",
    "IngestionResult",
    "PayloadTooLarge",
    "ValidationError",
    # rate limit
    "SqliteTokenBucketLimiter",
    "TokenBucketLimiter",
    "build_rate_limiter_from_env",
    "sign_response_policy",
    "verify_response_policy",
]


_EXPORT_MAP = {
    "AgentAuthContext": (".agent_service", "AgentAuthContext"),
    "AgentService": (".agent_service", "AgentService"),
    "generate_agent_api_key": (".agent_service", "generate_agent_api_key"),
    "AgentPrincipal": (".auth", "AgentPrincipal"),
    "EnvKeyStore": (".auth", "EnvKeyStore"),
    "KeyStore": (".auth", "KeyStore"),
    "StaticKeyStore": (".auth", "StaticKeyStore"),
    "extract_api_key": (".auth", "extract_api_key"),
    "hash_api_key": (".auth", "hash_api_key"),
    "require_agent_key": (".auth", "require_agent_key"),
    "IngestionError": (".ingestion", "IngestionError"),
    "IngestionPipeline": (".ingestion", "IngestionPipeline"),
    "IngestionResult": (".ingestion", "IngestionResult"),
    "PayloadTooLarge": (".ingestion", "PayloadTooLarge"),
    "ValidationError": (".ingestion", "ValidationError"),
    "SqliteTokenBucketLimiter": (".rate_limit", "SqliteTokenBucketLimiter"),
    "TokenBucketLimiter": (".rate_limit", "TokenBucketLimiter"),
    "build_rate_limiter_from_env": (".rate_limit", "build_rate_limiter_from_env"),
    "sign_response_policy": (".response_policy", "sign_response_policy"),
    "verify_response_policy": (".response_policy", "verify_response_policy"),
}


def __getattr__(name: str):
    if name not in _EXPORT_MAP:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attr_name = _EXPORT_MAP[name]
    value = getattr(import_module(module_name, __name__), attr_name)
    globals()[name] = value
    return value
