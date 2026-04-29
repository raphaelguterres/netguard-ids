"""
Flask blueprint that exposes the spec-compliant ingest endpoint
`POST /api/events`.

This is the modular, self-contained ingest path used by the new
EDR pipeline (auth → rate-limit → ingestion → detection → risk →
response). It lives next to the existing app.py routes; it does not
replace them.

Mounting:

    from server.api import build_blueprint
    from server.auth import EnvKeyStore
    from storage.repository import get_repository

    repo = get_repository("sqlite")
    repo.init_schema()
    bp = build_blueprint(repo, EnvKeyStore.from_env())
    app.register_blueprint(bp)

Or, for a standalone development server:

    python -m server.api      # starts Flask on :5000
"""

from __future__ import annotations

import logging
import os
from typing import Any

from .auth import KeyStore, extract_api_key, require_agent_key
from .ingestion import (
    IngestionError,
    IngestionPipeline,
    PayloadTooLarge,
    ValidationError,
)
from .rate_limit import TokenBucketLimiter
from storage.repository import Repository, get_repository

logger = logging.getLogger("netguard.server.api")


def build_blueprint(
    repo: Repository,
    key_store: KeyStore,
    *,
    limiter: TokenBucketLimiter | None = None,
    pipeline: IngestionPipeline | None = None,
    url_prefix: str = "/api",
    include_read_endpoints: bool = True,
) -> Any:
    """
    Build and return a Flask Blueprint. Lazy-imports flask.
    """
    from flask import Blueprint, jsonify, request  # lazy

    bp = Blueprint("netguard_edr", __name__, url_prefix=url_prefix)
    pipeline = pipeline or IngestionPipeline(repo)
    limiter = limiter or TokenBucketLimiter(rate_per_sec=20.0, burst=40)

    @bp.route("/events", methods=["POST"])
    @require_agent_key(key_store)
    def ingest():
        # 1. content-type guard
        if not request.is_json:
            return jsonify({
                "ok": False,
                "error": "invalid_content_type",
                "message": "Content-Type must be application/json",
            }), 415

        # 2. rate limit (per agent key)
        api_key = extract_api_key(request.headers)
        bucket_key = f"agent:{api_key[:24]}" if api_key else "agent:anon"
        if not limiter.allow(bucket_key):
            logger.warning("rate-limit exceeded for %s", bucket_key)
            return jsonify({
                "ok": False,
                "error": "rate_limited",
                "retry_after": 1,
            }), 429

        # 3. parse body
        try:
            payload = request.get_json(force=False, silent=False)
        except Exception as exc:
            return jsonify({
                "ok": False,
                "error": "invalid_json",
                "message": str(exc),
            }), 400

        # 4. ingestion pipeline
        try:
            result = pipeline.process(payload or {})
        except PayloadTooLarge as exc:
            return jsonify({"ok": False, "error": exc.code, "message": str(exc)}), exc.status
        except ValidationError as exc:
            return jsonify({"ok": False, "error": exc.code, "message": str(exc)}), exc.status
        except IngestionError as exc:
            return jsonify({"ok": False, "error": exc.code, "message": str(exc)}), exc.status
        except Exception:
            logger.exception("ingestion pipeline crashed")
            return jsonify({
                "ok": False,
                "error": "internal_error",
            }), 500

        return jsonify(result.to_dict()), 200

    @bp.route("/health", methods=["GET"])
    def health():
        return jsonify({
            "ok": True,
            "service": "netguard-edr-api",
        })

    if include_read_endpoints:
        @bp.route("/hosts", methods=["GET"])
        @require_agent_key(key_store)
        def list_hosts():
            # Read-only: list known hosts and their risk. No rate-limit
            # (calls are cheap and read-only).
            limit = min(int(request.args.get("limit", 200)), 1000)
            hosts = repo.list_hosts(limit=limit)
            return jsonify({
                "ok": True,
                "hosts": [h.to_dict() for h in hosts],
            })

        @bp.route("/alerts", methods=["GET"])
        @require_agent_key(key_store)
        def list_alerts():
            host = request.args.get("host_id")
            status = request.args.get("status")
            since = request.args.get("since")
            limit = min(int(request.args.get("limit", 200)), 1000)
            alerts = repo.list_alerts(
                host_id=host, since_iso=since, status=status, limit=limit,
            )
            return jsonify({
                "ok": True,
                "alerts": [a.to_dict() for a in alerts],
            })

    return bp


# ── Standalone dev server ────────────────────────────────────────────


def create_app() -> Any:
    """Create a minimal Flask app exposing the EDR blueprint only."""
    from flask import Flask  # lazy

    app = Flask("netguard-edr")

    db_path = os.environ.get("NETGUARD_EDR_DB", "")
    repo = get_repository("sqlite", db_path=db_path or None)
    repo.init_schema()

    from .auth import EnvKeyStore
    key_store = EnvKeyStore.from_env()

    bp = build_blueprint(repo, key_store)
    app.register_blueprint(bp)

    return app


if __name__ == "__main__":
    logging.basicConfig(
        level=os.environ.get("NETGUARD_LOG_LEVEL", "INFO"),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    app = create_app()
    host = os.environ.get("NETGUARD_BIND_HOST", "127.0.0.1")
    port = int(os.environ.get("NETGUARD_BIND_PORT", "5000"))
    app.run(host=host, port=port, debug=False)
