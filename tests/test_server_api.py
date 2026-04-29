"""
Tests for server.api / server.auth / server.ingestion / server.rate_limit.

Uses Flask test client; falls back gracefully if Flask isn't installed
(the auth + rate-limit + ingestion tests still pass without Flask).
"""

from __future__ import annotations

import pytest

from server.auth import (
    AgentPrincipal,
    EnvKeyStore,
    StaticKeyStore,
    extract_api_key,
    hash_api_key,
)
from server.ingestion import (
    IngestionPipeline,
    PayloadTooLarge,
    ValidationError,
)
from server.rate_limit import TokenBucketLimiter
from storage.sqlite_repository import SqliteRepository


def _repo(tmp_path) -> SqliteRepository:
    repo = SqliteRepository(db_path=tmp_path / "edr_api.db")
    repo.init_schema()
    return repo


# ── auth ─────────────────────────────────────────────────────────────


def test_hash_api_key_stable():
    assert hash_api_key("nga_abc") == hash_api_key("nga_abc")
    assert hash_api_key("nga_abc") != hash_api_key("nga_abd")


def test_env_key_store_accepts_listed():
    store = EnvKeyStore(["nga_one", "nga_two"])
    assert store.verify("nga_one") is not None
    assert store.verify("nga_two") is not None
    assert store.verify("nga_other") is None
    assert store.verify("") is None


def test_env_key_store_constant_time_safe():
    # We can't directly test timing, but we can test correctness with
    # very long fake keys (compare_digest fast-paths different lengths).
    store = EnvKeyStore(["x" * 256])
    assert store.verify("y" * 256) is None
    assert store.verify("x" * 256) is not None


def test_env_key_store_from_env(monkeypatch):
    monkeypatch.setenv("NETGUARD_AGENT_KEYS", "nga_a, nga_b ,, ")
    store = EnvKeyStore.from_env()
    assert store.verify("nga_a") is not None
    assert store.verify("nga_b") is not None


def test_static_key_store_returns_principal():
    p = AgentPrincipal(key_id="agent-7", host_id="h1")
    store = StaticKeyStore({"nga_secret": p})
    out = store.verify("nga_secret")
    assert out is not None
    assert out.key_id == "agent-7"
    assert out.host_id == "h1"


class _Headers(dict):
    def get(self, k, default=None):
        for kk, vv in self.items():
            if kk.lower() == k.lower():
                return vv
        return default


def test_extract_api_key_supports_both_headers():
    h = _Headers({"X-API-Key": "nga_1"})
    assert extract_api_key(h) == "nga_1"
    h2 = _Headers({"X-NetGuard-Agent-Key": "nga_2"})
    assert extract_api_key(h2) == "nga_2"
    h3 = _Headers({"Authorization": "Bearer nga_3"})
    assert extract_api_key(h3) == "nga_3"
    h4 = _Headers({})
    assert extract_api_key(h4) == ""


# ── rate limit ───────────────────────────────────────────────────────


def test_token_bucket_basic():
    rl = TokenBucketLimiter(rate_per_sec=1.0, burst=3)
    assert rl.allow("k") is True
    assert rl.allow("k") is True
    assert rl.allow("k") is True
    assert rl.allow("k") is False  # 4th in burst window


def test_token_bucket_independent_keys():
    rl = TokenBucketLimiter(rate_per_sec=1.0, burst=2)
    assert rl.allow("a")
    assert rl.allow("a")
    assert not rl.allow("a")
    # different key → fresh bucket
    assert rl.allow("b")


def test_token_bucket_invalid_config():
    with pytest.raises(ValueError):
        TokenBucketLimiter(rate_per_sec=0, burst=1)
    with pytest.raises(ValueError):
        TokenBucketLimiter(rate_per_sec=1, burst=0)


# ── ingestion ────────────────────────────────────────────────────────


def test_ingestion_validates_host_id(tmp_path):
    pipe = IngestionPipeline(_repo(tmp_path))
    with pytest.raises(ValidationError):
        pipe.process({"events": []})


def test_ingestion_validates_events_is_list(tmp_path):
    pipe = IngestionPipeline(_repo(tmp_path))
    with pytest.raises(ValidationError):
        pipe.process({"host_id": "h", "events": "not-a-list"})


def test_ingestion_rejects_oversized_batch(tmp_path):
    pipe = IngestionPipeline(_repo(tmp_path))
    huge = [{"event_type": "process_execution"}] * 600
    with pytest.raises(PayloadTooLarge):
        pipe.process({"host_id": "h", "events": huge})


def test_ingestion_persists_events_and_dedups(tmp_path):
    repo = _repo(tmp_path)
    pipe = IngestionPipeline(repo)
    payload = {
        "host_id": "h1",
        "hostname": "WIN-T",
        "agent_version": "1.0.0",
        "events": [
            {
                "event_id": "ev-1",
                "timestamp": "2026-04-27T12:00:00Z",
                "event_type": "process_execution",
                "process_name": "notepad.exe",
                "command_line": "notepad.exe foo.txt",
            },
        ],
    }
    r1 = pipe.process(payload)
    assert r1.accepted_events == 1
    assert r1.new_events == 1
    # Replay → no new events
    r2 = pipe.process(payload)
    assert r2.new_events == 0


def test_ingestion_replay_does_not_duplicate_detection_alerts(tmp_path):
    repo = _repo(tmp_path)
    pipe = IngestionPipeline(repo)
    payload = {
        "host_id": "h-retry",
        "hostname": "WIN-RETRY",
        "agent_version": "1.0.0",
        "events": [
            {
                "event_id": "ev-retry-ps",
                "timestamp": "2026-04-27T12:00:00Z",
                "event_type": "process_execution",
                "process_name": "powershell.exe",
                "command_line": "powershell -enc SQB3AHIAaaaaaaaaaaaaaaaaaaaaaaaaaa",
            },
        ],
    }

    first = pipe.process(payload)
    second = pipe.process(payload)

    assert first.alerts
    assert second.alerts
    assert first.alerts[0].alert_id == second.alerts[0].alert_id
    stored = [
        item for item in repo.list_alerts(host_id="h-retry", limit=20)
        if item.rule_id == "NG-EXEC-PS-ENC-001"
    ]
    assert len(stored) == 1


def test_ingestion_runs_detection(tmp_path):
    repo = _repo(tmp_path)
    pipe = IngestionPipeline(repo)
    result = pipe.process({
        "host_id": "h2",
        "hostname": "WIN-T",
        "agent_version": "1.0.0",
        "events": [
            {
                "event_type": "process_execution",
                "process_name": "powershell.exe",
                "command_line": "powershell -enc SQB3AHIAaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "timestamp": "2026-04-27T12:00:00Z",
            },
        ],
    })
    assert any(a.rule_id == "NG-EXEC-PS-ENC-001" for a in result.alerts)
    assert result.risk_score >= 30  # one HIGH alert
    assert result.risk_level in {"MEDIUM", "HIGH", "CRITICAL"}


def test_ingestion_normalizes_legacy_envelope(tmp_path):
    """The collector posts events with `details.evidence` etc.; pipeline
    should still parse them correctly."""
    repo = _repo(tmp_path)
    pipe = IngestionPipeline(repo)
    result = pipe.process({
        "host_id": "h3",
        "display_name": "WIN-LEGACY",
        "platform": "windows",
        "agent_version": "1.0.0",
        "events": [
            {
                "event_id": "legacy-1",
                "event_type": "script_execution",
                "process_name": "powershell.exe",
                "command_line": "powershell -enc dGVzdGluZ19sb25nX2Jhc2U2NF9wYXlsb2Fk",
                "timestamp": "2026-04-27T12:00:00Z",
                "details": {"confidence": 95, "evidence": "from collector"},
            },
        ],
    })
    assert result.new_events == 1
    assert result.alerts


def test_ingestion_derives_event_id_when_missing(tmp_path):
    repo = _repo(tmp_path)
    pipe = IngestionPipeline(repo)
    payload = {
        "host_id": "h4",
        "events": [{
            "event_type": "process_execution",
            "process_name": "x.exe",
            "command_line": "x.exe args",
            "timestamp": "2026-04-27T13:00:00Z",
        }],
    }
    r1 = pipe.process(payload)
    r2 = pipe.process(payload)
    # Same payload → derived id is deterministic → second call dedups.
    assert r1.new_events == 1
    assert r2.new_events == 0


def test_ingestion_empty_batch_still_updates_host_last_seen(tmp_path):
    repo = _repo(tmp_path)
    pipe = IngestionPipeline(repo)
    result = pipe.process({
        "host_id": "idle-host",
        "hostname": "WIN-IDLE",
        "agent_version": "1.0.0",
        "events": [],
    })
    host = repo.get_host("idle-host")
    assert result.accepted_events == 0
    assert host is not None
    assert host.hostname == "WIN-IDLE"
    assert host.last_seen


# ── Flask end-to-end ─────────────────────────────────────────────────


def _flask_or_skip():
    try:
        import flask  # noqa
        return True
    except ImportError:
        return False


@pytest.mark.skipif(not _flask_or_skip(), reason="flask not installed")
def test_flask_endpoint_requires_api_key(tmp_path):
    from flask import Flask

    from server.api import build_blueprint
    from server.auth import StaticKeyStore

    app = Flask("test")
    repo = _repo(tmp_path)
    store = StaticKeyStore({"nga_test": AgentPrincipal(key_id="t")})
    app.register_blueprint(build_blueprint(repo, store))

    client = app.test_client()
    # Missing key → 401
    r = client.post("/api/events", json={"host_id": "h", "events": []})
    assert r.status_code == 401

    # Bad key → 403
    r = client.post(
        "/api/events",
        headers={"X-API-Key": "wrong"},
        json={"host_id": "h", "events": []},
    )
    assert r.status_code == 403

    # Good key → 200
    r = client.post(
        "/api/events",
        headers={"X-API-Key": "nga_test"},
        json={"host_id": "h", "events": []},
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is True
    assert body["host_id"] == "h"


@pytest.mark.skipif(not _flask_or_skip(), reason="flask not installed")
def test_flask_endpoint_rejects_bad_content_type(tmp_path):
    from flask import Flask

    from server.api import build_blueprint
    from server.auth import StaticKeyStore

    app = Flask("test")
    repo = _repo(tmp_path)
    store = StaticKeyStore({"nga_test": AgentPrincipal(key_id="t")})
    app.register_blueprint(build_blueprint(repo, store))

    r = app.test_client().post(
        "/api/events",
        headers={"X-API-Key": "nga_test", "Content-Type": "text/plain"},
        data="oh no",
    )
    assert r.status_code == 415


@pytest.mark.skipif(not _flask_or_skip(), reason="flask not installed")
def test_flask_health_endpoint(tmp_path):
    from flask import Flask

    from server.api import build_blueprint
    from server.auth import StaticKeyStore

    app = Flask("test")
    repo = _repo(tmp_path)
    store = StaticKeyStore({"nga_test": AgentPrincipal(key_id="t")})
    app.register_blueprint(build_blueprint(repo, store))

    r = app.test_client().get("/api/health")
    assert r.status_code == 200
    assert r.get_json()["ok"] is True


@pytest.mark.skipif(not _flask_or_skip(), reason="flask not installed")
def test_flask_rate_limit_kicks_in(tmp_path):
    from flask import Flask

    from server.api import build_blueprint
    from server.auth import StaticKeyStore
    from server.rate_limit import TokenBucketLimiter

    app = Flask("test")
    repo = _repo(tmp_path)
    store = StaticKeyStore({"nga_test": AgentPrincipal(key_id="t")})
    limiter = TokenBucketLimiter(rate_per_sec=0.001, burst=2)
    app.register_blueprint(build_blueprint(repo, store, limiter=limiter))

    client = app.test_client()
    headers = {"X-API-Key": "nga_test"}
    body = {"host_id": "h", "events": []}
    assert client.post("/api/events", headers=headers, json=body).status_code == 200
    assert client.post("/api/events", headers=headers, json=body).status_code == 200
    # 3rd burns the bucket
    r = client.post("/api/events", headers=headers, json=body)
    assert r.status_code == 429
