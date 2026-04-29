from __future__ import annotations

from datetime import datetime, timedelta, timezone

from dashboard.soc_view import agent_liveness_from_last_seen


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def test_agent_liveness_marks_recent_agent_online():
    now = datetime(2026, 4, 29, 12, 0, tzinfo=timezone.utc)
    last_seen = _iso(now - timedelta(seconds=120))

    status = agent_liveness_from_last_seen(last_seen, now=now)

    assert status["agent_status"] == "online"
    assert status["last_seen_age_seconds"] == 120
    assert status["last_seen_age_label"] == "2m ago"


def test_agent_liveness_marks_stale_and_offline_agents():
    now = datetime(2026, 4, 29, 12, 0, tzinfo=timezone.utc)

    stale = agent_liveness_from_last_seen(
        _iso(now - timedelta(minutes=10)),
        now=now,
    )
    offline = agent_liveness_from_last_seen(
        _iso(now - timedelta(hours=2)),
        now=now,
    )

    assert stale["agent_status"] == "stale"
    assert offline["agent_status"] == "offline"
    assert offline["last_seen_age_label"] == "2h ago"


def test_agent_liveness_handles_missing_or_invalid_timestamp():
    assert agent_liveness_from_last_seen("") == {
        "agent_status": "offline",
        "last_seen_age_seconds": None,
        "last_seen_age_label": "never seen",
    }
    assert agent_liveness_from_last_seen("not-a-date")["agent_status"] == "offline"
