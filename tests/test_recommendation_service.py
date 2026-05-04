from __future__ import annotations

from services.recommendation_service import get_recommended_route


def _assert_safe_read_route(route: str) -> None:
    assert route.startswith(("/soc", "/soc-preview", "/admin/inbox"))
    for marker in ("/api/", "/delete", "/reset", "/rotate", "/revoke", "/actions", "/status"):
        assert marker not in route.lower()


def test_recommends_critical_incidents_before_hosts():
    recommendation = get_recommended_route(
        {
            "overview": {"events_24h": 9},
            "incidents": [{"status": "open", "severity": "critical"}],
            "hosts": [{"host_name": "win-01", "risk_score": 99, "highest_severity": "critical"}],
        }
    )

    assert recommendation["route"] == "/soc/incidents"
    assert recommendation["priority"] == "critical"
    assert recommendation["auto_redirect"] is True
    _assert_safe_read_route(recommendation["route"])


def test_recommends_highest_risk_host_when_no_critical_incident():
    recommendation = get_recommended_route(
        {
            "overview": {"events_24h": 4},
            "incidents": [],
            "hosts": [
                {"host_name": "win low", "risk_score": 35, "highest_severity": "medium"},
                {"host_name": "win critical", "risk_score": 91, "highest_severity": "high", "active_alerts": 3},
            ],
        }
    )

    assert recommendation["route"] == "/soc/hosts/win%20critical"
    assert recommendation["priority"] == "high"
    assert recommendation["auto_redirect"] is True
    _assert_safe_read_route(recommendation["route"])


def test_recommends_agent_health_for_offline_enrolled_agents():
    recommendation = get_recommended_route(
        {
            "overview": {"events_24h": 3},
            "hosts": [
                {"host_name": "win-01", "risk_score": 10, "status": "offline", "agent_enrolled": True},
            ],
        }
    )

    assert recommendation["route"] == "/soc/hosts"
    assert recommendation["priority"] == "medium"
    assert recommendation["auto_redirect"] is False
    _assert_safe_read_route(recommendation["route"])


def test_recommends_onboarding_when_no_telemetry_exists():
    recommendation = get_recommended_route({"overview": {"events_24h": 0}, "hosts": []})

    assert recommendation["route"] == "/soc/hosts"
    assert recommendation["priority"] == "info"
    assert "Connect an agent" in recommendation["label"]
    _assert_safe_read_route(recommendation["route"])


def test_recommends_operator_inbox_for_recent_alerts():
    recommendation = get_recommended_route(
        {
            "overview": {"events_24h": 5},
            "hosts": [{"host_name": "win-01", "risk_score": 22, "status": "online"}],
            "alerts": [{"severity": "medium"}],
        }
    )

    assert recommendation["route"] == "/admin/inbox"
    assert recommendation["priority"] == "medium"
    assert recommendation["auto_redirect"] is False
    _assert_safe_read_route(recommendation["route"])
