from __future__ import annotations

from datetime import datetime, timezone

from flask import Flask

from dashboard.soc_view import build_soc_blueprint
from storage.repository import Alert, Event, Host
from storage.sqlite_repository import SqliteRepository


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def test_soc_overview_exposes_recent_activity_and_severity_distribution(tmp_path):
    repo = SqliteRepository(tmp_path / "edr.db")
    repo.init_schema()

    timestamp = _now_iso()
    repo.upsert_host(
        Host(
            host_id="host-001",
            hostname="analyst-workstation",
            platform="Windows",
            agent_version="1.0.0",
            last_seen=timestamp,
            first_seen=timestamp,
            risk_score=45,
            risk_level="HIGH",
            metadata={
                "local_ip": "192.168.15.20",
                "mac_address": "aa:bb:cc:dd:ee:ff",
                "default_gateway": "192.168.15.1",
            },
        ),
    )
    repo.insert_event(
        Event(
            event_id="event-001",
            host_id="host-001",
            timestamp=timestamp,
            event_type="process",
            severity="HIGH",
            confidence=90,
            process_name="powershell.exe",
            command_line="powershell -enc SQBFAFgA",
            evidence="PowerShell encoded command",
        ),
    )
    repo.insert_alert(
        Alert(
            alert_id="alert-001",
            host_id="host-001",
            rule_id="NG-EXEC-PS-ENC-001",
            severity="HIGH",
            confidence=90,
            timestamp=timestamp,
            title="Suspicious PowerShell encoded command",
            evidence="powershell -enc",
            mitre_tactic="Execution",
            mitre_technique="T1059.001",
            event_ids=["event-001"],
        ),
    )

    app = Flask(__name__)
    app.register_blueprint(build_soc_blueprint(repo, url_prefix="/soc"))

    response = app.test_client().get("/soc/api/overview")
    assert response.status_code == 200
    body = response.get_json()

    assert body["ok"] is True
    assert body["summary"]["alert_count_24h"] == 1
    assert body["severity_counts"]["high"] == 1
    assert body["hosts"][0]["metadata"]["local_ip"] == "192.168.15.20"
    assert body["hosts"][0]["metadata"]["default_gateway"] == "192.168.15.1"
    assert {item["severity"] for item in body["severity_distribution"]} == {
        "critical",
        "high",
        "medium",
        "low",
        "info",
    }
    assert body["recent_alerts"][0]["rule_id"] == "NG-EXEC-PS-ENC-001"
    assert body["recent_alerts"][0]["severity"] == "high"
    assert body["recent_events"][0]["event_type"] == "process"
    assert body["recent_events"][0]["severity"] == "high"


def test_soc_grid_html_uses_mount_aware_api_paths(tmp_path):
    repo = SqliteRepository(tmp_path / "edr.db")
    repo.init_schema()

    app = Flask(__name__)
    app.register_blueprint(build_soc_blueprint(repo, url_prefix="/soc/grid"))

    response = app.test_client().get("/soc/grid")
    assert response.status_code == 200
    html = response.get_data(as_text=True)

    assert "const API_BASE = window.location.pathname.replace" in html
    assert 'fetchJson("/api/overview")' in html
    assert 'fetchJson("/api/rules")' in html
    assert "function hostNetworkSummary" in html
    assert 'fetch("api/overview"' not in html
    assert 'fetch("api/rules"' not in html
