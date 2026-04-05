from engine.attack_timeline import AttackTimelineEngine


def test_build_timeline():
    engine = AttackTimelineEngine()

    events = [
        {
            "timestamp": "2026-03-31T19:10:02Z",
            "host_id": "workstation-01",
            "event_type": "port_scan_suspected",
            "severity": "low",
            "message": "Port scan suspected from external source",
            "source": "netguard",
            "metadata": {},
        },
        {
            "timestamp": "2026-03-31T19:10:15Z",
            "host_id": "workstation-01",
            "event_type": "multiple_failed_logins",
            "severity": "high",
            "message": "Multiple failed logins detected",
            "source": "netguard",
            "metadata": {},
        },
        {
            "timestamp": "2026-03-31T19:10:45Z",
            "host_id": "workstation-01",
            "event_type": "suspicious_process_execution",
            "severity": "high",
            "message": "Encoded PowerShell execution detected",
            "source": "netguard",
            "metadata": {},
        },
    ]

    timelines = engine.build_timelines(events)

    assert len(timelines) == 1
    assert timelines[0].host_id == "workstation-01"
    assert timelines[0].risk_score > 0
    assert len(timelines[0].steps) == 3
    assert timelines[0].steps[0].phase == "Reconnaissance"