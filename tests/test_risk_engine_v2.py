"""
Tests for engine.soc_risk_scorer (spec-aligned).
"""

import uuid

from engine.soc_risk_scorer import (
    LEVEL_BANDS,
    SEV_INCREMENTS,
    aggregate_per_host,
    level_for,
    score_alerts,
    severity_increment,
)
from storage.repository import Alert


def _alert(host="h1", severity="low") -> Alert:
    return Alert(
        alert_id=str(uuid.uuid4()),
        host_id=host,
        rule_id="NG-T",
        severity=severity,
        confidence=80,
        timestamp="2026-04-27T12:00:00Z",
    )


def test_severity_increments_match_spec():
    # Low=+5, Medium=+15, High=+30, Critical=+50
    assert SEV_INCREMENTS == {"low": 5, "medium": 15, "high": 30, "critical": 50}


def test_severity_increment_unknown_zero():
    assert severity_increment("foo") == 0
    assert severity_increment("") == 0


def test_level_bands_thresholds():
    # 0-29 LOW, 30-59 MEDIUM, 60-79 HIGH, 80-100 CRITICAL
    assert level_for(0) == "LOW"
    assert level_for(29) == "LOW"
    assert level_for(30) == "MEDIUM"
    assert level_for(59) == "MEDIUM"
    assert level_for(60) == "HIGH"
    assert level_for(79) == "HIGH"
    assert level_for(80) == "CRITICAL"
    assert level_for(100) == "CRITICAL"


def test_level_clamping():
    assert level_for(-10) == "LOW"
    assert level_for(2000) == "CRITICAL"


def test_score_alerts_sums():
    score, level = score_alerts([
        _alert(severity="low"),       # +5
        _alert(severity="medium"),    # +15
        _alert(severity="high"),      # +30
    ])
    assert score == 50
    assert level == "MEDIUM"


def test_score_alerts_caps_at_100():
    score, level = score_alerts([_alert(severity="critical")] * 5)  # 250 → 100
    assert score == 100
    assert level == "CRITICAL"


def test_score_alerts_accepts_dicts():
    score, _ = score_alerts([
        {"severity": "high"},
        {"severity": "high"},
    ])
    assert score == 60


def test_score_with_base():
    score, _ = score_alerts([_alert(severity="medium")], base_score=50)
    assert score == 65


def test_aggregate_per_host():
    a = [
        _alert(host="h1", severity="critical"),
        _alert(host="h1", severity="high"),
        _alert(host="h2", severity="low"),
    ]
    out = aggregate_per_host(a)
    assert out["h1"]["risk_score"] == 80
    assert out["h1"]["risk_level"] == "CRITICAL"
    assert out["h1"]["alert_count"] == 2
    assert out["h2"]["risk_score"] == 5
    assert out["h2"]["risk_level"] == "LOW"


def test_level_bands_are_contiguous():
    # Sanity check the bands cover 0..100 with no gaps and no overlaps.
    coverage = set()
    for _, lo, hi in LEVEL_BANDS:
        for v in range(lo, hi + 1):
            assert v not in coverage, f"overlap at {v}"
            coverage.add(v)
    assert coverage == set(range(0, 101))
