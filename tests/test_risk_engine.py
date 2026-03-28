"""Tests — RiskEngine"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from engine.risk_engine import RiskEngine


@pytest.fixture
def engine():
    return RiskEngine(decay_enabled=False)  # disable decay for deterministic tests


def _alert(severity, host="host-01", tactic="execution"):
    return {
        "host_id":      host,
        "severity":     severity,
        "event_type":   "test_event",
        "rule_name":    "Test Rule",
        "mitre_tactic": tactic,
        "mitre":        {"tactic": tactic, "technique": "T1059"},
        "timestamp":    "2026-01-01T00:00:00Z",
    }


class TestScoreCalculation:
    def test_single_critical_event_has_nonzero_score(self, engine):
        score = engine.ingest_event(_alert("CRITICAL"))
        assert score > 0

    def test_high_severity_scores_higher_than_low(self, engine):
        e1 = RiskEngine(decay_enabled=False)
        e2 = RiskEngine(decay_enabled=False)
        s_high = e1.ingest_event(_alert("HIGH"))
        s_low  = e2.ingest_event(_alert("LOW"))
        assert s_high > s_low

    def test_score_capped_at_100(self, engine):
        for _ in range(20):
            engine.ingest_event(_alert("CRITICAL", tactic="impact"))
        score = engine.get_host("host-01")["score"]
        assert score <= 100

    def test_score_never_negative(self, engine):
        engine.ingest_event(_alert("LOW"))
        assert engine.get_host("host-01")["score"] >= 0


class TestRiskLevel:
    def test_low_score_gives_low_level(self, engine):
        engine.ingest_event(_alert("LOW"))
        host = engine.get_host("host-01")
        assert host["risk_level"] in ("LOW", "MEDIUM")

    def test_many_critical_gives_critical_level(self, engine):
        for _ in range(10):
            engine.ingest_event(_alert("CRITICAL", tactic="impact"))
        host = engine.get_host("host-01")
        assert host["risk_level"] == "CRITICAL"

    def test_risk_levels_are_valid_values(self, engine):
        engine.ingest_event(_alert("HIGH"))
        host = engine.get_host("host-01")
        assert host["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


class TestMultiHost:
    def test_separate_hosts_tracked_independently(self, engine):
        engine.ingest_event(_alert("CRITICAL", host="host-01"))
        engine.ingest_event(_alert("LOW",      host="host-02"))
        h1 = engine.get_host("host-01")
        h2 = engine.get_host("host-02")
        assert h1["score"] > h2["score"]

    def test_get_all_hosts_returns_all(self, engine):
        engine.ingest_event(_alert("HIGH", host="host-A"))
        engine.ingest_event(_alert("LOW",  host="host-B"))
        engine.ingest_event(_alert("MEDIUM", host="host-C"))
        hosts = engine.get_all_hosts()
        ids = {h["host_id"] for h in hosts}
        assert {"host-A", "host-B", "host-C"}.issubset(ids)

    def test_hosts_sorted_by_score_descending(self, engine):
        engine.ingest_event(_alert("CRITICAL", host="low-risk"))
        for _ in range(5):
            engine.ingest_event(_alert("CRITICAL", host="high-risk", tactic="impact"))
        hosts = engine.get_all_hosts()
        scores = [h["score"] for h in hosts]
        assert scores == sorted(scores, reverse=True)


class TestSummary:
    def test_summary_has_expected_keys(self, engine):
        engine.ingest_event(_alert("HIGH"))
        summary = engine.get_summary()
        for key in ("total_hosts","critical_hosts","high_hosts","max_score","avg_score"):
            assert key in summary

    def test_summary_counts_correct(self, engine):
        e = RiskEngine(decay_enabled=False)
        for _ in range(15):
            e.ingest_event(_alert("CRITICAL", host="h1", tactic="impact"))
        summary = e.get_summary()
        assert summary["critical_hosts"] >= 1


class TestReport:
    def test_report_has_all_sections(self, engine):
        engine.ingest_event(_alert("HIGH"))
        report = engine.generate_report("host-01")
        for key in ("host_id","score","risk_level","summary","by_severity","tactics"):
            assert key in report

    def test_report_unknown_host_returns_error(self, engine):
        report = engine.generate_report("nonexistent-host")
        assert "error" in report

    def test_reset_host_clears_data(self, engine):
        engine.ingest_event(_alert("CRITICAL"))
        assert engine.get_host("host-01") is not None
        engine.reset_host("host-01")
        assert engine.get_host("host-01") is None
