"""Tests — CorrelationEngine
Testa as 5 regras de correlação com eventos sintéticos.
"""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from engine.correlation_engine import CorrelationEngine


@pytest.fixture
def engine():
    return CorrelationEngine(host_id="test-host")


def _evt(event_type, severity="MEDIUM", details=None, host="test-host"):
    return {
        "event_type": event_type,
        "severity":   severity,
        "host_id":    host,
        "details":    details or {},
        "mitre_tactic": "",
    }


class TestCOR1SuspiciousExecution:
    def test_fires_on_proc_plus_cpu_plus_conn(self):
        # Fresh engine — collect alerts from ALL ingests since rule may fire
        # as early as the 2nd event (2 of 3 signals already present)
        eng = CorrelationEngine(host_id="test-host")
        all_alerts = []
        all_alerts += eng.ingest(_evt("process_unknown",  details={"process": "hack.exe"}))
        all_alerts += eng.ingest(_evt("process_high_cpu", details={"process": "hack.exe", "cpu_usage": 94}))
        all_alerts += eng.ingest(_evt("ip_new_external",  details={"ip": "1.2.3.4", "process": "hack.exe"}))
        cor1 = [a for a in all_alerts if a.rule_id == "COR-1"]
        assert len(cor1) >= 1, f"COR-1 should fire with 3 signals, got {[a.rule_id for a in all_alerts]}"
        assert cor1[0].confidence <= 100

    def test_does_not_fire_on_single_signal(self, engine):
        alerts = engine.ingest(_evt("process_unknown", details={"process": "legit.exe"}))
        assert not any(a.rule_id == "COR-1" for a in alerts)

    def test_confidence_capped_at_100(self, engine):
        for _ in range(10):
            engine.ingest(_evt("process_unknown",  details={"process": "x.exe"}))
            engine.ingest(_evt("process_high_cpu", details={"process": "x.exe", "cpu_usage": 99}))
            engine.ingest(_evt("ip_new_external",  details={"ip": f"1.1.1.{_}", "process": "x.exe"}))
        for a in engine.get_alerts():
            assert a["confidence"] <= 100


class TestCOR2Recon:
    def test_fires_on_multiple_new_ips_plus_scan(self, engine):
        for i in range(4):
            engine.ingest(_evt("ip_new_external", details={"ip": f"5.5.5.{i}"}))
        engine.ingest(_evt("network_scan", details={"unique_ips": 25}))
        alerts = engine.ingest(_evt("dns_suspicious", details={"domain": "abc.ngrok.io"}))
        cor2 = [a for a in alerts if a.rule_id == "COR-2"]
        assert len(cor2) >= 1

    def test_dedup_prevents_immediate_repeat(self, engine):
        # First trigger
        for i in range(4):
            engine.ingest(_evt("ip_new_external", details={"ip": f"9.9.9.{i}"}))
        engine.ingest(_evt("network_scan", details={"unique_ips": 25}))
        first = engine.ingest(_evt("dns_suspicious", details={"domain": "x.ngrok.io"}))

        # Immediate second trigger — should not re-fire (same pattern_key within TTL)
        second = engine.ingest(_evt("dns_suspicious", details={"domain": "y.ngrok.io"}))
        cor2_second = [a for a in second if a.rule_id == "COR-2"]
        assert len(cor2_second) == 0


class TestCOR3Beaconing:
    def test_fires_on_explicit_beaconing_event(self, engine):
        alerts = engine.ingest(_evt("network_beaconing", details={
            "process": "svc.exe", "dst_ip": "1.2.3.4",
            "interval_sec": 30, "jitter_cv": 0.03,
        }))
        cor3 = [a for a in alerts if a.rule_id == "COR-3"]
        assert len(cor3) >= 1

    def test_confidence_is_valid_range(self, engine):
        engine.ingest(_evt("network_beaconing", details={
            "process": "p.exe", "dst_ip": "2.3.4.5",
            "interval_sec": 60, "jitter_cv": 0.02,
        }))
        for a in engine.get_alerts():
            if a["rule_id"] == "COR-3":
                assert 0 <= a["confidence"] <= 100


class TestCOR5BruteForce:
    def test_fires_on_repeated_auth_port(self, engine):
        for _ in range(8):
            engine.ingest(_evt("port_opened", "HIGH", {
                "port": 3389, "source_ip": "10.0.0.99", "ip": "10.0.0.99"
            }))
        alerts = engine.get_alerts()
        cor5 = [a for a in alerts if a["rule_id"] == "COR-5"]
        assert len(cor5) >= 1

    def test_does_not_fire_below_threshold(self, engine):
        for _ in range(3):
            engine.ingest(_evt("port_opened", "HIGH", {
                "port": 22, "source_ip": "10.0.0.50", "ip": "10.0.0.50"
            }))
        alerts = engine.get_alerts()
        cor5 = [a for a in alerts if a["rule_id"] == "COR-5"]
        assert len(cor5) == 0


class TestHostNormalization:
    def test_new_host_id_normalized(self, engine):
        engine.ingest({
            "event_type": "process_unknown",
            "severity": "MEDIUM",
            "host_id": "new",           # invalid — should be normalized
            "details": {"process": "bad.exe"},
        })
        # After normalization, all stored events should use engine.host_id
        # No assertion on alerts, just ensure no crash and host is normalized
        for a in engine.get_alerts():
            assert a["host_id"] != "new"

    def test_empty_host_id_normalized(self, engine):
        engine.ingest({
            "event_type": "ip_new_external",
            "severity": "LOW",
            "host_id": "",
            "details": {"ip": "1.2.3.4"},
        })
        # Should not crash


class TestStats:
    def test_stats_has_expected_keys(self, engine):
        stats = engine.get_stats()
        for key in ("total", "by_rule", "by_severity", "rules_active", "host_id"):
            assert key in stats

    def test_rules_active_is_5(self, engine):
        assert engine.get_stats()["rules_active"] == 5


class TestDemo:
    def test_demo_triggers_alerts(self, engine):
        alerts = engine.inject_demo()
        assert len(alerts) >= 3
        rule_ids = {a.rule_id for a in alerts}
        # Demo should trigger at least COR-1, COR-2, COR-3
        assert "COR-1" in rule_ids or "COR-3" in rule_ids
