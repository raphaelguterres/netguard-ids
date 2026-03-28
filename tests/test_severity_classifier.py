"""Tests — SeverityClassifier"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from engine.severity_classifier import classify_severity, severity_score, is_high_priority


class TestEventType:
    def test_sqli_is_high(self):
        assert classify_severity(event_type="web_sqli") == "HIGH"

    def test_xss_is_high(self):
        assert classify_severity(event_type="web_xss") == "HIGH"

    def test_network_spike_is_high(self):
        assert classify_severity(event_type="network_spike") == "HIGH"

    def test_process_unknown_is_medium(self):
        assert classify_severity(event_type="process_unknown") == "MEDIUM"

    def test_new_ip_is_low(self):
        assert classify_severity(event_type="ip_new_external") == "LOW"

    def test_unknown_defaults_low(self):
        assert classify_severity(event_type="totally_unknown_xyz") == "LOW"

    def test_empty_defaults_low(self):
        assert classify_severity(event_type="") == "LOW"


class TestRuleName:
    def test_sql_injection_keyword(self):
        assert classify_severity(rule_name="SQL Injection Detectado") in ("HIGH", "CRITICAL")

    def test_brute_force_keyword(self):
        assert classify_severity(rule_name="Brute Force via SSH") in ("HIGH", "CRITICAL")

    def test_unknown_process_keyword(self):
        assert classify_severity(rule_name="Processo Desconhecido") == "MEDIUM"

    def test_new_ip_keyword(self):
        assert classify_severity(rule_name="New External IP") == "LOW"


class TestDetails:
    def test_cpu_95_is_critical(self):
        assert classify_severity(details={"cpu_usage": 95}) == "CRITICAL"

    def test_cpu_85_is_high(self):
        assert classify_severity(details={"cpu_usage": 85}) == "HIGH"

    def test_conn_count_110_is_critical(self):
        assert classify_severity(details={"conn_count": 110}) == "CRITICAL"


class TestHighestWins:
    def test_medium_type_with_high_cpu_escalates(self):
        # cpu_usage=92 >= 90 → CRITICAL wins over MEDIUM from process_unknown
        result = classify_severity(event_type="process_unknown", details={"cpu_usage": 92})
        assert result == "CRITICAL"

    def test_medium_type_with_high_cpu_yields_high(self):
        # cpu_usage=85 >= 80 → HIGH wins over MEDIUM from process_unknown
        result = classify_severity(event_type="process_unknown", details={"cpu_usage": 85})
        assert result == "HIGH"

    def test_critical_current_preserved(self):
        assert classify_severity(event_type="ip_new_external", current="CRITICAL") == "CRITICAL"

    def test_low_current_overridden_by_rule(self):
        result = classify_severity(current="LOW", rule_name="SQL Injection Detectado")
        assert result in ("HIGH", "CRITICAL")


class TestHelpers:
    def test_score_order(self):
        assert severity_score("LOW") < severity_score("MEDIUM") < severity_score("HIGH") < severity_score("CRITICAL")

    def test_high_priority_true(self):
        assert is_high_priority("HIGH") and is_high_priority("CRITICAL")

    def test_high_priority_false(self):
        assert not is_high_priority("MEDIUM") and not is_high_priority("LOW")
