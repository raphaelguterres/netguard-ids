"""Tests — RuleExecutor"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from engine.rule_executor import execute_rules, RuleRegistry, make_alert, Alert


# ── Sample rules ──────────────────────────────────────────────────

def rule_always_fires(event: dict):
    return make_alert(
        rule_name="Always Fires", event_type="test",
        severity="HIGH", description="test alert",
        details=event.get("details", {}),
    )

def rule_never_fires(event: dict):
    return None

def rule_fires_on_sqli(event: dict):
    if event.get("event_type") == "web_sqli":
        return make_alert(
            rule_name="SQLi Rule", event_type="web_sqli",
            severity="HIGH", description="sqli detected",
            details=event.get("details", {}),
        )
    return None

def rule_raises_exception(event: dict):
    raise ValueError("Simulated rule crash")

def rule_returns_multiple(event: dict):
    return [
        make_alert("Multi R1", "test", "LOW", "first", {}),
        make_alert("Multi R2", "test", "MEDIUM", "second", {}),
    ]


# ── Tests ─────────────────────────────────────────────────────────

class TestExecuteRules:
    def test_empty_rules_returns_no_alerts(self):
        result = execute_rules({"event_type": "test"}, [])
        assert result.alerts == []
        assert result.rules_executed == 0

    def test_always_fires_generates_alert(self):
        result = execute_rules({"event_type": "test", "details": {}}, [rule_always_fires])
        assert result.has_alerts
        assert len(result.alerts) == 1

    def test_never_fires_generates_no_alert(self):
        result = execute_rules({"event_type": "test"}, [rule_never_fires])
        assert not result.has_alerts

    def test_conditional_rule_fires_on_matching_event(self):
        event = {"event_type": "web_sqli", "details": {}}
        result = execute_rules(event, [rule_fires_on_sqli])
        assert result.has_alerts
        assert result.alerts[0].rule_name == "SQLi Rule"

    def test_conditional_rule_skips_non_matching_event(self):
        event = {"event_type": "process_started", "details": {}}
        result = execute_rules(event, [rule_fires_on_sqli])
        assert not result.has_alerts

    def test_failed_rule_does_not_break_pipeline(self):
        rules = [rule_raises_exception, rule_always_fires]
        result = execute_rules({"event_type": "test", "details": {}}, rules)
        assert result.has_alerts          # always_fires still ran
        assert result.rules_failed == 1   # exception was captured

    def test_multiple_alerts_from_single_rule(self):
        result = execute_rules({"event_type": "test"}, [rule_returns_multiple])
        assert len(result.alerts) == 2

    def test_rules_executed_count(self):
        result = execute_rules({}, [rule_always_fires, rule_never_fires, rule_fires_on_sqli])
        assert result.rules_executed == 3

    def test_highest_severity_property(self):
        result = execute_rules({"event_type": "test", "details": {}},
                               [rule_always_fires, rule_returns_multiple])
        assert result.highest_severity == "HIGH"

    def test_host_id_injected_into_alert(self):
        event = {"event_type": "test", "host_id": "server-01", "details": {}}
        result = execute_rules(event, [rule_always_fires])
        assert result.alerts[0].host_id == "server-01"

    def test_duration_ms_is_positive(self):
        result = execute_rules({}, [rule_always_fires])
        assert result.duration_ms >= 0


class TestRuleRegistry:
    def test_register_and_count(self):
        reg = RuleRegistry()
        reg.register(rule_always_fires)
        assert reg.count == 1

    def test_active_count_reflects_enabled(self):
        reg = RuleRegistry()
        reg.register(rule_always_fires)
        reg.register(rule_never_fires)
        reg.disable("rule_never_fires")
        assert reg.active_count == 1

    def test_disabled_rule_does_not_run(self):
        reg = RuleRegistry()
        reg.register(rule_always_fires)
        reg.disable("rule_always_fires")
        result = reg.execute({"event_type": "test", "details": {}})
        assert not result.has_alerts

    def test_re_enable_runs_again(self):
        reg = RuleRegistry()
        reg.register(rule_always_fires)
        reg.disable("rule_always_fires")
        reg.enable("rule_always_fires")
        result = reg.execute({"event_type": "test", "details": {}})
        assert result.has_alerts

    def test_tag_filter_runs_only_tagged(self):
        reg = RuleRegistry()
        reg.register(rule_always_fires, tags=["web"])
        reg.register(rule_never_fires, tags=["process"])
        result = reg.execute({"event_type": "test", "details": {}}, tags=["process"])
        assert not result.has_alerts  # only never_fires ran

    def test_chaining(self):
        reg = (RuleRegistry()
               .register(rule_always_fires)
               .register(rule_never_fires))
        assert reg.count == 2


class TestMakeAlert:
    def test_alert_has_correct_fields(self):
        a = make_alert(
            rule_name="Test Rule", event_type="test_event",
            severity="HIGH", description="test desc",
            details={"key": "value"},
            tactic="execution", technique="T1059",
        )
        assert a.rule_name == "Test Rule"
        assert a.severity == "HIGH"
        assert a.mitre_tactic == "execution"
        assert a.mitre_tech == "T1059"

    def test_alert_to_dict_has_all_keys(self):
        a = make_alert("R", "e", "LOW", "d", {})
        d = a.to_dict()
        for key in ("timestamp","host_id","rule_name","event_type",
                    "severity","source","description","details","mitre","tags"):
            assert key in d

    def test_alert_timestamp_is_set(self):
        a = make_alert("R", "e", "LOW", "d", {})
        assert len(a.timestamp) > 10
