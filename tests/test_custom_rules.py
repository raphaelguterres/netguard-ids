"""
Tests for custom_rules.py
"""
from custom_rules import evaluate_rule, _extract_field, _eval_condition


def _rule(logic="AND", conditions=None, severity="HIGH"):
    return {
        "name": "test", "logic": logic, "severity": severity,
        "conditions": conditions or [],
        "enabled": True,
    }

def _event(**kwargs):
    base = {
        "event_type": "test_event",
        "severity": "medium",
        "source": "192.168.1.1",
        "host_id": "srv-01",
        "rule_name": "Test Rule",
        "raw": "some raw log line",
        "timestamp": "2026-01-15T03:00:00Z",
        "details": {"process": "cmd.exe", "cpu": 95, "attempts": 5},
    }
    base.update(kwargs)
    return base


# ── _extract_field ────────────────────────────────────────────────
class TestExtractField:
    def test_top_level(self):
        e = _event(severity="critical")
        assert _extract_field(e, "severity") == "critical"

    def test_details_subfield(self):
        e = _event()
        assert _extract_field(e, "details.process") == "cmd.exe"

    def test_details_numeric(self):
        e = _event()
        assert _extract_field(e, "details.cpu") == 95

    def test_hour_from_timestamp(self):
        e = _event(timestamp="2026-01-15T03:30:00Z")
        assert _extract_field(e, "hour") == 3

    def test_weekday_from_timestamp(self):
        # 2026-01-15 is a Thursday → weekday=3
        e = _event(timestamp="2026-01-15T12:00:00Z")
        assert _extract_field(e, "weekday") == 3

    def test_missing_field_returns_none(self):
        e = _event()
        assert _extract_field(e, "nonexistent") is None

    def test_missing_details_subfield_returns_none(self):
        e = _event()
        assert _extract_field(e, "details.missing") is None


# ── _eval_condition ───────────────────────────────────────────────
class TestEvalCondition:
    def test_eq_match(self):
        e = _event(severity="critical")
        assert _eval_condition(e, {"field":"severity","operator":"eq","value":"critical"})

    def test_eq_no_match(self):
        e = _event(severity="low")
        assert not _eval_condition(e, {"field":"severity","operator":"eq","value":"critical"})

    def test_ne(self):
        e = _event(severity="low")
        assert _eval_condition(e, {"field":"severity","operator":"ne","value":"critical"})

    def test_contains(self):
        e = _event(raw="powershell -enc abc")
        assert _eval_condition(e, {"field":"raw","operator":"contains","value":"-enc"})

    def test_not_contains(self):
        e = _event(raw="normal log")
        assert _eval_condition(e, {"field":"raw","operator":"not_contains","value":"powershell"})

    def test_starts_with(self):
        e = _event(raw="powershell something")
        assert _eval_condition(e, {"field":"raw","operator":"starts_with","value":"power"})

    def test_ends_with(self):
        e = _event(raw="something.exe")
        assert _eval_condition(e, {"field":"raw","operator":"ends_with","value":".exe"})

    def test_gt(self):
        e = _event()
        assert _eval_condition(e, {"field":"details.cpu","operator":"gt","value":90})

    def test_lt(self):
        e = _event()
        assert _eval_condition(e, {"field":"details.cpu","operator":"lt","value":100})

    def test_gte(self):
        e = _event()
        assert _eval_condition(e, {"field":"details.cpu","operator":"gte","value":95})

    def test_lte(self):
        e = _event()
        assert _eval_condition(e, {"field":"details.cpu","operator":"lte","value":95})

    def test_between(self):
        e = _event(timestamp="2026-01-15T03:00:00Z")
        assert _eval_condition(e, {"field":"hour","operator":"between","value":[0,6]})

    def test_between_outside(self):
        e = _event(timestamp="2026-01-15T10:00:00Z")
        assert not _eval_condition(e, {"field":"hour","operator":"between","value":[0,6]})

    def test_in(self):
        e = _event(severity="critical")
        assert _eval_condition(e, {"field":"severity","operator":"in","value":["critical","high"]})

    def test_not_in(self):
        e = _event(severity="low")
        assert _eval_condition(e, {"field":"severity","operator":"not_in","value":["critical","high"]})

    def test_regex(self):
        e = _event(raw="ERROR: code 500")
        assert _eval_condition(e, {"field":"raw","operator":"regex","value":r"ERROR.*\d{3}"})

    def test_exists_true(self):
        e = _event()
        assert _eval_condition(e, {"field":"details.process","operator":"exists","value":True})

    def test_exists_false(self):
        e = _event()
        assert _eval_condition(e, {"field":"details.missing","operator":"exists","value":False})

    def test_missing_field_returns_false(self):
        e = _event()
        assert not _eval_condition(e, {"field":"nonexistent","operator":"eq","value":"x"})


# ── evaluate_rule ─────────────────────────────────────────────────
class TestEvaluateRule:
    def test_and_all_match(self):
        e = _event(timestamp="2026-01-15T03:00:00Z", event_type="user_login")
        rule = _rule("AND", [
            {"field":"hour","operator":"between","value":[0,6]},
            {"field":"event_type","operator":"contains","value":"login"},
        ])
        assert evaluate_rule(rule, e)

    def test_and_partial_match(self):
        e = _event(timestamp="2026-01-15T10:00:00Z", event_type="user_login")
        rule = _rule("AND", [
            {"field":"hour","operator":"between","value":[0,6]},
            {"field":"event_type","operator":"contains","value":"login"},
        ])
        assert not evaluate_rule(rule, e)

    def test_or_one_match(self):
        e = _event(raw="normal")
        rule = _rule("OR", [
            {"field":"raw","operator":"contains","value":"powershell"},
            {"field":"raw","operator":"contains","value":"normal"},
        ])
        assert evaluate_rule(rule, e)

    def test_or_no_match(self):
        e = _event(raw="benign log")
        rule = _rule("OR", [
            {"field":"raw","operator":"contains","value":"powershell"},
            {"field":"raw","operator":"contains","value":"malware"},
        ])
        assert not evaluate_rule(rule, e)

    def test_empty_conditions_returns_false(self):
        e = _event()
        assert not evaluate_rule(_rule("AND", []), e)

    def test_disabled_rule_returns_false(self):
        e = _event(event_type="user_login")
        rule = _rule("AND", [{"field":"event_type","operator":"eq","value":"user_login"}])
        rule["enabled"] = False
        assert not evaluate_rule(rule, e)
