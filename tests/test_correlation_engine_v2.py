"""
Tests for engine.soc_correlator.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from engine.soc_correlator import CorrelationConfig, SocCorrelator
from storage.repository import Alert


def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


def _alert(host="h1", rule="NG-X", severity="medium", offset_s=0,
           technique="T1059", tactic="Execution") -> Alert:
    return Alert(
        alert_id=str(uuid.uuid4()),
        host_id=host,
        rule_id=rule,
        severity=severity,
        confidence=80,
        timestamp=_iso(_now() + timedelta(seconds=offset_s)),
        title="t", evidence="e",
        mitre_tactic=tactic, mitre_technique=technique,
        event_ids=[], status="open",
    )


def test_powershell_plus_network_high():
    ps = _alert(rule="NG-EXEC-PS-ENC-001", severity="high",
                technique="T1059.001", tactic="Defense Evasion", offset_s=0)
    net = _alert(rule="NG-NET-RARE-PORT-001", severity="medium",
                 technique="T1071", tactic="Command and Control", offset_s=60)
    out = SocCorrelator().correlate([ps, net])
    assert any(a.rule_id == "CORR-PS-NET" and a.severity == "high" for a in out)


def test_persistence_plus_execution_critical():
    p = _alert(rule="NG-PERSIST-REG-RUN-001", severity="high",
               technique="T1547.001", tactic="Persistence", offset_s=0)
    e = _alert(rule="NG-EXEC-PS-DL-001", severity="high",
               technique="T1059.001", tactic="Execution", offset_s=120)
    out = SocCorrelator().correlate([p, e])
    crits = [a for a in out if a.rule_id == "CORR-PERSIST-EXEC"]
    assert crits and crits[0].severity == "critical"


def test_burst_high():
    cfg = CorrelationConfig(burst_window_s=60, burst_threshold=3)
    a1 = _alert(rule="NG-A", offset_s=0)
    a2 = _alert(rule="NG-B", offset_s=10)
    a3 = _alert(rule="NG-C", offset_s=20)
    out = SocCorrelator(cfg).correlate([a1, a2, a3])
    burst = [a for a in out if a.rule_id == "CORR-BURST"]
    assert burst, "burst rule should fire"
    assert burst[0].severity == "high"


def test_burst_below_threshold_silent():
    cfg = CorrelationConfig(burst_window_s=60, burst_threshold=3)
    out = SocCorrelator(cfg).correlate([
        _alert(offset_s=0), _alert(offset_s=10),
    ])
    assert not [a for a in out if a.rule_id == "CORR-BURST"]


def test_burst_outside_window():
    cfg = CorrelationConfig(burst_window_s=30, burst_threshold=3)
    out = SocCorrelator(cfg).correlate([
        _alert(offset_s=0), _alert(offset_s=10), _alert(offset_s=300),
    ])
    assert not [a for a in out if a.rule_id == "CORR-BURST"]


def test_auth_mix_high():
    f = _alert(rule="NG-AUTH-FAIL-001", severity="medium", offset_s=0)
    s = _alert(rule="NG-AUTH-SUCCESS-001", severity="low", offset_s=120)
    out = SocCorrelator().correlate([f, s])
    mix = [a for a in out if a.rule_id == "CORR-AUTH-MIX"]
    assert mix and mix[0].severity == "high"


def test_no_correlation_across_hosts():
    p = _alert(host="h1", rule="NG-PERSIST-X", tactic="Persistence", offset_s=0)
    e = _alert(host="h2", rule="NG-EXEC-X",    tactic="Execution",    offset_s=10)
    assert not SocCorrelator().correlate([p, e])


def test_correlator_dedups_minute_bucket():
    # Two near-identical bursts within the same minute bucket should
    # produce one CORR-BURST alert.
    cfg = CorrelationConfig(burst_window_s=60, burst_threshold=3)
    bunch = [_alert(offset_s=i) for i in (0, 5, 10, 15, 20)]
    out = SocCorrelator(cfg).correlate(bunch)
    burst = [a for a in out if a.rule_id == "CORR-BURST"]
    assert len(burst) == 1


def test_correlator_uses_stable_ids_for_same_source_alerts():
    ps = _alert(
        rule="NG-EXEC-PS-ENC-001",
        technique="T1059.001",
        tactic="Defense Evasion",
        offset_s=0,
    )
    net = _alert(
        rule="NG-NET-RARE-PORT-001",
        technique="T1071",
        tactic="Command and Control",
        offset_s=60,
    )
    first = SocCorrelator().correlate([ps, net])
    second = SocCorrelator().correlate([ps, net])

    assert first
    assert second
    assert first[0].alert_id == second[0].alert_id


def test_empty_input_returns_empty():
    assert SocCorrelator().correlate([]) == []
