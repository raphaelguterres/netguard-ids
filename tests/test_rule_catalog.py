from __future__ import annotations

from pathlib import Path
import textwrap

from xdr.detections.process_rules import SuspiciousPowerShellRule
from xdr.rule_catalog import build_detection_rule_catalog


def test_rule_catalog_summarizes_builtin_and_yaml_rules(tmp_path):
    rule_path = tmp_path / "sigma_power.yml"
    rule_path.write_text(
        textwrap.dedent(
            """
            title: Catalog Sigma PowerShell
            id: NG-CATALOG-001
            level: high
            status: test
            logsource:
              product: windows
              category: process_creation
            tags:
              - attack.t1059.001
            mitre:
              tactic: execution
              technique: T1059.001
            detection:
              selection:
                CommandLine|contains: "-enc"
              condition: selection
            """
        ).strip(),
        encoding="utf-8",
    )

    catalog = build_detection_rule_catalog(
        rules=[SuspiciousPowerShellRule()],
        yaml_dir=tmp_path,
    )

    assert catalog["summary"]["total_rules"] == 2
    assert catalog["summary"]["by_source"] == {"builtin": 1, "yaml": 1}
    assert catalog["summary"]["yaml_health"]["loaded_files"] == 1
    assert catalog["summary"]["event_type_coverage"]["covered"] == [
        "process_execution",
        "script_execution",
    ]
    rules_by_id = {item["rule_id"]: item for item in catalog["rules"]}
    assert rules_by_id["NG-EDR-001"]["severity"] == "dynamic"
    assert rules_by_id["NG-CATALOG-001"]["sigma_like"] is True
    source_file = rules_by_id["NG-CATALOG-001"]["source_file"]
    assert not Path(source_file).is_absolute()
    assert source_file.endswith("sigma_power.yml")


def test_rule_catalog_reports_invalid_yaml_without_absolute_paths(tmp_path):
    broken_path = tmp_path / "broken.yml"
    broken_path.write_text(
        textwrap.dedent(
            """
            id: NG-BROKEN-001
            title: Broken Rule
            detection:
              all:
                - field: process_name
                  operator: not_real
                  value: powershell.exe
            """
        ).strip(),
        encoding="utf-8",
    )

    catalog = build_detection_rule_catalog(rules=[], yaml_dir=tmp_path)
    health = catalog["summary"]["yaml_health"]

    assert catalog["rules"] == []
    assert health["total_files"] == 1
    assert health["loaded_files"] == 0
    assert health["skipped_files"] == 1
    assert not Path(health["errors"][0]["source_path"]).is_absolute()
    assert health["errors"][0]["source_path"].endswith("broken.yml")
    assert "not_real" in health["errors"][0]["error"]
