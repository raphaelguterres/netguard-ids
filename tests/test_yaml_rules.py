import os
import shutil
import sys
import textwrap
import unittest
import uuid

os.environ.setdefault("IDS_ENV", "test")
os.environ.setdefault("TOKEN_SIGNING_SECRET", "yaml-rules-test-signing-key")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
WORK_TMP = os.path.join(ROOT, ".tmp_test_workspace")
os.makedirs(WORK_TMP, exist_ok=True)

from rules.yaml_loader import load_yaml_rules
from xdr.detection import BehaviorDetectionEngine
from xdr.detections.yaml_rules import YamlRuleSet
from xdr.pipeline import XDRPipeline


class TestYamlRuleLoader(unittest.TestCase):
    def test_invalid_yaml_rule_is_skipped(self):
        tmpdir = os.path.join(WORK_TMP, f"yaml-rules-{uuid.uuid4().hex}")
        os.makedirs(tmpdir, exist_ok=True)
        try:
            valid_rule = textwrap.dedent(
                """
                id: NG-TMP-001
                title: Temporary Test Rule
                severity: medium
                event_types:
                  - process_execution
                detection:
                  all:
                    - field: process_name
                      operator: equals
                      value: powershell.exe
                """
            ).strip()
            invalid_rule = textwrap.dedent(
                """
                id: NG-TMP-002
                title: Broken Rule
                detection:
                  all:
                    - field: process_name
                      operator: not_supported
                      value: powershell.exe
                """
            ).strip()
            with open(os.path.join(tmpdir, "valid.yml"), "w", encoding="utf-8") as handle:
                handle.write(valid_rule)
            with open(os.path.join(tmpdir, "invalid.yml"), "w", encoding="utf-8") as handle:
                handle.write(invalid_rule)

            registry = load_yaml_rules(tmpdir)
            rule_ids = {rule.rule_id for rule in registry.rules}
            self.assertEqual(rule_ids, {"NG-TMP-001"})
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_sigma_like_selection_rule_with_logsource_loads_and_matches(self):
        tmpdir = os.path.join(WORK_TMP, f"sigma-rules-{uuid.uuid4().hex}")
        os.makedirs(tmpdir, exist_ok=True)
        try:
            sigma_rule = textwrap.dedent(
                """
                title: Sigma Style Encoded PowerShell
                id: NG-SIGMA-001
                status: test
                author: NetGuard Labs
                level: high
                logsource:
                  product: windows
                  category: process_creation
                references:
                  - https://attack.mitre.org/techniques/T1059/001/
                falsepositives:
                  - administrative automation
                detection:
                  selection:
                    Image|endswith:
                      - powershell.exe
                    CommandLine|contains|all:
                      - powershell
                      - "-enc"
                  condition: selection
                """
            ).strip()
            with open(os.path.join(tmpdir, "sigma_powershell.yml"), "w", encoding="utf-8") as handle:
                handle.write(sigma_rule)

            registry = load_yaml_rules(tmpdir)
            self.assertEqual(len(registry.rules), 1)
            loaded_rule = registry.rules[0]
            self.assertEqual(loaded_rule.severity, "high")
            self.assertEqual(loaded_rule.event_types, ("process_execution",))
            self.assertEqual(loaded_rule.metadata["status"], "test")

            pipeline = XDRPipeline(
                detection_engine=BehaviorDetectionEngine(
                    rules=[YamlRuleSet(rules_dir=tmpdir)],
                ),
            )
            outcome = pipeline.process_payload(
                {
                    "host_id": "sigma-host-01",
                    "event_type": "process_execution",
                    "severity": "medium",
                    "timestamp": "2026-04-23T10:03:00Z",
                    "process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "command_line": "powershell.exe -NoProfile -enc ZQBjAGgAbwA=",
                    "source": "agent",
                    "platform": "windows",
                    "details": {},
                }
            )[0]
            detections = {item.rule_id: item for item in outcome.detections}
            self.assertIn("NG-SIGMA-001", detections)
            self.assertEqual(detections["NG-SIGMA-001"].details["metadata"]["author"], "NetGuard Labs")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_sigma_or_with_multi_field_selection_is_rejected(self):
        tmpdir = os.path.join(WORK_TMP, f"sigma-unsafe-or-{uuid.uuid4().hex}")
        os.makedirs(tmpdir, exist_ok=True)
        try:
            unsafe_rule = textwrap.dedent(
                """
                title: Unsafe OR Shape
                id: NG-SIGMA-UNSAFE-001
                level: high
                logsource:
                  product: windows
                  category: process_creation
                detection:
                  selection_a:
                    Image|endswith: powershell.exe
                    CommandLine|contains: "-enc"
                  selection_b:
                    Image|endswith: cmd.exe
                  condition: selection_a or selection_b
                """
            ).strip()
            with open(os.path.join(tmpdir, "unsafe_or.yml"), "w", encoding="utf-8") as handle:
                handle.write(unsafe_rule)

            registry = load_yaml_rules(tmpdir)
            self.assertEqual(registry.rules, ())
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestYamlRulesInPipeline(unittest.TestCase):
    def setUp(self):
        self.pipeline = XDRPipeline()

    def test_powershell_yaml_rule_triggers(self):
        outcome = self.pipeline.process_payload(
            {
                "host_id": "yaml-host-01",
                "event_type": "process_execution",
                "severity": "medium",
                "timestamp": "2026-04-23T10:00:00Z",
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -enc ZQBjAGgAbwA=",
                "parent_process": "winword.exe",
                "source": "agent",
                "platform": "windows",
                "details": {},
            }
        )[0]
        detection_ids = {item.rule_id for item in outcome.detections}
        self.assertIn("NG-YAML-PS-001", detection_ids)

    def test_bruteforce_yaml_rule_triggers_after_threshold(self):
        last = None
        for idx in range(5):
            last = self.pipeline.process_payload(
                {
                    "host_id": "yaml-auth-01",
                    "event_type": "authentication",
                    "severity": "medium",
                    "timestamp": f"2026-04-23T10:01:0{idx}Z",
                    "username": "alice",
                    "auth_result": "failure",
                    "auth_source_ip": "10.10.10.10",
                    "source": "agent",
                    "details": {},
                }
            )[0]
        self.assertIsNotNone(last)
        detection_ids = {item.rule_id for item in last.detections}
        self.assertIn("NG-YAML-AUTH-001", detection_ids)

    def test_port_scan_yaml_rule_triggers_after_many_unique_destinations(self):
        last = None
        for idx in range(15):
            last = self.pipeline.process_payload(
                {
                    "host_id": "yaml-net-01",
                    "event_type": "network_connection",
                    "severity": "low",
                    "timestamp": f"2026-04-23T10:02:{idx:02d}Z",
                    "network_direction": "outbound",
                    "network_dst_ip": f"203.0.113.{idx + 1}",
                    "network_dst_port": 443,
                    "source": "agent",
                    "details": {},
                }
            )[0]
        self.assertIsNotNone(last)
        detection_ids = {item.rule_id for item in last.detections}
        self.assertIn("NG-YAML-NET-001", detection_ids)
