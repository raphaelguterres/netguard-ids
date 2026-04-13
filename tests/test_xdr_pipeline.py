import unittest

from xdr.pipeline import XDRPipeline


def _base_event(**overrides):
    payload = {
        "host_id": "host-01",
        "event_type": "process_execution",
        "severity": "medium",
        "timestamp": "2026-04-13T12:00:00Z",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc ZQBjAGgAbwA=",
        "username": "alice",
        "source": "agent",
        "platform": "windows",
        "pid": 1337,
        "parent_process": "winword.exe",
        "details": {"cpu": 20},
    }
    payload.update(overrides)
    return payload


class TestXDRPipeline(unittest.TestCase):
    def setUp(self):
        self.pipeline = XDRPipeline()

    def test_suspicious_powershell_generates_detection_and_response(self):
        outcome = self.pipeline.process_payload(_base_event())[0]

        self.assertGreaterEqual(len(outcome.detections), 1)
        self.assertEqual(outcome.detections[0].rule_id, "NG-EDR-001")
        self.assertTrue(any(action.action_type == "kill_process" for action in outcome.actions))
        self.assertGreater(outcome.host_risk_score, 0)

    def test_repeated_scripts_trigger_correlation(self):
        payloads = [_base_event(timestamp=f"2026-04-13T12:00:0{i}Z") for i in range(3)]
        outcomes = self.pipeline.process_payload({"events": payloads})

        self.assertTrue(any(outcome.correlations for outcome in outcomes))
        last = outcomes[-1]
        self.assertEqual(last.correlations[0].rule_id, "NG-XDR-COR-001")

    def test_auth_failures_trigger_bruteforce_rule(self):
        auth_event = {
            "host_id": "host-auth",
            "event_type": "authentication",
            "severity": "medium",
            "timestamp": "2026-04-13T12:10:00Z",
            "username": "alice",
            "auth_result": "failure",
            "auth_source_ip": "10.0.0.50",
            "source": "agent",
            "details": {},
        }
        last = None
        for _ in range(5):
            last = self.pipeline.process_payload(auth_event)[0]
        self.assertIsNotNone(last)
        self.assertTrue(any(item.rule_id == "NG-EDR-003" for item in last.detections))

    def test_invalid_event_type_raises_value_error(self):
        with self.assertRaises(ValueError):
            self.pipeline.process_payload(
                {
                    "host_id": "broken",
                    "event_type": "unsupported",
                    "severity": "low",
                    "timestamp": "2026-04-13T12:00:00Z",
                    "source": "agent",
                    "details": {},
                }
            )
