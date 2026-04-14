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

    def test_security_events_preserve_endpoint_host_and_timestamp(self):
        outcome = self.pipeline.process_payload(_base_event())[0]

        security_events = outcome.to_security_events()
        self.assertGreaterEqual(len(security_events), 1)
        self.assertEqual(security_events[0].host_id, "host-01")
        self.assertEqual(security_events[0].timestamp, "2026-04-13T12:00:00Z")

    def test_detection_output_includes_recommended_action_and_related_events(self):
        outcome = self.pipeline.process_payload(_base_event())[0]

        detection = outcome.detections[0]
        self.assertTrue(detection.related_events)
        self.assertTrue(detection.recommended_action)

    def test_success_after_failures_triggers_credential_abuse_detection(self):
        failure = {
            "host_id": "host-auth-seq",
            "event_type": "authentication",
            "severity": "medium",
            "timestamp": "2026-04-13T12:10:00Z",
            "username": "alice",
            "auth_result": "failure",
            "auth_source_ip": "10.0.0.77",
            "source": "agent",
            "details": {},
        }
        for idx in range(3):
            failure["timestamp"] = f"2026-04-13T12:10:0{idx}Z"
            self.pipeline.process_payload(dict(failure))

        success = dict(failure)
        success["timestamp"] = "2026-04-13T12:10:15Z"
        success["auth_result"] = "success"
        outcome = self.pipeline.process_payload(success)[0]
        self.assertTrue(any(item.rule_id == "NG-EDR-009" for item in outcome.detections))

    def test_login_outside_baseline_window_triggers_detection(self):
        baseline_event = {
            "host_id": "host-login-baseline",
            "event_type": "authentication",
            "severity": "low",
            "username": "alice",
            "auth_result": "success",
            "auth_source_ip": "10.0.0.12",
            "source": "agent",
            "details": {},
        }
        for day in range(1, 7):
            event = dict(baseline_event)
            event["timestamp"] = f"2026-04-{day:02d}T09:00:00Z"
            self.pipeline.process_payload(event)

        odd_hour = dict(baseline_event)
        odd_hour["timestamp"] = "2026-04-13T03:00:00Z"
        outcome = self.pipeline.process_payload(odd_hour)[0]
        self.assertTrue(any(item.rule_id == "NG-EDR-010" for item in outcome.detections))

    def test_repeated_outbound_beaconing_triggers_network_detection(self):
        network_event = {
            "host_id": "host-beacon",
            "event_type": "network_connection",
            "severity": "medium",
            "timestamp": "2026-04-13T12:20:00Z",
            "network_direction": "outbound",
            "network_dst_ip": "8.8.8.8",
            "network_dst_port": 8443,
            "source": "agent",
            "details": {},
        }
        last = None
        for idx in range(5):
            event = dict(network_event)
            event["timestamp"] = f"2026-04-13T12:20:{idx * 10:02d}Z"
            last = self.pipeline.process_payload(event)[0]
        self.assertIsNotNone(last)
        self.assertTrue(any(item.rule_id == "NG-EDR-012" for item in last.detections))

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
