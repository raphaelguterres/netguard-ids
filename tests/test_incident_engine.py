import os
import shutil
import sys
import unittest
import uuid

os.environ.setdefault("IDS_ENV", "test")
os.environ.setdefault("TOKEN_SIGNING_SECRET", "incident-engine-test-signing-key")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
WORK_TMP = os.path.join(ROOT, ".tmp_test_workspace")
os.makedirs(WORK_TMP, exist_ok=True)

from engine.incident_engine import IncidentEngine


class TestIncidentEngine(unittest.TestCase):
    def setUp(self):
        self.case_dir = os.path.join(WORK_TMP, f"incident-engine-{uuid.uuid4().hex}")
        os.makedirs(self.case_dir, exist_ok=True)
        self.db_path = os.path.join(self.case_dir, "incident-engine.db")
        self.engine = IncidentEngine(self.db_path, tenant_id="tenant-a")

    def tearDown(self):
        conn = getattr(self.engine._repo._local, "conn", None)
        if conn is not None:
            conn.close()
        shutil.rmtree(self.case_dir, ignore_errors=True)

    def test_open_update_and_timeline_flow(self):
        incident = self.engine.open_incident(
            title="Suspicious PowerShell on host-01",
            severity="high",
            source="xdr",
            host_id="host-01",
            event_ids=["evt-001"],
            tags=["powershell", "execution"],
            actor="analyst",
            initial_comment="Initial triage started.",
        )
        self.assertEqual(incident["status"], "open")
        self.assertEqual(incident["severity"], "high")
        self.assertEqual(incident["host_id"], "host-01")
        self.assertEqual(incident["event_ids"], ["evt-001"])

        updated = self.engine.update_severity(
            int(incident["id"]),
            "critical",
            actor="analyst",
            note="Escalated after encoded command evidence.",
        )
        self.assertEqual(updated["severity"], "critical")

        assigned = self.engine.assign(int(incident["id"]), "soc-tier2", actor="manager")
        self.assertEqual(assigned["assigned_to"], "soc-tier2")

        commented = self.engine.add_comment(
            int(incident["id"]),
            "Host isolated pending forensic review.",
            actor="soc-tier2",
        )
        self.assertEqual(commented["assigned_to"], "soc-tier2")

        resolved = self.engine.update_status(
            int(incident["id"]),
            "resolved",
            actor="soc-tier2",
            note="Containment completed.",
        )
        self.assertEqual(resolved["status"], "resolved")
        self.assertTrue(resolved["closed_at"])

        timeline = self.engine.get_timeline(int(incident["id"]))
        actions = [item["action"] for item in timeline]
        self.assertIn("opened", actions)
        self.assertIn("severity->critical", actions)
        self.assertIn("assigned", actions)
        self.assertIn("comment", actions)
        self.assertIn("status->resolved", actions)

    def test_ingest_edr_alert_groups_recent_open_incidents(self):
        first = self.engine.ingest_edr_alert(
            {
                "score": 80,
                "host_id": "host-edr-01",
                "process_name": "powershell.exe",
                "source_ip": "10.0.0.10",
                "findings": [{"reason": "encoded command"}],
            }
        )
        self.assertIsNotNone(first)
        self.assertEqual(first["severity"], "critical")

        second = self.engine.ingest_edr_alert(
            {
                "score": 90,
                "host_id": "host-edr-01",
                "process_name": "cmd.exe",
                "source_ip": "10.0.0.10",
                "findings": [{"reason": "child process fan-out"}],
            }
        )
        self.assertIsNotNone(second)
        self.assertEqual(first["id"], second["id"])

        incidents = self.engine.list_incidents(host_id="host-edr-01", limit=10)
        self.assertEqual(len(incidents), 1)
        timeline = self.engine.get_timeline(int(second["id"]))
        self.assertTrue(any("Novo alerta EDR agrupado" in item["detail"] for item in timeline))
