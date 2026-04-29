import os
import shutil
import sys
import unittest
import uuid

os.environ.setdefault("IDS_AUTH", "false")
os.environ.setdefault("IDS_DASHBOARD_AUTH", "false")
os.environ.setdefault("IDS_CSRF_DISABLED", "false")
os.environ.setdefault("IDS_ENV", "test")
os.environ.setdefault("TOKEN_SIGNING_SECRET", "incidents-api-test-signing-key")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
WORK_TMP = os.path.join(ROOT, ".tmp_test_workspace")
os.makedirs(WORK_TMP, exist_ok=True)

import app as app_module
from auth import get_or_create_token
from engine.incident_engine import IncidentEngine
from models.event_model import make_event
from storage.event_repository import EventRepository


class TestIncidentsApi(unittest.TestCase):
    def setUp(self):
        self.case_dir = os.path.join(WORK_TMP, f"incidents-api-{uuid.uuid4().hex}")
        os.makedirs(self.case_dir, exist_ok=True)
        self.events_db = os.path.join(self.case_dir, "events.db")
        self.incidents_db = os.path.join(self.case_dir, "incidents.db")
        self.repo = EventRepository(db_path=self.events_db, tenant_id="default")
        self.engine = IncidentEngine(self.incidents_db, tenant_id="default")
        self.client = app_module.app.test_client()
        self.admin_token = get_or_create_token()

        self._orig_repo = app_module.repo
        self._orig_app_repo = getattr(app_module.app, "_repo", None)
        self._orig_get_incidents = app_module._get_incidents

        app_module.repo = self.repo
        app_module.app._repo = self.repo
        app_module._get_incidents = lambda: self.engine

    def tearDown(self):
        repo_conn = getattr(self.repo._local, "conn", None)
        if repo_conn is not None:
            repo_conn.close()
        incident_conn = getattr(self.engine._repo._local, "conn", None)
        if incident_conn is not None:
            incident_conn.close()
        app_module.repo = self._orig_repo
        app_module.app._repo = self._orig_app_repo
        app_module._get_incidents = self._orig_get_incidents
        shutil.rmtree(self.case_dir, ignore_errors=True)

    def _headers(self):
        return {"X-API-Token": self.admin_token}

    def _seed_event(self) -> str:
        event = make_event(
            event_type="suspicious_powershell",
            severity="HIGH",
            source="xdr.agent",
            details={
                "source_ip": "10.0.0.20",
                "summary": "Encoded PowerShell from Office parent process.",
                "description": "Office spawned PowerShell with encoded command.",
                "tactic": "execution",
                "technique": "T1059.001",
            },
            rule_id="NG-YAML-PS-001",
            rule_name="Suspicious PowerShell Encoded Command",
            mitre_tactic="execution",
            mitre_technique="T1059.001",
            tags=["xdr", "powershell"],
            raw="powershell.exe -enc ZQBjAGgAbwA=",
        )
        event.host_id = "endpoint-77"
        admin_repo = EventRepository(db_path=self.events_db, tenant_id="admin")
        admin_repo.save_batch([event])
        admin_conn = getattr(admin_repo._local, "conn", None)
        if admin_conn is not None:
            admin_conn.close()
        return event.event_id

    def test_create_incident_from_event_and_run_lifecycle(self):
        event_id = self._seed_event()

        created = self.client.post(
            "/api/incidents",
            json={"event_id": event_id, "comment": "Escalated from detection queue."},
            headers=self._headers(),
        )
        self.assertEqual(created.status_code, 201, created.get_data(as_text=True))
        created_body = created.get_json()
        self.assertTrue(created_body["ok"])
        incident = created_body["incident"]
        self.assertEqual(incident["host_id"], "endpoint-77")
        self.assertIn(event_id, incident["event_ids"])

        iid = int(incident["id"])
        severity = self.client.patch(
            f"/api/incidents/{iid}/severity",
            json={"severity": "critical", "note": "Business critical asset."},
            headers=self._headers(),
        )
        self.assertEqual(severity.status_code, 200, severity.get_data(as_text=True))
        self.assertEqual(severity.get_json()["incident"]["severity"], "critical")

        comment = self.client.post(
            f"/api/incidents/{iid}/comments",
            json={"note": "EDR isolate command scheduled."},
            headers=self._headers(),
        )
        self.assertEqual(comment.status_code, 200, comment.get_data(as_text=True))

        status = self.client.patch(
            f"/api/incidents/{iid}/status",
            json={"status": "investigating", "note": "Analyst reviewing process tree."},
            headers=self._headers(),
        )
        self.assertEqual(status.status_code, 200, status.get_data(as_text=True))
        self.assertEqual(status.get_json()["incident"]["status"], "investigating")

        listed = self.client.get(
            "/api/incidents?severity=critical&limit=10",
            headers=self._headers(),
        )
        self.assertEqual(listed.status_code, 200, listed.get_data(as_text=True))
        listed_body = listed.get_json()
        self.assertEqual(len(listed_body["incidents"]), 1)
        self.assertEqual(listed_body["incidents"][0]["id"], iid)

        host_filtered = self.client.get(
            "/api/incidents?host_id=endpoint-77&limit=10",
            headers=self._headers(),
        )
        self.assertEqual(host_filtered.status_code, 200, host_filtered.get_data(as_text=True))
        self.assertEqual(len(host_filtered.get_json()["incidents"]), 1)

        detail = self.client.get(f"/api/incidents/{iid}", headers=self._headers())
        self.assertEqual(detail.status_code, 200, detail.get_data(as_text=True))
        timeline_actions = [item["action"] for item in detail.get_json()["timeline"]]
        self.assertIn("opened", timeline_actions)
        self.assertIn("severity->critical", timeline_actions)
        self.assertIn("comment", timeline_actions)
        self.assertIn("status->investigating", timeline_actions)

    def test_create_incident_rejects_unknown_event_id(self):
        response = self.client.post(
            "/api/incidents",
            json={"event_id": "missing-event-id"},
            headers=self._headers(),
        )
        self.assertEqual(response.status_code, 404, response.get_data(as_text=True))
        self.assertIn("Evento", response.get_json()["error"])

    def test_create_incident_is_idempotent_for_active_event(self):
        event_id = self._seed_event()

        first = self.client.post(
            "/api/incidents",
            json={"event_id": event_id, "comment": "First escalation."},
            headers=self._headers(),
        )
        self.assertEqual(first.status_code, 201, first.get_data(as_text=True))
        first_incident = first.get_json()["incident"]

        second = self.client.post(
            "/api/incidents",
            json={"event_id": event_id, "comment": "Duplicate escalation."},
            headers=self._headers(),
        )
        self.assertEqual(second.status_code, 200, second.get_data(as_text=True))
        second_body = second.get_json()
        self.assertTrue(second_body["deduplicated"])
        self.assertEqual(second_body["incident"]["id"], first_incident["id"])

        listed = self.client.get(
            "/api/incidents?host_id=endpoint-77&limit=10",
            headers=self._headers(),
        )
        self.assertEqual(listed.status_code, 200, listed.get_data(as_text=True))
        self.assertEqual(len(listed.get_json()["incidents"]), 1)

        detail = self.client.get(
            f"/api/incidents/{first_incident['id']}",
            headers=self._headers(),
        )
        timeline = detail.get_json()["timeline"]
        self.assertTrue(
            any("Duplicate create request grouped" in item["detail"] for item in timeline)
        )
