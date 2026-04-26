import os
import shutil
import sys
import unittest
import uuid

os.environ.setdefault("IDS_AUTH", "false")
os.environ.setdefault("IDS_DASHBOARD_AUTH", "false")
os.environ.setdefault("IDS_CSRF_DISABLED", "false")
os.environ.setdefault("IDS_ENV", "test")
os.environ.setdefault("TOKEN_SIGNING_SECRET", "agent-server-test-signing-key")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
WORK_TMP = os.path.join(ROOT, ".tmp_test_workspace")
os.makedirs(WORK_TMP, exist_ok=True)

import app as app_module
from auth import get_or_create_token
from storage.event_repository import EventRepository
from storage.host_repository import HostRepository


class TestAgentServerApi(unittest.TestCase):
    def setUp(self):
        self.case_dir = os.path.join(WORK_TMP, f"agent-server-{uuid.uuid4().hex}")
        os.makedirs(self.case_dir, exist_ok=True)
        self.db_path = os.path.join(self.case_dir, "agent-events.db")
        self.repo = EventRepository(db_path=self.db_path, tenant_id="default")
        self.client = app_module.app.test_client()
        self.admin_token = get_or_create_token()

        self._orig_repo = app_module.repo
        self._orig_app_repo = getattr(app_module.app, "_repo", None)
        self._orig_xdr_pipeline = app_module._xdr_pipeline_singleton
        self._orig_playbook = app_module._playbook_engine_singleton
        self._orig_forensics = app_module._forensics_engine_singleton
        self._orig_ti_feed = app_module._ti_feed_singleton
        self._orig_ti_scheduler = app_module._ti_feed_scheduler_started

        app_module.repo = self.repo
        app_module.app._repo = self.repo
        app_module._xdr_pipeline_singleton = None
        app_module._playbook_engine_singleton = None
        app_module._forensics_engine_singleton = None
        app_module._ti_feed_singleton = None
        app_module._ti_feed_scheduler_started = False

    def tearDown(self):
        conn = getattr(self.repo._local, "conn", None)
        if conn is not None:
            conn.close()
        app_module.repo = self._orig_repo
        app_module.app._repo = self._orig_app_repo
        app_module._xdr_pipeline_singleton = self._orig_xdr_pipeline
        app_module._playbook_engine_singleton = self._orig_playbook
        app_module._forensics_engine_singleton = self._orig_forensics
        app_module._ti_feed_singleton = self._orig_ti_feed
        app_module._ti_feed_scheduler_started = self._orig_ti_scheduler
        shutil.rmtree(self.case_dir, ignore_errors=True)

    def _admin_headers(self):
        return {"X-API-Token": self.admin_token}

    def test_agent_registration_heartbeat_and_event_ingest(self):
        register = self.client.post(
            "/api/agent/register",
            json={
                "host_id": "agent-host-01",
                "display_name": "Finance Workstation",
                "platform": "windows",
                "agent_version": "2.1.0",
                "metadata": {"site": "hq"},
                "tags": ["finance", "windows"],
            },
            headers=self._admin_headers(),
        )
        self.assertEqual(register.status_code, 201, register.get_data(as_text=True))
        body = register.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["host"]["host_id"], "agent-host-01")
        self.assertEqual(body["host"]["tenant_id"], "admin")
        self.assertTrue(body["api_key"].startswith("nga_"))

        agent_key = body["api_key"]
        heartbeat = self.client.post(
            "/api/agent/heartbeat",
            json={
                "host_id": "agent-host-01",
                "display_name": "Finance Workstation",
                "platform": "windows",
                "agent_version": "2.1.0",
                "snapshot_summary": {"process_count": 42},
                "metadata": {"site": "hq"},
            },
            headers={"X-NetGuard-Agent-Key": agent_key},
        )
        self.assertEqual(heartbeat.status_code, 200, heartbeat.get_data(as_text=True))
        heartbeat_body = heartbeat.get_json()
        self.assertTrue(heartbeat_body["ok"])
        self.assertEqual(heartbeat_body["host"]["status"], "online")

        ingest = self.client.post(
            "/api/agent/events",
            json={
                "host_id": "agent-host-01",
                "platform": "windows",
                "agent_version": "2.1.0",
                "events": [
                    {
                        "event_type": "process_execution",
                        "severity": "high",
                        "timestamp": "2026-04-23T12:00:00Z",
                        "process_name": "powershell.exe",
                        "command_line": "powershell.exe -enc ZQBjAGgAbwA=",
                        "parent_process": "winword.exe",
                        "pid": 2211,
                        "details": {"source_ip": "10.0.0.5"},
                    }
                ],
            },
            headers={"X-NetGuard-Agent-Key": agent_key},
        )
        self.assertEqual(ingest.status_code, 200, ingest.get_data(as_text=True))
        ingest_body = ingest.get_json()
        self.assertTrue(ingest_body["ok"])
        self.assertEqual(ingest_body["processed"], 1)
        self.assertGreaterEqual(ingest_body["saved_events"], 1)
        self.assertEqual(ingest_body["host"]["host_id"], "agent-host-01")

        stored_host = HostRepository(db_path=self.db_path, tenant_id="admin").get_host("agent-host-01")
        self.assertIsNotNone(stored_host)
        self.assertEqual(stored_host["display_name"], "Finance Workstation")
        self.assertTrue(stored_host["last_seen"])
        self.assertTrue(stored_host["last_event_at"])
        self.assertGreaterEqual(self.repo.count(tenant_id="admin"), 1)

    def test_hosts_overview_and_timeline_use_registered_host_inventory(self):
        register = self.client.post(
            "/api/agent/register",
            json={
                "host_id": "agent-host-01",
                "display_name": "Finance Workstation",
                "platform": "windows",
                "agent_version": "2.1.0",
            },
            headers=self._admin_headers(),
        )
        self.assertEqual(register.status_code, 201, register.get_data(as_text=True))
        agent_key = register.get_json()["api_key"]

        heartbeat = self.client.post(
            "/api/agent/heartbeat",
            json={
                "host_id": "agent-host-01",
                "display_name": "Finance Workstation",
                "platform": "windows",
                "agent_version": "2.1.0",
            },
            headers={"X-NetGuard-Agent-Key": agent_key},
        )
        self.assertEqual(heartbeat.status_code, 200, heartbeat.get_data(as_text=True))

        ingest = self.client.post(
            "/api/agent/events",
            json={
                "host_id": "agent-host-01",
                "platform": "windows",
                "agent_version": "2.1.0",
                "events": [
                    {
                        "event_type": "process_execution",
                        "severity": "high",
                        "timestamp": "2026-04-23T12:00:00Z",
                        "process_name": "powershell.exe",
                        "command_line": "powershell.exe -enc ZQBjAGgAbwA=",
                        "details": {
                            "mitre_technique": "T1059.001",
                            "mitre_tactic": "execution",
                        },
                    }
                ],
            },
            headers={"X-NetGuard-Agent-Key": agent_key},
        )
        self.assertEqual(ingest.status_code, 200, ingest.get_data(as_text=True))

        hosts = self.client.get("/api/hosts", headers=self._admin_headers())
        self.assertEqual(hosts.status_code, 200, hosts.get_data(as_text=True))
        hosts_body = hosts.get_json()
        self.assertGreaterEqual(hosts_body["total"], 1)
        host = next(
            item for item in hosts_body["hosts"]
            if item["host_id"] == "agent-host-01"
        )
        self.assertEqual(host["hostname"], "Finance Workstation")
        self.assertEqual(host["agent_status"], "online")
        self.assertGreaterEqual(host["event_count_24h"], 1)
        self.assertIn("execution/T1059.001", host["mitre_techniques"])

        timeline = self.client.get(
            "/api/hosts/agent-host-01/timeline",
            headers=self._admin_headers(),
        )
        self.assertEqual(timeline.status_code, 200, timeline.get_data(as_text=True))
        timeline_body = timeline.get_json()
        self.assertEqual(timeline_body["host_id"], "agent-host-01")
        self.assertGreaterEqual(timeline_body["total"], 1)
        self.assertTrue(
            any(event["_mitre_technique"] == "T1059.001" for event in timeline_body["events"])
        )

    def test_viewer_tenant_cannot_register_host(self):
        tenant_token = "ng_viewer_tenant_test_token_1234567890"
        self.repo.create_tenant(
            tenant_id="tenant-viewer",
            name="Viewer Tenant",
            token=tenant_token,
            role="viewer",
            max_hosts=5,
        )

        response = self.client.post(
            "/api/agent/register",
            json={"host_id": "blocked-host-01"},
            headers={"Authorization": f"Bearer {tenant_token}"},
        )
        self.assertEqual(response.status_code, 403, response.get_data(as_text=True))
        self.assertIn("Permissao", response.get_json()["error"])

    def test_agent_key_cannot_write_other_host(self):
        register = self.client.post(
            "/api/agent/register",
            json={"host_id": "agent-host-locked", "platform": "linux"},
            headers=self._admin_headers(),
        )
        self.assertEqual(register.status_code, 201, register.get_data(as_text=True))
        agent_key = register.get_json()["api_key"]

        response = self.client.post(
            "/api/agent/heartbeat",
            json={"host_id": "different-host"},
            headers={"X-NetGuard-Agent-Key": agent_key},
        )
        self.assertEqual(response.status_code, 403, response.get_data(as_text=True))
        self.assertIn("Permissao", response.get_json()["error"])
