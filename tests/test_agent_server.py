import os
import shutil
import sys
import time
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

    def test_scoped_ingest_token_can_write_events_but_not_manage_hosts(self):
        tenant_token = "ng_ingest_scoped_test_token_1234567890"
        self.repo.create_tenant(
            tenant_id="tenant-ingest",
            name="Ingest Scoped Tenant",
            token=tenant_token,
            role="viewer",
            scopes=["events:write"],
            max_hosts=5,
        )

        heartbeat = self.client.post(
            "/api/agent/heartbeat",
            json={
                "host_id": "scoped-ingest-host",
                "display_name": "Scoped Ingest Host",
                "platform": "windows",
            },
            headers={"Authorization": f"Bearer {tenant_token}"},
        )
        self.assertEqual(heartbeat.status_code, 200, heartbeat.get_data(as_text=True))
        self.assertEqual(heartbeat.get_json()["host"]["tenant_id"], "tenant-ingest")

        register = self.client.post(
            "/api/agent/register",
            json={"host_id": "scoped-register-blocked", "platform": "windows"},
            headers={"Authorization": f"Bearer {tenant_token}"},
        )
        self.assertEqual(register.status_code, 403, register.get_data(as_text=True))

        create_token = self.client.post(
            "/api/agent/enrollment-token",
            json={"tenant_id": "tenant-ingest"},
            headers={"Authorization": f"Bearer {tenant_token}"},
        )
        self.assertEqual(create_token.status_code, 403, create_token.get_data(as_text=True))

    def test_response_actions_require_response_queue_scope(self):
        tenant_token = "ng_host_manage_no_response_scope_1234567890"
        self.repo.create_tenant(
            tenant_id="tenant-host-manager",
            name="Host Manager Tenant",
            token=tenant_token,
            role="analyst",
            scopes=["hosts:manage"],
            max_hosts=5,
        )

        register = self.client.post(
            "/api/agent/register",
            json={"host_id": "scope-action-host", "platform": "windows"},
            headers={"Authorization": f"Bearer {tenant_token}"},
        )
        self.assertEqual(register.status_code, 201, register.get_data(as_text=True))

        queued = self.client.post(
            "/api/agent/hosts/scope-action-host/actions",
            json={"action_type": "ping", "reason": "scope regression"},
            headers={"Authorization": f"Bearer {tenant_token}"},
        )
        self.assertEqual(queued.status_code, 403, queued.get_data(as_text=True))
        self.assertEqual(queued.get_json()["error"], "insufficient_scope")

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

    def test_enrollment_token_registers_host_once_without_admin_header(self):
        create = self.client.post(
            "/api/agent/enrollment-token",
            json={
                "tenant_id": "default",
                "expires_in_seconds": 600,
                "max_uses": 1,
            },
            headers=self._admin_headers(),
        )
        self.assertEqual(create.status_code, 201, create.get_data(as_text=True))
        created = create.get_json()
        self.assertTrue(created["token"].startswith("nge_"))
        self.assertEqual(created["enrollment"]["tenant_id"], "default")
        self.assertEqual(created["enrollment"]["remaining_uses"], 1)

        register = self.client.post(
            "/api/agent/register",
            json={
                "host_id": "enrolled-host-01",
                "display_name": "Endpoint 01",
                "platform": "windows",
                "agent_version": "1.0.0",
                "enrollment_token": created["token"],
            },
        )
        self.assertEqual(register.status_code, 201, register.get_data(as_text=True))
        body = register.get_json()
        self.assertEqual(body["host"]["tenant_id"], "default")
        self.assertEqual(body["host"]["enrollment_method"], "enrollment_token")
        self.assertTrue(body["api_key"].startswith("nga_"))

        reused = self.client.post(
            "/api/agent/register",
            json={
                "host_id": "enrolled-host-02",
                "platform": "windows",
                "enrollment_token": created["token"],
            },
        )
        self.assertEqual(reused.status_code, 403, reused.get_data(as_text=True))
        self.assertEqual(reused.get_json()["error"], "invalid_enrollment_token")

    def test_revoked_host_key_cannot_send_heartbeat(self):
        register = self.client.post(
            "/api/agent/register",
            json={"host_id": "agent-host-revoked", "platform": "windows"},
            headers=self._admin_headers(),
        )
        self.assertEqual(register.status_code, 201, register.get_data(as_text=True))
        agent_key = register.get_json()["api_key"]

        revoke = self.client.post(
            "/api/agent/hosts/agent-host-revoked/revoke",
            headers=self._admin_headers(),
        )
        self.assertEqual(revoke.status_code, 200, revoke.get_data(as_text=True))
        self.assertEqual(revoke.get_json()["host"]["status"], "revoked")

        heartbeat = self.client.post(
            "/api/agent/heartbeat",
            json={"host_id": "agent-host-revoked"},
            headers={"X-API-Key": agent_key},
        )
        self.assertEqual(heartbeat.status_code, 401, heartbeat.get_data(as_text=True))

    def test_rotated_host_key_invalidates_old_secret(self):
        register = self.client.post(
            "/api/agent/register",
            json={"host_id": "agent-host-rotated", "platform": "windows"},
            headers=self._admin_headers(),
        )
        self.assertEqual(register.status_code, 201, register.get_data(as_text=True))
        old_key = register.get_json()["api_key"]

        agent_attempt = self.client.post(
            "/api/agent/hosts/agent-host-rotated/rotate-key",
            headers={"X-NetGuard-Agent-Key": old_key},
        )
        self.assertEqual(agent_attempt.status_code, 401, agent_attempt.get_data(as_text=True))

        rotate = self.client.post(
            "/api/agent/hosts/agent-host-rotated/rotate-key",
            headers=self._admin_headers(),
        )
        self.assertEqual(rotate.status_code, 200, rotate.get_data(as_text=True))
        rotated = rotate.get_json()
        new_key = rotated["api_key"]
        self.assertTrue(new_key.startswith("nga_"))
        self.assertNotEqual(new_key, old_key)
        self.assertEqual(rotated["host"]["api_key_prefix"], new_key[:16])

        old_heartbeat = self.client.post(
            "/api/agent/heartbeat",
            json={"host_id": "agent-host-rotated"},
            headers={"X-NetGuard-Agent-Key": old_key},
        )
        self.assertEqual(old_heartbeat.status_code, 401, old_heartbeat.get_data(as_text=True))

        new_heartbeat = self.client.post(
            "/api/agent/heartbeat",
            json={"host_id": "agent-host-rotated", "platform": "windows"},
            headers={"X-NetGuard-Agent-Key": new_key},
        )
        self.assertEqual(new_heartbeat.status_code, 200, new_heartbeat.get_data(as_text=True))
        self.assertEqual(new_heartbeat.get_json()["host"]["status"], "online")

    def test_agent_action_queue_poll_and_ack_flow(self):
        register = self.client.post(
            "/api/agent/register",
            json={"host_id": "agent-action-host", "platform": "windows"},
            headers=self._admin_headers(),
        )
        self.assertEqual(register.status_code, 201, register.get_data(as_text=True))
        agent_key = register.get_json()["api_key"]

        queued = self.client.post(
            "/api/agent/hosts/agent-action-host/actions",
            json={
                "action_type": "collect_diagnostics",
                "reason": "triage test",
                "payload": {"include": ["buffer", "host"]},
            },
            headers=self._admin_headers(),
        )
        self.assertEqual(queued.status_code, 201, queued.get_data(as_text=True))
        action = queued.get_json()["action"]
        self.assertTrue(action["action_id"].startswith("act_"))
        self.assertEqual(action["status"], "pending")

        poll = self.client.get(
            "/api/agent/actions",
            headers={"X-NetGuard-Agent-Key": agent_key},
        )
        self.assertEqual(poll.status_code, 200, poll.get_data(as_text=True))
        actions = poll.get_json()["actions"]
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["action_id"], action["action_id"])
        self.assertEqual(actions[0]["status"], "leased")

        ack = self.client.post(
            f"/api/agent/actions/{action['action_id']}/ack",
            json={"status": "succeeded", "result": {"buffer_pending": 0}},
            headers={"X-NetGuard-Agent-Key": agent_key},
        )
        self.assertEqual(ack.status_code, 200, ack.get_data(as_text=True))
        self.assertEqual(ack.get_json()["action"]["status"], "succeeded")

        listed = self.client.get(
            "/api/agent/hosts/agent-action-host/actions",
            headers=self._admin_headers(),
        )
        self.assertEqual(listed.status_code, 200, listed.get_data(as_text=True))
        self.assertEqual(listed.get_json()["actions"][0]["status"], "succeeded")

    def test_guarded_agent_action_requires_policy_secret(self):
        previous_secret = os.environ.pop("NETGUARD_RESPONSE_POLICY_SECRET", None)
        try:
            register = self.client.post(
                "/api/agent/register",
                json={"host_id": "agent-guarded-no-policy", "platform": "windows"},
                headers=self._admin_headers(),
            )
            self.assertEqual(register.status_code, 201, register.get_data(as_text=True))

            blocked = self.client.post(
                "/api/agent/hosts/agent-guarded-no-policy/actions",
                json={"action_type": "isolate_host", "reason": "test destructive deny"},
                headers=self._admin_headers(),
            )
            self.assertEqual(blocked.status_code, 403, blocked.get_data(as_text=True))
            self.assertEqual(blocked.get_json()["error"], "destructive_actions_disabled")
        finally:
            if previous_secret is not None:
                os.environ["NETGUARD_RESPONSE_POLICY_SECRET"] = previous_secret

    def test_guarded_agent_action_accepts_short_lived_signed_policy(self):
        from server.response_policy import sign_response_policy

        previous_secret = os.environ.get("NETGUARD_RESPONSE_POLICY_SECRET")
        secret = "policy-test-secret-" + uuid.uuid4().hex
        os.environ["NETGUARD_RESPONSE_POLICY_SECRET"] = secret
        try:
            host_id = "agent-guarded-signed-policy"
            register = self.client.post(
                "/api/agent/register",
                json={"host_id": host_id, "platform": "windows"},
                headers=self._admin_headers(),
            )
            self.assertEqual(register.status_code, 201, register.get_data(as_text=True))
            agent_key = register.get_json()["api_key"]

            invalid = self.client.post(
                f"/api/agent/hosts/{host_id}/actions",
                json={
                    "action_type": "isolate_host",
                    "policy_nonce": uuid.uuid4().hex,
                    "policy_expires_at": int(time.time()) + 120,
                    "policy_signature": "bad-signature",
                },
                headers=self._admin_headers(),
            )
            self.assertEqual(invalid.status_code, 403, invalid.get_data(as_text=True))
            self.assertEqual(invalid.get_json()["error"], "invalid_policy_signature")

            expires_at = int(time.time()) + 120
            nonce = uuid.uuid4().hex
            signature = sign_response_policy(
                secret,
                tenant_id="admin",
                host_id=host_id,
                action_type="isolate_host",
                nonce=nonce,
                expires_at=expires_at,
            )
            queued = self.client.post(
                f"/api/agent/hosts/{host_id}/actions",
                json={
                    "action_type": "isolate_host",
                    "reason": "signed policy test",
                    "policy_nonce": nonce,
                    "policy_expires_at": expires_at,
                    "policy_signature": signature,
                },
                headers=self._admin_headers(),
            )
            self.assertEqual(queued.status_code, 201, queued.get_data(as_text=True))
            self.assertEqual(queued.get_json()["action"]["action_type"], "isolate_host")
            self.assertEqual(queued.get_json()["action"]["status"], "pending")

            poll = self.client.get(
                "/api/agent/actions",
                headers={"X-NetGuard-Agent-Key": agent_key},
            )
            self.assertEqual(poll.status_code, 200, poll.get_data(as_text=True))
            leased_action = poll.get_json()["actions"][0]
            policy = leased_action["payload"]["policy"]
            self.assertEqual(policy["tenant_id"], "admin")
            self.assertEqual(policy["host_id"], host_id)
            self.assertEqual(policy["action_type"], "isolate_host")
            self.assertEqual(policy["nonce"], nonce)
            self.assertEqual(policy["expires_at"], expires_at)
            self.assertEqual(policy["signature"], signature)
        finally:
            if previous_secret is None:
                os.environ.pop("NETGUARD_RESPONSE_POLICY_SECRET", None)
            else:
                os.environ["NETGUARD_RESPONSE_POLICY_SECRET"] = previous_secret

    def test_agent_action_cancel_endpoint_prevents_future_leases(self):
        register = self.client.post(
            "/api/agent/register",
            json={"host_id": "agent-action-cancel-host", "platform": "windows"},
            headers=self._admin_headers(),
        )
        self.assertEqual(register.status_code, 201, register.get_data(as_text=True))
        agent_key = register.get_json()["api_key"]

        queued = self.client.post(
            "/api/agent/hosts/agent-action-cancel-host/actions",
            json={"action_type": "flush_buffer", "reason": "queued by mistake"},
            headers=self._admin_headers(),
        )
        self.assertEqual(queued.status_code, 201, queued.get_data(as_text=True))
        action_id = queued.get_json()["action"]["action_id"]

        cancelled = self.client.post(
            f"/api/agent/actions/{action_id}/cancel",
            json={"reason": "operator cancelled before lease"},
            headers=self._admin_headers(),
        )
        self.assertEqual(cancelled.status_code, 200, cancelled.get_data(as_text=True))
        self.assertEqual(cancelled.get_json()["action"]["status"], "cancelled")

        poll = self.client.get(
            "/api/agent/actions",
            headers={"X-NetGuard-Agent-Key": agent_key},
        )
        self.assertEqual(poll.status_code, 200, poll.get_data(as_text=True))
        self.assertEqual(poll.get_json()["actions"], [])
