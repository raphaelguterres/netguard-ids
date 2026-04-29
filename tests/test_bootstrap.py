import os
import sys
import unittest
import uuid
from unittest.mock import patch


os.environ.setdefault("IDS_AUTH", "false")
os.environ.setdefault("IDS_DASHBOARD_AUTH", "false")
os.environ.setdefault("IDS_CSRF_DISABLED", "false")
os.environ.setdefault("HTTPS_ONLY", "false")
os.environ.setdefault("IDS_ENV", "test")
os.environ.setdefault("TOKEN_SIGNING_SECRET", "bootstrap-test-signing-key")
os.environ.pop("DATABASE_URL", None)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("NETGUARD_AGENT_KEYS", "nga_bootstrap_test_key")
os.environ.setdefault("NETGUARD_EDR_DB", os.path.join(ROOT, ".tmp", "bootstrap-edr.db"))
sys.path.insert(0, ROOT)

import app as app_module


class TestBootstrapContract(unittest.TestCase):
    def test_create_app_returns_singleton_app(self):
        self.assertIs(app_module.create_app(), app_module.app)

    def test_background_service_specs_cover_core_services(self):
        labels = {spec["label"] for spec in app_module._background_service_specs()}
        self.assertTrue(
            {
                "SOC Engine",
                "Monitoring",
                "Threat Intel scheduler",
                "Trial expiry scheduler",
            }.issubset(labels)
        )

    def test_start_background_services_honors_enabled_and_disabled_specs(self):
        calls = []

        def starter_enabled():
            calls.append("enabled")

        def starter_disabled():
            calls.append("disabled-starter")

        def disabled_hook():
            calls.append("disabled-hook")

        specs = (
            {"label": "Enabled", "feature_env": "ENV_ENABLED", "starter": starter_enabled},
            {
                "label": "Disabled",
                "feature_env": "ENV_DISABLED",
                "starter": starter_disabled,
                "on_disabled": disabled_hook,
            },
        )

        def _enabled(feature_env: str, legacy_disable_env=None):
            return feature_env == "ENV_ENABLED"

        with patch.object(app_module, "_background_service_specs", return_value=specs):
            with patch.object(app_module, "_background_autostart_enabled", side_effect=_enabled):
                app_module.start_background_services()

        self.assertEqual(calls, ["enabled", "disabled-hook"])

    def test_modular_edr_blueprints_registered(self):
        self.assertIn("netguard_edr", app_module.app.blueprints)
        self.assertIn("netguard_soc", app_module.app.blueprints)
        self.assertIsNotNone(getattr(app_module.app, "_edr_repo", None))

    def test_modular_api_events_accepts_authenticated_empty_batch(self):
        client = app_module.app.test_client()
        host_id = f"bootstrap-host-{uuid.uuid4().hex[:8]}"
        response = client.post(
            "/api/events",
            headers={"X-API-Key": "nga_bootstrap_test_key"},
            json={
                "host_id": host_id,
                "hostname": "Bootstrap Test Host",
                "agent_version": "1.0.0",
                "events": [],
            },
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        body = response.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["host_id"], host_id)

    def test_modular_soc_grid_overview_route_available(self):
        client = app_module.app.test_client()
        response = client.get("/soc/grid/api/overview")
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        body = response.get_json()
        self.assertTrue(body["ok"])
        self.assertIn("summary", body)
        self.assertIn("agent_status_counts", body)
        self.assertIn("online_hosts", body["summary"])

    def test_modular_soc_grid_rules_route_available(self):
        client = app_module.app.test_client()
        response = client.get("/soc/grid/api/rules")
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        body = response.get_json()
        self.assertTrue(body["ok"])
        self.assertIn("rules", body)
        self.assertIn("summary", body)
        self.assertIn("yaml_health", body["summary"])
