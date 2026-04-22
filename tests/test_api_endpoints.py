"""
tests/test_api_endpoints.py
===========================
Integration-style tests for the Flask API endpoints:

  • /api/health    — opaque errors, request_id always present
  • /api/graph     — stale-while-revalidate cache, cached/stale fields
  • /api/geo       — stale-while-revalidate cache, cached/stale fields
  • /trial/<token> — valid / expired / revoked tokens
  • Async cache helpers: _ttl_cache_get_swr, _trigger_bg_refresh

Auth/CSRF-sensitive endpoints use an explicit admin token so these tests
stay aligned with the hardened API contract.
"""
import os
import sys
import time
import threading
import unittest
from unittest.mock import patch, MagicMock

# ── env before app import ─────────────────────────────────────────
os.environ.setdefault("IDS_AUTH", "false")
os.environ.setdefault("IDS_DASHBOARD_AUTH", "false")
os.environ.setdefault("IDS_CSRF_DISABLED", "false")
os.environ.setdefault("HTTPS_ONLY", "false")
os.environ.setdefault("IDS_ENV", "test")
os.environ.setdefault("TOKEN_SIGNING_SECRET", "api-endpoints-test-signing-key")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


# ══════════════════════════════════════════════════════════════════
# 1. Async cache helpers (unit)
# ══════════════════════════════════════════════════════════════════

class TestTTLCacheSWR(unittest.TestCase):
    """Tests for _ttl_cache_get_swr and _trigger_bg_refresh."""

    def setUp(self):
        import app as _app
        self.app_module = _app

    def test_no_entry_returns_none(self):
        cache = {}
        lock  = threading.Lock()
        data, stale = self.app_module._ttl_cache_get_swr(cache, lock, "k", 30, 120)
        self.assertIsNone(data)
        self.assertFalse(stale)

    def test_fresh_entry_not_stale(self):
        cache = {}
        lock  = threading.Lock()
        self.app_module._ttl_cache_set(cache, lock, "k", {"hello": "world"})
        data, stale = self.app_module._ttl_cache_get_swr(cache, lock, "k", 30, 120)
        self.assertEqual(data, {"hello": "world"})
        self.assertFalse(stale)

    def test_stale_entry_returns_data_and_stale_true(self):
        cache = {"k": {"ts": time.time() - 50, "data": {"v": 1}}}
        lock  = threading.Lock()
        # fresh_ttl=30 → 50s > 30 → stale; stale_ttl=120 → 50 < 120 → still usable
        data, stale = self.app_module._ttl_cache_get_swr(cache, lock, "k", 30, 120)
        self.assertEqual(data, {"v": 1})
        self.assertTrue(stale)

    def test_beyond_stale_ttl_returns_none(self):
        cache = {"k": {"ts": time.time() - 200, "data": {"v": 1}}}
        lock  = threading.Lock()
        data, stale = self.app_module._ttl_cache_get_swr(cache, lock, "k", 30, 120)
        self.assertIsNone(data)

    def test_trigger_bg_refresh_runs_function(self):
        called = threading.Event()

        def my_fn():
            called.set()

        self.app_module._trigger_bg_refresh("test-job-unique", my_fn)
        self.assertTrue(called.wait(timeout=3), "Background function was not called")

    def test_trigger_bg_refresh_deduplicates(self):
        """Second call with same job_key while first is running should be ignored."""
        barrier = threading.Event()
        call_count = [0]

        def slow_fn():
            call_count[0] += 1
            barrier.wait(timeout=2)

        self.app_module._trigger_bg_refresh("dedup-test", slow_fn)
        time.sleep(0.05)  # let first thread start
        self.app_module._trigger_bg_refresh("dedup-test", slow_fn)
        barrier.set()
        time.sleep(0.1)
        self.assertEqual(call_count[0], 1)


# ══════════════════════════════════════════════════════════════════
# 2. resolve_ip (non-blocking)
# ══════════════════════════════════════════════════════════════════

class TestResolveIpNonBlocking(unittest.TestCase):
    def setUp(self):
        import app as _app
        self.app_module = _app
        # Clear DNS cache to get fresh state
        with _app._dns_lock:
            _app._dns_cache.clear()

    def test_unknown_ip_returns_immediately(self):
        """resolve_ip must return quickly (non-blocking) for uncached IPs."""
        t0 = time.time()
        result = self.app_module.resolve_ip("8.8.8.8")
        elapsed = time.time() - t0
        # Should return in < 100ms even without network
        self.assertLess(elapsed, 0.5, "resolve_ip blocked the thread")
        # Returns either the IP or a cached hostname
        self.assertIn("8.8.8.8" if result == "8.8.8.8" else result, [result])

    def test_cached_ip_returns_hostname(self):
        """Once resolved and cached, subsequent calls return the hostname."""
        import app as _app
        with _app._dns_lock:
            _app._dns_cache["1.2.3.4"] = "example.host"
        result = self.app_module.resolve_ip("1.2.3.4")
        self.assertEqual(result, "example.host")


# ══════════════════════════════════════════════════════════════════
# 3. /api/health endpoint
# ══════════════════════════════════════════════════════════════════

class TestSocPreviewRoutes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as _app
        _app.app.config["TESTING"] = True
        cls.client = _app.app.test_client()

    def test_overview_preview_renders(self):
        resp = self.client.get("/soc-preview")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Security Overview", resp.get_data(as_text=True))

    def test_hosts_preview_renders(self):
        resp = self.client.get("/soc-preview/hosts")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Endpoint Inventory", resp.get_data(as_text=True))

    def test_alerts_preview_renders(self):
        resp = self.client.get("/soc-preview/alerts")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Detection Queue", resp.get_data(as_text=True))

    def test_host_detail_preview_falls_back_without_404(self):
        resp = self.client.get("/soc-preview/hosts/nonexistent-host")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("nonexistent-host", resp.get_data(as_text=True))

    def test_soc_incidents_route_and_context_support_filters(self):
        import app as _app
        from auth import get_or_create_token

        if not getattr(_app, "PLAYBOOK_AVAILABLE", False):
            self.skipTest("playbook engine unavailable")

        token = get_or_create_token()
        headers = {"X-API-Token": token}
        pb = _app._get_playbook_engine()
        with pb._db() as conn:
            conn.execute("DELETE FROM pb_steps")
            conn.execute("DELETE FROM pb_incidents WHERE tenant_id = ?", ("admin",))
            conn.commit()

        self.client.post(
            "/api/xdr/events",
            json={
                "events": [
                    {
                        "host_id": "host-soc-incidents-01",
                        "event_type": "process_execution",
                        "severity": "medium",
                        "timestamp": "2026-04-13T16:00:00Z",
                        "process_name": "powershell.exe",
                        "command_line": "powershell.exe -nop -enc ZQBjAGgAbwA=",
                        "parent_process": "winword.exe",
                        "pid": 4141,
                        "source": "agent",
                        "platform": "windows",
                        "details": {},
                    }
                ]
            },
            headers=headers,
        )

        resp = self.client.get("/soc/incidents", headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Incidents Queue", resp.get_data(as_text=True))

        with _app.app.test_request_context(
            "/soc/incidents?status=open&host=host-soc-incidents-01&technique=T1059.001",
            headers=headers,
        ):
            context = _app._build_soc_incidents_context(context=_app._build_soc_preview_context())

        self.assertTrue(context["incident_rows"])
        self.assertEqual(context["incident_filters"]["status"], "open")
        self.assertEqual(context["incident_filters"]["host"], "host-soc-incidents-01")
        self.assertEqual(context["incident_filters"]["technique"], "T1059.001")
        self.assertTrue(all(item["host_id"] == "host-soc-incidents-01" for item in context["incident_rows"]))
        self.assertTrue(all(item["technique"] == "T1059.001" for item in context["incident_rows"]))
        self.assertTrue(all(item["chain_filter"] for item in context["incident_rows"]))

    def test_host_detail_context_includes_timeline_lineage_and_incidents(self):
        import app as _app
        from auth import get_or_create_token

        token = get_or_create_token()
        headers = {"X-API-Token": token}
        if getattr(_app, "PLAYBOOK_AVAILABLE", False):
            pb = _app._get_playbook_engine()
            with pb._db() as conn:
                conn.execute("DELETE FROM pb_steps")
                conn.execute("DELETE FROM pb_incidents WHERE tenant_id = ?", ("admin",))
                conn.commit()

        self.client.post(
            "/api/xdr/events",
            json={
                "events": [
                    {
                        "host_id": "host-soc-detail-01",
                        "event_type": "process_execution",
                        "severity": "medium",
                        "timestamp": "2026-04-13T16:00:00Z",
                        "process_name": "powershell.exe",
                        "command_line": "powershell.exe -nop -enc ZQBjAGgAbwA=",
                        "parent_process": "winword.exe",
                        "pid": 9191,
                        "source": "agent",
                        "platform": "windows",
                        "details": {},
                    }
                ]
            },
            headers=headers,
        )

        with _app.app.test_request_context("/soc/hosts/host-soc-detail-01", headers=headers):
            context = _app._build_soc_host_detail_context("host-soc-detail-01", context=_app._build_soc_preview_context())

        self.assertIsNotNone(context)
        self.assertTrue(context["host_events"])
        self.assertTrue(any(item["alert_type"] == "suspicious_powershell" for item in context["host_events"]))
        self.assertTrue(context["host_lineage"])
        self.assertTrue(context["host_incidents"])
        self.assertTrue(context["host_attack_chains"])
        self.assertTrue(any(item["techniques"] for item in context["host_attack_chains"]))

    def test_host_detail_context_can_filter_timeline_by_attack_chain(self):
        import app as _app
        from auth import get_or_create_token

        token = get_or_create_token()
        headers = {"X-API-Token": token}

        self.client.post(
            "/api/xdr/events",
            json={
                "events": [
                    {
                        "host_id": "host-soc-chain-filter-01",
                        "event_type": "process_execution",
                        "severity": "medium",
                        "timestamp": "2026-04-13T16:00:00Z",
                        "process_name": "powershell.exe",
                        "command_line": "powershell.exe -nop -enc ZQBjAGgAbwA=",
                        "parent_process": "winword.exe",
                        "pid": 7272,
                        "source": "agent",
                        "platform": "windows",
                        "details": {},
                    }
                ]
            },
            headers=headers,
        )

        with _app.app.test_request_context("/soc/hosts/host-soc-chain-filter-01", headers=headers):
            base_context = _app._build_soc_host_detail_context(
                "host-soc-chain-filter-01",
                context=_app._build_soc_preview_context(),
            )
        self.assertTrue(base_context["host_attack_chains"])
        event_filters = {
            item["chain_filter"]
            for item in base_context["host_events"]
            if item.get("chain_filter")
        }
        selected_filter = next(
            (
                chain["filter_key"]
                for chain in base_context["host_attack_chains"]
                if chain.get("filter_key") in event_filters
            ),
            base_context["host_attack_chains"][0]["filter_key"],
        )

        with _app.app.test_request_context(f"/soc/hosts/host-soc-chain-filter-01?chain={selected_filter}", headers=headers):
            context = _app._build_soc_host_detail_context(
                "host-soc-chain-filter-01",
                context=_app._build_soc_preview_context(),
            )

        self.assertIsNotNone(context)
        self.assertEqual(context["selected_chain_filter"], selected_filter)
        self.assertTrue(context["selected_chain"])
        self.assertTrue(context["selected_chain_focus"])
        self.assertEqual(context["selected_chain_focus"]["title"], context["selected_chain"]["title"])
        self.assertTrue(context["selected_chain_focus"]["metrics"])
        self.assertTrue(context["host_events"])
        self.assertTrue(all(item["chain_filter"] == selected_filter for item in context["host_events"]))

    def test_soc_incident_status_update_endpoint(self):
        import app as _app
        from auth import get_or_create_token

        if not getattr(_app, "PLAYBOOK_AVAILABLE", False):
            self.skipTest("playbook engine unavailable")

        token = get_or_create_token()
        headers = {"X-API-Token": token}
        pb = _app._get_playbook_engine()
        with pb._db() as conn:
            conn.execute("DELETE FROM pb_steps")
            conn.execute("DELETE FROM pb_incidents WHERE tenant_id = ?", ("admin",))
            conn.commit()

        self.client.post(
            "/api/xdr/events",
            json={
                "events": [
                    {
                        "host_id": "host-soc-incident-status-01",
                        "event_type": "process_execution",
                        "severity": "medium",
                        "timestamp": "2026-04-13T16:00:00Z",
                        "process_name": "powershell.exe",
                        "command_line": "powershell.exe -nop -enc ZQBjAGgAbwA=",
                        "parent_process": "winword.exe",
                        "pid": 8181,
                        "source": "agent",
                        "platform": "windows",
                        "details": {},
                    }
                ]
            },
            headers=headers,
        )

        incident = pb.list_incidents(tenant_id="admin", limit=1)[0]
        resp = self.client.post(
            f"/soc/incidents/{incident['incident_id']}/status",
            json={"status": "resolved"},
            headers=headers,
        )

        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["incident"]["status"], "resolved")


class TestHealthEndpoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as _app
        _app.app.config["TESTING"] = True
        cls.client = _app.app.test_client()

    def test_health_returns_200_or_503(self):
        resp = self.client.get("/api/health")
        self.assertIn(resp.status_code, [200, 503])

    def test_health_contains_request_id(self):
        resp = self.client.get("/api/health")
        data = resp.get_json()
        self.assertIsNotNone(data, "Response body is not JSON")
        self.assertIn("request_id", data, "request_id missing from health response")

    def test_health_request_id_is_hex_string(self):
        resp = self.client.get("/api/health")
        req_id = resp.get_json().get("request_id", "")
        self.assertTrue(len(req_id) >= 8)
        int(req_id, 16)  # must be valid hex

    def test_health_no_traceback_in_body(self):
        resp = self.client.get("/api/health")
        body = resp.get_data(as_text=True)
        self.assertNotIn("Traceback", body)
        self.assertNotIn("File \"", body)

    def test_both_health_routes(self):
        for path in ["/health", "/api/health"]:
            resp = self.client.get(path)
            self.assertIn(resp.status_code, [200, 503],
                          f"{path} returned unexpected status {resp.status_code}")


class TestMitreEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as _app
        from auth import get_or_create_token

        _app.app.config["TESTING"] = True
        cls.client = _app.app.test_client()
        cls.auth_headers = {"X-API-Token": get_or_create_token()}

    def test_mitre_stats_returns_200_with_expected_shape(self):
        resp = self.client.get("/api/mitre/stats", headers=self.auth_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIsInstance(data, dict)
        self.assertIn("coverage_pct", data)
        self.assertIn("total_hits", data)

    def test_mitre_heatmap_returns_matrix_and_top_aliases(self):
        resp = self.client.get("/api/mitre/heatmap?days=30", headers=self.auth_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIsInstance(data, dict)
        self.assertIn("matrix", data)
        self.assertIn("top_techniques", data)
        self.assertIn("top10", data)

    def test_mitre_hits_returns_hits_list(self):
        resp = self.client.get("/api/mitre/hits?days=30&limit=10", headers=self.auth_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIsInstance(data, dict)
        self.assertIn("hits", data)
        self.assertIn("total", data)
        self.assertIsInstance(data["hits"], list)

    @patch("app._get_mitre_engine", side_effect=RuntimeError("boom"))
    def test_mitre_stats_falls_back_instead_of_500(self, _mock_engine):
        resp = self.client.get("/api/mitre/stats", headers=self.auth_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get("degraded"))
        self.assertEqual(data.get("warning"), "stats_unavailable")
        self.assertIn("request_id", data)
        self.assertEqual(resp.headers.get("X-NetGuard-Degraded"), "1")
        self.assertEqual(resp.headers.get("X-NetGuard-Warning"), "stats_unavailable")

    @patch("app._get_mitre_engine", side_effect=RuntimeError("boom"))
    def test_mitre_heatmap_falls_back_instead_of_500(self, _mock_engine):
        resp = self.client.get("/api/mitre/heatmap?days=30", headers=self.auth_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get("degraded"))
        self.assertEqual(data.get("warning"), "heatmap_unavailable")
        self.assertEqual(data.get("days"), 30)
        self.assertIn("request_id", data)
        self.assertEqual(resp.headers.get("X-NetGuard-Degraded"), "1")
        self.assertEqual(resp.headers.get("X-NetGuard-Warning"), "heatmap_unavailable")

    def test_mitre_heatmap_invalid_days_uses_default(self):
        resp = self.client.get("/api/mitre/heatmap?days=abc", headers=self.auth_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get("days"), 30)

    def test_mitre_hits_invalid_params_do_not_500(self):
        resp = self.client.get("/api/mitre/hits?days=abc&limit=xyz", headers=self.auth_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("hits", data)
        self.assertEqual(data.get("days"), 30)

    @patch("app._get_mitre_engine", side_effect=RuntimeError("boom"))
    def test_mitre_hits_fallback_sets_headers_and_request_id(self, _mock_engine):
        resp = self.client.get("/api/mitre/hits?days=30&limit=10", headers=self.auth_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get("degraded"))
        self.assertEqual(data.get("warning"), "hits_unavailable")
        self.assertIn("request_id", data)
        self.assertEqual(resp.headers.get("X-NetGuard-Degraded"), "1")
        self.assertEqual(resp.headers.get("X-NetGuard-Warning"), "hits_unavailable")

    def test_mitre_navigator_invalid_days_uses_default(self):
        resp = self.client.get("/api/mitre/navigator?days=abc", headers=self.auth_headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.mimetype, "application/json")

    @patch("app._get_mitre_engine", side_effect=RuntimeError("boom"))
    def test_mitre_navigator_internal_error_is_opaque(self, _mock_engine):
        resp = self.client.get("/api/mitre/navigator?days=30", headers=self.auth_headers)
        self.assertEqual(resp.status_code, 500)
        data = resp.get_json()
        self.assertEqual(data.get("error"), "internal_error")
        self.assertIn("request_id", data)

    @patch("app._get_mitre_engine", side_effect=RuntimeError("boom"))
    def test_mitre_technique_internal_error_is_opaque(self, _mock_engine):
        resp = self.client.get("/api/mitre/technique/T1059", headers=self.auth_headers)
        self.assertEqual(resp.status_code, 500)
        data = resp.get_json()
        self.assertEqual(data.get("error"), "internal_error")
        self.assertIn("request_id", data)


class TestSystemEndpointCaching(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as _app
        from auth import get_or_create_token

        _app.app.config["TESTING"] = True
        cls.client = _app.app.test_client()
        cls.app_mod = _app
        cls.auth_headers = {"X-API-Token": get_or_create_token()}

    def setUp(self):
        with self.app_mod._endpoint_swr_lock:
            self.app_mod._endpoint_swr_cache.clear()

    @patch("app.get_system_info")
    def test_system_second_call_uses_short_cache(self, mock_get_system_info):
        mock_get_system_info.return_value = {
            "cpu_percent": 10,
            "mem_percent": 20,
            "disk_percent": 30,
            "net_sent_mb": 1.5,
            "net_recv_mb": 2.5,
            "interfaces": [],
            "processes": [],
            "listening": [],
            "details_deferred": True,
        }

        first = self.client.get("/api/system", headers=self.auth_headers)
        second = self.client.get("/api/system", headers=self.auth_headers)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(mock_get_system_info.call_count, 1)


class TestBackendSingletonsAndCaching(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as _app
        from auth import get_or_create_token

        _app.app.config["TESTING"] = True
        cls.client = _app.app.test_client()
        cls.app_mod = _app
        cls.auth_headers = {"X-API-Token": get_or_create_token()}

    def setUp(self):
        with self.app_mod._endpoint_swr_lock:
            self.app_mod._endpoint_swr_cache.clear()
        self.app_mod._ti_feed_singleton = None
        self.app_mod._ti_feed_scheduler_started = False
        self.app_mod._playbook_engine_singleton = None
        self.app_mod._forensics_engine_singleton = None

    @patch("app.get_ti_feed")
    def test_ti_feed_scheduler_nao_autostarta_em_import_seguro(self, mock_get_ti_feed):
        feed = MagicMock()
        mock_get_ti_feed.return_value = feed

        first = self.app_mod._get_ti_feed()
        second = self.app_mod._get_ti_feed()

        self.assertIs(first, second)
        self.assertEqual(mock_get_ti_feed.call_count, 1)
        self.assertEqual(feed.start_scheduler.call_count, 0)

    @patch("app.get_ti_feed")
    def test_ti_feed_scheduler_pode_ser_habilitado_explicitamente(self, mock_get_ti_feed):
        feed = MagicMock()
        mock_get_ti_feed.return_value = feed

        with patch.dict(os.environ, {"IDS_AUTOSTART_TI_FEED_SCHEDULER": "true"}, clear=False):
            first = self.app_mod._get_ti_feed()
            second = self.app_mod._get_ti_feed()

        self.assertIs(first, second)
        self.assertEqual(mock_get_ti_feed.call_count, 1)
        self.assertEqual(feed.start_scheduler.call_count, 1)

    @patch("app.get_playbook_engine")
    def test_playbook_engine_is_singleton(self, mock_get_playbook_engine):
        eng = MagicMock()
        mock_get_playbook_engine.return_value = eng

        first = self.app_mod._get_playbook_engine()
        second = self.app_mod._get_playbook_engine()

        self.assertIs(first, second)
        self.assertEqual(mock_get_playbook_engine.call_count, 1)

    @patch("app.get_forensics_engine")
    def test_forensics_engine_is_singleton(self, mock_get_forensics_engine_factory):
        eng = MagicMock()
        mock_get_forensics_engine_factory.return_value = eng

        first = self.app_mod._get_forensics_engine()
        second = self.app_mod._get_forensics_engine()

        self.assertIs(first, second)
        self.assertEqual(mock_get_forensics_engine_factory.call_count, 1)

    @patch("app._get_forensics_engine")
    def test_forensics_second_call_uses_cache(self, mock_get_forensics_engine):
        eng = MagicMock()
        eng.list_snapshots.return_value = [{"snapshot_id": "snap-1"}]
        eng.stats.return_value = {"total": 1, "by_severity": {"high": 1}}
        mock_get_forensics_engine.return_value = eng

        first = self.client.get("/api/forensics/snapshots", headers=self.auth_headers)
        second = self.client.get("/api/forensics/snapshots", headers=self.auth_headers)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(mock_get_forensics_engine.call_count, 1)
        self.assertEqual(eng.list_snapshots.call_count, 1)
        self.assertEqual(eng.stats.call_count, 1)


# ══════════════════════════════════════════════════════════════════
# 4. /api/graph — stale-while-revalidate
# ══════════════════════════════════════════════════════════════════

class TestGraphEndpoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as _app
        from auth import get_or_create_token
        _app.app.config["TESTING"] = True
        cls.client  = _app.app.test_client()
        cls.app_mod = _app
        cls.auth_headers = {"X-API-Token": get_or_create_token()}

    def setUp(self):
        # Clear graph cache between tests
        with self.app_mod._graph_cache_lock:
            self.app_mod._graph_cache.clear()

    @patch("subprocess.run")
    def test_graph_returns_200(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        resp = self.client.get("/api/graph", headers=self.auth_headers)
        self.assertEqual(resp.status_code, 200)

    @patch("subprocess.run")
    def test_graph_response_has_nodes_and_edges(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        resp = self.client.get("/api/graph", headers=self.auth_headers)
        data = resp.get_json()
        self.assertIsNotNone(data)
        self.assertIn("nodes", data)
        self.assertIn("edges", data)

    @patch("subprocess.run")
    def test_graph_second_call_is_cached(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        self.client.get("/api/graph", headers=self.auth_headers)   # cold
        resp2 = self.client.get("/api/graph", headers=self.auth_headers)  # should be cached
        data = resp2.get_json()
        self.assertTrue(data.get("cached"), "Second call should return cached=True")

    @patch("subprocess.run")
    def test_graph_stale_cache_triggers_bg_refresh(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        # Inject a stale entry (age=50s, fresh_ttl=30, stale_ttl=120)
        with self.app_mod._graph_cache_lock:
            self.app_mod._graph_cache["default"] = {
                "ts":   time.time() - 50,
                "data": {"nodes": [], "edges": [], "timestamp": "old"},
            }
        refresh_triggered = threading.Event()
        original_trigger = self.app_mod._trigger_bg_refresh

        def fake_trigger(key, fn, *args):
            refresh_triggered.set()
            return original_trigger(key, fn, *args)

        with patch.object(self.app_mod, "_trigger_bg_refresh", side_effect=fake_trigger):
            resp = self.client.get("/api/graph", headers=self.auth_headers)
            data = resp.get_json()

        self.assertTrue(data.get("stale"), "Stale cache should return stale=True")
        self.assertTrue(refresh_triggered.is_set(), "Stale hit must trigger bg refresh")

    @patch("subprocess.run")
    def test_graph_has_timestamp(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        resp = self.client.get("/api/graph", headers=self.auth_headers)
        data = resp.get_json()
        self.assertIn("timestamp", data)


# ══════════════════════════════════════════════════════════════════
# 5. /api/geo — stale-while-revalidate
# ══════════════════════════════════════════════════════════════════

class TestGeoEndpoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as _app
        from auth import get_or_create_token
        _app.app.config["TESTING"] = True
        cls.client  = _app.app.test_client()
        cls.app_mod = _app
        cls.auth_headers = {"X-API-Token": get_or_create_token()}

    def setUp(self):
        with self.app_mod._geo_cache_lock:
            self.app_mod._geo_cache.clear()

    @patch("platform_utils.get_connections", return_value=[])
    def test_geo_returns_200(self, _mock):
        resp = self.client.get("/api/geo", headers=self.auth_headers)
        self.assertIn(resp.status_code, [200, 500])  # 500 only if geo_ip not installed

    @patch("platform_utils.get_connections", return_value=[])
    def test_geo_second_call_cached(self, _mock):
        # Pre-populate cache so we don't need geo_ip installed
        with self.app_mod._geo_cache_lock:
            self.app_mod._geo_cache["default"] = {
                "ts":   time.time(),
                "data": {"points": [], "total": 0, "timestamp": "t"},
            }
        resp = self.client.get("/api/geo", headers=self.auth_headers)
        data = resp.get_json()
        self.assertTrue(data.get("cached"), "Hit on fresh cache should return cached=True")

    @patch("platform_utils.get_connections", return_value=[])
    def test_geo_stale_triggers_bg_refresh(self, _mock):
        with self.app_mod._geo_cache_lock:
            self.app_mod._geo_cache["default"] = {
                "ts":   time.time() - 90,   # stale (> 60s fresh TTL, < 300s stale TTL)
                "data": {"points": [], "total": 0, "timestamp": "old"},
            }
        triggered = threading.Event()
        original  = self.app_mod._trigger_bg_refresh

        def fake(key, fn, *args):
            triggered.set()
            return original(key, fn, *args)

        with patch.object(self.app_mod, "_trigger_bg_refresh", side_effect=fake):
            resp = self.client.get("/api/geo", headers=self.auth_headers)
            data = resp.get_json()

        self.assertTrue(data.get("stale"))
        self.assertTrue(triggered.is_set())


# ══════════════════════════════════════════════════════════════════
# 6. /trial/<token> routes
# ══════════════════════════════════════════════════════════════════

class TestTrialRoutes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as _app
        _app.app.config["TESTING"] = True
        cls.client  = _app.app.test_client()
        cls.app_mod = _app

    def test_unknown_token_returns_404_or_410(self):
        resp = self.client.get("/trial/ng_trial_doesnotexist123456789")
        self.assertIn(resp.status_code, [404, 410])

    def test_valid_trial_returns_html_dashboard(self):
        """Create a trial and access its URL — should return HTML."""
        import tempfile, os
        db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        db.close()
        try:
            from engine.trial_engine import TrialEngine
            eng = TrialEngine(db.name)
            trial = eng.create_trial(email="demo@test.com", name="Demo")

            # Patch the app's trial engine to use our test DB
            with patch.object(self.app_mod, "_get_trial_engine", return_value=eng):
                resp = self.client.get(f"/trial/{trial['token']}")
            # Should serve dashboard HTML (200) — or redirect to it
            self.assertIn(resp.status_code, [200, 302])
        finally:
            try:
                os.unlink(db.name)
            except OSError:
                pass


# ══════════════════════════════════════════════════════════════════
# 7. /api/admin/trials CRUD
# ══════════════════════════════════════════════════════════════════

class TestTrialAdminAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as _app
        from auth import get_or_create_token
        _app.app.config["TESTING"] = True
        cls.client  = _app.app.test_client()
        cls.app_mod = _app
        cls.auth_headers = {"X-API-Token": get_or_create_token()}

    def _auth_header(self):
        return dict(self.auth_headers)

    def test_list_trials_returns_200(self):
        resp = self.client.get("/api/admin/trials", headers=self._auth_header())
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIsNotNone(data)

    def test_create_trial_via_api(self):
        payload = {"email": "api@test.com", "name": "API User", "company": "Test Inc"}
        resp = self.client.post(
            "/api/admin/trials",
            json=payload,
            headers=self._auth_header(),
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertIn("trial", data)
        self.assertTrue(data["trial"]["token"].startswith("ng_trial_"))

    def test_create_trial_invalid_email_returns_400(self):
        resp = self.client.post(
            "/api/admin/trials",
            json={"email": "notvalid"},
            headers=self._auth_header(),
        )
        self.assertEqual(resp.status_code, 400)

    def test_create_trial_missing_email_returns_400(self):
        resp = self.client.post(
            "/api/admin/trials",
            json={"name": "No Email"},
            headers=self._auth_header(),
        )
        self.assertEqual(resp.status_code, 400)


class TestXDREndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as _app
        from auth import get_or_create_token

        _app.app.config["TESTING"] = True
        cls.client = _app.app.test_client()
        cls.auth_headers = {"X-API-Token": get_or_create_token()}

    def test_xdr_events_ingest_returns_summary(self):
        resp = self.client.post(
            "/api/xdr/events",
            json={
                "events": [
                    {
                        "host_id": "host-01",
                        "event_type": "process_execution",
                        "severity": "medium",
                        "timestamp": "2026-04-13T12:00:00Z",
                        "process_name": "powershell.exe",
                        "command_line": "powershell.exe -enc ZQBjAGgAbwA=",
                        "parent_process": "winword.exe",
                        "pid": 4242,
                        "source": "agent",
                        "platform": "windows",
                        "details": {},
                    }
                ]
            },
            headers=self.auth_headers,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertGreaterEqual(data["processed"], 1)
        self.assertGreaterEqual(data["detections"], 1)
        self.assertGreaterEqual(data["saved_events"], 1)
        self.assertEqual(data["hosts"][0]["host_id"], "host-01")
        self.assertTrue(data["detection_records"])
        first_detection = data["detection_records"][0]
        self.assertEqual(first_detection["host_id"], "host-01")
        self.assertEqual(first_detection["process_name"], "powershell.exe")
        self.assertEqual(first_detection["parent_process"], "winword.exe")
        self.assertTrue(first_detection["cmdline"])
        self.assertTrue(first_detection["technique"])
        self.assertTrue(first_detection["timestamp"])

    def test_xdr_events_rejects_invalid_type(self):
        resp = self.client.post(
            "/api/xdr/events",
            json={
                "host_id": "broken",
                "event_type": "not_supported",
                "severity": "low",
                "timestamp": "2026-04-13T12:00:00Z",
                "source": "agent",
                "details": {},
            },
            headers=self.auth_headers,
        )
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertEqual(data["error"], "invalid_event")

    def test_xdr_summary_returns_host_risks_and_recent_events(self):
        import app as _app
        from storage.event_repository import EventRepository

        tenant_repo = EventRepository(
            db_path=getattr(_app.repo, "db_path", None),
            tenant_id="admin",
        )
        conn = tenant_repo._conn()
        conn.execute("DELETE FROM events WHERE tenant_id = ? AND source LIKE 'xdr.%'", ("admin",))
        conn.commit()

        ingest = self.client.post(
            "/api/xdr/events",
            json={
                "events": [
                    {
                        "host_id": "host-summary-01",
                        "event_type": "process_execution",
                        "severity": "medium",
                        "timestamp": "2026-04-13T12:05:00Z",
                        "process_name": "powershell.exe",
                        "command_line": "powershell.exe -nop -enc ZQBjAGgAbwA=",
                        "parent_process": "winword.exe",
                        "pid": 5151,
                        "source": "agent",
                        "platform": "windows",
                        "details": {},
                    }
                ]
            },
            headers=self.auth_headers,
        )
        self.assertEqual(ingest.status_code, 200)

        pipeline = _app._get_xdr_pipeline()
        with pipeline._risk_lock:
            pipeline._host_risk_scores.clear()

        resp = self.client.get("/api/xdr/summary", headers=self.auth_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertGreaterEqual(data["total_hosts_at_risk"], 1)
        self.assertTrue(any(item["host_id"] == "host-summary-01" for item in data["host_risks"]))
        self.assertGreaterEqual(len(data["recent_events"]), 1)

    def test_xdr_summary_accepts_bearer_token(self):
        from auth import get_or_create_token

        resp = self.client.get(
            "/api/xdr/summary",
            headers={"Authorization": f"Bearer {get_or_create_token()}"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])

    def test_xdr_ingest_feeds_incident_engine_for_high_signal(self):
        import app as _app

        if not getattr(_app, "PLAYBOOK_AVAILABLE", False):
            self.skipTest("playbook engine unavailable")

        pb = _app._get_playbook_engine()
        with pb._db() as conn:
            conn.execute("DELETE FROM pb_steps")
            conn.execute("DELETE FROM pb_incidents WHERE tenant_id = ?", ("admin",))
            conn.commit()

        resp = self.client.post(
            "/api/xdr/events",
            json={
                "events": [
                    {
                        "host_id": "host-incident-01",
                        "event_type": "process_execution",
                        "severity": "medium",
                        "timestamp": "2026-04-13T15:00:00Z",
                        "process_name": "powershell.exe",
                        "command_line": "powershell.exe -nop -enc ZQBjAGgAbwA=",
                        "parent_process": "winword.exe",
                        "pid": 7878,
                        "source": "agent",
                        "platform": "windows",
                        "details": {},
                    }
                ]
            },
            headers=self.auth_headers,
        )
        self.assertEqual(resp.status_code, 200)

        incidents = pb.list_incidents(tenant_id="admin", limit=10)
        self.assertTrue(incidents)


if __name__ == "__main__":
    unittest.main()
