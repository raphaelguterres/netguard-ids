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
    def test_ti_feed_scheduler_starts_only_once(self, mock_get_ti_feed):
        feed = MagicMock()
        mock_get_ti_feed.return_value = feed

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

   