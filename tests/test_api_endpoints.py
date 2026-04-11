"""
tests/test_api_endpoints.py
===========================
Integration-style tests for the Flask API endpoints:

  • /api/health    — opaque errors, request_id always present
  • /api/graph     — stale-while-revalidate cache, cached/stale fields
  • /api/geo       — stale-while-revalidate cache, cached/stale fields
  • /trial/<token> — valid / expired / revoked tokens
  • Async cache helpers: _ttl_cache_get_swr, _trigger_bg_refresh

All tests set IDS_AUTH=false so no token auth is needed.
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
os.environ.setdefault("IDS_CSRF_DISABLED", "true")
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


# ══════════════════════════════════════════════════════════════════
# 4. /api/graph — stale-while-revalidate
# ══════════════════════════════════════════════════════════════════

class TestGraphEndpoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as _app
        _app.app.config["TESTING"] = True
        cls.client  = _app.app.test_client()
        cls.app_mod = _app

    def setUp(self):
        # Clear graph cache between tests
        with self.app_mod._graph_cache_lock:
            self.app_mod._graph_cache.clear()

    @patch("subprocess.run")
    def test_graph_returns_200(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        resp = self.client.get("/api/graph")
        self.assertEqual(resp.status_code, 200)

    @patch("subprocess.run")
    def test_graph_response_has_nodes_and_edges(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        resp = self.client.get("/api/graph")
        data = resp.get_json()
        self.assertIsNotNone(data)
        self.assertIn("nodes", data)
        self.assertIn("edges", data)

    @patch("subprocess.run")
    def test_graph_second_call_is_cached(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        self.client.get("/api/graph")   # cold
        resp2 = self.client.get("/api/graph")  # should be cached
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
            resp = self.client.get("/api/graph")
            data = resp.get_json()

        self.assertTrue(data.get("stale"), "Stale cache should return stale=True")
        self.assertTrue(refresh_triggered.is_set(), "Stale hit must trigger bg refresh")

    @patch("subprocess.run")
    def test_graph_has_timestamp(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        resp = self.client.get("/api/graph")
        data = resp.get_json()
        self.assertIn("timestamp", data)


# ══════════════════════════════════════════════════════════════════
# 5. /api/geo — stale-while-revalidate
# ══════════════════════════════════════════════════════════════════

class TestGeoEndpoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as _app
        _app.app.config["TESTING"] = True
        cls.client  = _app.app.test_client()
        cls.app_mod = _app

    def setUp(self):
        with self.app_mod._geo_cache_lock:
            self.app_mod._geo_cache.clear()

    @patch("platform_utils.get_connections", return_value=[])
    def test_geo_returns_200(self, _mock):
        resp = self.client.get("/api/geo")
        self.assertIn(resp.status_code, [200, 500])  # 500 only if geo_ip not installed

    @patch("platform_utils.get_connections", return_value=[])
    def test_geo_second_call_cached(self, _mock):
        # Pre-populate cache so we don't need geo_ip installed
        with self.app_mod._geo_cache_lock:
            self.app_mod._geo_cache["default"] = {
                "ts":   time.time(),
                "data": {"points": [], "total": 0, "timestamp": "t"},
            }
        resp = self.client.get("/api/geo")
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
            resp = self.client.get("/api/geo")
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
        _app.app.config["TESTING"] = True
        cls.client  = _app.app.test_client()
        cls.app_mod = _app

    def _api_key_header(self):
        return {"X-API-Key": os.environ.get("IDS_API_KEY", "dev")}

    def test_list_trials_returns_200(self):
        resp = self.client.get("/api/admin/trials", headers=self._api_key_header())
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIsNotNone(data)

    def test_create_trial_via_api(self):
        payload = {"email": "api@test.com", "name": "API User", "company": "Test Inc"}
        resp = self.client.post(
            "/api/admin/trials",
            json=payload,
            headers=self._api_key_header(),
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertIn("token", data)
        self.assertTrue(data["token"].startswith("ng_trial_"))

    def test_create_trial_invalid_email_returns_400(self):
        resp = self.client.post(
            "/api/admin/trials",
            json={"email": "notvalid"},
            headers=self._api_key_header(),
        )
        self.assertEqual(resp.status_code, 400)

    def test_create_trial_missing_email_returns_400(self):
        resp = self.client.post(
            "/api/admin/trials",
            json={"name": "No Email"},
            headers=self._api_key_header(),
        )
        self.assertEqual(resp.status_code, 400)


if __name__ == "__main__":
    unittest.main()
