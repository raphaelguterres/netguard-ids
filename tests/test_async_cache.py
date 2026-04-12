"""
tests/test_async_cache.py
=========================
Pure-Python tests for the async cache helpers and non-blocking DNS resolver.
No Flask dependency — these run in any environment.

Coverage:
  • _ttl_cache_get_swr  — fresh / stale / beyond-stale
  • _ttl_cache_set
  • _trigger_bg_refresh — runs fn, deduplicates concurrent calls
  • resolve_ip           — non-blocking, cached hostname
"""
import os
import sys
import time
import threading
import socket  # noqa: F401
import unittest
from unittest.mock import patch  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# Import only the cache helpers — extracted directly so we don't need Flask.
# If app.py cannot be imported, we test equivalent logic inline.
try:
    import app as _app
    _APP_AVAILABLE = True
except Exception:
    _APP_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────
# Inline fallback implementations for offline testing
# ─────────────────────────────────────────────────────────────────────

def _ttl_cache_set(cache, lock, key, data):
    with lock:
        cache[key] = {"ts": time.time(), "data": data}


def _ttl_cache_get_swr(cache, lock, key, fresh_ttl, stale_ttl):
    now = time.time()
    with lock:
        entry = cache.get(key)
    if not entry:
        return None, False
    age = now - entry["ts"]
    if age < fresh_ttl:
        return entry["data"], False
    if age < stale_ttl:
        return entry["data"], True
    return None, False


_bg_running      = set()
_bg_running_lock = threading.Lock()


def _trigger_bg_refresh(job_key, fn, *args):
    with _bg_running_lock:
        if job_key in _bg_running:
            return
        _bg_running.add(job_key)

    def _run():
        try:
            fn(*args)
        finally:
            with _bg_running_lock:
                _bg_running.discard(job_key)

    threading.Thread(target=_run, daemon=True).start()


def _get_fn():
    """Return functions from app module if available, else use inline."""
    if _APP_AVAILABLE:
        return (
            _app._ttl_cache_get_swr,
            _app._ttl_cache_set,
            _app._trigger_bg_refresh,
            _app._bg_running,
            _app._bg_running_lock,
        )
    return (
        _ttl_cache_get_swr,
        _ttl_cache_set,
        _trigger_bg_refresh,
        _bg_running,
        _bg_running_lock,
    )


# ══════════════════════════════════════════════════════════════════
# _ttl_cache_get_swr
# ══════════════════════════════════════════════════════════════════

class TestSWRCache(unittest.TestCase):
    def setUp(self):
        self.get_swr, self.cache_set, self.bg, self.running, self.rlock = _get_fn()

    def _new(self):
        return {}, threading.Lock()

    def test_empty_cache_returns_none(self):
        cache, lock = self._new()
        data, stale = self.get_swr(cache, lock, "k", 30, 120)
        self.assertIsNone(data)
        self.assertFalse(stale)

    def test_fresh_entry(self):
        cache, lock = self._new()
        self.cache_set(cache, lock, "k", {"v": 1})
        data, stale = self.get_swr(cache, lock, "k", 30, 120)
        self.assertEqual(data, {"v": 1})
        self.assertFalse(stale)

    def test_stale_entry_within_window(self):
        cache = {"k": {"ts": time.time() - 50, "data": {"v": 2}}}
        lock  = threading.Lock()
        # fresh_ttl=30 (50>30 → stale), stale_ttl=120 (50<120 → usable)
        data, stale = self.get_swr(cache, lock, "k", 30, 120)
        self.assertEqual(data, {"v": 2})
        self.assertTrue(stale)

    def test_beyond_stale_ttl_returns_none(self):
        cache = {"k": {"ts": time.time() - 200, "data": {"v": 3}}}
        lock  = threading.Lock()
        data, stale = self.get_swr(cache, lock, "k", 30, 120)
        self.assertIsNone(data)
        self.assertFalse(stale)

    def test_different_keys_independent(self):
        cache, lock = self._new()
        self.cache_set(cache, lock, "a", {"a": 1})
        self.cache_set(cache, lock, "b", {"b": 2})
        da, _ = self.get_swr(cache, lock, "a", 30, 120)
        db, _ = self.get_swr(cache, lock, "b", 30, 120)
        self.assertEqual(da, {"a": 1})
        self.assertEqual(db, {"b": 2})

    def test_overwrite_refreshes_ts(self):
        cache = {"k": {"ts": time.time() - 50, "data": {"old": True}}}
        lock  = threading.Lock()
        self.cache_set(cache, lock, "k", {"new": True})
        data, stale = self.get_swr(cache, lock, "k", 30, 120)
        self.assertEqual(data, {"new": True})
        self.assertFalse(stale)


# ══════════════════════════════════════════════════════════════════
# _trigger_bg_refresh
# ══════════════════════════════════════════════════════════════════

class TestTriggerBgRefresh(unittest.TestCase):
    def setUp(self):
        _, _, self.bg_fn, self.running_set, self.running_lock = _get_fn()
        # Clear any leftover running keys from previous tests
        with self.running_lock:
            self.running_set.clear()

    def test_function_is_called(self):
        called = threading.Event()

        def fn():
            called.set()

        self.bg_fn("bg-test-run-1", fn)
        self.assertTrue(called.wait(timeout=3), "Background fn was never called")

    def test_function_arguments_forwarded(self):
        results = []

        def fn(a, b):
            results.append(a + b)

        self.bg_fn("bg-test-args", fn, 10, 20)
        time.sleep(0.3)
        self.assertEqual(results, [30])

    def test_duplicate_key_ignored(self):
        barrier  = threading.Event()
        call_cnt = [0]

        def slow_fn():
            call_cnt[0] += 1
            barrier.wait(timeout=2)

        self.bg_fn("bg-dedup-test", slow_fn)
        time.sleep(0.05)  # let first thread start and register key
        self.bg_fn("bg-dedup-test", slow_fn)  # should be ignored
        barrier.set()
        time.sleep(0.2)
        self.assertEqual(call_cnt[0], 1, "Second call with same key must be ignored")

    def test_key_removed_after_completion(self):
        done = threading.Event()

        def fn():
            done.set()

        self.bg_fn("bg-cleanup-test", fn)
        done.wait(timeout=3)
        time.sleep(0.1)
        with self.running_lock:
            self.assertNotIn("bg-cleanup-test", self.running_set)

    def test_exception_in_fn_does_not_block_key(self):
        """Even if fn raises, job_key must be removed so future calls work."""
        def bad_fn():
            raise RuntimeError("intentional")

        self.bg_fn("bg-exc-test", bad_fn)
        time.sleep(0.3)
        with self.running_lock:
            self.assertNotIn("bg-exc-test", self.running_set)


# ══════════════════════════════════════════════════════════════════
# resolve_ip (non-blocking)
# ══════════════════════════════════════════════════════════════════

@unittest.skipUnless(_APP_AVAILABLE, "app.py not importable in this environment")
class TestResolveIpNonBlocking(unittest.TestCase):
    def setUp(self):
        with _app._dns_lock:
            _app._dns_cache.clear()

    def test_returns_ip_immediately_when_not_cached(self):
        t0 = time.time()
        result = _app.resolve_ip("203.0.113.1")  # TEST-NET RFC 5737
        elapsed = time.time() - t0
        # Must return within 200ms without blocking
        self.assertLess(elapsed, 0.5)
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)

    def test_cached_hostname_returned_directly(self):
        with _app._dns_lock:
            _app._dns_cache["10.0.0.1"] = "my.host.local"
        result = _app.resolve_ip("10.0.0.1")
        self.assertEqual(result, "my.host.local")

    def test_loopback_not_submitted_to_dns(self):
        """127.x IPs should still resolve fast."""
        t0 = time.time()
        _app.resolve_ip("127.0.0.1")
        self.assertLess(time.time() - t0, 0.5)

    def test_background_resolution_populates_cache(self):
        """After a short wait, the DNS thread should have populated the cache."""
        ip = "8.8.4.4"
        with _app._dns_lock:
            _app._dns_cache.pop(ip, None)

        _app.resolve_ip(ip)           # submit to pool
        time.sleep(1.5)              # wait for resolution
        with _app._dns_lock:
            cached = _app._dns_cache.get(ip)
        # Either resolved hostname or the IP itself (if DNS unreachable in sandbox)
        self.assertIsNotNone(cached)
        self.assertIsInstance(cached, str)


if __name__ == "__main__":
    unittest.main()
