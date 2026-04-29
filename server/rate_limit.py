"""
Token-bucket rate limiter, in-process.

For multi-process deploys put a real bucket in Redis; this is a
single-process default. The interface is identical, so swapping is
straightforward.

Usage:

    limiter = TokenBucketLimiter(rate_per_sec=20, burst=40)
    if not limiter.allow(key="agent:host_xyz"):
        return 429

Design notes:

- Per-key bucket created lazily; old buckets are GC'd on access if
  idle longer than `idle_purge_s`. No background thread.
- Time monotonic, not wall clock — clock jumps don't break it.
- `allow()` returns True/False; `acquire()` returns the wait time.
- Thread-safe (single RLock around the dict; per-bucket lock would be
  faster but premature).
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

logger = logging.getLogger("netguard.server.rate_limit")


@dataclass
class _Bucket:
    tokens: float
    capacity: float
    refill_rate: float    # tokens per second
    last: float           # monotonic timestamp

    def take(self, n: float, now: float) -> bool:
        # Refill since last access.
        elapsed = max(0.0, now - self.last)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last = now
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False


class TokenBucketLimiter:
    def __init__(
        self,
        rate_per_sec: float = 20.0,
        burst: int = 40,
        idle_purge_s: float = 600.0,
    ):
        if rate_per_sec <= 0 or burst <= 0:
            raise ValueError("rate_per_sec and burst must be positive")
        self.rate = float(rate_per_sec)
        self.capacity = float(burst)
        self.idle_purge_s = float(idle_purge_s)
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.RLock()

    def allow(self, key: str, cost: float = 1.0) -> bool:
        """Returns True if the request fits within the budget."""
        if not key:
            return True  # don't rate-limit unkeyed events
        now = time.monotonic()
        with self._lock:
            self._maybe_purge(now)
            b = self._buckets.get(key)
            if b is None:
                b = _Bucket(
                    tokens=self.capacity,
                    capacity=self.capacity,
                    refill_rate=self.rate,
                    last=now,
                )
                self._buckets[key] = b
            return b.take(cost, now)

    def remaining(self, key: str) -> float:
        with self._lock:
            b = self._buckets.get(key)
            if b is None:
                return self.capacity
            now = time.monotonic()
            elapsed = max(0.0, now - b.last)
            return min(b.capacity, b.tokens + elapsed * b.refill_rate)

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._buckets.clear()
            else:
                self._buckets.pop(key, None)

    def _maybe_purge(self, now: float) -> None:
        # Cheap O(N) scan; only triggers when we have many buckets.
        if len(self._buckets) < 1024:
            return
        cutoff = now - self.idle_purge_s
        stale = [k for k, b in self._buckets.items() if b.last < cutoff]
        for k in stale:
            self._buckets.pop(k, None)
        if stale:
            logger.debug("rate-limit purge: removed %d idle buckets", len(stale))


# ── Module-level default (configured by /server/api.py) ──────────────

_default = TokenBucketLimiter()


def default_limiter() -> TokenBucketLimiter:
    return _default
