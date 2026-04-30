"""
Token-bucket rate limiters for the modular EDR API.

`TokenBucketLimiter` is the fast in-process default for local/dev.
`SqliteTokenBucketLimiter` persists buckets in a shared SQLite file so
multiple WSGI workers on the same host enforce the same budget without
adding Redis as a dependency.
`RedisTokenBucketLimiter` is the production option for multi-node
deployments where several app instances must share the same budget.

Usage:

    limiter = TokenBucketLimiter(rate_per_sec=20, burst=40)
    if not limiter.allow(key="agent:host_xyz"):
        return 429

Design notes:

- Per-key bucket created lazily; old buckets are GC'd on access if
  idle longer than `idle_purge_s`. No background thread.
- Time monotonic, not wall clock — clock jumps don't break it.
- `allow()` returns True/False; `remaining()` exposes the current budget.
- Thread-safe (single RLock around the dict; per-bucket lock would be
  faster but premature).
"""

from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("netguard.server.rate_limit")

_RATE_LIMIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS rate_limit_buckets (
    key          TEXT PRIMARY KEY,
    tokens       REAL NOT NULL,
    capacity     REAL NOT NULL,
    refill_rate  REAL NOT NULL,
    updated_at   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_rate_limit_updated
    ON rate_limit_buckets(updated_at);
"""

_REDIS_TOKEN_BUCKET_SCRIPT = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local capacity = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local ttl = tonumber(ARGV[5])

local data = redis.call("HMGET", key, "tokens", "updated_at")
local tokens = tonumber(data[1])
local updated_at = tonumber(data[2])

if tokens == nil then
    tokens = capacity
end
if updated_at == nil then
    updated_at = now
end

local elapsed = math.max(0, now - updated_at)
tokens = math.min(capacity, tokens + (elapsed * rate))

local allowed = 0
local retry_after = 0
if tokens >= cost then
    allowed = 1
    tokens = tokens - cost
else
    if rate > 0 then
        retry_after = (cost - tokens) / rate
    end
end

redis.call("HSET", key, "tokens", tokens, "updated_at", now)
redis.call("EXPIRE", key, ttl)
return { allowed, tokens, retry_after }
"""


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

class SqliteTokenBucketLimiter:
    """
    Shared token bucket backed by SQLite.

    Uses wall-clock seconds rather than `time.monotonic()` because state
    is shared across processes. Negative deltas are clamped to zero so a
    small clock adjustment cannot mint tokens.
    """

    def __init__(
        self,
        db_path: str | Path,
        rate_per_sec: float = 20.0,
        burst: int = 40,
        idle_purge_s: float = 3600.0,
        timeout_s: float = 5.0,
    ):
        if rate_per_sec <= 0 or burst <= 0:
            raise ValueError("rate_per_sec and burst must be positive")
        self.db_path = Path(db_path)
        self.rate = float(rate_per_sec)
        self.capacity = float(burst)
        self.idle_purge_s = float(idle_purge_s)
        self.timeout_s = float(timeout_s)
        self._lock = threading.RLock()
        self._ops = 0
        self._init_db()

    @contextmanager
    def _conn(self):
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        conn = sqlite3.connect(str(self.db_path), timeout=self.timeout_s)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._lock, self._conn() as conn:
            conn.executescript(_RATE_LIMIT_SCHEMA)

    def allow(self, key: str, cost: float = 1.0) -> bool:
        if not key:
            return True
        now = time.time()
        with self._lock, self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT tokens, updated_at
                FROM rate_limit_buckets
                WHERE key = ?
                """,
                (key,),
            ).fetchone()
            if row is None:
                tokens = self.capacity
            else:
                elapsed = max(0.0, now - float(row[1]))
                tokens = min(self.capacity, float(row[0]) + elapsed * self.rate)

            allowed = tokens >= cost
            if allowed:
                tokens -= cost

            conn.execute(
                """
                INSERT INTO rate_limit_buckets
                    (key, tokens, capacity, refill_rate, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    tokens = excluded.tokens,
                    capacity = excluded.capacity,
                    refill_rate = excluded.refill_rate,
                    updated_at = excluded.updated_at
                """,
                (key, float(tokens), self.capacity, self.rate, now),
            )
            self._ops += 1
            if self._ops % 128 == 0:
                self._purge_locked(conn, now)
            return allowed

    def remaining(self, key: str) -> float:
        if not key:
            return self.capacity
        now = time.time()
        with self._lock, self._conn() as conn:
            row = conn.execute(
                """
                SELECT tokens, updated_at
                FROM rate_limit_buckets
                WHERE key = ?
                """,
                (key,),
            ).fetchone()
        if row is None:
            return self.capacity
        elapsed = max(0.0, now - float(row[1]))
        return min(self.capacity, float(row[0]) + elapsed * self.rate)

    def reset(self, key: str | None = None) -> None:
        with self._lock, self._conn() as conn:
            if key is None:
                conn.execute("DELETE FROM rate_limit_buckets")
            else:
                conn.execute("DELETE FROM rate_limit_buckets WHERE key = ?", (key,))

    def _purge_locked(self, conn, now: float) -> None:
        cutoff = now - self.idle_purge_s
        conn.execute(
            "DELETE FROM rate_limit_buckets WHERE updated_at < ?",
            (cutoff,),
        )


class RedisTokenBucketLimiter:
    """
    Shared token bucket backed by Redis.

    Redis is intended for horizontally scaled API nodes. Bucket updates are
    performed through one Lua script so allow/deny decisions stay atomic even
    when multiple Flask/Gunicorn instances receive agent telemetry at once.
    """

    def __init__(
        self,
        redis_url: str = "redis://127.0.0.1:6379/0",
        *,
        prefix: str = "netguard:rate_limit",
        rate_per_sec: float = 20.0,
        burst: int = 40,
        idle_purge_s: float = 3600.0,
        client=None,
        time_fn=None,
    ):
        if rate_per_sec <= 0 or burst <= 0:
            raise ValueError("rate_per_sec and burst must be positive")
        self.redis_url = (redis_url or "redis://127.0.0.1:6379/0").strip()
        self.prefix = (prefix or "netguard:rate_limit").strip().strip(":")
        self.rate = float(rate_per_sec)
        self.capacity = float(burst)
        self.idle_purge_s = float(idle_purge_s)
        self._client = client or _build_redis_client(self.redis_url)
        self._time_fn = time_fn or time.time

    def allow(self, key: str, cost: float = 1.0) -> bool:
        if not key:
            return True
        try:
            result = self._client.eval(
                _REDIS_TOKEN_BUCKET_SCRIPT,
                1,
                self._redis_key(key),
                float(self._time_fn()),
                self.rate,
                self.capacity,
                float(cost),
                max(1, int(self.idle_purge_s)),
            )
            return bool(int(_redis_scalar(result, 0, 0)))
        except Exception as exc:  # pragma: no cover - exercised with real Redis outages.
            logger.error("redis rate-limit check failed closed: %s", exc)
            return False

    def remaining(self, key: str) -> float:
        if not key:
            return self.capacity
        redis_key = self._redis_key(key)
        try:
            tokens, updated_at = self._client.hmget(redis_key, "tokens", "updated_at")
        except Exception as exc:  # pragma: no cover - exercised with real Redis outages.
            logger.error("redis rate-limit remaining check failed: %s", exc)
            return 0.0
        if tokens is None or updated_at is None:
            return self.capacity
        token_value = _redis_float(tokens, self.capacity)
        updated_value = _redis_float(updated_at, float(self._time_fn()))
        elapsed = max(0.0, float(self._time_fn()) - updated_value)
        return min(self.capacity, token_value + elapsed * self.rate)

    def reset(self, key: str | None = None) -> None:
        if key is None:
            raise ValueError("RedisTokenBucketLimiter.reset() requires a key")
        self._client.delete(self._redis_key(key))

    def _redis_key(self, key: str) -> str:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return f"{self.prefix}:{digest}"


def _default_sqlite_rate_limit_path() -> Path:
    explicit = (os.environ.get("NETGUARD_RATE_LIMIT_DB") or "").strip()
    if explicit:
        return Path(explicit)
    edr_db = (os.environ.get("NETGUARD_EDR_DB") or "").strip()
    if edr_db:
        return Path(edr_db).with_name("netguard_rate_limit.db")
    if os.name == "nt":
        return Path(r"C:\ProgramData\NetGuard\netguard_rate_limit.db")
    return Path("/var/lib/netguard/netguard_rate_limit.db")


def build_rate_limiter_from_env(
    *,
    rate_per_sec: float = 20.0,
    burst: int = 40,
    redis_client=None,
) -> TokenBucketLimiter | SqliteTokenBucketLimiter | RedisTokenBucketLimiter:
    """
    Build the API limiter from env.

    NETGUARD_RATE_LIMIT_BACKEND=memory|sqlite|redis
    NETGUARD_RATE_LIMIT_DB=/var/lib/netguard/netguard_rate_limit.db
    NETGUARD_RATE_LIMIT_REDIS_URL=redis://127.0.0.1:6379/0
    NETGUARD_RATE_LIMIT_REDIS_PREFIX=netguard:rate_limit
    NETGUARD_RATE_LIMIT_RATE_PER_SEC=20
    NETGUARD_RATE_LIMIT_BURST=40
    """
    rate = _env_float("NETGUARD_RATE_LIMIT_RATE_PER_SEC", rate_per_sec)
    burst_value = _env_int("NETGUARD_RATE_LIMIT_BURST", burst)
    backend = (os.environ.get("NETGUARD_RATE_LIMIT_BACKEND") or "memory").strip().lower()
    if backend in {"sqlite", "shared", "file"}:
        return SqliteTokenBucketLimiter(
            _default_sqlite_rate_limit_path(),
            rate_per_sec=rate,
            burst=burst_value,
        )
    if backend in {"redis", "cache", "shared-cache"}:
        return RedisTokenBucketLimiter(
            _env_str("NETGUARD_RATE_LIMIT_REDIS_URL", "redis://127.0.0.1:6379/0"),
            prefix=_env_str("NETGUARD_RATE_LIMIT_REDIS_PREFIX", "netguard:rate_limit"),
            rate_per_sec=rate,
            burst=burst_value,
            client=redis_client,
        )
    if backend not in {"", "memory", "local", "in-memory", "in_memory"}:
        raise ValueError(f"unsupported NETGUARD_RATE_LIMIT_BACKEND={backend!r}")
    return TokenBucketLimiter(rate_per_sec=rate, burst=burst_value)


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return float(default)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return int(default)


def _env_str(name: str, default: str) -> str:
    value = (os.environ.get(name) or "").strip()
    return value or default


def _build_redis_client(redis_url: str):
    try:
        import redis  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "NETGUARD_RATE_LIMIT_BACKEND=redis requires the 'redis' package"
        ) from exc
    return redis.Redis.from_url(
        redis_url,
        socket_connect_timeout=2.0,
        socket_timeout=2.0,
    )


def _redis_scalar(result, index: int, default):
    try:
        return result[index]
    except (IndexError, TypeError):
        return default


def _redis_float(value, default: float) -> float:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


_default = TokenBucketLimiter()


def default_limiter() -> TokenBucketLimiter:
    return _default
