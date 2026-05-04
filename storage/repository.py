"""
Storage abstraction for the NetGuard EDR/SOC platform.

Provides an ABC (`Repository`) describing the persistence operations the
detection / correlation / risk engines and the SOC dashboard depend on,
plus a typed result model.

Two implementations live next to this module:

- `sqlite_repository.SqliteRepository` — default, file-backed, no extra
  deps. Used in dev, CI, single-tenant on-prem.
- `postgres_repository.PostgresRepository` — production / multi-tenant.
  Lazy-imports `psycopg`; fails clearly if the driver isn't installed.

The split exists so the rest of the codebase never imports
`sqlite3` or `psycopg` directly — swap backends by changing one factory
call.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, Iterable


# ── Domain models (engine-friendly dicts) ─────────────────────────────


@dataclass(slots=True)
class Host:
    host_id: str
    hostname: str = ""
    platform: str = ""
    agent_version: str = ""
    last_seen: str = ""
    first_seen: str = ""
    risk_score: int = 0
    risk_level: str = "LOW"
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "host_id": self.host_id,
            "hostname": self.hostname,
            "platform": self.platform,
            "agent_version": self.agent_version,
            "last_seen": self.last_seen,
            "first_seen": self.first_seen,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class Event:
    event_id: str
    host_id: str
    timestamp: str
    event_type: str
    severity: str = "low"
    confidence: int = 0
    process_name: str = ""
    pid: int | None = None
    ppid: int | None = None
    command_line: str = ""
    user: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int | None = None
    mitre_tactic: str = ""
    mitre_technique: str = ""
    evidence: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "host_id": self.host_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "process_name": self.process_name,
            "pid": self.pid,
            "ppid": self.ppid,
            "command_line": self.command_line,
            "user": self.user,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "evidence": self.evidence,
            "raw": dict(self.raw),
        }


@dataclass(slots=True)
class Alert:
    alert_id: str
    host_id: str
    rule_id: str
    severity: str
    confidence: int
    timestamp: str
    title: str = ""
    evidence: str = ""
    mitre_tactic: str = ""
    mitre_technique: str = ""
    event_ids: list[str] = field(default_factory=list)
    status: str = "open"  # open | acknowledged | closed

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "host_id": self.host_id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "title": self.title,
            "evidence": self.evidence,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "event_ids": list(self.event_ids),
            "status": self.status,
        }


# ── Abstract repository ───────────────────────────────────────────────


class Repository(abc.ABC):
    """
    Persistence interface used by detection_engine, correlation_engine,
    risk_engine and the SOC dashboard.

    Implementations MUST be safe to call from multiple threads; the
    detection engine and the API ingestion pipeline often share the
    same instance.
    """

    # ── lifecycle ──

    @abc.abstractmethod
    def init_schema(self) -> None:
        """Create tables/indexes if they don't exist. Idempotent."""

    @abc.abstractmethod
    def schema_version(self) -> int:
        """Return the latest applied repository schema migration version."""

    @abc.abstractmethod
    def migration_history(self) -> list[dict[str, Any]]:
        """Return applied schema migrations in ascending version order."""

    @abc.abstractmethod
    def migration_status(self) -> dict[str, Any]:
        """Return schema version, pending migrations, and drift indicators."""

    @abc.abstractmethod
    def close(self) -> None:
        """Release pools, file handles, etc."""

    # ── hosts ──

    @abc.abstractmethod
    def upsert_host(self, host: Host) -> None: ...

    @abc.abstractmethod
    def get_host(self, host_id: str) -> Host | None: ...

    @abc.abstractmethod
    def list_hosts(self, *, limit: int = 200) -> list[Host]: ...

    @abc.abstractmethod
    def update_host_risk(self, host_id: str, score: int, level: str) -> None: ...

    @abc.abstractmethod
    def touch_host_seen(self, host_id: str, when_iso: str) -> None: ...

    # ── events ──

    @abc.abstractmethod
    def insert_event(self, event: Event) -> bool:
        """Returns True if newly inserted, False if dedup hit on event_id."""

    @abc.abstractmethod
    def insert_events(self, events: Iterable[Event]) -> int:
        """Bulk-insert; returns count newly inserted."""

    @abc.abstractmethod
    def list_events(
        self,
        *,
        host_id: str | None = None,
        event_type: str | None = None,
        since_iso: str | None = None,
        limit: int = 500,
    ) -> list[Event]: ...

    # ── alerts ──

    @abc.abstractmethod
    def insert_alert(self, alert: Alert) -> bool: ...

    @abc.abstractmethod
    def list_alerts(
        self,
        *,
        host_id: str | None = None,
        since_iso: str | None = None,
        status: str | None = None,
        limit: int = 200,
    ) -> list[Alert]: ...

    @abc.abstractmethod
    def update_alert_status(self, alert_id: str, status: str) -> None: ...

    # ── aggregates (SOC dashboard) ──

    @abc.abstractmethod
    def alert_counts_by_severity(
        self,
        *,
        since_iso: str | None = None,
    ) -> dict[str, int]: ...

    @abc.abstractmethod
    def top_mitre_techniques(
        self,
        *,
        since_iso: str | None = None,
        limit: int = 10,
    ) -> list[tuple[str, int]]: ...


# ── Factory ───────────────────────────────────────────────────────────


def get_repository(backend: str = "sqlite", **kwargs) -> Repository:
    """
    Single entry point. `backend` is one of: "sqlite", "postgres".
    Extra kwargs are forwarded to the implementation's __init__.

    Example:
        repo = get_repository("sqlite", db_path="/var/lib/netguard/edr.db")
        repo.init_schema()
    """
    backend = (backend or "sqlite").lower()
    if backend == "sqlite":
        from .sqlite_repository import SqliteRepository
        return SqliteRepository(**kwargs)
    if backend in {"postgres", "postgresql", "pg"}:
        from .postgres_repository import PostgresRepository
        return PostgresRepository(**kwargs)
    raise ValueError(f"unknown storage backend: {backend!r}")
