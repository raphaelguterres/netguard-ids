"""
Tests for storage.repository (abstract) + sqlite_repository (default).

Postgres backend is exercised separately when NETGUARD_PG_DSN is set;
no live Postgres in CI by default.
"""

from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone

import pytest

from storage.migrations import SCHEMA_VERSION
from storage.repository import Alert, Event, Host, get_repository
from storage.sqlite_repository import SqliteRepository


def _ts(offset_s: int = 0) -> str:
    from datetime import timedelta
    t = datetime.now(timezone.utc) + timedelta(seconds=offset_s)
    return t.isoformat().replace("+00:00", "Z")


@pytest.fixture
def repo(tmp_path) -> SqliteRepository:
    db = tmp_path / "edr_test.db"
    r = SqliteRepository(db_path=db)
    r.init_schema()
    return r


def _mk_event(host_id="h1", **kwargs) -> Event:
    base = dict(
        event_id=str(uuid.uuid4()),
        host_id=host_id,
        timestamp=_ts(),
        event_type="process_execution",
        severity="low",
        confidence=80,
        process_name="powershell.exe",
        pid=1234,
        ppid=789,
        command_line="powershell.exe -NoP",
        user="DOMAIN\\jdoe",
        src_ip="",
        dst_ip="",
        dst_port=None,
        mitre_tactic="",
        mitre_technique="",
        evidence="",
        raw={},
    )
    base.update(kwargs)
    return Event(**base)


def _mk_alert(host_id="h1", **kwargs) -> Alert:
    base = dict(
        alert_id=str(uuid.uuid4()),
        host_id=host_id,
        rule_id="NG-TEST-001",
        severity="medium",
        confidence=80,
        timestamp=_ts(),
        title="t",
        evidence="e",
        mitre_tactic="Execution",
        mitre_technique="T1059",
        event_ids=[],
        status="open",
    )
    base.update(kwargs)
    return Alert(**base)


def test_factory_builds_sqlite(tmp_path):
    repo = get_repository("sqlite", db_path=tmp_path / "x.db")
    repo.init_schema()
    assert isinstance(repo, SqliteRepository)
    assert repo.schema_version() == SCHEMA_VERSION


def test_unknown_backend_raises():
    with pytest.raises(ValueError, match="unknown storage backend"):
        get_repository("nonsense")


def test_postgres_factory_lazy_imports():
    # Without NETGUARD_PG_DSN we expect ValueError, not ImportError —
    # the dsn check runs before the driver-import path on this branch.
    os.environ.pop("NETGUARD_PG_DSN", None)
    with pytest.raises((RuntimeError, ValueError)):
        get_repository("postgres")


def test_schema_migrations_are_recorded_idempotently(repo):
    assert repo.schema_version() == SCHEMA_VERSION
    history = repo.migration_history()
    assert len(history) == SCHEMA_VERSION
    assert history[-1]["version"] == SCHEMA_VERSION
    assert history[0]["name"] == "initial_edr_schema"
    assert history[0]["description"]
    assert history[0]["checksum"]

    repo.init_schema()
    history_after_second_init = repo.migration_history()
    assert len(history_after_second_init) == SCHEMA_VERSION
    assert history_after_second_init[-1]["version"] == SCHEMA_VERSION


def test_migration_status_reports_clean_schema(repo):
    status = repo.migration_status()

    assert status["ok"] is True
    assert status["schema_version"] == SCHEMA_VERSION
    assert status["latest_version"] == SCHEMA_VERSION
    assert status["pending"] == []
    assert status["mismatched"] == []
    assert status["unknown"] == []
    assert len(status["history"]) == SCHEMA_VERSION


def test_schema_version_before_init_is_zero(tmp_path):
    repo = SqliteRepository(db_path=tmp_path / "not_initialized.db")
    assert repo.schema_version() == 0
    assert repo.migration_history() == []
    status = repo.migration_status()
    assert status["ok"] is False
    assert status["pending"]


def test_init_schema_upgrades_legacy_migration_table(tmp_path):
    db_path = tmp_path / "legacy_migrations.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            INSERT INTO schema_migrations (version, name, applied_at)
            VALUES (1, 'initial_edr_schema', '2026-04-01T00:00:00Z')
            """
        )

    repo = SqliteRepository(db_path=db_path)
    repo.init_schema()
    history = repo.migration_history()

    assert repo.schema_version() == SCHEMA_VERSION
    assert len(history) == SCHEMA_VERSION
    assert all(item["description"] for item in history)
    assert all(item["checksum"] for item in history)
    assert repo.migration_status()["ok"] is True


def test_upsert_and_get_host(repo):
    h = Host(
        host_id="hX",
        hostname="WIN-A",
        platform="windows",
        agent_version="1.0.0",
        last_seen=_ts(),
        first_seen=_ts(),
        risk_score=42,
        risk_level="MEDIUM",
        tags=["finance"],
    )
    repo.upsert_host(h)
    fetched = repo.get_host("hX")
    assert fetched is not None
    assert fetched.hostname == "WIN-A"
    assert fetched.risk_score == 42
    assert fetched.tags == ["finance"]

    # Idempotent + updates
    h.hostname = "WIN-A-RENAMED"
    repo.upsert_host(h)
    again = repo.get_host("hX")
    assert again.hostname == "WIN-A-RENAMED"


def test_list_hosts_orders_by_last_seen(repo):
    repo.upsert_host(Host(host_id="a", hostname="a", last_seen=_ts(-100)))
    repo.upsert_host(Host(host_id="b", hostname="b", last_seen=_ts(0)))
    repo.upsert_host(Host(host_id="c", hostname="c", last_seen=_ts(-50)))
    ids = [h.host_id for h in repo.list_hosts()]
    assert ids[:3] == ["b", "c", "a"]


def test_event_dedup_on_event_id(repo):
    ev = _mk_event(event_id="dup-1")
    assert repo.insert_event(ev) is True
    # second call same id → no-op
    assert repo.insert_event(ev) is False
    rows = repo.list_events(host_id="h1")
    assert len(rows) == 1
    assert rows[0].event_id == "dup-1"


def test_event_filters(repo):
    repo.insert_event(_mk_event(host_id="h1", event_type="process_execution"))
    repo.insert_event(_mk_event(host_id="h1", event_type="network_connection"))
    repo.insert_event(_mk_event(host_id="h2", event_type="process_execution"))

    h1_only = repo.list_events(host_id="h1")
    assert len(h1_only) == 2

    proc_only = repo.list_events(event_type="process_execution")
    assert len(proc_only) == 2
    assert all(e.event_type == "process_execution" for e in proc_only)

    h2 = repo.list_events(host_id="h2")
    assert len(h2) == 1


def test_alert_dedup_and_status_update(repo):
    a = _mk_alert(alert_id="al-1")
    assert repo.insert_alert(a) is True
    assert repo.insert_alert(a) is False
    repo.update_alert_status("al-1", "acknowledged")
    fetched = repo.list_alerts(host_id="h1")
    assert fetched[0].status == "acknowledged"


def test_alert_status_validation(repo):
    a = _mk_alert(alert_id="al-2")
    repo.insert_alert(a)
    with pytest.raises(ValueError):
        repo.update_alert_status("al-2", "deleted")


def test_alert_aggregations(repo):
    for sev in ["low", "low", "medium", "high", "critical"]:
        repo.insert_alert(_mk_alert(severity=sev))
    counts = repo.alert_counts_by_severity()
    assert counts.get("low") == 2
    assert counts.get("medium") == 1
    assert counts.get("high") == 1
    assert counts.get("critical") == 1


def test_top_mitre_techniques(repo):
    for tech in ["T1059.001", "T1059.001", "T1059.001", "T1027", "T1218.005"]:
        repo.insert_alert(_mk_alert(mitre_technique=tech))
    top = repo.top_mitre_techniques(limit=2)
    assert top[0] == ("T1059.001", 3)
    # second can be either since both are 1
    assert top[1][1] == 1


def test_touch_host_seen_creates_row(repo):
    repo.touch_host_seen("ghost", _ts())
    h = repo.get_host("ghost")
    assert h is not None
    assert h.last_seen != ""


def test_update_host_risk_clamps(repo):
    repo.upsert_host(Host(host_id="h", last_seen=_ts()))
    repo.update_host_risk("h", 250, "CRITICAL")
    assert repo.get_host("h").risk_score == 100
    repo.update_host_risk("h", -10, "LOW")
    assert repo.get_host("h").risk_score == 0


def test_bulk_insert_events(repo):
    evs = [_mk_event(event_id=f"bulk-{i}") for i in range(5)]
    n = repo.insert_events(evs)
    assert n >= 5
    rows = repo.list_events(host_id="h1")
    ids = {e.event_id for e in rows}
    assert {f"bulk-{i}" for i in range(5)}.issubset(ids)
