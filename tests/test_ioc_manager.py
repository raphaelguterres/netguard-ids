"""
Tests for ioc_manager.py
"""
import os
import tempfile
import pytest
from ioc_manager import IOCManager, get_ioc_manager


@pytest.fixture
def mgr():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db = f.name
    m = IOCManager(db, "test-tenant")
    yield m
    os.unlink(db)


# ── Detecção de tipo ──────────────────────────────────────────────
class TestDetectType:
    def test_ipv4(self, mgr):
        assert mgr._detect_ioc_type("1.2.3.4") == "ip"

    def test_ipv6(self, mgr):
        assert mgr._detect_ioc_type("2001:db8::1") == "ip"

    def test_md5(self, mgr):
        assert mgr._detect_ioc_type("a" * 32) == "hash"

    def test_sha1(self, mgr):
        assert mgr._detect_ioc_type("a" * 40) == "hash"

    def test_sha256(self, mgr):
        assert mgr._detect_ioc_type("a" * 64) == "hash"

    def test_domain(self, mgr):
        assert mgr._detect_ioc_type("evil.com") == "domain"

    def test_url(self, mgr):
        assert mgr._detect_ioc_type("http://evil.com/payload") == "url"

    def test_unknown(self, mgr):
        assert mgr._detect_ioc_type("not_anything") == "unknown"


# ── CRUD ──────────────────────────────────────────────────────────
class TestCRUD:
    def test_add_and_get(self, mgr):
        ioc = mgr.add_ioc({"value": "1.2.3.4", "description": "test"})
        assert ioc["value"] == "1.2.3.4"
        assert ioc["ioc_type"] == "ip"
        assert ioc["enabled"] == 1

    def test_list(self, mgr):
        mgr.add_ioc({"value": "1.2.3.4"})
        mgr.add_ioc({"value": "evil.com"})
        iocs = mgr.list_iocs()
        assert len(iocs) == 2

    def test_delete(self, mgr):
        ioc = mgr.add_ioc({"value": "1.2.3.4"})
        mgr.delete_ioc(ioc["id"])
        assert mgr.list_iocs() == []

    def test_toggle(self, mgr):
        ioc = mgr.add_ioc({"value": "1.2.3.4"})
        toggled = mgr.toggle_ioc(ioc["id"])
        assert toggled["enabled"] == 0
        toggled2 = mgr.toggle_ioc(ioc["id"])
        assert toggled2["enabled"] == 1

    def test_duplicate_raises(self, mgr):
        mgr.add_ioc({"value": "1.2.3.4"})
        with pytest.raises(ValueError, match="já existe"):
            mgr.add_ioc({"value": "1.2.3.4"})


# ── Checks ────────────────────────────────────────────────────────
class TestChecks:
    def test_check_ip_hit(self, mgr):
        mgr.add_ioc({"value": "10.20.30.40"})
        result = mgr.check_ip("10.20.30.40")
        assert result is not None
        assert result["value"] == "10.20.30.40"

    def test_check_ip_miss(self, mgr):
        assert mgr.check_ip("9.9.9.9") is None

    def test_check_ip_disabled_not_matched(self, mgr):
        ioc = mgr.add_ioc({"value": "10.20.30.40"})
        mgr.toggle_ioc(ioc["id"])  # disable
        assert mgr.check_ip("10.20.30.40") is None

    def test_check_domain_exact(self, mgr):
        mgr.add_ioc({"value": "evil.com", "ioc_type": "domain"})
        assert mgr.check_domain("evil.com") is not None

    def test_check_domain_subdomain(self, mgr):
        mgr.add_ioc({"value": "evil.com", "ioc_type": "domain"})
        assert mgr.check_domain("sub.evil.com") is not None

    def test_check_domain_miss(self, mgr):
        mgr.add_ioc({"value": "evil.com", "ioc_type": "domain"})
        assert mgr.check_domain("notevil.com") is None

    def test_check_hash(self, mgr):
        h = "a" * 32
        mgr.add_ioc({"value": h, "ioc_type": "hash"})
        assert mgr.check_hash(h) is not None

    def test_check_all_returns_hits(self, mgr):
        mgr.add_ioc({"value": "1.2.3.4"})
        hits = mgr.check_all(ip="1.2.3.4")
        assert len(hits) == 1

    def test_hit_counter_increments(self, mgr):
        mgr.add_ioc({"value": "1.2.3.4"})
        mgr.check_ip("1.2.3.4")
        mgr.check_ip("1.2.3.4")
        iocs = mgr.list_iocs()
        assert iocs[0]["hit_count"] == 2


# ── Import CSV ────────────────────────────────────────────────────
class TestImportCSV:
    def test_import_single_column(self, mgr):
        csv = "1.2.3.4\nevil.com\n"
        result = mgr.import_csv(csv)
        assert result["imported"] == 2

    def test_import_two_columns(self, mgr):
        csv = "value,description\n1.2.3.4,Bad IP\n"
        result = mgr.import_csv(csv)
        assert result["imported"] == 1

    def test_import_skips_duplicates(self, mgr):
        mgr.add_ioc({"value": "1.2.3.4"})
        csv = "1.2.3.4\n"
        result = mgr.import_csv(csv)
        assert result["skipped"] == 1

    def test_import_empty(self, mgr):
        result = mgr.import_csv("")
        assert result["imported"] == 0


# ── Singleton ─────────────────────────────────────────────────────
def test_singleton():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db = f.name
    try:
        a = get_ioc_manager(db, "t1")
        b = get_ioc_manager(db, "t1")
        assert a is b
        c = get_ioc_manager(db, "t2")
        assert a is not c
    finally:
        os.unlink(db)
