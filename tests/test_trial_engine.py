"""
Tests for engine/trial_engine.py
"""
import os
import tempfile
import pytest
from engine.trial_engine import TrialEngine, get_trial_engine


@pytest.fixture
def engine():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db = f.name
    e = TrialEngine(db)
    yield e
    os.unlink(db)


class TestCreateTrial:
    def test_basic_create(self, engine):
        t = engine.create_trial("test@acme.com", name="Joao", company="ACME")
        assert t["email"] == "test@acme.com"
        assert t["token"].startswith("ng_trial_")
        assert t["duration_h"] == 72
        assert t["revoked"] == 0

    def test_email_normalized(self, engine):
        t = engine.create_trial("  TEST@ACME.COM  ")
        assert t["email"] == "test@acme.com"

    def test_invalid_email_raises(self, engine):
        with pytest.raises(ValueError):
            engine.create_trial("not-an-email")

    def test_custom_duration(self, engine):
        t = engine.create_trial("a@b.com", duration_h=24)
        assert t["duration_h"] == 24

    def test_duration_out_of_range_raises(self, engine):
        with pytest.raises(ValueError):
            engine.create_trial("a@b.com", duration_h=0)
        with pytest.raises(ValueError):
            engine.create_trial("a@b.com", duration_h=99999)


class TestValidateTrial:
    def test_valid_token(self, engine):
        t = engine.create_trial("a@b.com")
        r = engine.validate_trial(t["token"])
        assert r["valid"] is True
        assert r["remaining_seconds"] > 0

    def test_invalid_token(self, engine):
        r = engine.validate_trial("ng_trial_fake")
        assert r["valid"] is False
        assert r["reason"] == "token_not_found"

    def test_revoked_token(self, engine):
        t = engine.create_trial("a@b.com")
        engine.revoke_trial(t["token"])
        r = engine.validate_trial(t["token"])
        assert r["valid"] is False and r["revoked"] is True

    def test_access_count_increments(self, engine):
        t = engine.create_trial("a@b.com")
        engine.validate_trial(t["token"])
        engine.validate_trial(t["token"])
        assert engine.get_trial(t["token"])["access_count"] == 2

    def test_first_access_recorded(self, engine):
        t = engine.create_trial("a@b.com")
        assert engine.get_trial(t["token"])["first_access"] is None
        engine.validate_trial(t["token"])
        assert engine.get_trial(t["token"])["first_access"] is not None


class TestRevokeExtend:
    def test_revoke(self, engine):
        t = engine.create_trial("a@b.com")
        engine.revoke_trial(t["token"])
        assert engine.get_trial(t["token"])["revoked"] == 1

    def test_extend_increases_expiry(self, engine):
        t = engine.create_trial("a@b.com", duration_h=1)
        old_exp = engine.get_trial(t["token"])["expires_at"]
        engine.extend_trial(t["token"], extra_hours=24)
        assert engine.get_trial(t["token"])["expires_at"] > old_exp

    def test_extend_unknown_raises(self, engine):
        with pytest.raises(ValueError):
            engine.extend_trial("ng_trial_fake")


class TestListStats:
    def test_list_all(self, engine):
        engine.create_trial("a@b.com")
        engine.create_trial("b@b.com")
        assert len(engine.list_trials()) == 2

    def test_status_field(self, engine):
        engine.create_trial("a@b.com")
        assert engine.list_trials()[0]["status"] == "active"

    def test_stats(self, engine):
        t1 = engine.create_trial("a@b.com")
        engine.create_trial("b@b.com")
        engine.revoke_trial(t1["token"])
        s = engine.stats()
        assert s["total"] == 2
        assert s["active"] == 1
        assert s["revoked"] == 1


def test_singleton():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db = f.name
    try:
        a = get_trial_engine(db)
        b = get_trial_engine(db)
        assert a is b
    finally:
        os.unlink(db)
