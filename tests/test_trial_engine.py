"""
tests/test_trial_engine.py
==========================
Unit tests for engine/trial_engine.py

Coverage:
  • create_trial — happy path, duplicate email, invalid email
  • validate_trial — valid, expired, revoked, not found
  • revoke_trial / extend_trial
  • list_trials — active/expired filtering + computed fields
  • stats()
  • _record_access — access_count increment, first/last_access
"""
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from engine.trial_engine import TrialEngine, _fmt, _parse


class TestTrialEngineBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.engine = TrialEngine(self.tmp.name)

    def tearDown(self):
        try:
            os.unlink(self.tmp.name)
        except OSError:
            pass

    def _make(self, **kw):
        kw.setdefault("email", "test@example.com")
        kw.setdefault("name", "Test User")
        kw.setdefault("company", "Acme")
        return self.engine.create_trial(**kw)


# ─────────────────────────────────────────────────────────────────────
# create_trial
# ─────────────────────────────────────────────────────────────────────

class TestCreateTrial(TestTrialEngineBase):
    def test_returns_dict_with_token(self):
        t = self._make()
        self.assertIn("token", t)
        self.assertTrue(t["token"].startswith("ng_trial_"))

    def test_token_is_unique(self):
        t1 = self._make(email="a@a.com")
        t2 = self._make(email="b@b.com")
        self.assertNotEqual(t1["token"], t2["token"])

    def test_email_normalised_to_lowercase(self):
        t = self._make(email="UPPER@EXAMPLE.COM")
        self.assertEqual(t["email"], "upper@example.com")

    def test_default_duration_72h(self):
        t = self._make()
        self.assertEqual(t["duration_h"], 72)

    def test_custom_duration(self):
        t = self._make(duration_h=48)
        self.assertEqual(t["duration_h"], 48)

    def test_expires_at_in_future(self):
        t = self._make()
        exp = _parse(t["expires_at"])
        self.assertGreater(exp, datetime.now(timezone.utc))

    def test_invalid_email_raises(self):
        with self.assertRaises(ValueError):
            self.engine.create_trial(email="notanemail")

    def test_empty_email_raises(self):
        with self.assertRaises(ValueError):
            self.engine.create_trial(email="")

    def test_revoked_defaults_false(self):
        t = self._make()
        self.assertEqual(t["revoked"], 0)

    def test_access_count_starts_zero(self):
        t = self._make()
        self.assertEqual(t["access_count"], 0)


# ─────────────────────────────────────────────────────────────────────
# validate_trial
# ─────────────────────────────────────────────────────────────────────

class TestValidateTrial(TestTrialEngineBase):
    def test_valid_token_returns_valid_true(self):
        t = self._make()
        result = self.engine.validate_trial(t["token"])
        self.assertTrue(result["valid"])
        self.assertFalse(result["expired"])
        self.assertFalse(result["revoked"])

    def test_valid_token_has_remaining_seconds(self):
        t = self._make(duration_h=72)
        result = self.engine.validate_trial(t["token"])
        self.assertGreater(result["remaining_seconds"], 0)
        self.assertLessEqual(result["remaining_seconds"], 72 * 3600 + 5)

    def test_valid_token_increments_access_count(self):
        t = self._make()
        self.engine.validate_trial(t["token"])
        self.engine.validate_trial(t["token"])
        trial = self.engine.get_trial(t["token"])
        self.assertEqual(trial["access_count"], 2)

    def test_unknown_token_returns_not_found(self):
        result = self.engine.validate_trial("ng_trial_doesnotexist")
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "token_not_found")

    def test_revoked_token_returns_revoked(self):
        t = self._make()
        self.engine.revoke_trial(t["token"])
        result = self.engine.validate_trial(t["token"])
        self.assertFalse(result["valid"])
        self.assertTrue(result["revoked"])
        self.assertEqual(result["reason"], "revoked")

    def test_expired_token_returns_expired(self):
        # Create with 0-second duration by manipulating expires_at directly
        t = self._make(duration_h=72)
        # Manually set expires_at in the past via direct DB write
        import sqlite3
        past = _fmt(datetime.now(timezone.utc) - timedelta(hours=1))
        with sqlite3.connect(self.tmp.name) as c:
            c.execute("UPDATE trials SET expires_at=? WHERE token=?", (past, t["token"]))

        result = self.engine.validate_trial(t["token"])
        self.assertFalse(result["valid"])
        self.assertTrue(result["expired"])
        self.assertEqual(result["reason"], "expired")
        self.assertEqual(result["remaining_seconds"], 0)


# ─────────────────────────────────────────────────────────────────────
# revoke_trial
# ─────────────────────────────────────────────────────────────────────

class TestRevokeTrial(TestTrialEngineBase):
    def test_revoke_marks_trial_revoked(self):
        t = self._make()
        self.engine.revoke_trial(t["token"])
        trial = self.engine.get_trial(t["token"])
        self.assertEqual(trial["revoked"], 1)

    def test_revoke_unknown_returns_true(self):
        # Should not raise
        result = self.engine.revoke_trial("ng_trial_nonexistent")
        self.assertTrue(result)


# ─────────────────────────────────────────────────────────────────────
# extend_trial
# ─────────────────────────────────────────────────────────────────────

class TestExtendTrial(TestTrialEngineBase):
    def test_extend_increases_expires_at(self):
        t = self._make(duration_h=1)
        old_exp = _parse(t["expires_at"])
        updated = self.engine.extend_trial(t["token"], extra_hours=24)
        new_exp = _parse(updated["expires_at"])
        self.assertGreater(new_exp, old_exp)
        # Should be roughly 25h from now
        diff_h = (new_exp - datetime.now(timezone.utc)).total_seconds() / 3600
        self.assertGreater(diff_h, 23)

    def test_extend_reactivates_revoked(self):
        t = self._make()
        self.engine.revoke_trial(t["token"])
        self.engine.extend_trial(t["token"], extra_hours=24)
        trial = self.engine.get_trial(t["token"])
        self.assertEqual(trial["revoked"], 0)

    def test_extend_unknown_raises(self):
        with self.assertRaises(ValueError):
            self.engine.extend_trial("ng_trial_nonexistent", extra_hours=24)


# ─────────────────────────────────────────────────────────────────────
# list_trials
# ─────────────────────────────────────────────────────────────────────

class TestListTrials(TestTrialEngineBase):
    def test_empty_list(self):
        self.assertEqual(self.engine.list_trials(), [])

    def test_lists_created_trials(self):
        self._make(email="a@a.com")
        self._make(email="b@b.com")
        trials = self.engine.list_trials()
        self.assertEqual(len(trials), 2)

    def test_computed_status_active(self):
        t = self._make()
        trials = self.engine.list_trials()
        match = next(x for x in trials if x["token"] == t["token"])
        self.assertEqual(match["status"], "active")
        self.assertFalse(match["expired"])
        self.assertGreater(match["remaining_h"], 0)

    def test_computed_status_revoked(self):
        t = self._make()
        self.engine.revoke_trial(t["token"])
        trials = self.engine.list_trials()
        match = next(x for x in trials if x["token"] == t["token"])
        self.assertEqual(match["status"], "revoked")

    def test_filter_expired_false(self):
        # Create two trials; expire one manually
        import sqlite3
        t1 = self._make(email="active@a.com")
        t2 = self._make(email="expired@a.com")
        past = _fmt(datetime.now(timezone.utc) - timedelta(hours=1))
        with sqlite3.connect(self.tmp.name) as c:
            c.execute("UPDATE trials SET expires_at=? WHERE token=?", (past, t2["token"]))

        active_only = self.engine.list_trials(include_expired=False)
        tokens = [x["token"] for x in active_only]
        self.assertIn(t1["token"], tokens)
        self.assertNotIn(t2["token"], tokens)


# ─────────────────────────────────────────────────────────────────────
# stats()
# ─────────────────────────────────────────────────────────────────────

class TestStats(TestTrialEngineBase):
    def test_stats_initial_zeros(self):
        s = self.engine.stats()
        self.assertEqual(s["total"], 0)
        self.assertEqual(s["active"], 0)
        self.assertEqual(s["expired"], 0)

    def test_stats_counts_active(self):
        self._make(email="a@a.com")
        self._make(email="b@b.com")
        s = self.engine.stats()
        self.assertEqual(s["total"], 2)
        self.assertEqual(s["active"], 2)

    def test_stats_counts_revoked(self):
        t = self._make()
        self.engine.revoke_trial(t["token"])
        s = self.engine.stats()
        self.assertEqual(s["revoked"], 1)
        self.assertEqual(s["active"], 0)


# ─────────────────────────────────────────────────────────────────────
# helpers
# ─────────────────────────────────────────────────────────────────────

class TestHelpers(unittest.TestCase):
    def test_fmt_parse_roundtrip(self):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        self.assertEqual(_parse(_fmt(now)), now)

    def test_parse_invalid_returns_now(self):
        result = _parse("not-a-date")
        delta = abs((result - datetime.now(timezone.utc)).total_seconds())
        self.assertLess(delta, 5)


if __name__ == "__main__":
    unittest.main()
