"""Tests — AutoBlockEngine"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from engine.auto_block import AutoBlockEngine, BlockRecord, BLOCK_WHITELIST


@pytest.fixture
def engine():
    return AutoBlockEngine(threshold=75, enabled=True)

@pytest.fixture
def disabled_engine():
    return AutoBlockEngine(threshold=75, enabled=False)


class TestCheckAndBlock:
    def test_blocks_when_score_above_threshold(self, engine):
        rec = engine.check_and_block("1.2.3.4", score=80, reason="test")
        assert rec is not None
        assert rec.ip == "1.2.3.4"
        assert rec.active is True

    def test_does_not_block_below_threshold(self, engine):
        rec = engine.check_and_block("1.2.3.4", score=74, reason="test")
        assert rec is None

    def test_does_not_block_at_exact_threshold_minus_one(self, engine):
        rec = engine.check_and_block("5.5.5.5", score=74)
        assert rec is None

    def test_blocks_at_exact_threshold(self, engine):
        rec = engine.check_and_block("5.5.5.5", score=75)
        assert rec is not None

    def test_does_not_block_whitelisted_ip(self, engine):
        for ip in list(BLOCK_WHITELIST)[:3]:
            rec = engine.check_and_block(ip, score=100)
            assert rec is None, f"Whitelisted IP {ip} should not be blocked"

    def test_does_not_block_when_disabled(self, disabled_engine):
        rec = disabled_engine.check_and_block("1.2.3.4", score=100)
        assert rec is None

    def test_does_not_double_block_same_ip(self, engine):
        engine.check_and_block("9.9.9.9", score=80)
        rec2 = engine.check_and_block("9.9.9.9", score=90)
        assert rec2 is None


class TestBlock:
    def test_block_registers_record(self, engine):
        engine.block("2.2.2.2", score=90, reason="C2")
        assert engine.is_blocked("2.2.2.2")

    def test_block_record_has_correct_fields(self, engine):
        rec = engine.block("3.3.3.3", score=85, reason="scan", host_id="h1")
        assert rec.ip == "3.3.3.3"
        assert rec.score == 85
        assert rec.reason == "scan"
        assert rec.host_id == "h1"
        assert rec.rule_id.startswith("NETGUARD_BLOCK_")
        assert rec.blocked_at is not None

    def test_block_whitelist_returns_none(self, engine):
        rec = engine.block("127.0.0.1", score=100)
        assert rec is None

    def test_block_increments_total(self, engine):
        engine.block("4.4.4.4", score=80)
        engine.block("5.5.5.5", score=80)
        assert engine.stats()["total_blocked"] == 2


class TestUnblock:
    def test_unblock_removes_active_block(self, engine):
        engine.block("6.6.6.6", score=80)
        assert engine.is_blocked("6.6.6.6")
        engine.unblock("6.6.6.6")
        assert not engine.is_blocked("6.6.6.6")

    def test_unblock_nonexistent_returns_false(self, engine):
        result = engine.unblock("99.99.99.99")
        assert result is False

    def test_unblock_increments_counter(self, engine):
        engine.block("7.7.7.7", score=80)
        engine.unblock("7.7.7.7")
        assert engine.stats()["total_unblocked"] == 1

    def test_unblock_adds_to_history(self, engine):
        engine.block("8.8.8.8", score=80)
        engine.unblock("8.8.8.8")
        history = engine.get_history()
        actions = [h["action"] for h in history]
        assert "UNBLOCK" in actions


class TestGetBlocks:
    def test_get_blocks_returns_active_only(self, engine):
        engine.block("10.0.0.1", score=80)
        engine.block("10.0.0.2", score=85)
        engine.unblock("10.0.0.1")
        blocks = engine.get_blocks()
        ips = [b["ip"] for b in blocks]
        assert "10.0.0.2" in ips
        assert "10.0.0.1" not in ips

    def test_get_blocks_empty_initially(self, engine):
        assert engine.get_blocks() == []


class TestHistory:
    def test_history_records_block_and_unblock(self, engine):
        engine.block("11.1.1.1", score=80)
        engine.unblock("11.1.1.1")
        hist = engine.get_history()
        assert len(hist) == 2

    def test_history_has_required_keys(self, engine):
        engine.block("12.1.1.1", score=80, reason="test")
        hist = engine.get_history(1)
        assert "action" in hist[0]
        assert "ip"     in hist[0]
        assert "timestamp" in hist[0]


class TestStats:
    def test_stats_has_expected_keys(self, engine):
        stats = engine.stats()
        for key in ("enabled","threshold","active_blocks","total_blocked",
                    "total_unblocked","os","whitelist_size"):
            assert key in stats

    def test_stats_reflects_enabled_state(self, engine):
        assert engine.stats()["enabled"] is True
        engine.set_enabled(False)
        assert engine.stats()["enabled"] is False

    def test_set_threshold_clamped(self, engine):
        engine.set_threshold(200)
        assert engine.threshold == 100
        engine.set_threshold(-5)
        assert engine.threshold == 1


class TestCallback:
    def test_callback_called_on_block(self):
        calls = []
        eng = AutoBlockEngine(threshold=50, enabled=True,
                               callback=lambda e: calls.append(e))
        eng.block("20.1.1.1", score=60)
        assert len(calls) == 1
        assert calls[0]["action"] == "blocked"
        assert calls[0]["ip"] == "20.1.1.1"

    def test_callback_called_on_unblock(self):
        calls = []
        eng = AutoBlockEngine(threshold=50, enabled=True,
                               callback=lambda e: calls.append(e))
        eng.block("20.2.2.2", score=60)
        eng.unblock("20.2.2.2")
        assert any(c["action"] == "unblocked" for c in calls)


class TestBlockRecord:
    def test_to_dict_has_all_keys(self):
        rec = BlockRecord("1.1.1.1", 80, "test", "h1", "R1")
        d = rec.to_dict()
        for key in ("ip","score","reason","host_id","rule_name",
                    "blocked_at","rule_id","active"):
            assert key in d

    def test_rule_id_contains_ip(self):
        rec = BlockRecord("1.2.3.4", 80, "test")
        assert "1_2_3_4" in rec.rule_id
