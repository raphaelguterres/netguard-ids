"""Tests — BaselineEngine"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from engine.baseline_engine import BaselineEngine, BaselineType


@pytest.fixture
def baseline():
    return BaselineEngine(host_id="test-host")


class TestIsKnown:
    def test_unknown_process_returns_false(self, baseline):
        assert baseline.is_known_process("malware.exe") is False

    def test_unknown_ip_returns_false(self, baseline):
        assert baseline.is_known_ip("185.220.101.45") is False

    def test_unknown_port_returns_false(self, baseline):
        assert baseline.is_known_port(4444) is False


class TestLearn:
    def test_learn_process_marks_as_known(self, baseline):
        baseline.learn_process("chrome.exe")
        assert baseline.is_known_process("chrome.exe") is True

    def test_learn_ip_marks_as_known(self, baseline):
        baseline.learn_ip("8.8.8.8")
        assert baseline.is_known_ip("8.8.8.8") is True

    def test_learn_port_marks_as_known(self, baseline):
        baseline.learn_port(443)
        assert baseline.is_known_port(443) is True

    def test_learn_returns_true_for_new(self, baseline):
        assert baseline.learn_process("new.exe") is True

    def test_learn_returns_false_for_existing(self, baseline):
        baseline.learn_process("existing.exe")
        assert baseline.learn_process("existing.exe") is False

    def test_case_insensitive_process(self, baseline):
        baseline.learn_process("Chrome.exe")
        assert baseline.is_known_process("chrome.exe") is True


class TestCheckAndLearn:
    def test_new_process_unknown_then_learned(self, baseline):
        known, learned = baseline.check_and_learn_process("brand_new.exe")
        assert known is False
        assert learned is True

    def test_existing_process_known_not_learned(self, baseline):
        baseline.learn_process("old.exe")
        known, learned = baseline.check_and_learn_process("old.exe")
        assert known is True
        assert learned is False

    def test_subsequent_check_shows_known(self, baseline):
        baseline.check_and_learn_process("once.exe")
        known, _ = baseline.check_and_learn_process("once.exe")
        assert known is True


class TestBatch:
    def test_batch_learn_returns_new_only(self, baseline):
        baseline.learn_process("old.exe")
        new_ones = baseline.learn_processes_batch(["old.exe", "new1.exe", "new2.exe"])
        assert "old.exe" not in new_ones
        assert "new1.exe" in new_ones
        assert "new2.exe" in new_ones


class TestSeed:
    def test_seed_processes_are_known(self):
        b = BaselineEngine(host_id="h", seed_processes={"svchost.exe", "explorer.exe"})
        assert b.is_known_process("svchost.exe")
        assert b.is_known_process("explorer.exe")

    def test_seed_ports_are_known(self):
        b = BaselineEngine(host_id="h", seed_ports={80, 443})
        assert b.is_known_port(80)
        assert b.is_known_port(443)


class TestSnapshot:
    def test_snapshot_has_expected_keys(self, baseline):
        snap = baseline.snapshot()
        assert "host_id" in snap
        assert "sizes" in snap
        assert "timestamp" in snap

    def test_snapshot_size_reflects_learned(self, baseline):
        baseline.learn_process("a.exe")
        baseline.learn_process("b.exe")
        snap = baseline.snapshot()
        assert snap["sizes"][BaselineType.PROCESS] >= 2
