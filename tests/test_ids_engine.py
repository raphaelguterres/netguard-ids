import unittest
from unittest.mock import MagicMock

from ids_engine import DetectionEvent, IDSEngine


def _stats_payload():
    return {
        "total": 1,
        "by_severity": {"high": 1},
        "by_threat": {"Test Threat": 1},
        "by_status": {"active": 1},
        "top_attacker_ips": [],
        "hourly_last_24h": [],
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 0,
    }


class TestIDSEngineStatisticsCache(unittest.TestCase):
    def setUp(self):
        self.engine = IDSEngine(
            db_path=":memory:",
            whitelist_ips=[],
            whitelist_uas=[],
            auto_block=False,
        )
        self.engine.store.statistics = MagicMock(return_value=_stats_payload())
        self.engine.blocker.list_blocked = MagicMock(return_value={})

    def test_get_statistics_uses_internal_cache(self):
        first = self.engine.get_statistics()
        second = self.engine.get_statistics()

        self.assertEqual(self.engine.store.statistics.call_count, 1)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)

    def test_block_ip_invalidates_statistics_cache(self):
        self.engine.get_statistics()
        self.assertEqual(self.engine.store.statistics.call_count, 1)

        self.engine.blocker.block = MagicMock(return_value=True)
        self.engine.store.save_block = MagicMock()

        ok = self.engine.block_ip("10.20.30.40", "Manual test")

        self.assertTrue(ok)
        self.engine.get_statistics()
        self.assertEqual(self.engine.store.statistics.call_count, 2)

    def test_update_status_invalidates_statistics_cache(self):
        event = DetectionEvent(
            detection_id="evt-1",
            timestamp="2026-04-13T00:00:00Z",
            threat_name="Test Threat",
            severity="high",
            description="desc",
            source_ip="10.0.0.1",
            log_entry="log",
            method="signature",
            mitre_tactic="TA0001",
            mitre_technique="T1059",
        )
        self.engine.store.insert(event)

        self.engine.get_statistics()
        self.assertEqual(self.engine.store.statistics.call_count, 1)

        ok = self.engine.update_status(event.detection_id, "resolved", "done")

        self.assertTrue(ok)
        self.engine.get_statistics()
        self.assertEqual(self.engine.store.statistics.call_count, 2)
