import os
import sqlite3
import tempfile
import unittest
import uuid
from unittest.mock import patch

from engine.mitre_engine import MitreEngine


class TestMitreEngine(unittest.TestCase):
    def setUp(self):
        self.tmp_root = os.path.join(os.path.dirname(__file__), "_tmp_mitre_engine")
        os.makedirs(self.tmp_root, exist_ok=True)
        self.tmpdir = os.path.join(self.tmp_root, str(uuid.uuid4()))
        os.makedirs(self.tmpdir, exist_ok=True)
        self.db_path = os.path.join(self.tmpdir, "mitre_test.db")
        self.engine = MitreEngine(self.db_path, "tenant-test")
        self.engine.record_hit(
            {
                "event_id": "evt-1",
                "threat": "PowerShell suspicious",
                "severity": "high",
                "source_ip": "10.0.0.5",
            },
            [
                {
                    "id": "T1059",
                    "name": "Command and Scripting Interpreter",
                    "tactic": "TA0002",
                }
            ],
        )

    def tearDown(self):
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except OSError:
                pass
        if os.path.isdir(self.tmpdir):
            try:
                os.rmdir(self.tmpdir)
            except OSError:
                pass

    def test_heat_map_exposes_legacy_top10_alias(self):
        data = self.engine.heat_map(30)
        self.assertIn("top_techniques", data)
        self.assertIn("top10", data)
        self.assertEqual(data["top10"], data["top_techniques"])

    def test_stats_returns_degraded_payload_when_db_is_locked(self):
        with patch.object(self.engine, "_db", side_effect=sqlite3.OperationalError("database is locked")):
            data = self.engine.stats()
        self.assertTrue(data["degraded"])
        self.assertEqual(data["warning"], "database_locked")

    def test_heat_map_returns_degraded_payload_when_db_is_locked(self):
        with patch.object(self.engine, "_db", side_effect=sqlite3.OperationalError("database is locked")):
            data = self.engine.heat_map(30)
        self.assertTrue(data["degraded"])
        self.assertEqual(data["warning"], "database_locked")
        self.assertIn("matrix", data)

    def test_technique_detail_contains_frontend_friendly_fields(self):
        detail = self.engine.technique_detail("T1059")
        self.assertEqual(detail["id"], "T1059")
        self.assertIn("name", detail)
        self.assertIn("tactic_name", detail)
        self.assertIn("url", detail)
        self.assertIn("hits", detail)
        self.assertIn("count", detail)

    def test_init_does_not_raise_when_database_is_locked(self):
        with patch.object(MitreEngine, "_db", side_effect=sqlite3.OperationalError("database is locked")):
            engine = MitreEngine(self.db_path, "tenant-init-lock")
        self.assertFalse(engine._schema_ready)


if __name__ == "__main__":
    unittest.main()
