import os
import sqlite3
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

os.environ.setdefault("TOKEN_SIGNING_SECRET", "event-repo-test-signing-key")

from security import hash_token
from storage.event_repository import EventRepository


class TestEventRepositoryTokenStorage(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()

    def tearDown(self):
        try:
            os.unlink(self.tmp.name)
        except OSError:
            pass

    def _repo(self):
        return EventRepository(db_path=self.tmp.name)

    def _fetch_tenant_row(self, tenant_id):
        conn = sqlite3.connect(self.tmp.name)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT tenant_id, token, token_hash, token_prefix, scopes FROM tenants WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def test_create_tenant_persists_safe_token_material(self):
        repo = self._repo()
        tenant_id = "tenant-create"
        token = "ng_create_token_abcdefghijklmnopqrstuvwxyz123456"

        ok = repo.create_tenant(
            tenant_id=tenant_id,
            name="Create Test",
            token=token,
            plan="pro",
            max_hosts=10,
        )

        self.assertTrue(ok)
        row = self._fetch_tenant_row(tenant_id)
        self.assertIsNotNone(row)
        self.assertEqual(row["token_hash"], hash_token(token))
        self.assertEqual(row["token_prefix"], token[:16])
        self.assertTrue(row["token"].startswith("tk_"))
        self.assertNotEqual(row["token"], token)

        tenant = repo.get_tenant_by_token(token)
        self.assertIsNotNone(tenant)
        self.assertEqual(tenant["tenant_id"], tenant_id)
        self.assertEqual(tenant["token"], token[:16])
        self.assertEqual(tenant["token_prefix"], token[:16])
        self.assertNotIn("token_hash", tenant)
        self.assertIn("events:write", tenant["scopes"])
        self.assertIn("hosts:manage", tenant["scopes"])

    def test_create_tenant_can_persist_narrow_token_scopes(self):
        repo = self._repo()
        tenant_id = "tenant-scoped"
        token = "ng_scoped_token_abcdefghijklmnopqrstuvwxyz123456"

        ok = repo.create_tenant(
            tenant_id=tenant_id,
            name="Scoped Test",
            token=token,
            role="viewer",
            scopes=["events:write"],
        )

        self.assertTrue(ok)
        row = self._fetch_tenant_row(tenant_id)
        self.assertEqual(row["scopes"], '["events:write"]')

        tenant = repo.get_tenant_by_token(token)
        self.assertEqual(tenant["role"], "viewer")
        self.assertEqual(tenant["scopes"], ["events:write"])

    def test_legacy_schema_migration_status_is_recorded(self):
        repo = self._repo()

        status = repo.legacy_migration_status()

        self.assertTrue(status["ok"], status)
        self.assertEqual(status["component"], "event_repository")
        self.assertEqual(status["schema_version"], status["latest_version"])
        self.assertEqual(status["pending"], [])
        self.assertEqual(status["failed"], [])
        self.assertEqual(status["mismatched"], [])
        self.assertEqual(status["unknown"], [])
        self.assertGreaterEqual(len(status["history"]), 1)
        self.assertEqual(status["history"][0]["status"], "applied")
        self.assertTrue(status["history"][0]["checksum"])

    def test_update_tenant_token_scrubs_plaintext_and_preserves_lookup(self):
        repo = self._repo()
        tenant_id = "tenant-rotate"
        old_token = "ng_old_token_abcdefghijklmnopqrstuvwxyz123456"
        new_token = "ng_new_token_abcdefghijklmnopqrstuvwxyz654321"

        repo.create_tenant(
            tenant_id=tenant_id,
            name="Rotate Test",
            token=old_token,
            plan="pro",
            max_hosts=10,
        )

        ok = repo.update_tenant_token(tenant_id, new_token, hash_token(new_token))
        self.assertTrue(ok)

        row = self._fetch_tenant_row(tenant_id)
        self.assertEqual(row["token_hash"], hash_token(new_token))
        self.assertEqual(row["token_prefix"], new_token[:16])
        self.assertTrue(row["token"].startswith("tk_"))
        self.assertNotEqual(row["token"], new_token)
        self.assertIsNone(repo.get_tenant_by_token(old_token))

        tenant = repo.get_tenant_by_token(new_token)
        self.assertIsNotNone(tenant)
        self.assertEqual(tenant["tenant_id"], tenant_id)

    def test_legacy_plaintext_token_is_hardened_on_repository_init(self):
        token = "ng_legacy_token_abcdefghijklmnopqrstuvwxyz987654"
        conn = sqlite3.connect(self.tmp.name)
        try:
            conn.execute("""
                CREATE TABLE tenants (
                    tenant_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    token TEXT NOT NULL UNIQUE,
                    plan TEXT NOT NULL DEFAULT 'free',
                    max_hosts INTEGER DEFAULT 1,
                    created_at TEXT,
                    active INTEGER DEFAULT 1
                )
            """)
            conn.execute("""
                INSERT INTO tenants (tenant_id, name, token, plan, max_hosts, created_at, active)
                VALUES (?, ?, ?, ?, ?, datetime('now'), 1)
            """, ("tenant-legacy", "Legacy Tenant", token, "pro", 10))
            conn.commit()
        finally:
            conn.close()

        repo = self._repo()
        row = self._fetch_tenant_row("tenant-legacy")

        self.assertIsNotNone(row)
        self.assertEqual(row["token_hash"], hash_token(token))
        self.assertEqual(row["token_prefix"], token[:16])
        self.assertTrue(row["token"].startswith("tk_"))
        self.assertNotEqual(row["token"], token)

        tenant = repo.get_tenant_by_token(token)
        self.assertIsNotNone(tenant)
        self.assertEqual(tenant["tenant_id"], "tenant-legacy")
        self.assertEqual(tenant["token"], token[:16])

    def test_onboarding_ticket_is_shared_across_repository_instances(self):
        repo_a = self._repo()
        repo_b = self._repo()
        ticket = "ticket-shared"
        payload = {"token": "ng_shared_token", "name": "Worker A"}

        self.assertTrue(repo_a.save_onboarding_ticket(ticket, payload, ttl_seconds=60))

        consumed = repo_b.consume_onboarding_ticket(ticket)
        self.assertEqual(consumed, payload)
        self.assertIsNone(repo_a.consume_onboarding_ticket(ticket))

    def test_onboarding_ticket_expiration_is_enforced(self):
        repo = self._repo()
        ticket = "ticket-expired"
        payload = {"token": "ng_expired_token"}

        self.assertTrue(repo.save_onboarding_ticket(ticket, payload, ttl_seconds=1))
        time.sleep(1.1)
        self.assertEqual(repo.purge_expired_onboarding_tickets(), 1)
        self.assertIsNone(repo.consume_onboarding_ticket(ticket))


if __name__ == "__main__":
    unittest.main(verbosity=2)
