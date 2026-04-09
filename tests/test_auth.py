import os
import sys
import unittest

from flask import Flask


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import auth  # noqa: E402


class TestAuthCsrfFlow(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        self._orig_auth_enabled = auth.AUTH_ENABLED
        self._orig_dashboard_auth = auth.DASHBOARD_AUTH
        self._orig_csrf_enabled = auth._CSRF_ENABLED
        self._orig_verify_any_token = auth.verify_any_token

    def tearDown(self):
        auth.AUTH_ENABLED = self._orig_auth_enabled
        auth.DASHBOARD_AUTH = self._orig_dashboard_auth
        auth._CSRF_ENABLED = self._orig_csrf_enabled
        auth.verify_any_token = self._orig_verify_any_token

    def _status_code(self, result):
        if isinstance(result, tuple):
            return result[1]
        return getattr(result, "status_code", None)

    def test_require_session_emite_cookie_csrf_em_modo_local(self):
        auth.DASHBOARD_AUTH = False
        auth._CSRF_ENABLED = True

        @auth.require_session
        def page():
            return "ok"

        with self.app.test_request_context("/dashboard"):
            resp = page()

        cookies = resp.headers.getlist("Set-Cookie")
        self.assertTrue(any("csrf_token=" in c for c in cookies))

    def test_require_session_emite_cookie_csrf_com_cookie_valido(self):
        auth.DASHBOARD_AUTH = True
        auth._CSRF_ENABLED = True
        auth.verify_any_token = lambda token, repo=None: {"valid": token == "ok-token"}

        @auth.require_session
        def page():
            return "ok"

        with self.app.test_request_context(
            "/dashboard",
            headers={"Cookie": "netguard_token=ok-token"},
        ):
            resp = page()

        cookies = resp.headers.getlist("Set-Cookie")
        self.assertTrue(any("csrf_token=" in c for c in cookies))

    def test_csrf_protect_bloqueia_post_sem_token(self):
        auth._CSRF_ENABLED = True

        @auth.csrf_protect
        def mutate():
            return "ok"

        with self.app.test_request_context("/mutate", method="POST"):
            result = mutate()

        self.assertEqual(self._status_code(result), 403)

    def test_csrf_protect_aceita_bearer_header_sem_cookie_csrf(self):
        auth._CSRF_ENABLED = True

        @auth.csrf_protect
        def mutate():
            return "ok"

        with self.app.test_request_context(
            "/mutate",
            method="POST",
            headers={"Authorization": "Bearer ng_test_token"},
        ):
            result = mutate()

        self.assertEqual(result, "ok")

    def test_csrf_protect_aceita_double_submit_cookie(self):
        auth._CSRF_ENABLED = True

        @auth.csrf_protect
        def mutate():
            return "ok"

        with self.app.test_request_context(
            "/mutate",
            method="POST",
            headers={
                "Cookie": "csrf_token=abc123",
                "X-CSRFToken": "abc123",
            },
        ):
            result = mutate()

        self.assertEqual(result, "ok")


if __name__ == "__main__":
    unittest.main(verbosity=2)
