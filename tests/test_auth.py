import os
import sys
import types
import unittest
from unittest.mock import patch

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

    def test_resolve_repo_faz_fallback_para_modulo_app(self):
        orig_main = sys.modules.get("__main__")
        orig_app = sys.modules.get("app")
        fake_repo = object()
        sys.modules["__main__"] = types.SimpleNamespace()
        sys.modules["app"] = types.SimpleNamespace(repo=fake_repo)
        try:
            self.assertIs(auth._resolve_repo(), fake_repo)
        finally:
            if orig_main is not None:
                sys.modules["__main__"] = orig_main
            else:
                sys.modules.pop("__main__", None)
            if orig_app is not None:
                sys.modules["app"] = orig_app
            else:
                sys.modules.pop("app", None)


class TestStartupGuards(unittest.TestCase):

    def test_loopback_bind_eh_aceito_sem_auth(self):
        auth.ensure_safe_startup("127.0.0.1", auth_enabled=False)
        auth.ensure_safe_startup("localhost", auth_enabled=False)
        auth.ensure_safe_startup("::1", auth_enabled=False)

    def test_bind_publico_sem_auth_falha_fechado(self):
        with self.assertRaises(RuntimeError):
            auth.ensure_safe_startup("0.0.0.0", auth_enabled=False)

        with self.assertRaises(RuntimeError):
            auth.ensure_safe_startup("192.168.1.50", auth_enabled=False)

    def test_bind_publico_com_auth_ligada_eh_permitido(self):
        auth.ensure_safe_startup("0.0.0.0", auth_enabled=True)

    def test_override_explicito_permite_bind_inseguro(self):
        with patch.dict(os.environ, {"IDS_ALLOW_INSECURE_DEV": "true"}, clear=False):
            auth.ensure_safe_startup("0.0.0.0", auth_enabled=False)

    def test_is_loopback_bind_classifica_hosts_corretamente(self):
        self.assertTrue(auth.is_loopback_bind("127.0.0.1"))
        self.assertTrue(auth.is_loopback_bind("localhost"))
        self.assertTrue(auth.is_loopback_bind("[::1]"))
        self.assertFalse(auth.is_loopback_bind("0.0.0.0"))
        self.assertFalse(auth.is_loopback_bind("example.com"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
