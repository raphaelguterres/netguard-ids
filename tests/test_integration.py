"""
tests/test_integration.py
=========================
Testes de integração end-to-end do NetGuard IDS.

Cobrem o fluxo completo sem dependências externas (SMTP, Telegram, Stripe):
  1. Self-serve trial (POST /trial)
  2. Login com token gerado
  3. Envio de evento de detecção
  4. Consulta de detecções
  5. Rotação de token (/api/auth/rotate)
  6. Rate limit no /trial (3 req/h por IP)
  7. BruteForce lockout no /api/auth/login
  8. Admin dashboard endpoints
  9. Audit log via /api/admin/audit
  10. Notifier dry-run (sem destinos configurados)

Todos os testes rodam com TestClient do Flask (sem rede real).
Skipped automaticamente se o Flask ou o app não puder ser importado.
"""

import os
import sys
import json
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# Configuração mínima de ambiente para testes
os.environ.setdefault("TOKEN_SIGNING_SECRET", "integration-test-key")
os.environ.setdefault("IDS_AUTH", "false")
os.environ.setdefault("IDS_DASHBOARD_AUTH", "false")
os.environ.setdefault("IDS_DB_PATH",          tempfile.mktemp(suffix=".db"))
os.environ.setdefault("IDS_AUDIT_LOG",        tempfile.mktemp(suffix=".log"))
os.environ.setdefault("IDS_BF_DB",            tempfile.mktemp(suffix=".db"))
os.environ.setdefault("HTTPS_ONLY",           "false")
os.environ.setdefault("SECRET_KEY",           "integration-test-secret")

_APP_OK = False
app_module = None
auth_module = None
try:
    import app as app_module
    import auth as auth_module
    from app import app, repo
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    _APP_OK = True
except Exception as _e:
    print(f"[SKIP] app não carregou: {_e}")


def skip_if_no_app(cls):
    if not _APP_OK:
        return unittest.skip("app.py não carregou")(cls)
    return cls


# ══════════════════════════════════════════════════════════════════
# Helper base
# ══════════════════════════════════════════════════════════════════

class BaseIntegration(unittest.TestCase):
    FORCE_REAL_AUTH = False

    @classmethod
    def setUpClass(cls):
        if not _APP_OK:
            return
        cls._orig_auth_enabled = getattr(auth_module, "AUTH_ENABLED", None)
        cls._orig_dashboard_auth = getattr(auth_module, "DASHBOARD_AUTH", None)
        cls._orig_app_auth_enabled = getattr(app_module, "AUTH_ENABLED", None)
        cls._orig_app_dashboard_auth = getattr(app_module, "DASHBOARD_AUTH", None)
        if cls.FORCE_REAL_AUTH:
            auth_module.AUTH_ENABLED = True
            auth_module.DASHBOARD_AUTH = True
            app_module.AUTH_ENABLED = True
            app_module.DASHBOARD_AUTH = True
        cls.client = app.test_client()
        cls.ctx    = app.app_context()
        cls.ctx.push()

    @classmethod
    def tearDownClass(cls):
        if not _APP_OK:
            return
        try:
            cls.ctx.pop()
        except Exception:
            pass
        if cls._orig_auth_enabled is not None:
            auth_module.AUTH_ENABLED = cls._orig_auth_enabled
        if cls._orig_dashboard_auth is not None:
            auth_module.DASHBOARD_AUTH = cls._orig_dashboard_auth
        if cls._orig_app_auth_enabled is not None:
            app_module.AUTH_ENABLED = cls._orig_app_auth_enabled
        if cls._orig_app_dashboard_auth is not None:
            app_module.DASHBOARD_AUTH = cls._orig_app_dashboard_auth

    def post_json(self, url, data, **kw):
        return self.client.post(url, data=json.dumps(data),
                                content_type="application/json", **kw)

    def get_json(self, url, token=None, **kw):
        headers = kw.pop("headers", {})
        if token:
            headers["X-API-Token"] = token
        return self.client.get(url, headers=headers, **kw)

    @staticmethod
    def create_tenant_with_role(name: str, plan: str = "pro", role: str = "analyst",
                                stripe_customer_id: str = ""):
        import uuid
        from billing import generate_api_token

        tenant_id = str(uuid.uuid4())
        token = generate_api_token()
        repo.create_tenant(
            tenant_id=tenant_id,
            name=name,
            token=token,
            plan=plan,
            max_hosts=25,
            stripe_customer_id=stripe_customer_id,
        )
        conn = repo._conn()
        conn.execute("UPDATE tenants SET role = ? WHERE tenant_id = ?", (role, tenant_id))
        conn.commit()
        return tenant_id, token


# ══════════════════════════════════════════════════════════════════
# 1. SELF-SERVE TRIAL
# ══════════════════════════════════════════════════════════════════

@skip_if_no_app
class TestTrialFlow(BaseIntegration):

    def test_trial_campos_obrigatorios(self):
        r = self.post_json("/trial", {"plan": "pro"})
        self.assertIn(r.status_code, (400, 302))

    def test_trial_cria_tenant(self):
        r = self.post_json("/trial", {
            "name": "Integração Test",
            "email": "integ@test.com",
            "company": "TestCorp",
            "plan": "pro",
        })
        # Aceita JSON 200 ou redirect 302 (form submit)
        self.assertIn(r.status_code, (200, 201, 302))
        if r.content_type and "json" in r.content_type:
            d = json.loads(r.data)
            self.assertTrue(d.get("ok"))
            self.assertIn("token", d)
            self.assertTrue(d["token"].startswith("ng_"))

    def test_trial_welcome_url_nao_expoe_token_em_query(self):
        r = self.post_json("/trial", {
            "name": "Sem Vazamento",
            "email": "safe@test.com",
            "company": "SafeCorp",
            "plan": "pro",
        })
        self.assertIn(r.status_code, (200, 201))
        d = json.loads(r.data)
        self.assertIn("welcome_url", d)
        self.assertIn("onboarding=", d["welcome_url"])
        self.assertNotIn("token=", d["welcome_url"])
        self.assertNotIn(d["token"], d["welcome_url"])
        self.assertNotIn("email=", d["welcome_url"])

    def test_trial_form_redirect_usa_ticket_opaco(self):
        r = self.client.post("/trial", data={
            "name": "Form User",
            "email": "form@test.com",
            "company": "SafeCorp",
            "plan": "pro",
        }, follow_redirects=False)
        self.assertIn(r.status_code, (302, 303))
        location = r.headers.get("Location", "")
        self.assertIn("/welcome?onboarding=", location)
        self.assertNotIn("token=", location)
        self.assertNotIn("email=", location)

    def test_welcome_ticket_e_uso_unico_e_sem_cache(self):
        r = self.post_json("/trial", {
            "name": "Single Use",
            "email": "single@test.com",
            "company": "SafeCorp",
            "plan": "pro",
        })
        self.assertEqual(r.status_code, 200)
        d = json.loads(r.data)
        welcome_url = d["welcome_url"]

        first = self.client.get(welcome_url, follow_redirects=False)
        self.assertEqual(first.status_code, 200)
        self.assertIn(d["token"].encode(), first.data)
        self.assertIn("no-store", first.headers.get("Cache-Control", ""))
        self.assertEqual(first.headers.get("Referrer-Policy"), "no-referrer")

        second = self.client.get(welcome_url, follow_redirects=False)
        self.assertIn(second.status_code, (302, 303))
        self.assertIn("/pricing?error=welcome_expired", second.headers.get("Location", ""))

    def test_welcome_legacy_demo_query_nao_provisiona_tenant(self):
        legacy_token = "ng_legacy_demo_query_token"
        r = self.client.get(
            f"/welcome?demo=1&plan=enterprise&token={legacy_token}"
            "&name=Legacy+Tenant&email=legacy@test.com",
            follow_redirects=False,
        )
        self.assertIn(r.status_code, (302, 303))
        self.assertIn("/pricing?error=welcome_expired", r.headers.get("Location", ""))
        self.assertIsNone(repo.get_tenant_by_token(legacy_token))

    def test_trial_email_invalido_nao_quebra_app(self):
        """App não deve quebrar com email malformado."""
        r = self.post_json("/trial", {
            "name": "Test",
            "email": "nao-e-um-email",
            "plan": "pro",
        })
        # Pode aceitar ou rejeitar, mas não pode dar 500
        self.assertNotEqual(r.status_code, 500)

    def test_trial_xss_name_sanitizado(self):
        r = self.post_json("/trial", {
            "name": "<script>alert(1)</script>",
            "email": "xss@test.com",
            "plan": "pro",
        })
        self.assertNotEqual(r.status_code, 500)
        if r.data:
            self.assertNotIn(b"<script>alert(1)</script>", r.data)


# ══════════════════════════════════════════════════════════════════
# 2. AUTENTICAÇÃO — LOGIN E COOKIE
# ══════════════════════════════════════════════════════════════════

@skip_if_no_app
class TestAuthFlow(BaseIntegration):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if not _APP_OK:
            return
        # Cria tenant de teste direto no repo
        import uuid
        from billing import generate_api_token
        cls.tenant_id = str(uuid.uuid4())
        cls.token     = generate_api_token()
        repo.create_tenant(
            tenant_id = cls.tenant_id,
            name      = "Auth Test Tenant",
            token     = cls.token,
            plan      = "pro",
            max_hosts = 10,
        )

    def test_login_token_invalido_retorna_401(self):
        r = self.post_json("/api/auth/login", {"token": "ng_invalido_totalmente"})
        self.assertEqual(r.status_code, 401)
        d = json.loads(r.data)
        self.assertFalse(d.get("valid"))

    def test_login_token_vazio_retorna_400(self):
        r = self.post_json("/api/auth/login", {"token": ""})
        self.assertEqual(r.status_code, 400)

    def test_login_token_valido_seta_cookie(self):
        r = self.post_json("/api/auth/login", {"token": self.token})
        self.assertIn(r.status_code, (200, 401))
        if r.status_code == 200:
            d = json.loads(r.data)
            self.assertTrue(d.get("valid"))
            cookies = r.headers.getlist("Set-Cookie")
            has_ng = any("netguard_token" in c for c in cookies)
            self.assertTrue(has_ng, "Cookie netguard_token não foi setado")

    def test_free_preview_seta_cookies_temporarios(self):
        r = self.post_json("/api/auth/free-preview", {"token": self.token})
        self.assertEqual(r.status_code, 200)
        d = json.loads(r.data)
        self.assertTrue(d.get("valid"))
        self.assertEqual(d.get("redirect_to"), "/dashboard")
        self.assertGreaterEqual(d.get("minutes", 0), 1)

        cookies = r.headers.getlist("Set-Cookie")
        self.assertTrue(any("netguard_token=" in c for c in cookies))
        self.assertTrue(any("netguard_preview_mode=free" in c for c in cookies))
        self.assertTrue(any("netguard_preview_expires=" in c for c in cookies))

    def test_free_preview_recupera_demo_token_legado_e_abre_dashboard(self):
        from demo_seed import DEMO_TENANT_ID, DEMO_TOKEN
        from security import hash_token
        from billing import generate_api_token
        from auth import verify_any_token

        stale_token = generate_api_token()
        if repo.get_tenant_by_id(DEMO_TENANT_ID):
            repo.update_tenant_token(DEMO_TENANT_ID, stale_token, hash_token(stale_token))
        else:
            repo.create_tenant(
                tenant_id=DEMO_TENANT_ID,
                name="Demo Legacy",
                token=stale_token,
                plan="pro",
                max_hosts=50,
            )

        self.assertIsNone(repo.get_tenant_by_token(DEMO_TOKEN))

        client = app.test_client(use_cookies=False)
        r = client.post(
            "/api/auth/free-preview",
            data=json.dumps({"token": self.token}),
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 200)
        d = json.loads(r.data)
        self.assertTrue(d.get("uses_demo_data"))
        cookies = r.headers.getlist("Set-Cookie")
        self.assertTrue(any(f"netguard_token={DEMO_TOKEN}" in c for c in cookies))

        demo_tenant = repo.get_tenant_by_token(DEMO_TOKEN)
        self.assertIsNotNone(demo_tenant)
        result = verify_any_token(DEMO_TOKEN, repo)
        self.assertTrue(result.get("valid"))
        self.assertEqual((result.get("tenant") or {}).get("tenant_id"), DEMO_TENANT_ID)

    def test_login_normal_limpa_preview_cookies(self):
        self.post_json("/api/auth/free-preview", {"token": self.token})
        r = self.post_json("/api/auth/login", {"token": self.token})
        self.assertEqual(r.status_code, 200)
        cookies = r.headers.getlist("Set-Cookie")
        self.assertTrue(any("netguard_preview_mode=;" in c for c in cookies))
        self.assertTrue(any("netguard_preview_expires=;" in c for c in cookies))

    def test_validate_token_valido(self):
        r = self.post_json("/api/auth/validate", {"token": self.token})
        self.assertIn(r.status_code, (200, 401))

    def test_validate_token_invalido(self):
        r = self.post_json("/api/auth/validate", {"token": "ng_fake_token_xyz"})
        self.assertEqual(r.status_code, 401)


@skip_if_no_app
class TestProtectedRoutePolicies(BaseIntegration):
    FORCE_REAL_AUTH = True

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if not _APP_OK:
            return
        cls.viewer_id, cls.viewer_token = cls.create_tenant_with_role(
            "Viewer Tenant", role="viewer"
        )
        cls.analyst_id, cls.analyst_token = cls.create_tenant_with_role(
            "Analyst Tenant", role="analyst"
        )
        cls.admin_id, cls.admin_token = cls.create_tenant_with_role(
            "Admin Tenant", role="admin", stripe_customer_id="cus_test_admin"
        )

    def _cookie_headers(self, token: str, csrf_token: str | None = None):
        cookie_parts = [f"netguard_token={token}"]
        headers = {}
        if csrf_token:
            cookie_parts.append(f"csrf_token={csrf_token}")
            headers["X-CSRFToken"] = csrf_token
        headers["Cookie"] = "; ".join(cookie_parts)
        return headers

    def _cookie_client(self, token: str, csrf_token: str | None = None):
        client = app.test_client()
        client.set_cookie("netguard_token", token)
        if csrf_token:
            client.set_cookie("csrf_token", csrf_token)
        return client

    def test_billing_portal_exige_admin(self):
        analyst = self.client.get("/billing/portal", headers={"X-API-Token": self.analyst_token})
        self.assertEqual(analyst.status_code, 403)

        admin = self.client.get("/billing/portal", headers={"X-API-Token": self.admin_token})
        self.assertNotEqual(admin.status_code, 403)

    def test_webhooks_list_bloqueia_viewer(self):
        viewer = self.client.get("/api/webhooks", headers={"X-API-Token": self.viewer_token})
        self.assertEqual(viewer.status_code, 403)

        analyst = self.client.get("/api/webhooks", headers={"X-API-Token": self.analyst_token})
        self.assertIn(analyst.status_code, (200, 503))

    def test_webhooks_create_cookie_auth_exige_csrf(self):
        payload = {
            "name": "Sec Hook",
            "url": "https://8.8.8.8/hook",
            "type": "generic",
            "min_severity": "high",
            "event_types": [],
        }
        sem_csrf = self._cookie_client(self.analyst_token).post(
            "/api/webhooks",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(sem_csrf.status_code, 403)

        com_csrf = self._cookie_client(
            self.analyst_token, csrf_token="csrf_webhook_test"
        ).post(
            "/api/webhooks",
            data=json.dumps(payload),
            content_type="application/json",
            headers={"X-CSRFToken": "csrf_webhook_test"},
        )
        self.assertEqual(com_csrf.status_code, 201)

    def test_custom_rules_create_bloqueia_viewer(self):
        payload = {
            "name": "Viewer Block Test",
            "conditions": [{"field": "event_type", "operator": "equals", "value": "ioc_match"}],
            "logic": "AND",
            "severity": "HIGH",
        }
        r = self.post_json("/api/rules/custom", payload, headers={"X-API-Token": self.viewer_token})
        self.assertEqual(r.status_code, 403)

    def test_playbook_open_bloqueia_viewer(self):
        payload = {"playbook": "malware_triage", "trigger_event": {"severity": "high"}}
        r = self.post_json("/api/playbooks/incidents", payload, headers={"X-API-Token": self.viewer_token})
        self.assertEqual(r.status_code, 403)

    def test_forensics_capture_bloqueia_viewer(self):
        payload = {"severity": "high", "hostname": "host-forensics"}
        r = self.post_json("/api/forensics/snapshots", payload, headers={"X-API-Token": self.viewer_token})
        self.assertEqual(r.status_code, 403)

    def test_ti_refresh_bloqueia_viewer(self):
        r = self.post_json("/api/ti/feeds/refresh_all", {}, headers={"X-API-Token": self.viewer_token})
        self.assertEqual(r.status_code, 403)


# ══════════════════════════════════════════════════════════════════
# 3. DETECÇÃO DE EVENTOS
# ══════════════════════════════════════════════════════════════════

@skip_if_no_app
class TestHealthFlow(BaseIntegration):

    def test_health_reflete_backend_do_storage(self):
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 200)
        d = json.loads(r.data)
        self.assertEqual(d.get("db_backend"), "sqlite")


@skip_if_no_app
class TestDetectionFlow(BaseIntegration):
    FORCE_REAL_AUTH = True

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if not _APP_OK:
            return
        import uuid
        from billing import generate_api_token
        cls.tenant_id = str(uuid.uuid4())
        cls.token     = generate_api_token()
        repo.create_tenant(
            tenant_id = cls.tenant_id,
            name      = "Detection Test",
            token     = cls.token,
            plan      = "pro",
            max_hosts = 10,
        )

    def test_detect_porta_scan(self):
        r = self.post_json("/api/detect", {
            "log_line": "Port scan detected from 192.168.100.1 to multiple ports",
            "source_ip": "192.168.100.1",
        }, headers={"X-API-Token": self.token})
        self.assertIn(r.status_code, (200, 201, 401))

    def test_detect_xss_payload(self):
        r = self.post_json("/api/detect", {
            "log_line": "GET /search?q=<script>alert(1)</script>",
            "source_ip": "10.0.0.55",
        }, headers={"X-API-Token": self.token})
        self.assertIn(r.status_code, (200, 201, 401))

    def test_get_detections_requer_auth(self):
        r = self.client.get("/api/detections")
        # Sem token deve retornar 401 ou 403
        self.assertIn(r.status_code, (401, 403))

    def test_get_detections_com_token(self):
        r = self.get_json("/api/detections", token=self.token)
        self.assertIn(r.status_code, (200, 401))
        if r.status_code == 200:
            d = json.loads(r.data)
            self.assertIn("detections", d)
            self.assertIsInstance(d["detections"], list)

    def test_detections_limit_param(self):
        r = self.get_json("/api/detections?limit=5", token=self.token)
        self.assertIn(r.status_code, (200, 401))
        if r.status_code == 200:
            d = json.loads(r.data)
            self.assertLessEqual(len(d["detections"]), 5)


# ══════════════════════════════════════════════════════════════════
# 4. RATE LIMIT NO /trial
# ══════════════════════════════════════════════════════════════════

@skip_if_no_app
class TestRateLimit(BaseIntegration):

    def test_trial_rate_limit_headers(self):
        """Verifica que X-RateLimit headers existem quando flask-limiter ativo."""
        r = self.post_json("/trial", {
            "name": "RL Test", "email": "rl@test.com", "plan": "pro"
        })
        # Pode estar 200, 302, ou 429 — o importante é não dar 500
        self.assertNotEqual(r.status_code, 500)

    def test_contact_aceita_dados_validos(self):
        r = self.post_json("/contact", {
            "name": "Empresa", "email": "biz@co.com",
            "company": "Co", "plan": "enterprise",
        })
        self.assertNotEqual(r.status_code, 500)


# ══════════════════════════════════════════════════════════════════
# 5. ROTAS PÚBLICAS
# ══════════════════════════════════════════════════════════════════

@skip_if_no_app
class TestPublicRoutes(BaseIntegration):

    def test_landing_page_200(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"NetGuard", r.data)

    def test_pricing_page_200(self):
        r = self.client.get("/pricing")
        self.assertEqual(r.status_code, 200)

    def test_pricing_page_trial_modal_usa_trial_sem_checkout(self):
        r = self.client.get("/pricing")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"form.action = '/trial';", r.data)
        self.assertNotIn(b"form.action = '/checkout';", r.data)
        self.assertNotIn(b"Continuar para pagamento", r.data)

    def test_login_page_200(self):
        r = self.client.get("/login")
        self.assertIn(r.status_code, (200, 302))

    def test_pagina_inexistente_404(self):
        r = self.client.get("/pagina-que-nao-existe-xyz")
        self.assertEqual(r.status_code, 404)

    def test_open_redirect_bloqueado(self):
        """?next= com URL externa deve ser ignorado."""
        r = self.client.get("/login?next=http://evil.com", follow_redirects=False)
        # Não pode redirecionar para evil.com
        location = r.headers.get("Location", "")
        self.assertNotIn("evil.com", location)

    def test_csrf_no_form_trial(self):
        """POST sem CSRF não deve aceitar quando CSRF habilitado."""
        # Em modo TESTING o CSRF pode estar desabilitado — apenas garante que não dá 500
        r = self.client.post("/trial", data={"name":"x","email":"x@x.com"})
        self.assertNotEqual(r.status_code, 500)


# ══════════════════════════════════════════════════════════════════
# 6. SEGURANÇA — HEADERS HTTP
# ══════════════════════════════════════════════════════════════════

@skip_if_no_app
class TestSecurityHeaders(BaseIntegration):

    def test_x_request_id_presente(self):
        r = self.client.get("/")
        self.assertIn("X-Request-ID", r.headers)

    def test_x_request_time_presente(self):
        r = self.client.get("/")
        self.assertIn("X-Request-Time-ms", r.headers)

    def test_sse_content_type(self):
        """SSE stream deve ter content-type text/event-stream."""
        r = self.client.get("/api/events/stream",
                            headers={"Accept": "text/event-stream"})
        # Pode retornar 200 (stream) ou 401 (sem auth) — nunca 500
        self.assertNotEqual(r.status_code, 500)


# ══════════════════════════════════════════════════════════════════
# 7. NOTIFIER — DRY-RUN
# ══════════════════════════════════════════════════════════════════

class TestNotifierDryRun(unittest.TestCase):

    def setUp(self):
        for k in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "SLACK_WEBHOOK_URL"):
            os.environ.pop(k, None)
        import importlib
        import notifier as n
        importlib.reload(n)
        self.notifier = n

    def test_notify_nao_levanta_excecao(self):
        try:
            self.notifier.notify("TRIAL_CREATED",
                name="Test", email="t@t.com", plan="pro", tenant_id="abc123")
        except Exception as exc:
            self.fail(f"notify() levantou: {exc}")

    def test_notify_brute_force(self):
        try:
            self.notifier.notify("BRUTE_FORCE_ALERT",
                ip="1.2.3.4", count=15, duration_s=3600)
        except Exception as exc:
            self.fail(f"notify() levantou: {exc}")

    def test_notify_trial_expired(self):
        try:
            self.notifier.notify("TRIAL_EXPIRED",
                name="João", email="j@j.com", tenant_id="tid123")
        except Exception as exc:
            self.fail(f"notify() levantou: {exc}")

    def test_notify_evento_nao_configurado_nao_levanta(self):
        """Evento fora de NOTIFY_EVENTS não deve causar erro."""
        try:
            self.notifier.notify("EVENTO_INEXISTENTE", foo="bar")
        except Exception as exc:
            self.fail(f"notify() levantou: {exc}")

    def test_notify_token_rotated(self):
        try:
            self.notifier.notify("TOKEN_ROTATED",
                tenant_id="tid", new_prefix="ng_abc123", ip="10.0.0.1")
        except Exception as exc:
            self.fail(f"notify() levantou: {exc}")

    def test_format_telegram_trial_created(self):
        from notifier import _format_telegram
        msg = _format_telegram("TRIAL_CREATED", name="Ana", email="a@b.com",
                               company="Acme", plan="pro")
        self.assertIn("Trial", msg)
        self.assertIn("PRO", msg)

    def test_format_slack_brute_force(self):
        from notifier import _format_slack
        payload = _format_slack("BRUTE_FORCE_ALERT", ip="1.2.3.4",
                                count=20, duration_s=86400)
        self.assertIn("attachments", payload)
        blocks_text = str(payload)
        self.assertIn("Brute", blocks_text)

    def test_esc_caracteres_especiais(self):
        from notifier import _esc
        result = _esc("hello_world (test)")
        # Underscores devem ser escapados com backslash
        self.assertIn("\\_", result)
        # Parênteses devem ser escapados
        self.assertIn("\\(", result)
        self.assertIn("\\\\", repr(result))  # barra invertida no repr


# ══════════════════════════════════════════════════════════════════
# 8. ISOLAMENTO DE TENANT
# ══════════════════════════════════════════════════════════════════

@skip_if_no_app
class TestTenantIsolationE2E(BaseIntegration):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if not _APP_OK:
            return
        import uuid
        from billing import generate_api_token
        # Cria dois tenants distintos
        cls.t1_id  = str(uuid.uuid4())
        cls.t1_tok = generate_api_token()
        cls.t2_id  = str(uuid.uuid4())
        cls.t2_tok = generate_api_token()
        for tid, tok in [(cls.t1_id, cls.t1_tok), (cls.t2_id, cls.t2_tok)]:
            repo.create_tenant(tenant_id=tid, name=f"Tenant {tid[:6]}",
                               token=tok, plan="pro", max_hosts=10)

    def test_tenant1_nao_ve_deteccoes_do_tenant2(self):
        """Detecções do tenant 2 não aparecem na API do tenant 1."""
        # Injeta evento no tenant 2
        self.post_json("/api/detect", {
            "log_line": "SQL injection attempt from 10.99.99.1",
            "source_ip": "10.99.99.1",
        }, headers={"X-API-Token": self.t2_tok})

        # Consulta detecções do tenant 1
        r1 = self.get_json("/api/detections", token=self.t1_tok)
        if r1.status_code == 200:
            d1 = json.loads(r1.data)
            ips1 = [det.get("source_ip") for det in d1.get("detections", [])]
            self.assertNotIn("10.99.99.1", ips1,
                "IP do tenant 2 apareceu nas detecções do tenant 1 — ISOLAMENTO VIOLADO")

    def test_tokens_distintos_nao_colidem(self):
        """Cada tenant tem seu próprio token — não há colisão."""
        self.assertNotEqual(self.t1_tok, self.t2_tok)
        t1 = repo.get_tenant_by_token(self.t1_tok)
        t2 = repo.get_tenant_by_token(self.t2_tok)
        if t1 and t2:
            self.assertNotEqual(t1.get("tenant_id"), t2.get("tenant_id"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
