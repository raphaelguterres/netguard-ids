"""
tests/test_security.py
======================
Cobertura completa do módulo security.py — primitivas de segurança enterprise.

Classes de teste
----------------
  TestTokenHashing         — hash_token / verify_token (HMAC-SHA256)
  TestBruteForceGuard      — lockout escalonado persistido em SQLite
  TestRequireRole          — RBAC decorator
  TestMaskSensitive        — mascaramento de dados sensíveis em logs
  TestSensitiveDataFilter  — filtro de logging
  TestValidateRedirectUrl  — open redirect protection
  TestSafeFilename         — path traversal em downloads
  TestSanitizeCsvCell      — CSV injection prevention
  TestRotateToken          — token rotation
  TestValidateAbsSession   — session timeout absoluto/idle
  TestGetBfGuard           — singleton factory

Total esperado: ~75 asserções
"""
import os
import sys
import time
import logging
import tempfile
import threading
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import security as security_module

# Chave de teste isolada — nunca usar em produção
os.environ.setdefault("TOKEN_SIGNING_SECRET", "test-signing-key-for-unit-tests-only")

from security import (
    hash_token,
    verify_token,
    BruteForceGuard,
    get_bf_guard,
    require_role,
    mask_sensitive,
    SensitiveDataFilter,
    validate_redirect_url,
    safe_filename,
    sanitize_csv_cell,
    sanitize_csv_row,
    rotate_token,
    validate_absolute_session,
    SESSION_MAX_AGE_SECONDS,
    SESSION_IDLE_TIMEOUT,
    role_level,
)


# ══════════════════════════════════════════════════════════════════
# 1. HASH DE TOKENS
# ══════════════════════════════════════════════════════════════════

class TestTokenHashing(unittest.TestCase):

    def test_hash_retorna_string_nao_vazia(self):
        h = hash_token("ng_meutoken123")
        self.assertIsInstance(h, str)
        self.assertTrue(len(h) > 0)

    def test_hash_e_hexdigest_sha256(self):
        h = hash_token("qualquertoken")
        # SHA-256 hexdigest = 64 chars
        self.assertEqual(len(h), 64)
        self.assertRegex(h, r'^[0-9a-f]{64}$')

    def test_hash_deterministico(self):
        t = "ng_determinismo"
        self.assertEqual(hash_token(t), hash_token(t))

    def test_tokens_diferentes_geram_hashes_diferentes(self):
        self.assertNotEqual(hash_token("ng_token_a"), hash_token("ng_token_b"))

    def test_verify_token_correto(self):
        t = "ng_testtoken"
        h = hash_token(t)
        self.assertTrue(verify_token(t, h))

    def test_verify_token_errado(self):
        h = hash_token("ng_original")
        self.assertFalse(verify_token("ng_diferente", h))

    def test_verify_token_vazio_retorna_false(self):
        self.assertFalse(verify_token("", hash_token("ng_x")))
        self.assertFalse(verify_token("ng_x", ""))
        self.assertFalse(verify_token("", ""))

    def test_hash_nao_e_plaintext(self):
        t = "ng_supersecret"
        h = hash_token(t)
        self.assertNotIn(t, h)


# ══════════════════════════════════════════════════════════════════
# 2. BRUTE FORCE GUARD
# ══════════════════════════════════════════════════════════════════

class TestBruteForceGuard(unittest.TestCase):

    def setUp(self):
        # Banco temporário isolado por teste
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.bf = BruteForceGuard(self.tmp.name)

    def tearDown(self):
        try:
            os.unlink(self.tmp.name)
        except OSError:
            pass

    def test_novo_ip_nao_esta_bloqueado(self):
        self.assertFalse(self.bf.is_locked("1.2.3.4"))

    def test_failure_count_zero_inicial(self):
        self.assertEqual(self.bf.failure_count("1.2.3.4"), 0)

    def test_record_failure_incrementa_contador(self):
        self.bf.record_failure("1.2.3.4")
        self.assertEqual(self.bf.failure_count("1.2.3.4"), 1)
        self.bf.record_failure("1.2.3.4")
        self.assertEqual(self.bf.failure_count("1.2.3.4"), 2)

    def test_lockout_apos_3_falhas(self):
        ip = "10.0.0.1"
        for _ in range(3):
            self.bf.record_failure(ip)
        self.assertTrue(self.bf.is_locked(ip))

    def test_lockout_remaining_positivo_quando_bloqueado(self):
        ip = "10.0.0.2"
        for _ in range(3):
            self.bf.record_failure(ip)
        self.assertGreater(self.bf.lockout_remaining(ip), 0)

    def test_lockout_remaining_zero_quando_nao_bloqueado(self):
        self.assertEqual(self.bf.lockout_remaining("1.2.3.99"), 0)

    def test_reset_libera_ip(self):
        ip = "10.0.0.3"
        for _ in range(3):
            self.bf.record_failure(ip)
        self.assertTrue(self.bf.is_locked(ip))
        self.bf.reset(ip)
        self.assertFalse(self.bf.is_locked(ip))
        self.assertEqual(self.bf.failure_count(ip), 0)

    def test_ips_diferentes_sao_isolados(self):
        for _ in range(3):
            self.bf.record_failure("10.0.1.1")
        self.assertFalse(self.bf.is_locked("10.0.1.2"))

    def test_lockout_5_falhas_maior_que_3(self):
        ip = "10.0.0.4"
        for _ in range(3):
            self.bf.record_failure(ip)
        rem_3 = self.bf.lockout_remaining(ip)
        # Reseta e testa com 5 falhas
        self.bf.reset(ip)
        for _ in range(5):
            self.bf.record_failure(ip)
        rem_5 = self.bf.lockout_remaining(ip)
        self.assertGreater(rem_5, rem_3)

    def test_purge_expired_nao_levanta_excecao(self):
        try:
            n = self.bf.purge_expired()
            self.assertIsInstance(n, int)
        except Exception as exc:
            self.fail(f"purge_expired levantou: {exc}")

    def test_thread_safety(self):
        """10 threads registrando falhas para o mesmo IP não devem corromper o estado."""
        ip = "10.0.2.1"
        errors = []

        def worker():
            try:
                self.bf.record_failure(ip)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], f"Erros em thread: {errors}")
        count = self.bf.failure_count(ip)
        self.assertGreaterEqual(count, 1)


# ══════════════════════════════════════════════════════════════════
# 3. RBAC — require_role
# ══════════════════════════════════════════════════════════════════

class TestRequireRole(unittest.TestCase):

    def setUp(self):
        """
        Liga AUTH_ENABLED durante os testes de RBAC.

        Por que: require_role() em security.py tem early-return quando
        auth.AUTH_ENABLED é False (modo dev local sem autenticacao). Sem
        esse patch os testes nunca atingem o bloco do gate 403 e toda
        chamada passa direto — falsos positivos em cima de decoradores
        realmente quebrados em prod.
        """
        try:
            import auth
            self._auth_enabled_orig = getattr(auth, "AUTH_ENABLED", False)
            auth.AUTH_ENABLED = True
        except Exception:
            self._auth_enabled_orig = None

    def tearDown(self):
        try:
            import auth
            if self._auth_enabled_orig is not None:
                auth.AUTH_ENABLED = self._auth_enabled_orig
        except Exception:
            pass

    def _call_with_role(self, fn, role):
        """Chama a função decorada dentro de um contexto Flask mínimo."""
        try:
            from flask import Flask, g as flask_g
        except ImportError:
            self.skipTest("Flask não disponível")
        app = Flask(__name__)
        with app.app_context():
            with app.test_request_context("/"):
                flask_g.tenant_role = role
                return fn()

    def test_admin_pode_tudo(self):
        @require_role("analyst")
        def endpoint():
            return "ok"
        result = self._call_with_role(endpoint, "admin")
        self.assertEqual(result, "ok")

    def test_role_correta_passa(self):
        @require_role("analyst")
        def endpoint():
            return "passou"
        result = self._call_with_role(endpoint, "analyst")
        self.assertEqual(result, "passou")

    def test_role_insuficiente_retorna_403(self):
        try:
            from flask import Flask, g as flask_g
        except ImportError:
            self.skipTest("Flask não disponível")
        @require_role("admin")
        def endpoint():
            return "secreto"
        app = Flask(__name__)
        with app.app_context():
            with app.test_request_context("/"):
                flask_g.tenant_role = "viewer"
                result = endpoint()
                if isinstance(result, tuple):
                    _, status = result
                    self.assertEqual(status, 403)
                else:
                    self.fail("Deveria ter retornado 403")

    def test_viewer_bloqueado_em_analyst_endpoint(self):
        try:
            from flask import Flask, g as flask_g
        except ImportError:
            self.skipTest("Flask não disponível")
        @require_role("analyst", "admin")
        def endpoint():
            return "ok"
        app = Flask(__name__)
        with app.app_context():
            with app.test_request_context("/"):
                flask_g.tenant_role = "viewer"
                result = endpoint()
                if isinstance(result, tuple):
                    _, status = result
                    self.assertEqual(status, 403)
                else:
                    self.fail("Deveria ter retornado 403")

    def test_roles_niveis(self):
        self.assertGreater(role_level("admin"), role_level("analyst"))
        self.assertGreater(role_level("analyst"), role_level("viewer"))
        self.assertEqual(role_level("invalid_role"), 0)


# ══════════════════════════════════════════════════════════════════
# 4. MASCARAMENTO DE DADOS SENSÍVEIS
# ══════════════════════════════════════════════════════════════════

class TestMaskSensitive(unittest.TestCase):

    def test_token_ng_e_mascarado(self):
        texto = "token=ng_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890123"
        result = mask_sensitive(texto)
        self.assertNotIn("ng_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890123", result)
        self.assertIn("***", result)

    def test_hex_token_longo_e_mascarado(self):
        hex_token = "a" * 44  # 44 chars hex
        result = mask_sensitive(f"auth={hex_token}")
        self.assertNotIn(hex_token, result)
        self.assertIn("***", result)

    def test_email_e_mascarado(self):
        result = mask_sensitive("user joao.silva@empresa.com.br logado")
        self.assertNotIn("joao.silva@empresa.com.br", result)
        self.assertIn("jo", result)   # primeiros 2 chars mantidos

    def test_senha_em_json_e_mascarada(self):
        payload = '{"username": "admin", "password": "SuperSenha123"}'
        result = mask_sensitive(payload)
        self.assertNotIn("SuperSenha123", result)
        self.assertIn('"***"', result)

    def test_stripe_key_e_mascarado(self):
        # Constrói o padrão em partes para não acionar secret scanners
        # (nunca é uma chave real — apenas valida o mascaramento)
        prefix = "sk_" + "live" + "_"
        body   = "A" * 24  # 24 chars alfanuméricos fictícios
        sk = prefix + body
        result = mask_sensitive(f"stripe={sk}")
        self.assertNotIn(body, result)
        self.assertIn("***", result)

    def test_smtp_pass_e_mascarado(self):
        result = mask_sensitive("SMTP_PASS=minha_senha_secreta")
        self.assertNotIn("minha_senha_secreta", result)
        self.assertIn("***", result)

    def test_texto_sem_dados_sensiveis_passa_intacto(self):
        texto = "Detecção de porta scan no servidor de produção"
        self.assertEqual(mask_sensitive(texto), texto)

    def test_string_vazia_retorna_vazia(self):
        self.assertEqual(mask_sensitive(""), "")

    def test_none_retorna_none(self):
        # None deve ser tolerado sem exceção
        result = mask_sensitive(None)
        self.assertIsNone(result)


# ══════════════════════════════════════════════════════════════════
# 5. SENSITIVE DATA FILTER
# ══════════════════════════════════════════════════════════════════

class TestSensitiveDataFilter(unittest.TestCase):

    def setUp(self):
        self.logger = logging.getLogger("test.sensitive_filter")
        self.logger.setLevel(logging.DEBUG)
        self.handler = logging.handlers_captured = []
        # Handler captura mensagens formatadas
        self._records = []
        class CapturingHandler(logging.Handler):
            def __init__(self_, records):
                super().__init__()
                self_._records = records
            def emit(self_, record):
                self_._records.append(record)
        self._h = CapturingHandler(self._records)
        self._h.addFilter(SensitiveDataFilter())
        self.logger.addHandler(self._h)

    def tearDown(self):
        self.logger.removeHandler(self._h)

    def test_token_mascarado_no_log(self):
        token = "ng_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890123"
        self.logger.info("token=%s", token)
        record = self._records[-1]
        self.assertNotIn(token, record.getMessage())

    def test_texto_normal_passa(self):
        self.logger.info("Detecção de porta scan: 3 eventos")
        record = self._records[-1]
        self.assertIn("porta scan", record.getMessage())

    def test_filtro_retorna_true(self):
        """Filter.filter() deve sempre retornar True para não suprimir mensagens."""
        import logging
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="teste com ng_tokenABCDEFGHIJKLMNOPQRSTUVWXYZ1234", args=(),
            exc_info=None,
        )
        f = SensitiveDataFilter()
        result = f.filter(record)
        self.assertTrue(result)


# ══════════════════════════════════════════════════════════════════
# 6. VALIDATE REDIRECT URL
# ══════════════════════════════════════════════════════════════════

class TestValidateRedirectUrl(unittest.TestCase):

    def test_path_relativo_valido(self):
        self.assertEqual(validate_redirect_url("/dashboard"), "/dashboard")

    def test_path_raiz(self):
        self.assertEqual(validate_redirect_url("/"), "/")

    def test_nenhum_url_retorna_barra(self):
        self.assertEqual(validate_redirect_url(""), "/")
        self.assertEqual(validate_redirect_url(None), "/")

    def test_url_absoluta_http_bloqueada(self):
        self.assertEqual(validate_redirect_url("http://evil.com"), "/")

    def test_url_absoluta_https_bloqueada(self):
        self.assertEqual(validate_redirect_url("https://evil.com"), "/")

    def test_protocol_relative_bloqueada(self):
        self.assertEqual(validate_redirect_url("//evil.com/xss"), "/")

    def test_javascript_scheme_bloqueado(self):
        self.assertEqual(validate_redirect_url("javascript:alert(1)"), "/")

    def test_data_uri_bloqueado(self):
        self.assertEqual(validate_redirect_url("data:text/html,<h1>xss</h1>"), "/")

    def test_path_traversal_bloqueado(self):
        self.assertEqual(validate_redirect_url("/../../etc/passwd"), "/")
        self.assertEqual(validate_redirect_url("/../admin"), "/")

    def test_path_sem_barra_inicial_bloqueado(self):
        self.assertEqual(validate_redirect_url("admin"), "/")
        self.assertEqual(validate_redirect_url("evil.com"), "/")

    def test_path_com_query_string_valido(self):
        result = validate_redirect_url("/search?q=portscan")
        self.assertEqual(result, "/search?q=portscan")

    def test_path_com_subdir_valido(self):
        result = validate_redirect_url("/api/detections?limit=50")
        self.assertEqual(result, "/api/detections?limit=50")


# ══════════════════════════════════════════════════════════════════
# 7. SAFE FILENAME
# ══════════════════════════════════════════════════════════════════

class TestSafeFilename(unittest.TestCase):

    def test_nome_simples(self):
        self.assertEqual(safe_filename("export.csv"), "export.csv")

    def test_remove_path_unix(self):
        self.assertEqual(safe_filename("/etc/passwd"), "passwd")

    def test_remove_path_windows(self):
        self.assertEqual(safe_filename("C:\\Windows\\system32\\cmd.exe"), "cmd.exe")

    def test_traversal_duplo_ponto(self):
        result = safe_filename("../../../etc/passwd")
        self.assertNotIn("..", result)
        self.assertNotIn("/", result)

    def test_caracteres_especiais_removidos(self):
        result = safe_filename("file;rm -rf *.db")
        self.assertNotIn(";", result)
        self.assertNotIn(" ", result)

    def test_extensao_preservada(self):
        result = safe_filename("relatorio_2024.pdf")
        self.assertIn(".pdf", result)

    def test_vazio_retorna_default(self):
        self.assertEqual(safe_filename(""), "download")
        self.assertEqual(safe_filename(None), "download")

    def test_comprimento_maximo(self):
        longo = "a" * 100 + ".csv"
        result = safe_filename(longo)
        self.assertLessEqual(len(result), 64)


# ══════════════════════════════════════════════════════════════════
# 8. SANITIZE CSV CELL
# ══════════════════════════════════════════════════════════════════

class TestSanitizeCsvCell(unittest.TestCase):

    def test_formula_igual_prefixada(self):
        self.assertEqual(sanitize_csv_cell("=SUM(A1)"), "'=SUM(A1)")

    def test_formula_mais_prefixada(self):
        self.assertEqual(sanitize_csv_cell("+malicious"), "'+malicious")

    def test_formula_menos_prefixada(self):
        self.assertEqual(sanitize_csv_cell("-malicious"), "'-malicious")

    def test_formula_arroba_prefixada(self):
        self.assertEqual(sanitize_csv_cell("@SUM"), "'@SUM")

    def test_tab_prefixado(self):
        self.assertEqual(sanitize_csv_cell("\tInjection"), "'\tInjection")

    def test_texto_normal_nao_alterado(self):
        self.assertEqual(sanitize_csv_cell("192.168.1.1"), "192.168.1.1")
        self.assertEqual(sanitize_csv_cell("Port scan detected"), "Port scan detected")

    def test_numero_nao_alterado(self):
        self.assertEqual(sanitize_csv_cell("42"), "42")

    def test_vazio_nao_alterado(self):
        self.assertEqual(sanitize_csv_cell(""), "")

    def test_valor_nao_string_converte(self):
        result = sanitize_csv_cell(42)
        self.assertIsInstance(result, str)

    def test_sanitize_csv_row(self):
        row = {"ip": "1.2.3.4", "cmd": "=SYSTEM()", "count": 5}
        result = sanitize_csv_row(row)
        self.assertEqual(result["ip"], "1.2.3.4")
        self.assertEqual(result["cmd"], "'=SYSTEM()")
        self.assertEqual(result["count"], 5)  # inteiro não alterado


# ══════════════════════════════════════════════════════════════════
# 9. ROTATE TOKEN
# ══════════════════════════════════════════════════════════════════

class TestRotateToken(unittest.TestCase):

    def _gen(self):
        import secrets, base64
        return "ng_" + base64.urlsafe_b64encode(secrets.token_bytes(24)).rstrip(b"=").decode()

    def test_retorna_novo_token_e_hash(self):
        new_t, new_h = rotate_token("ng_oldtoken", self._gen)
        self.assertTrue(new_t.startswith("ng_"))
        self.assertEqual(len(new_h), 64)

    def test_novo_token_diferente_do_antigo(self):
        old = "ng_oldtoken_abc123"
        new_t, _ = rotate_token(old, self._gen)
        self.assertNotEqual(new_t, old)

    def test_hash_verifica_novo_token(self):
        new_t, new_h = rotate_token("ng_old", self._gen)
        self.assertTrue(verify_token(new_t, new_h))

    def test_hash_nao_verifica_token_antigo(self):
        old = "ng_oldtoken_xyz"
        new_t, new_h = rotate_token(old, self._gen)
        self.assertFalse(verify_token(old, new_h))


# ══════════════════════════════════════════════════════════════════
# 10. SESSION TIMEOUT ABSOLUTO E IDLE
# ══════════════════════════════════════════════════════════════════

class TestValidateAbsSession(unittest.TestCase):

    def test_sessao_recente_valida(self):
        iat = time.time()
        lat = time.time()
        valid, reason = validate_absolute_session(iat, lat)
        self.assertTrue(valid)
        self.assertEqual(reason, "ok")

    def test_sessao_expirada_absoluta(self):
        iat = time.time() - SESSION_MAX_AGE_SECONDS - 10
        valid, reason = validate_absolute_session(iat)
        self.assertFalse(valid)
        self.assertIn("session_expired_absolute", reason)

    def test_sessao_expirada_por_inatividade(self):
        iat = time.time()
        lat = time.time() - SESSION_IDLE_TIMEOUT - 10
        valid, reason = validate_absolute_session(iat, lat)
        self.assertFalse(valid)
        self.assertIn("session_expired_idle", reason)

    def test_sem_iat_retorna_invalida(self):
        valid, reason = validate_absolute_session(None)
        self.assertFalse(valid)
        self.assertEqual(reason, "session_missing_iat")

    def test_sem_last_activity_apenas_checa_absoluto(self):
        iat = time.time()
        valid, reason = validate_absolute_session(iat, None)
        self.assertTrue(valid)

    def test_constantes_razoaveis(self):
        self.assertGreaterEqual(SESSION_MAX_AGE_SECONDS, 3600)    # pelo menos 1h
        self.assertGreaterEqual(SESSION_IDLE_TIMEOUT, 300)        # pelo menos 5min
        self.assertLess(SESSION_IDLE_TIMEOUT, SESSION_MAX_AGE_SECONDS)


# ══════════════════════════════════════════════════════════════════
# 11. GET_BF_GUARD SINGLETON
# ══════════════════════════════════════════════════════════════════

class TestGetBfGuard(unittest.TestCase):

    def _reset_cache(self):
        for guard in list(getattr(security_module, "_bf_guards", {}).values()):
            try:
                guard.close()
            except Exception:
                pass
        getattr(security_module, "_bf_guards", {}).clear()

    def setUp(self):
        self._reset_cache()

    def tearDown(self):
        self._reset_cache()

    def test_retorna_instancia_bruteforce(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        guard = None
        try:
            guard = get_bf_guard(tmp.name)
            self.assertIsInstance(guard, BruteForceGuard)
        finally:
            if guard is not None:
                guard.close()
            os.unlink(tmp.name)

    def test_singleton_mesma_instancia(self):
        """Duas chamadas com mesmo path retornam o mesmo objeto."""
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        g1 = g2 = None
        try:
            g1 = get_bf_guard(tmp.name)
            g2 = get_bf_guard(tmp.name)
            self.assertIs(g1, g2)
        finally:
            if g1 is not None:
                g1.close()
            if g2 is not None and g2 is not g1:
                g2.close()
            os.unlink(tmp.name)

    def test_paths_diferentes_retornam_instancias_diferentes(self):
        tmp1 = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp2 = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp1.close()
        tmp2.close()
        g1 = g2 = None
        try:
            g1 = get_bf_guard(tmp1.name)
            g2 = get_bf_guard(tmp2.name)
            self.assertIsNot(g1, g2)
        finally:
            if g1 is not None:
                g1.close()
            if g2 is not None:
                g2.close()
            os.unlink(tmp1.name)
            os.unlink(tmp2.name)


# ══════════════════════════════════════════════════════════════════
# 12. SSRF GUARD — _validate_webhook_url
# ══════════════════════════════════════════════════════════════════

class TestSSRFGuard(unittest.TestCase):
    """
    Verifica que _validate_webhook_url levanta ValueError para destinos
    privados / reservados e aceita URLs públicas legítimas.
    """

    def _module(self):
        import importlib, sys
        sys.path.insert(0, os.path.join(ROOT, "engine"))
        return importlib.import_module("webhook_engine")

    def _import(self):
        return self._module()._validate_webhook_url

    def test_url_publica_https_valida(self):
        validate = self._import()
        # Deve não levantar — hooks.slack.com é público
        try:
            validate("https://hooks.slack.com/services/T000/B000/XXXX")
        except ValueError as e:
            # Aceita falha de DNS em CI sem acesso à rede
            if "SSRF" in str(e):
                self.fail(f"URL pública bloqueada por SSRF: {e}")

    def test_localhost_bloqueado(self):
        validate = self._import()
        with self.assertRaises(ValueError, msg="localhost deve ser bloqueado"):
            validate("http://localhost:5000/internal")

    def test_loopback_127_bloqueado(self):
        validate = self._import()
        with self.assertRaises(ValueError):
            validate("http://127.0.0.1:8080/steal")

    def test_rfc1918_10_x_bloqueado(self):
        validate = self._import()
        with self.assertRaises(ValueError):
            validate("http://10.0.0.1/internal")

    def test_rfc1918_192_168_bloqueado(self):
        validate = self._import()
        with self.assertRaises(ValueError):
            validate("http://192.168.1.1/admin")

    def test_rfc1918_172_16_bloqueado(self):
        validate = self._import()
        with self.assertRaises(ValueError):
            validate("http://172.16.0.1/secret")

    def test_link_local_169_254_bloqueado(self):
        """169.254.169.254 é o endpoint de metadados de cloud (AWS/GCP/Azure)."""
        validate = self._import()
        with self.assertRaises(ValueError):
            validate("http://169.254.169.254/latest/meta-data/iam/security-credentials/")

    def test_scheme_invalido_bloqueado(self):
        validate = self._import()
        with self.assertRaises(ValueError):
            validate("file:///etc/passwd")

    def test_ftp_scheme_bloqueado(self):
        validate = self._import()
        with self.assertRaises(ValueError):
            validate("ftp://example.com/data")

    def test_url_vazia_bloqueada(self):
        validate = self._import()
        with self.assertRaises(ValueError):
            validate("")

    def test_host_local_bloqueado(self):
        validate = self._import()
        with self.assertRaises(ValueError):
            validate("http://myserver.local/webhook")

    def test_sem_hostname_bloqueado(self):
        validate = self._import()
        with self.assertRaises(ValueError):
            validate("https:///no-host")

    def test_falha_dns_bloqueia_destino(self):
        mod = self._module()
        with mock.patch.object(mod.socket, "getaddrinfo", side_effect=OSError("dns down")):
            with self.assertRaises(ValueError):
                mod._validate_webhook_url("https://example.com/webhook")


# ══════════════════════════════════════════════════════════════════
# 13. SECRET MASKING — WebhookEngine._row_safe
# ══════════════════════════════════════════════════════════════════
class TestWebhookDispatchSecurity(unittest.TestCase):

    def _module(self):
        import importlib, sys
        sys.path.insert(0, os.path.join(ROOT, "engine"))
        return importlib.import_module("webhook_engine")

    def test_send_revalida_url_antes_do_dispatch(self):
        mod = self._module()
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()

        class _FakeResponse:
            status = 204

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        try:
            engine = mod.WebhookEngine(tmp.name)
            wh = {
                "id": 1,
                "url": "https://example.com/webhook",
                "type": "generic",
                "secret": "",
            }
            event = {
                "severity": "high",
                "threat": "Teste",
                "event_type": "ioc",
                "source_ip": "1.1.1.1",
                "hostname": "host-a",
                "timestamp": "2026-04-11T00:00:00Z",
                "details": {},
            }
            with mock.patch.object(mod, "_validate_webhook_url") as validate:
                with mock.patch.object(mod.urllib.request, "urlopen", return_value=_FakeResponse()):
                    ok, code, err = engine._send(wh, event)
            validate.assert_called_once_with("https://example.com/webhook")
            self.assertTrue(ok)
            self.assertEqual(code, 204)
            self.assertIsNone(err)
        finally:
            os.unlink(tmp.name)


class TestWebhookSecretMasking(unittest.TestCase):
    """
    Verifica que _row_safe mascara o campo secret e remove a URL completa.
    """

    def _engine_class(self):
        import importlib, sys
        sys.path.insert(0, os.path.join(ROOT, "engine"))
        mod = importlib.import_module("webhook_engine")
        return mod.WebhookEngine

    def test_secret_mascarado_em_row_safe(self):
        WH = self._engine_class()
        fake_row = {
            "id": 1, "tenant_id": "t1", "name": "Slack",
            "url": "https://hooks.slack.com/services/T000/B000/VERYSECRETTOKEN",
            "type": "slack", "min_severity": "high",
            "event_types": "[]", "enabled": 1,
            "secret": "mysupersecret",
            "created_at": "2024-01-01T00:00:00Z",
            "last_hit": None, "hit_count": 0, "fail_count": 0,
        }
        result = WH._row_safe(fake_row)
        # Secret deve estar mascarado
        self.assertNotEqual(result.get("secret"), "mysupersecret")
        self.assertIn("****", result.get("secret", ""))

    def test_url_completa_removida_de_row_safe(self):
        WH = self._engine_class()
        full_url = "https://hooks.slack.com/services/T000/B000/VERYSECRETTOKEN"
        fake_row = {
            "id": 1, "tenant_id": "t1", "name": "Slack",
            "url": full_url, "type": "slack", "min_severity": "high",
            "event_types": "[]", "enabled": 1, "secret": "s3cr3t",
            "created_at": "2024-01-01T00:00:00Z",
            "last_hit": None, "hit_count": 0, "fail_count": 0,
        }
        result = WH._row_safe(fake_row)
        # URL completa não deve estar no resultado
        self.assertNotIn("url", result)
        # url_display deve estar presente e não conter o path secreto
        self.assertIn("url_display", result)
        self.assertNotIn("/services/T000/B000/VERYSECRETTOKEN", result["url_display"])

    def test_secret_vazio_permanece_vazio(self):
        WH = self._engine_class()
        fake_row = {
            "id": 1, "tenant_id": "t1", "name": "Teams",
            "url": "https://outlook.office.com/webhook/abc", "type": "teams",
            "min_severity": "high", "event_types": "[]", "enabled": 1,
            "secret": "", "created_at": "2024-01-01T00:00:00Z",
            "last_hit": None, "hit_count": 0, "fail_count": 0,
        }
        result = WH._row_safe(fake_row)
        self.assertEqual(result.get("secret"), "")

    def test_row_real_preserva_secret(self):
        """_row() (uso interno) NÃO deve mascarar o secret."""
        WH = self._engine_class()
        fake_row = {
            "id": 1, "tenant_id": "t1", "name": "Generic",
            "url": "https://example.com/hook", "type": "generic",
            "min_severity": "high", "event_types": "[]", "enabled": 1,
            "secret": "realtoken123", "created_at": "2024-01-01T00:00:00Z",
            "last_hit": None, "hit_count": 0, "fail_count": 0,
        }
        result = WH._row(fake_row)
        self.assertEqual(result.get("secret"), "realtoken123")
        self.assertIn("url", result)


# ══════════════════════════════════════════════════════════════════
# 14. TOKEN EM QUERY STRING — deve ser rejeitado em _extract_token
# ══════════════════════════════════════════════════════════════════

class TestTokenQueryStringRemoval(unittest.TestCase):
    """
    Garante que _extract_token() NÃO lê token de request.args (query param).
    Token válido só pode vir de Header (Bearer/X-API-Token) ou Cookie.
    """

    def _import_extract(self):
        import importlib, sys
        sys.path.insert(0, ROOT)
        mod = importlib.import_module("auth")
        return mod._extract_token

    def test_token_no_bearer_header_e_lido(self):
        try:
            from flask import Flask
        except ImportError:
            self.skipTest("Flask não disponível")
        extract = self._import_extract()
        app = Flask(__name__)
        with app.test_request_context("/", headers={"Authorization": "Bearer mytoken123"}):
            self.assertEqual(extract(), "mytoken123")

    def test_token_no_x_api_token_header_e_lido(self):
        try:
            from flask import Flask
        except ImportError:
            self.skipTest("Flask não disponível")
        extract = self._import_extract()
        app = Flask(__name__)
        with app.test_request_context("/", headers={"X-API-Token": "apitoken456"}):
            self.assertEqual(extract(), "apitoken456")

    def test_token_no_cookie_e_lido(self):
        try:
            from flask import Flask
        except ImportError:
            self.skipTest("Flask não disponível")
        extract = self._import_extract()
        app = Flask(__name__)
        with app.test_request_context("/", environ_base={"HTTP_COOKIE": "netguard_token=cookietoken789"}):
            self.assertEqual(extract(), "cookietoken789")

    def test_token_em_query_string_e_IGNORADO(self):
        """Segurança crítica: token em query param vaza em logs de servidor."""
        try:
            from flask import Flask
        except ImportError:
            self.skipTest("Flask não disponível")
        extract = self._import_extract()
        app = Flask(__name__)
        # Apenas query param — nenhum header nem cookie
        with app.test_request_context("/?token=secretleaked"):
            result = extract()
            # Deve retornar string vazia (não leu o query param)
            self.assertNotEqual(result, "secretleaked",
                                "_extract_token NÃO deve ler token de query string")

    def test_sem_token_retorna_vazio(self):
        try:
            from flask import Flask
        except ImportError:
            self.skipTest("Flask não disponível")
        extract = self._import_extract()
        app = Flask(__name__)
        with app.test_request_context("/"):
            self.assertEqual(extract(), "")


# ══════════════════════════════════════════════════════════════════
# 15. RBAC POR PERFIL — viewer / analyst / admin em endpoints
# ══════════════════════════════════════════════════════════════════

class TestRBACProfiles(unittest.TestCase):
    """
    Testa os perfis viewer/analyst/admin nos decoradores @require_role
    usando contextos Flask leves (sem app completo).
    """

    def setUp(self):
        """
        Liga AUTH_ENABLED durante os testes de RBAC.

        Mesmo motivo de TestRequireRole.setUp: sem isso, require_role()
        faz early-return em modo dev e o 403 nunca dispara.
        """
        try:
            import auth
            self._auth_enabled_orig = getattr(auth, "AUTH_ENABLED", False)
            auth.AUTH_ENABLED = True
        except Exception:
            self._auth_enabled_orig = None

    def tearDown(self):
        try:
            import auth
            if self._auth_enabled_orig is not None:
                auth.AUTH_ENABLED = self._auth_enabled_orig
        except Exception:
            pass

    def _make_app(self):
        try:
            from flask import Flask
            return Flask(__name__)
        except ImportError:
            self.skipTest("Flask não disponível")

    def _call(self, fn, role):
        from flask import g as flask_g
        app = self._make_app()
        with app.app_context():
            with app.test_request_context("/"):
                flask_g.tenant_role = role
                return fn()

    # ── Endpoint que exige admin ─────────────────────────────────

    def _admin_endpoint(self):
        @require_role("admin")
        def fn():
            return ("ok", 200)
        return fn

    def test_admin_no_endpoint_admin(self):
        result = self._call(self._admin_endpoint(), "admin")
        self.assertEqual(result, ("ok", 200))

    def test_analyst_bloqueado_em_endpoint_admin(self):
        result = self._call(self._admin_endpoint(), "analyst")
        self.assertIsInstance(result, tuple)
        self.assertEqual(result[1], 403)

    def test_viewer_bloqueado_em_endpoint_admin(self):
        result = self._call(self._admin_endpoint(), "viewer")
        self.assertIsInstance(result, tuple)
        self.assertEqual(result[1], 403)

    # ── Endpoint que exige analyst ou admin ─────────────────────

    def _analyst_endpoint(self):
        @require_role("analyst", "admin")
        def fn():
            return ("ok", 200)
        return fn

    def test_admin_no_endpoint_analyst(self):
        result = self._call(self._analyst_endpoint(), "admin")
        self.assertEqual(result, ("ok", 200))

    def test_analyst_no_endpoint_analyst(self):
        result = self._call(self._analyst_endpoint(), "analyst")
        self.assertEqual(result, ("ok", 200))

    def test_viewer_bloqueado_em_endpoint_analyst(self):
        result = self._call(self._analyst_endpoint(), "viewer")
        self.assertIsInstance(result, tuple)
        self.assertEqual(result[1], 403)

    # ── CSRF double-submit cookie ────────────────────────────────

    def test_csrf_protect_bloqueia_sem_header(self):
        """POST sem X-CSRFToken header deve retornar 403 quando CSRF ativado."""
        try:
            from flask import Flask
            from auth import csrf_protect, _CSRF_ENABLED
        except ImportError:
            self.skipTest("Flask/auth não disponível")
        if not _CSRF_ENABLED:
            self.skipTest("CSRF desativado neste ambiente")

        @csrf_protect
        def mutate():
            return ("mutated", 200)

        app = Flask(__name__)
        with app.test_request_context(
            "/api/test",
            method="POST",
            environ_base={"HTTP_COOKIE": "csrf_token=abc123"},
            # Intencionalmente sem X-CSRFToken header
        ):
            result = mutate()
            self.assertIsInstance(result, tuple)
            self.assertEqual(result[1], 403)

    def test_csrf_protect_passa_com_header_correto(self):
        """POST com X-CSRFToken matching o cookie deve passar."""
        try:
            from flask import Flask
            from auth import csrf_protect, _CSRF_ENABLED
        except ImportError:
            self.skipTest("Flask/auth não disponível")
        if not _CSRF_ENABLED:
            self.skipTest("CSRF desativado neste ambiente")

        @csrf_protect
        def mutate():
            return ("mutated", 200)

        csrf_val = "securecsrftoken_xyz"
        app = Flask(__name__)
        with app.test_request_context(
            "/api/test",
            method="POST",
            headers={"X-CSRFToken": csrf_val},
            environ_base={"HTTP_COOKIE": f"csrf_token={csrf_val}"},
        ):
            result = mutate()
            self.assertEqual(result, ("mutated", 200))

    def test_csrf_protect_ignora_get(self):
        """GET requests não precisam de CSRF token."""
        try:
            from flask import Flask
            from auth import csrf_protect
        except ImportError:
            self.skipTest("Flask/auth não disponível")

        @csrf_protect
        def read_only():
            return ("ok", 200)

        app = Flask(__name__)
        with app.test_request_context("/api/test", method="GET"):
            result = read_only()
            self.assertEqual(result, ("ok", 200))


if __name__ == "__main__":
    unittest.main(verbosity=2)
