"""
NetGuard — Autenticação e HTTPS
Token-based auth + certificado self-signed para HTTPS local.

Uso:
  - Token: gerado automaticamente no primeiro run, salvo em .netguard_token
  - HTTPS: certificado self-signed gerado automaticamente em netguard.pem

Acesso após ativar:
  https://127.0.0.1:5443  (HTTPS)
  http://127.0.0.1:5000   (HTTP — redireciona para HTTPS se ativado)
"""

import os
import secrets
import hashlib  # noqa: F401
import logging
import pathlib
from functools import wraps
from datetime import datetime, timezone  # noqa: F401
from flask import request, jsonify, redirect

logger = logging.getLogger("netguard.auth")

# ── Configuração ──────────────────────────────────────────────────
TOKEN_FILE    = pathlib.Path(__file__).parent / ".netguard_token"
CERT_FILE     = pathlib.Path(__file__).parent / "netguard.pem"
KEY_FILE      = pathlib.Path(__file__).parent / "netguard.key"
AUTH_ENABLED  = os.environ.get("IDS_AUTH", "false").lower() == "true"
HTTPS_ENABLED = os.environ.get("IDS_HTTPS", "false").lower() == "true"
HTTPS_PORT    = int(os.environ.get("IDS_HTTPS_PORT", 5443))


# ── Token management ──────────────────────────────────────────────

def get_or_create_token() -> str:
    """Retorna token existente ou gera um novo."""
    if TOKEN_FILE.exists():
        token = TOKEN_FILE.read_text().strip()
        if len(token) >= 32:
            return token

    token = secrets.token_urlsafe(32)
    TOKEN_FILE.write_text(token)
    TOKEN_FILE.chmod(0o600)  # Somente o dono pode ler
    logger.info("Token gerado e salvo em %s", TOKEN_FILE)
    return token


def verify_token(token: str) -> bool:
    """Verifica se é o token de admin (arquivo .netguard_token)."""
    expected = get_or_create_token()
    return secrets.compare_digest(token.encode(), expected.encode())


def verify_any_token(token: str, repo=None) -> dict:
    """
    Verifica token de admin OU token de tenant SaaS (ng_xxx).

    Retorna dict com:
      {"valid": True,  "type": "admin"|"tenant", "tenant": {...}}
      {"valid": False, "type": None}
    """
    if not token:
        return {"valid": False, "type": None}

    # 1. Token de admin
    if verify_token(token):
        return {"valid": True, "type": "admin", "tenant": None}

    # 2. Token de tenant (ng_xxx) — requer repo
    if repo is not None and token.startswith("ng_"):
        try:
            tenant = repo.get_tenant_by_token(token)
            if tenant:
                return {"valid": True, "type": "tenant", "tenant": dict(tenant)}
        except Exception as _e:
            logger.debug("verify_any_token tenant lookup error: %s", _e)

    return {"valid": False, "type": None}


# ── Helpers internos ──────────────────────────────────────────────

def _extract_token() -> str:
    """Extrai token de header Bearer, query param ou cookie."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    t = request.args.get("token", "").strip()
    if t:
        return t
    return request.cookies.get("netguard_token", "").strip()


def _is_browser_request() -> bool:
    """Retorna True se a requisição provavelmente veio de um browser (não API)."""
    accept = request.headers.get("Accept", "")
    return "text/html" in accept


# ── Proteção de dashboard (sempre ativa, independente de IDS_AUTH) ─

# Pode desativar com IDS_DASHBOARD_AUTH=false (ex.: desenvolvimento local)
DASHBOARD_AUTH = os.environ.get("IDS_DASHBOARD_AUTH", "true").lower() != "false"

def require_session(f):
    """
    Decorador para rotas HTML (dashboard).
    Sempre redireciona para /login se não houver cookie de sessão válido.

    Diferente de @auth (que respeita IDS_AUTH), este é sempre ativo.
    Desative com: IDS_DASHBOARD_AUTH=false
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not DASHBOARD_AUTH:
            return f(*args, **kwargs)

        token = request.cookies.get("netguard_token", "").strip()
        if not token:
            next_url = request.path
            if request.query_string:
                next_url += "?" + request.query_string.decode()
            logger.info("Sessão ausente → /login | ip=%s | path=%s",
                        request.remote_addr, request.path)
            return redirect(f"/login?next={next_url}")

        # Valida o cookie (admin token ou tenant token)
        # repo é injetado como parâmetro opcional via g ou importado sob demanda
        try:
            from flask import g
            repo = getattr(g, "_repo", None)
        except Exception:
            repo = None

        # Tenta importar repo do app se não estiver em g
        if repo is None:
            try:
                import sys
                app_module = sys.modules.get("__main__") or sys.modules.get("app")
                if app_module:
                    repo = getattr(app_module, "repo", None)
            except Exception:
                pass

        result = verify_any_token(token, repo)
        if not result["valid"]:
            logger.warning("Cookie inválido → /login | ip=%s", request.remote_addr)
            resp = redirect(f"/login?next={request.path}&expired=1")
            resp.delete_cookie("netguard_token")
            return resp

        return f(*args, **kwargs)
    return decorated


# ── Decorador de autenticação ─────────────────────────────────────

_valid_token = None  # cache em memória

def auth(f):
    """
    Decorador que protege uma rota Flask com token.

    Aceita token em:
      - Header:      Authorization: Bearer <token>
      - Query param: ?token=<token>
      - Cookie:      netguard_token=<token>

    Comportamento por tipo de request:
      - Browser (Accept: text/html) → redireciona para /login?next=<path>
      - API (Accept: application/json ou outros) → retorna 401 JSON

    Se AUTH_ENABLED=false, passa direto (default).
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not AUTH_ENABLED:
            return f(*args, **kwargs)

        global _valid_token
        if _valid_token is None:
            _valid_token = get_or_create_token()

        token = _extract_token()

        if not token or not secrets.compare_digest(
            token.encode(), _valid_token.encode()
        ):
            logger.warning("Auth falhou | ip=%s | path=%s",
                           request.remote_addr, request.path)

            # Browser → redireciona para login
            if _is_browser_request():
                next_url = request.path
                if request.query_string:
                    next_url += "?" + request.query_string.decode()
                return redirect(f"/login?next={next_url}")

            # API → retorna 401 JSON
            return jsonify({
                "error": "Unauthorized",
                "message": "Token inválido ou ausente. "
                           "Consulte .netguard_token para o token de acesso.",
            }), 401

        return f(*args, **kwargs)
    return decorated


# ── Proteção CSRF (double-submit cookie) ─────────────────────────

# Desative com IDS_CSRF_DISABLED=true (apenas desenvolvimento local)
_CSRF_ENABLED = os.environ.get("IDS_CSRF_DISABLED", "false").lower() != "true"

_CSRF_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _get_or_set_csrf_cookie(response=None):
    """
    Retorna o token CSRF do cookie existente ou gera um novo.
    Se `response` for passado, define o cookie nele.
    """
    from flask import request as _req, make_response  # noqa: F401
    token = _req.cookies.get("csrf_token")
    if not token:
        token = secrets.token_hex(32)
    if response is not None:
        response.set_cookie(
            "csrf_token", token,
            samesite="Strict",
            httponly=False,   # JavaScript precisa ler para enviar no header
            max_age=8 * 3600,
        )
    return token


def csrf_protect(f):
    """
    Decorador que valida CSRF token em mutações (POST/PUT/PATCH/DELETE).
    Cliente deve enviar o valor do cookie csrf_token no header X-CSRFToken.
    Pattern: double-submit cookie.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not _CSRF_ENABLED or request.method in _CSRF_SAFE_METHODS:
            return f(*args, **kwargs)

        cookie_token = request.cookies.get("csrf_token", "")
        header_token = request.headers.get("X-CSRFToken", "")

        if not cookie_token or not header_token:
            logger.warning("CSRF token ausente | ip=%s | path=%s",
                           request.remote_addr, request.path)
            return jsonify({"error": "CSRF token ausente"}), 403

        if not secrets.compare_digest(cookie_token, header_token):
            logger.warning("CSRF token inválido | ip=%s | path=%s",
                           request.remote_addr, request.path)
            return jsonify({"error": "CSRF token inválido"}), 403

        return f(*args, **kwargs)
    return decorated


# ── HTTPS / certificado self-signed ──────────────────────────────

def generate_self_signed_cert() -> tuple:
    """
    Gera certificado self-signed para HTTPS local.
    Retorna (cert_path, key_path) ou (None, None) se cryptography não instalado.
    """
    if CERT_FILE.exists() and KEY_FILE.exists():
        logger.debug("Certificado HTTPS existente encontrado")
        return str(CERT_FILE), str(KEY_FILE)

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime as dt
        import ipaddress

        logger.info("Gerando certificado self-signed para HTTPS...")

        # Gera chave privada RSA 2048
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Cria certificado
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "NetGuard IDS"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetGuard"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime.now(dt.timezone.utc))
            .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        # Salva arquivos
        CERT_FILE.write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )
        KEY_FILE.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        KEY_FILE.chmod(0o600)

        logger.info("Certificado HTTPS gerado: %s", CERT_FILE)
        return str(CERT_FILE), str(KEY_FILE)

    except ImportError:
        logger.warning("HTTPS: instale 'cryptography' para habilitar: "
                       "pip install cryptography")
        return None, None
    except Exception as e:
        logger.error("Erro ao gerar certificado: %s", e)
        return None, None


def get_ssl_context():
    """Retorna ssl_context para Flask se HTTPS habilitado."""
    if not HTTPS_ENABLED:
        return None

    cert, key = generate_self_signed_cert()
    if cert and key:
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        logger.info("HTTPS ativado na porta %d", HTTPS_PORT)
        return ctx

    return None


def print_startup_info():
    """Imprime informações de acesso no startup."""
    token = get_or_create_token() if AUTH_ENABLED else None
    https = HTTPS_ENABLED and CERT_FILE.exists()

    print("\n" + "─" * 50)
    if https:
        print(f"  🔒 Dashboard: https://127.0.0.1:{HTTPS_PORT}")
    else:
        print(f"  🌐 Dashboard: http://127.0.0.1:5000")

    if AUTH_ENABLED and token:
        print(f"  🔑 Token: {token}")
        print(f"  📋 Salvo em: {TOKEN_FILE}")
    else:
        print(f"  ⚠️  Auth desativada — qualquer pessoa na rede pode acessar")
        print(f"     Para ativar: $env:IDS_AUTH='true'")
    print("─" * 50 + "\n")
