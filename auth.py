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
import logging
import pathlib
import sys
import ipaddress
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
    try:
        TOKEN_FILE.chmod(0o600)  # Somente o dono pode ler (ignorado no Windows)
    except (OSError, NotImplementedError):
        pass
    logger.info("Token gerado e salvo em %s", TOKEN_FILE)
    return token


def rotate_admin_token() -> str:
    """
    Gera um NOVO admin token, sobrescreve o arquivo .netguard_token e
    retorna o novo valor. O token antigo é invalidado imediatamente.

    Usado pelo endpoint /api/admin/rotate-admin-token.
    """
    new_token = secrets.token_urlsafe(32)
    TOKEN_FILE.write_text(new_token)
    try:
        TOKEN_FILE.chmod(0o600)
    except (OSError, NotImplementedError):
        pass
    logger.warning("Admin token rotacionado — novo token gravado em %s", TOKEN_FILE)
    return new_token


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
    """Extrai token de header Bearer/X-API-Token, query param ou cookie."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    api_token = request.headers.get("X-API-Token", "").strip()
    if api_token:
        return api_token
    # NOTE: token-in-query-string removed — leaks in server logs + browser history.
    # Única exceção permitida: ticket opaco de onboarding de uso único (handled separately).
    return request.cookies.get("netguard_token", "").strip()


def _is_browser_request() -> bool:
    """Retorna True se a requisição provavelmente veio de um browser (não API)."""
    accept = request.headers.get("Accept", "")
    return "text/html" in accept


def _has_explicit_token_auth() -> bool:
    """
    True quando a autenticação veio de um segredo enviado explicitamente pela requisição.

    Esse cenário não depende de cookies automáticos do browser, então não sofre
    o mesmo risco clássico de CSRF do fluxo de sessão.
    """
    auth_header = request.headers.get("Authorization", "")
    api_token   = request.headers.get("X-API-Token", "").strip()
    return auth_header.startswith("Bearer ") or bool(api_token)


def _resolve_repo():
    """Tenta localizar o repositório compartilhado da aplicação."""
    try:
        from flask import g
        repo = getattr(g, "_repo", None)
        if repo is not None:
            return repo
    except Exception:
        pass

    try:
        from flask import current_app
        repo = getattr(current_app, "_repo", None)
        if repo is not None:
            return repo
    except Exception:
        pass

    for module_name in ("__main__", "app"):
        try:
            app_module = sys.modules.get(module_name)
            repo = getattr(app_module, "repo", None) if app_module else None
            if repo is not None:
                return repo
        except Exception:
            pass
    return None


def is_loopback_bind(host: str) -> bool:
    """
    Retorna True quando o host de bind representa apenas loopback local.

    Trata nomes comuns (`localhost`) e IPv4/IPv6. Wildcards (`0.0.0.0`, `::`)
    são considerados não-loopback porque expõem em todas as interfaces.
    """
    normalized = (host or "").strip().lower()
    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1]

    if normalized in {"localhost", "127.0.0.1", "::1"}:
        return True
    if normalized in {"", "0.0.0.0", "::", "*"}:
        return False

    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def ensure_safe_startup(
    host: str,
    *,
    auth_enabled: bool | None = None,
    allow_insecure_dev: bool | None = None,
) -> None:
    """
    Falha fechado quando alguém tenta subir a aplicação sem auth fora de loopback.

    Mantém o fluxo rápido de desenvolvimento local (`127.0.0.1`/`localhost`) mas
    evita exposição acidental em LAN/Internet. O bypass exige opt-in explícito
    via `IDS_ALLOW_INSECURE_DEV=true`.
    """
    if auth_enabled is None:
        auth_enabled = AUTH_ENABLED
    if allow_insecure_dev is None:
        allow_insecure_dev = (
            os.environ.get("IDS_ALLOW_INSECURE_DEV", "false").lower() == "true"
        )

    if auth_enabled or is_loopback_bind(host) or allow_insecure_dev:
        return

    raise RuntimeError(
        "Refusing to start NetGuard with IDS_AUTH=false on a non-loopback bind "
        f"('{host}'). Set IDS_AUTH=true, bind IDS_HOST to 127.0.0.1/localhost, "
        "or set IDS_ALLOW_INSECURE_DEV=true only for isolated labs."
    )


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
        from flask import make_response

        if not DASHBOARD_AUTH:
            resp = make_response(f(*args, **kwargs))
            if _CSRF_ENABLED:
                _get_or_set_csrf_cookie(resp)
            return resp

        token = request.cookies.get("netguard_token", "").strip()
        if not token:
            next_url = request.path
            if request.query_string:
                next_url += "?" + request.query_string.decode()
            logger.info("Sessão ausente → /login | ip=%s | path=%s",
                        request.remote_addr, request.path)
            resp = redirect(f"/login?next={next_url}")
            if _CSRF_ENABLED:
                _get_or_set_csrf_cookie(resp)
            return resp

        # Valida o cookie (admin token ou tenant token)
        repo = _resolve_repo()

        result = verify_any_token(token, repo)
        if not result["valid"]:
            logger.warning("Cookie inválido → /login | ip=%s", request.remote_addr)
            resp = redirect(f"/login?next={request.path}&expired=1")
            resp.delete_cookie("netguard_token")
            if _CSRF_ENABLED:
                _get_or_set_csrf_cookie(resp)
            return resp

        resp = make_response(f(*args, **kwargs))
        if _CSRF_ENABLED:
            _get_or_set_csrf_cookie(resp)
        return resp
    return decorated


# ── Decorador de autenticação ─────────────────────────────────────

_valid_token = None  # cache em memória

def auth(f):
    """
    Decorador que protege uma rota Flask com token.

    Aceita token em:
      - Header:      Authorization: Bearer <token>
      - Cookie:      netguard_token=<token>

    Comportamento por tipo de request:
      - Browser (Accept: text/html) → redireciona para /login?next=<path>
      - API (Accept: application/json ou outros) → retorna 401 JSON

    Respeita AUTH_ENABLED globalmente: quando False (dev local single-user),
    nenhuma rota exige token — inclusive /api/*. Isso é intencional, já que
    o dev mode é "máquina única, usuário = admin automático".

    Em prod (AUTH_ENABLED=True), todas as rotas protegidas exigem token válido.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not AUTH_ENABLED:
            return f(*args, **kwargs)

        token = _extract_token()
        repo = _resolve_repo()
        result = verify_any_token(token, repo)

        if not result["valid"]:
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


# ─────────────────────────────────────────────────────────────────
# Proteção CSRF — pattern double-submit cookie
# ─────────────────────────────────────────────────────────────────
#
# POR QUE:
#   A sessão admin autentica via cookie (HttpOnly + Secure). Sem CSRF, um
#   site malicioso aberto na mesma sessão do browser poderia disparar um
#   POST pra /api/admin/* — o browser anexaria o cookie automaticamente
#   e o servidor trataria como ação legítima. CSRF fecha esse vetor.
#
# COMO FUNCIONA (double-submit cookie):
#   1. Servidor gera token aleatório e coloca em cookie csrf_token (NÃO
#      HttpOnly — JS precisa ler pra mandar no header).
#   2. Client lê o cookie e anexa no header X-CSRFToken de cada request
#      mutativa (POST/PUT/PATCH/DELETE).
#   3. Servidor compara cookie vs header com compare_digest. Se diferem
#      ou faltam, 403.
#
# POR QUE FUNCIONA:
#   Um site cross-origin malicioso NÃO CONSEGUE ler o cookie csrf_token
#   (Same-Origin Policy). O navegador manda o cookie automaticamente mas
#   sem saber o valor ele não consegue preencher o header X-CSRFToken
#   → compare_digest falha → 403.
#
# BYPASS INTENCIONAL:
#   Clientes que autenticam via header explícito (Authorization / X-API-Token)
#   não dependem de cookie de sessão — portanto não sofrem CSRF. Pular a
#   checagem pra esses evita que clientes server-to-server quebrem.
#
# SAMESITE=STRICT:
#   Defesa em profundidade. Mesmo sem o double-submit, o browser não
#   enviaria o cookie em navegação cross-site. Os dois juntos cobrem
#   navegadores legados + extensões de browser maliciosas.

# Desative com IDS_CSRF_DISABLED=true APENAS em dev local.
# Em prod, rodar com isso ligado é perda imediata da proteção.
_CSRF_ENABLED = os.environ.get("IDS_CSRF_DISABLED", "false").lower() != "true"

_CSRF_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _get_or_set_csrf_cookie(response=None):
    """
    Retorna o token CSRF do cookie existente ou gera um novo.
    Se `response` for passado, define o cookie nele.

    Idempotente: se o cliente já tem o cookie, reusa. Novo token = nova
    sessão CSRF (o cliente precisa pegar o valor novo antes do próximo POST).
    max_age 8h casa com a duração típica de uma sessão operacional.
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

    Contrato do cliente (já implementado em admin.html via helper _csrfToken()):
      - Ler valor do cookie csrf_token
      - Enviar no header X-CSRFToken em toda request mutativa

    Bypass para clientes com autenticação explícita via header:
      - Authorization: Bearer ... / X-API-Token: ...
      - Rationale: esses fluxos não dependem do cookie de sessão, logo
        não têm o vetor "cookie anexado automaticamente" que CSRF explora.

    Retornos:
      - 403 + {"error": "CSRF token ausente"} se cookie OU header faltam
      - 403 + {"error": "CSRF token inválido"} se valores não conferem
      - passa pro handler se tudo OK
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not _CSRF_ENABLED or request.method in _CSRF_SAFE_METHODS:
            return f(*args, **kwargs)

        # Clientes API autenticados por header não dependem de cookie de sessão.
        if _has_explicit_token_auth():
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


def print_startup_info(host: str = "127.0.0.1"):
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
        if is_loopback_bind(host):
            print(f"     Bind atual: {host} (somente loopback local)")
            if DASHBOARD_AUTH:
                print(f"     Login local: abra /login e clique em 'Entrar em modo local'")
                print(f"     Token real não é exibido no modo local")
        else:
            print(f"     Bind atual: {host} (NÃO recomendado sem auth)")
    print("─" * 50 + "\n")


# ─────────────────────────────────────────────────────────────────
# TOTP 2FA (RFC 6238) — opt-in, stdlib-only
# ─────────────────────────────────────────────────────────────────
#
# POR QUE EXISTE:
#   O login admin depende de um único token bearer (.netguard_token). Se o
#   token vaza (post em log, screenshot, commit acidental), o atacante entra
#   direto. 2FA TOTP exige um fator adicional que está FORA do repo e FORA
#   do servidor: o secret fica no celular do operador.
#
# POR QUE OPT-IN (e não obrigatório):
#   Durante dev/demo o operador roda sem TOTP pra iterar rápido. Ativar é
#   uma ação explícita: /api/admin/totp/setup cria .netguard_totp. Enquanto
#   o arquivo não existe, o login pede só o bearer token.
#
# POR QUE STDLIB-ONLY (sem pyotp):
#   Manter a superfície de dependências mínima. TOTP = HMAC-SHA1 + unpack
#   + módulo — 20 linhas. Cada dep a menos é uma CVE a menos pra auditar.
#
# ACTIVATION GATE (dupla):
#   1) Arquivo .netguard_totp existe (secret está configurado)
#   2) env IDS_ADMIN_TOTP != 'false' (kill switch pra emergência)
#   Precisa dos dois pra 2FA ser exigido. Remover o arquivo OU setar a env
#   como 'false' desativa.

TOTP_FILE        = pathlib.Path(__file__).parent / ".netguard_totp"
TOTP_ISSUER      = os.environ.get("IDS_TOTP_ISSUER", "NetGuard IDS")
TOTP_ACCOUNT     = os.environ.get("IDS_TOTP_ACCOUNT", "admin")
# Janela de tolerância — aceita código do período anterior/posterior.
# Por que ±1: relógios de celulares dessincronizam em segundos; sem janela
# o usuário vê "código inválido" por 2-3s no fim de cada janela de 30s.
# Janela muito larga (>2) aumenta brute-force window — 1 é o default da RFC.
TOTP_WINDOW      = int(os.environ.get("IDS_TOTP_WINDOW", "1"))

def _b32_decode(s: str) -> bytes:
    """
    Decodifica base32 tolerante — aceita o formato que os apps mostram
    (uppercase, com espaços, sem padding). Google Authenticator mostra
    o secret em grupos tipo 'ABCD EFGH...'; se o usuário colar isso no
    form de teste o código tem que funcionar.
    """
    import base64
    s = s.strip().replace(" ", "").replace("-", "").upper()
    pad = (-len(s)) % 8
    return base64.b32decode(s + "=" * pad, casefold=True)

def _b32_encode(raw: bytes) -> str:
    """Base32 sem padding — é o formato que o otpauth:// espera."""
    import base64
    return base64.b32encode(raw).decode("ascii").rstrip("=")

def totp_is_enabled() -> bool:
    """
    True se TOTP está ativo AGORA (deve ser exigido no próximo login admin).
    Duas condições:
      1) IDS_ADMIN_TOTP != 'false' (env kill-switch)
      2) .netguard_totp existe e tem secret mínimo (>=16 chars base32)
    O check de tamanho protege contra arquivo corrompido/vazio.
    """
    if os.environ.get("IDS_ADMIN_TOTP", "auto").lower() == "false":
        return False
    return TOTP_FILE.exists() and len(TOTP_FILE.read_text(encoding="utf-8").strip()) >= 16

def totp_get_secret() -> str:
    """Lê o secret base32 de .netguard_totp. Retorna '' se não existir."""
    if not TOTP_FILE.exists():
        return ""
    return TOTP_FILE.read_text(encoding="utf-8").strip()

def totp_generate_secret() -> str:
    """
    Gera NOVO secret TOTP (160 bits = 20 bytes, base32 sem padding) e grava
    em .netguard_totp. Sobrescreve se já existir. Retorna o secret base32.

    Por que 160 bits: recomendação da RFC 4226 §4 — HMAC-SHA1 usa chaves
    do tamanho do bloco hash (SHA1 = 160). Menos que isso reduz a entropia
    efetiva; mais que isso não agrega (a HMAC trunca internamente).

    Chmod 0o600 pra evitar que outros users do host leiam o arquivo. Em
    Windows o chmod vira no-op e a proteção fica a cargo do ACL da pasta.

    Sobrescrever secret anterior é intencional: chamar setup é equivalente
    a "regerar" — o admin precisa reescanear o QR no app autenticador
    ANTES de fazer logout (senão fica trancado fora).
    """
    raw = secrets.token_bytes(20)
    secret_b32 = _b32_encode(raw)
    TOTP_FILE.write_text(secret_b32, encoding="utf-8")
    try:
        TOTP_FILE.chmod(0o600)
    except (OSError, NotImplementedError):
        pass
    logger.warning("TOTP secret gerado e gravado em %s", TOTP_FILE)
    return secret_b32

def totp_disable() -> bool:
    """
    Remove .netguard_totp. Retorna True se existia.

    Caminho de emergência: admin perdeu o celular. Quem tem acesso ao
    host remove o arquivo e o login volta a aceitar só o token bearer.
    Alternativa sem acesso a arquivo: setar IDS_ADMIN_TOTP=false.
    """
    try:
        if TOTP_FILE.exists():
            TOTP_FILE.unlink()
            logger.warning("TOTP desativado — arquivo %s removido", TOTP_FILE)
            return True
    except Exception as exc:
        logger.error("Falha ao remover %s: %s", TOTP_FILE, exc)
    return False

def _totp_code_at(secret_b32: str, counter: int) -> str:
    """
    Calcula o código TOTP de 6 dígitos pra um counter (RFC 6238).

    Algoritmo (fixo pela RFC — não mexer):
      1. HMAC-SHA1(secret, counter_big_endian_8bytes)
      2. Dynamic truncation: offset = último nibble do digest (0..15)
      3. Pega 4 bytes a partir do offset, mascara bit alto (evita sinal)
      4. Mod 10^6 pra reduzir a 6 dígitos decimais, pad com zeros

    Mantém SHA1/6-dígitos/30s mesmo sabendo que SHA1 tem colisões —
    é o default de TODOS os apps autenticadores. Mudar quebra compat.
    """
    import hmac, hashlib, struct
    key = _b32_decode(secret_b32)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = ((digest[offset]   & 0x7F) << 24 |
                (digest[offset+1] & 0xFF) << 16 |
                (digest[offset+2] & 0xFF) << 8  |
                (digest[offset+3] & 0xFF)) % 1_000_000
    return f"{code_int:06d}"

def totp_verify(code: str, at_time: float = None) -> bool:
    """
    Verifica código TOTP (6 dígitos) contra o secret em .netguard_totp.

    Proteções:
      - Fail-closed: sem TOTP habilitado, sempre False. O caller NUNCA
        deve chamar isso pra decidir "2FA precisa?" — use totp_is_enabled.
      - compare_digest: comparação de tempo constante, evita timing attack
        pra distinguir "1º dígito errado" de "6º dígito errado".
      - Janela ±TOTP_WINDOW: tolera sync drift. NUNCA aumente pra >2 em
        prod — cada incremento dobra a superfície de brute-force.

    Não implementa replay-prevention (cada código pode ser usado 2x dentro
    da janela). Pra SOC/IDS o risco é aceitável: o atacante precisaria
    roubar o código DENTRO de 30-60s. Se esse risco importar, adicionar
    cache de "last_used_counter" e rejeitar deltas <= ele.
    """
    import time as _time
    if not totp_is_enabled():
        return False
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return False
    secret = totp_get_secret()
    if not secret:
        return False
    ts = at_time if at_time is not None else _time.time()
    counter_now = int(ts // 30)
    for delta in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
        try:
            expected = _totp_code_at(secret, counter_now + delta)
        except Exception:
            return False
        if secrets.compare_digest(expected, code):
            return True
    return False

def totp_provisioning_uri(secret_b32: str = None, account: str = None, issuer: str = None) -> str:
    """
    Monta a URI otpauth:// que o admin cola no Google Authenticator / 1Password
    (ou escaneia como QR code).

    Formato (padrão Google Authenticator Key URI):
      otpauth://totp/{issuer}:{account}?secret=...&issuer=...&algorithm=SHA1&digits=6&period=30

    Por que passar issuer tanto no label quanto no query param: apps antigos
    leem do label (colon-separated), apps novos leem do query. Passar nos
    dois maximiza compat (Authy antigo, Microsoft Authenticator, etc).

    URL-encoda issuer/account pra suportar espaços ("NetGuard IDS" vira
    "NetGuard%20IDS") — senão o app quebra ou mostra label truncado.
    """
    from urllib.parse import quote
    s = (secret_b32 or totp_get_secret()).replace("=", "")
    issuer_safe  = quote(issuer  or TOTP_ISSUER,  safe="")
    account_safe = quote(account or TOTP_ACCOUNT, safe="")
    label = f"{issuer_safe}:{account_safe}"
    return f"otpauth://totp/{label}?secret={s}&issuer={issuer_safe}&algorithm=SHA1&digits=6&period=30"
