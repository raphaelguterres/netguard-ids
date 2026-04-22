"""
security.py — NetGuard IDS · Módulo central de segurança
=========================================================
Primitivas de segurança enterprise reutilizáveis em toda a aplicação.
Zero dependências externas além da stdlib Python.

Funcionalidades
---------------
  hash_token / verify_token   — HMAC-SHA256 de tokens de API (nunca plaintext no DB)
  BruteForceGuard             — lockout escalado (5m→15m→1h→24h) persistido em SQLite
  require_role                — decorador RBAC (admin, analyst, viewer)
  mask_sensitive              — redação de PII em logs (tokens, e-mails, cartões)
  validate_redirect_url       — proteção contra open redirect
  safe_filename               — proteção contra path traversal em downloads
  validate_absolute_session   — timeout absoluto de sessão (complementa max_age do cookie)
"""

from __future__ import annotations

import functools
import hashlib
import hmac
import logging
import os
import re
import sqlite3
import threading
import time
from typing import Optional

logger = logging.getLogger("netguard.security")

# ── Chave de assinatura dos tokens ───────────────────────────────
# Lida em tempo de importação; usa SECRET_KEY do ambiente se disponível.
# Nunca exponha ou logue esta chave.
INSECURE_DEV_SIGNING_KEY = "netguard-insecure-dev-key-change-in-prod"
_WEAK_SIGNING_SECRETS = {
    INSECURE_DEV_SIGNING_KEY,
    "dev",
    "secret",
    "changeme",
    "insecure",
}


def _is_dev_or_test_runtime() -> bool:
    for env_name in ("NETGUARD_ENV", "IDS_ENV", "FLASK_ENV"):
        current = os.environ.get(env_name, "").strip().lower()
        if current in {"dev", "development", "local", "test", "testing"}:
            return True
    return bool(os.environ.get("PYTEST_CURRENT_TEST"))


def _load_signing_key() -> bytes:
    explicit_secret = os.environ.get("TOKEN_SIGNING_SECRET", "").strip()
    if explicit_secret:
        if (
            not _is_dev_or_test_runtime()
            and explicit_secret.strip().lower() in _WEAK_SIGNING_SECRETS
        ):
            raise RuntimeError(
                "TOKEN_SIGNING_SECRET usa um valor inseguro de desenvolvimento. "
                "Configure um segredo exclusivo antes de iniciar em producao."
            )
        return explicit_secret.encode("utf-8")

    if not _is_dev_or_test_runtime():
        raise RuntimeError(
            "TOKEN_SIGNING_SECRET e obrigatorio fora de desenvolvimento/testes. "
            "Configure um segredo forte no ambiente antes de iniciar o NetGuard."
        )

    fallback_secret = os.environ.get("SECRET_KEY", "").strip() or INSECURE_DEV_SIGNING_KEY
    logger.warning(
        "TOKEN_SIGNING_SECRET ausente; usando fallback permitido apenas em dev/test. "
        "Configure TOKEN_SIGNING_SECRET antes de expor a instancia."
    )
    return fallback_secret.encode("utf-8")


_SIGNING_KEY: bytes = _load_signing_key()


# ══════════════════════════════════════════════════════════════════
# 1. HASH DE TOKENS — HMAC-SHA256
# ══════════════════════════════════════════════════════════════════

def hash_token(token: str) -> str:
    """
    Retorna HMAC-SHA256 hexdigest do token.

    Propriedades:
    - Determinístico (mesmo token → mesmo hash)
    - Não reversível sem a chave de assinatura
    - Tokens de 43+ chars têm 258+ bits de entropia → brute-force inviável
    - Comparação constante via verify_token() evita timing attacks

    Uso:
        stored_hash = hash_token(token)         # ao criar
        ok          = verify_token(token, stored_hash)  # ao autenticar
    """
    return hmac.new(_SIGNING_KEY, token.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_token(token: str, stored_hash: str) -> bool:
    """
    Compara token com hash armazenado em tempo constante.
    Retorna False se qualquer argumento for vazio/None.
    """
    if not token or not stored_hash:
        return False
    expected = hash_token(token)
    return hmac.compare_digest(expected, stored_hash)


# ══════════════════════════════════════════════════════════════════
# 2. BRUTE FORCE GUARD — lockout escalado persistido em SQLite
# ══════════════════════════════════════════════════════════════════

_BF_SCHEMA = """
CREATE TABLE IF NOT EXISTS bf_attempts (
    key        TEXT PRIMARY KEY,
    count      INTEGER NOT NULL DEFAULT 0,
    locked_until REAL  NOT NULL DEFAULT 0,
    last_attempt REAL  NOT NULL DEFAULT 0
);
"""

# Backoff progressivo: após N falhas → bloqueio por T segundos
_LOCKOUT_THRESHOLDS = [
    (3,  5 * 60),    # 3 falhas  → 5 minutos
    (5,  15 * 60),   # 5 falhas  → 15 minutos
    (10, 60 * 60),   # 10 falhas → 1 hora
    (20, 24 * 60 * 60),  # 20 falhas → 24 horas
]


class BruteForceGuard:
    """
    Rastreador de tentativas de login por chave (IP, email, token).
    Persistido em SQLite — sobrevive a restarts da aplicação.

    Uso:
        bf = BruteForceGuard("netguard_security.db")

        ip = request.remote_addr
        if bf.is_locked(ip):
            return jsonify({"error": "Conta bloqueada temporariamente"}), 429

        ok = check_password(...)
        if ok:
            bf.reset(ip)
        else:
            wait = bf.record_failure(ip)
            if wait:
                logger.warning("IP %s bloqueado por %ds após falhas", ip, wait)
    """

    def __init__(self, db_path: str = "netguard_security.db"):
        self.db_path = db_path
        self._local  = threading.local()
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_BF_SCHEMA)
            conn.commit()
            self._local.conn = conn
        return self._local.conn

    def _init_db(self) -> None:
        try:
            self._conn()
        except Exception as exc:
            logger.error("[BruteForceGuard] Falha ao inicializar DB: %s", exc)

    def close(self) -> None:
        """Fecha a conexão SQLite da thread atual, quando existir."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            return
        try:
            conn.close()
        except Exception:
            pass
        try:
            del self._local.conn
        except Exception:
            pass

    def is_locked(self, key: str) -> bool:
        """Retorna True se a chave está em período de lockout."""
        try:
            row = self._conn().execute(
                "SELECT locked_until FROM bf_attempts WHERE key = ?", (key,)
            ).fetchone()
            if row and row["locked_until"] > time.time():
                return True
        except Exception:
            pass
        return False

    def lockout_remaining(self, key: str) -> int:
        """Retorna segundos restantes de lockout (0 se não bloqueado)."""
        try:
            row = self._conn().execute(
                "SELECT locked_until FROM bf_attempts WHERE key = ?", (key,)
            ).fetchone()
            if row:
                remaining = int(row["locked_until"] - time.time())
                return max(0, remaining)
        except Exception:
            pass
        return 0

    def failure_count(self, key: str) -> int:
        """Retorna número de falhas acumuladas para a chave."""
        try:
            row = self._conn().execute(
                "SELECT count FROM bf_attempts WHERE key = ?", (key,)
            ).fetchone()
            return row["count"] if row else 0
        except Exception:
            return 0

    def record_failure(self, key: str) -> Optional[int]:
        """
        Registra uma falha de autenticação.
        Retorna duração do lockout em segundos se bloqueado, None se não.
        """
        try:
            conn = self._conn()
            conn.execute("""
                INSERT INTO bf_attempts (key, count, locked_until, last_attempt)
                VALUES (?, 1, 0, ?)
                ON CONFLICT(key) DO UPDATE SET
                    count        = count + 1,
                    last_attempt = excluded.last_attempt
            """, (key, time.time()))
            conn.commit()

            row = conn.execute(
                "SELECT count FROM bf_attempts WHERE key = ?", (key,)
            ).fetchone()
            count = row["count"] if row else 0

            # Determina lockout baseado no contador atual
            lockout_secs = 0
            for threshold, duration in reversed(_LOCKOUT_THRESHOLDS):
                if count >= threshold:
                    lockout_secs = duration
                    break

            if lockout_secs > 0:
                locked_until = time.time() + lockout_secs
                conn.execute(
                    "UPDATE bf_attempts SET locked_until = ? WHERE key = ?",
                    (locked_until, key)
                )
                conn.commit()
                logger.warning(
                    "[security] Brute force lockout | key=%s | count=%d | duration=%ds",
                    key[:20], count, lockout_secs,
                )
                return lockout_secs

        except Exception as exc:
            logger.error("[BruteForceGuard] record_failure error: %s", exc)
        return None

    def reset(self, key: str) -> None:
        """Limpa o contador após autenticação bem-sucedida."""
        try:
            self._conn().execute(
                "DELETE FROM bf_attempts WHERE key = ?", (key,)
            )
            self._conn().commit()
        except Exception:
            pass

    def purge_expired(self) -> int:
        """Remove registros expirados. Chame periodicamente."""
        try:
            cur = self._conn().execute(
                "DELETE FROM bf_attempts WHERE locked_until < ? AND count < 5",
                (time.time() - 86400,)  # limpa após 24h se menos de 5 falhas
            )
            self._conn().commit()
            return cur.rowcount
        except Exception:
            return 0


# ══════════════════════════════════════════════════════════════════
# 3. RBAC — Role-Based Access Control
# ══════════════════════════════════════════════════════════════════

_ADMIN_RL_SCHEMA = """
CREATE TABLE IF NOT EXISTS admin_rate_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip    TEXT NOT NULL,
    request_path TEXT NOT NULL,
    event_ts     REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_admin_rate_events_ip_ts
    ON admin_rate_events(source_ip, event_ts);
"""


class AdminRateLimitGuard:
    """
    Rate limit persistido em SQLite para endpoints admin.

    Compartilha estado entre workers do mesmo host sem depender da memoria
    privada do processo.
    """

    def __init__(self, db_path: str = "netguard_security.db"):
        self.db_path = db_path
        self._local = threading.local()
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=5)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_ADMIN_RL_SCHEMA)
            conn.commit()
            self._local.conn = conn
        return self._local.conn

    def _init_db(self) -> None:
        try:
            self._conn()
        except Exception as exc:
            logger.error("[AdminRateLimitGuard] Falha ao inicializar DB: %s", exc)

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            return
        try:
            conn.close()
        except Exception:
            pass
        try:
            del self._local.conn
        except Exception:
            pass

    def check_and_record(
        self,
        source_ip: str,
        request_path: str,
        limit: int,
        window_seconds: int,
    ) -> tuple[bool, int, int]:
        """
        Retorna (allowed, current_count, retry_after_seconds).
        """
        source_ip = source_ip or "-"
        request_path = request_path or "-"
        limit = max(1, int(limit))
        window_seconds = max(1, int(window_seconds))
        now = time.time()
        cutoff = now - window_seconds
        conn = self._conn()

        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "DELETE FROM admin_rate_events WHERE event_ts < ?",
                (cutoff,),
            )
            row = conn.execute(
                """
                SELECT COUNT(*) AS total, MIN(event_ts) AS oldest
                FROM admin_rate_events
                WHERE source_ip = ? AND event_ts >= ?
                """,
                (source_ip, cutoff),
            ).fetchone()
            current_count = int(row["total"] or 0) if row else 0
            oldest = float(row["oldest"]) if row and row["oldest"] else now

            if current_count >= limit:
                conn.commit()
                retry_after = max(1, int(window_seconds - (now - oldest)))
                return False, current_count, retry_after

            conn.execute(
                """
                INSERT INTO admin_rate_events (source_ip, request_path, event_ts)
                VALUES (?, ?, ?)
                """,
                (source_ip, request_path, now),
            )
            conn.commit()
            return True, current_count + 1, 0
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise


ROLES = {
    "admin":    {"level": 100, "label": "Administrador"},
    "analyst":  {"level": 50,  "label": "Analista SOC"},
    "viewer":   {"level": 10,  "label": "Observador"},
}

# Mapa de endpoint → role mínima necessária
# Endpoints não listados aqui requerem apenas autenticação (qualquer role)
ENDPOINT_ROLES: dict[str, str] = {
    # Escrita / ações destrutivas → analyst ou acima
    "block_ip":       "analyst",
    "unblock_ip":     "analyst",
    "update_status":  "analyst",
    "billing_portal": "admin",
    "admin_trials":   "admin",
    "rotate_token":   "admin",
}


def require_role(*roles: str):
    """
    Decorador que exige que o tenant autenticado tenha uma das roles listadas.

    Uso:
        @app.route("/api/block", methods=["POST"])
        @auth                       # autentica primeiro
        @require_role("analyst", "admin")
        def block_ip():
            ...

    A role é extraída do objeto de tenant retornado por get_tenant_by_token()
    e armazenada em flask.g.tenant_role durante o middleware de autenticação.
    """
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            # Importa dentro da função para evitar circular import
            try:
                from flask import g, jsonify
                # Modo local sem autenticação → acesso total (sem RBAC)
                try:
                    from auth import AUTH_ENABLED as _auth_on
                except Exception:
                    _auth_on = False
                if not _auth_on:
                    return fn(*args, **kwargs)
                tenant_role = getattr(g, "tenant_role", "viewer")
                if tenant_role not in roles and tenant_role != "admin":
                    logger.warning(
                        "[RBAC] Acesso negado | role=%s | required=%s | endpoint=%s",
                        tenant_role, roles, fn.__name__,
                    )
                    return jsonify({
                        "error": "Permissão insuficiente",
                        "required_role": list(roles),
                        "your_role": tenant_role,
                    }), 403
            except Exception:
                pass  # Fora de contexto Flask — ignora
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def role_level(role: str) -> int:
    """Retorna o nível numérico da role (maior = mais privilegiado)."""
    return ROLES.get(role, {}).get("level", 0)


# ══════════════════════════════════════════════════════════════════
# 4. MASCARAMENTO DE DADOS SENSÍVEIS EM LOGS
# ══════════════════════════════════════════════════════════════════

# Padrões de dados sensíveis para mascarar
_SENSITIVE_PATTERNS = [
    # Tokens NetGuard completos (ng_ + 43 chars base64url)
    (re.compile(r'\bng_[A-Za-z0-9_-]{20,}\b'), lambda m: m.group()[:8] + "***"),
    # Tokens admin (token hex longo)
    (re.compile(r'\b[a-f0-9]{40,}\b'), lambda m: m.group()[:8] + "***"),
    # Senhas em JSON bodies
    (re.compile(r'("password"\s*:\s*)"[^"]{3,}"', re.IGNORECASE),
     lambda m: m.group(1) + '"***"'),
    # E-mails
    (re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'),
     lambda m: _mask_email(m.group())),
    # Números de cartão (sequências de 13-16 dígitos separadas por espaço/hífen)
    (re.compile(r'\b(?:\d[ -]?){13,16}\b'),
     lambda m: "****-****-****-" + m.group().replace(" ", "").replace("-", "")[-4:]),
    # Stripe secret keys
    (re.compile(r'\bsk_(live|test)_[A-Za-z0-9]{20,}\b'),
     lambda m: m.group()[:12] + "***"),
    # Chaves de API genéricas em JSON
    (re.compile(r'("(?:api_key|secret|token|password|pass|passwd)"\s*:\s*)"[^"]{4,}"',
                re.IGNORECASE),
     lambda m: m.group(1) + '"***"'),
    # SMTP passwords em env vars
    (re.compile(r'(SMTP_PASS\s*=\s*)\S+', re.IGNORECASE),
     lambda m: m.group(1) + "***"),
]


def _mask_email(email: str) -> str:
    parts = email.split("@")
    if len(parts) != 2:
        return "***@***"
    local = parts[0]
    domain = parts[1]
    masked_local = local[:2] + "*" * max(1, len(local) - 2)
    return f"{masked_local}@{domain}"


def mask_sensitive(text: str) -> str:
    """
    Redige dados sensíveis em uma string de log.
    Preserva a estrutura do texto, apenas substitui valores sensíveis.
    """
    if not text:
        return text
    result = str(text)
    for pattern, replacer in _SENSITIVE_PATTERNS:
        result = pattern.sub(replacer, result)
    return result


class SensitiveDataFilter(logging.Filter):
    """
    Filtro de logging que aplica mask_sensitive() em todas as mensagens.
    Adicione ao handler raiz para proteção automática.

    Uso:
        handler = logging.StreamHandler()
        handler.addFilter(SensitiveDataFilter())
    """
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.getMessage, str):
            record.msg = mask_sensitive(str(record.msg))
        else:
            try:
                record.msg = mask_sensitive(str(record.msg))
                record.args = None  # já formatado
            except Exception:
                pass
        return True


# ══════════════════════════════════════════════════════════════════
# 5. VALIDAÇÃO DE REDIRECT URL — proteção contra open redirect
# ══════════════════════════════════════════════════════════════════

def validate_redirect_url(url: str, allowed_host: str = None) -> str:
    """
    Valida e sanitiza uma URL de redirecionamento.
    Retorna '/' se a URL for externa ou suspeita.

    Regras:
    - Apenas caminhos relativos são permitidos (começam com '/')
    - URLs com esquema (http://, https://, //) são rejeitadas
    - Caminhos com '..' são rejeitados (path traversal)
    - Retorna '/' como fallback seguro
    """
    if not url:
        return "/"
    url = url.strip()

    # Rejeita qualquer URL com protocolo ou protocol-relative
    if re.match(r'^(https?:)?//', url, re.IGNORECASE):
        logger.warning("[security] Open redirect bloqueado: %s", url[:60])
        return "/"

    # Rejeita URIs com esquema não-HTTP (javascript:, data:, etc.)
    if re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*:', url):
        logger.warning("[security] URI scheme suspeito bloqueado: %s", url[:60])
        return "/"

    # Rejeita path traversal
    if ".." in url:
        logger.warning("[security] Path traversal em redirect bloqueado: %s", url[:60])
        return "/"

    # Deve começar com '/'
    if not url.startswith("/"):
        return "/"

    return url


# ══════════════════════════════════════════════════════════════════
# 6. SAFE FILENAME — proteção contra path traversal em downloads
# ══════════════════════════════════════════════════════════════════

_SAFE_FILENAME_RE = re.compile(r'[^a-zA-Z0-9_\-\.]')


def safe_filename(filename: str, default: str = "download") -> str:
    """
    Retorna um nome de arquivo seguro para uso em Content-Disposition.
    Remove qualquer componente de path e caracteres perigosos.
    """
    if not filename:
        return default
    # Remove componentes de path (Windows e Unix)
    name = os.path.basename(filename.replace("\\", "/"))
    # Remove caracteres não permitidos
    name = _SAFE_FILENAME_RE.sub("_", name)
    # Limita tamanho
    name = name[:64]
    return name or default


# ══════════════════════════════════════════════════════════════════
# 7. CSV INJECTION — sanitização de células antes do export
# ══════════════════════════════════════════════════════════════════

_CSV_INJECTION_START = re.compile(r'^[=+\-@\t\r]')


def sanitize_csv_cell(value: str) -> str:
    """
    Escapa células CSV que iniciam com caracteres de fórmula.
    Excel/LibreOffice executariam '=SYSTEM()' se não escapado.
    Prefixo com ' (apóstrofe) — inerte, visível apenas na barra de fórmulas.
    """
    if not isinstance(value, str):
        return str(value)
    if _CSV_INJECTION_START.match(value):
        return "'" + value
    return value


def sanitize_csv_row(row: dict) -> dict:
    """Aplica sanitize_csv_cell() em todos os valores string de um dict."""
    return {k: sanitize_csv_cell(v) if isinstance(v, str) else v
            for k, v in row.items()}


# ══════════════════════════════════════════════════════════════════
# 8. SESSION TIMEOUT ABSOLUTO
# ══════════════════════════════════════════════════════════════════

SESSION_MAX_AGE_SECONDS = int(os.environ.get("SESSION_MAX_AGE", str(8 * 3600)))   # 8h
SESSION_IDLE_TIMEOUT    = int(os.environ.get("SESSION_IDLE_TIMEOUT", str(30 * 60)))  # 30min


def validate_absolute_session(cookie_issued_at: Optional[float],
                               last_activity: Optional[float] = None) -> tuple[bool, str]:
    """
    Valida a idade absoluta e o tempo de inatividade de uma sessão.

    Parâmetros
    ----------
    cookie_issued_at : timestamp Unix de quando o cookie foi emitido
    last_activity    : timestamp Unix da última requisição (opcional)

    Retorna
    -------
    (válida: bool, motivo: str)
    """
    now = time.time()

    if cookie_issued_at is None:
        return False, "session_missing_iat"

    age = now - cookie_issued_at
    if age > SESSION_MAX_AGE_SECONDS:
        return False, f"session_expired_absolute ({int(age)}s > {SESSION_MAX_AGE_SECONDS}s)"

    if last_activity is not None:
        idle = now - last_activity
        if idle > SESSION_IDLE_TIMEOUT:
            return False, f"session_expired_idle ({int(idle)}s > {SESSION_IDLE_TIMEOUT}s)"

    return True, "ok"


def make_session_payload(tenant_id: str, role: str = "analyst") -> dict:
    """Cria o payload a ser serializado no cookie de sessão."""
    return {
        "tenant_id": tenant_id,
        "role":      role,
        "iat":       time.time(),          # issued at
        "lat":       time.time(),          # last activity
    }


# ══════════════════════════════════════════════════════════════════
# 9. TOKEN ROTATION
# ══════════════════════════════════════════════════════════════════

def rotate_token(old_token: str, generate_fn) -> tuple[str, str]:
    """
    Gera um novo token e retorna (new_token, new_hash).

    Parâmetros
    ----------
    old_token   : token atual (para log)
    generate_fn : função que gera o novo token (ex: billing.generate_api_token)

    Uso em app.py:
        new_token, new_hash = rotate_token(current_token, generate_api_token)
        repo.update_tenant_token(tenant_id, new_hash)
        # invalidar cookie antigo e emitir novo
    """
    new_token = generate_fn()
    new_hash  = hash_token(new_token)
    logger.info(
        "[security] Token rotacionado | old_prefix=%s | new_prefix=%s",
        old_token[:8] if old_token else "?",
        new_token[:8],
    )
    return new_token, new_hash


# ══════════════════════════════════════════════════════════════════
# 10. SINGLETON BruteForceGuard para o app
# ══════════════════════════════════════════════════════════════════

_bf_guards: dict[str, BruteForceGuard] = {}
_bf_lock = threading.Lock()
_admin_rl_guards: dict[str, AdminRateLimitGuard] = {}
_admin_rl_lock = threading.Lock()


def get_bf_guard(db_path: str = "netguard_security.db") -> BruteForceGuard:
    """Retorna uma instância singleton por caminho de banco."""
    normalized = os.path.abspath(db_path or "netguard_security.db")
    guard = _bf_guards.get(normalized)
    if guard is None:
        with _bf_lock:
            guard = _bf_guards.get(normalized)
            if guard is None:
                guard = BruteForceGuard(normalized)
                _bf_guards[normalized] = guard
    return guard


def get_admin_rate_guard(db_path: str = "netguard_security.db") -> AdminRateLimitGuard:
    """Retorna uma instância singleton do rate limit admin por caminho de banco."""
    normalized = os.path.abspath(db_path or "netguard_security.db")
    guard = _admin_rl_guards.get(normalized)
    if guard is None:
        with _admin_rl_lock:
            guard = _admin_rl_guards.get(normalized)
            if guard is None:
                guard = AdminRateLimitGuard(normalized)
                _admin_rl_guards[normalized] = guard
    return guard
