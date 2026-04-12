"""
NetGuard IDS v3.0 — Servidor completo
Monitor de rede real + API REST + Dashboard executivo.
Um único processo. Sem simulador. Sem dados falsos.
"""

import os, re, json, sys, time, logging, functools, pathlib, threading, subprocess, socket, ipaddress, secrets  # noqa: F401
from platform_utils import (  # noqa: F401
    OS, IS_WINDOWS, IS_LINUX,
    get_processes, get_pid_name_map, get_listen_ports,
    get_security_events, get_arp_table, ping as platform_ping, get_hostname,
    get_connections as platform_get_connections,
)

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    psutil = None
    PSUTIL_OK = False
    logging.getLogger("ids.api").warning("psutil não instalado — instale com: pip install psutil")
from datetime import datetime, timezone
from flask import Flask, jsonify, request, Response
from flask_cors import CORS
from ids_engine import IDSEngine, LogProcessor

# SOC Detection Engine — arquivo único, sem subpacotes
try:
    from soc_engine import SOCEngine
    SOC_IMPORT_OK = True
except Exception as _se:
    SOCEngine = None
    SOC_IMPORT_OK = False
    print(f"[WARN] SOC Engine import failed: {_se}")

detection_engine = None
DE_AVAILABLE = False

# Threat Hunter
try:
    from engine.threat_hunter import ThreatHunter
    _threat_hunter = None
    HUNTER_AVAILABLE = True
except Exception as _th_err:
    ThreatHunter     = None
    _threat_hunter   = None
    HUNTER_AVAILABLE = False
    print(f"[WARN] ThreatHunter: {_th_err}")

# Lateral Movement Detector
try:
    from engine.lateral_movement import LateralMovementDetector
    _lateral_detector = LateralMovementDetector()
    LATERAL_AVAILABLE = True
except Exception as _lm_err:
    LateralMovementDetector = None
    _lateral_detector       = None
    LATERAL_AVAILABLE       = False
    print(f"[WARN] LateralMovement: {_lm_err}")

# Honeypot
try:
    from engine.honeypot import Honeypot
    _honeypot = Honeypot()
    HONEYPOT_AVAILABLE = True
except Exception as _hp_err:
    Honeypot = None; _honeypot = None; HONEYPOT_AVAILABLE = False
    print(f"[WARN] Honeypot: {_hp_err}")

# DNS Monitor
try:
    from engine.dns_monitor import DNSMonitor
    _dns_monitor = DNSMonitor()
    DNS_AVAILABLE = True
except Exception as _dns_err:
    DNSMonitor = None; _dns_monitor = None; DNS_AVAILABLE = False
    print(f"[WARN] DNSMonitor: {_dns_err}")

# IP Enrichment (Shodan + WHOIS)
try:
    from engine.enrichment import IPEnrichment
    _enrichment = IPEnrichment()
    ENRICH_AVAILABLE = True
except Exception as _en_err:
    IPEnrichment = None; _enrichment = None; ENRICH_AVAILABLE = False
    print(f"[WARN] IPEnrichment: {_en_err}")

# YARA Engine
try:
    from engine.yara_engine import YaraEngine
    _yara_engine = YaraEngine()
    YARA_AVAILABLE = True
except Exception as _yr_err:
    YaraEngine   = None
    _yara_engine = None
    YARA_AVAILABLE = False
    print(f"[WARN] YaraEngine: {_yr_err}")

# Auto Block Engine
try:
    from engine.auto_block import auto_block, AutoBlockEngine, BLOCK_WHITELIST  # noqa: F401
    AUTOBLOCK_AVAILABLE = True
except Exception as _ab_err:
    auto_block = None
    AUTOBLOCK_AVAILABLE = False
    print(f"[WARN] AutoBlock: {_ab_err}")

# Billing (Stripe)
try:
    from billing import (  # noqa: F401
        PLANS, STRIPE_PUBLISHABLE_KEY, CONTACT_EMAIL, billing_active,
        create_checkout_session, create_portal_session,
        retrieve_checkout_session, handle_webhook,
        generate_api_token, get_plan,
    )
    BILLING_OK = True
except Exception as _bill_err:
    BILLING_OK = False
    print(f"[WARN] Billing module: {_bill_err}")

# Mailer — envio assíncrono via SMTP (falha silenciosa se não configurado)
try:
    from mailer import send_welcome, send_contact_confirmation
    MAILER_OK = True
except Exception as _mail_err:
    MAILER_OK = False
    def send_welcome(*a, **kw): pass          # noqa: E302
    def send_contact_confirmation(*a, **kw): pass  # noqa: E302
    print(f"[WARN] Mailer module: {_mail_err}")

# Notifier — Telegram/Slack para eventos de negócio
try:
    from notifier import notify as _notify
    NOTIFIER_OK = True
except Exception as _notif_err:
    NOTIFIER_OK = False
    def _notify(event, **kw): pass  # noqa: E302
    print(f"[WARN] Notifier module: {_notif_err}")

# Auth + HTTPS
try:
    from auth import (  # noqa: F401
        auth, AUTH_ENABLED, get_ssl_context, print_startup_info, HTTPS_PORT,
        verify_any_token, _extract_token, require_session, DASHBOARD_AUTH,
        csrf_protect,
    )
    AUTH_MODULE_OK = True
except Exception as _auth_err:
    # Fallback: auth decorator que não faz nada
    def auth(f): return f
    def require_session(f): return f
    def csrf_protect(f): return f
    AUTH_ENABLED    = False
    DASHBOARD_AUTH  = False
    AUTH_MODULE_OK  = False
    def get_ssl_context(): return None
    def print_startup_info(): pass
    def verify_any_token(token, repo=None): return {"valid": False, "type": None}
    def _extract_token(): return ""
    print(f"[WARN] Auth module: {_auth_err}")

# Correlation Engine
try:
    from engine.correlation_engine import get_correlation_engine
    def _on_correlation(alert):
        try:
            log_ao_vivo({
                "type":   "correlation",
                "sev":    alert.get("severity","").lower(),
                "threat": f"[{alert.get('rule_id')}] {alert.get('rule_name')}",
                "ip":     alert.get("host_id",""),
                "msg":    alert.get("description","")[:80],
            })
        except Exception:
            pass
        logger.warning("CORRELATION | %s | conf=%d%% | %s",
                       alert.get("rule_id"), alert.get("confidence",0),
                       alert.get("rule_name"))
    _corr_engine = None
    CORR_AVAILABLE = True
except Exception as _ce:
    get_correlation_engine = None
    _corr_engine = None
    CORR_AVAILABLE = False
    print(f"[WARN] Correlation Engine: {_ce}")

# ML Baseline
try:
    from engine.ml_baseline import MLBaseline
    _ml_baseline = None
    ML_AVAILABLE = True
except Exception as _ml_err:
    MLBaseline   = None
    _ml_baseline = None
    ML_AVAILABLE = False
    print(f"[WARN] ML Baseline: {_ml_err}")

# Risk Engine
try:
    from engine.risk_engine import risk_engine
    RISK_AVAILABLE = True
except Exception as _re:
    risk_engine = None
    RISK_AVAILABLE = False
    print(f"[WARN] Risk Engine: {_re}")

# VirusTotal
try:
    from engine.virustotal import VirusTotalClient
    _vt_client = VirusTotalClient()
    VT_AVAILABLE = True
except Exception as _vt_err:
    VirusTotalClient = None
    _vt_client       = None
    VT_AVAILABLE     = False
    print(f"[WARN] VirusTotal: {_vt_err}")

# Fail2Ban Engine
try:
    from fail2ban_engine import fail2ban, JAILS as F2B_JAILS
    F2B_AVAILABLE = True
except ImportError:
    fail2ban = None
    F2B_JAILS = {}
    F2B_AVAILABLE = False

# Kill Chain Correlator
try:
    from killchain import correlator as kc_correlator, TACTIC_LABELS, TACTIC_COLORS  # noqa: F401
    KC_AVAILABLE = True
except ImportError:
    kc_correlator = None
    KC_AVAILABLE = False

# OWASP Engine
try:
    from owasp_engine import owasp as owasp_engine, TESTING_PAYLOADS
    OWASP_AVAILABLE = True
except ImportError:
    owasp_engine = None
    OWASP_AVAILABLE = False
    TESTING_PAYLOADS = {}

# Sigma Rules Engine
try:
    from sigma_rules import sigma as sigma_engine
    logger_sigma = logging.getLogger("ids.sigma")
except ImportError:
    sigma_engine = None

# Threat Feeds (AbuseIPDB + ThreatFox)
try:
    from threat_feeds import enrich_ip, enrich_async, check_threatfox_ip, stats as feed_stats  # noqa: F401
    FEEDS_AVAILABLE = True
except ImportError:
    FEEDS_AVAILABLE = False
    def enrich_ip(ip): return {}
    def enrich_async(ip, cb=None): pass

# MITRE ATT&CK Engine
try:
    from engine.mitre_engine import get_mitre_engine
    MITRE_AVAILABLE = True
    logger.info("MITRE ATT&CK Engine disponível") if False else None  # lazy-init
except Exception as _me:
    get_mitre_engine = None
    MITRE_AVAILABLE = False
    print(f"[WARN] MITRE Engine: {_me}")

# ── Logging ───────────────────────────────────────────────────────
import uuid as _uuid_mod

# Contexto de request local (thread-safe)
_request_ctx = threading.local()


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

class JSONFormatter(logging.Formatter):
    """Logs estruturados em JSON — compatível com Datadog, Loki, CloudWatch e ELK."""

    STATIC_FIELDS = {
        "service": "netguard-ids",
        "version": "3.0",
    }

    def format(self, r: logging.LogRecord) -> str:
        record: dict = {
            "ts":      _utc_iso(),
            "level":   r.levelname,
            "logger":  r.name,
            "msg":     r.getMessage(),
        }
        # Adiciona campos estáticos
        record.update(self.STATIC_FIELDS)

        # Contexto de request HTTP (se dentro de um request Flask)
        req_id = getattr(_request_ctx, "request_id", None)
        if req_id:
            record["request_id"] = req_id
        tenant = getattr(_request_ctx, "tenant_id", None)
        if tenant:
            record["tenant_id"] = tenant

        # Campos extras passados via logger.xxx(msg, extra={...})
        for key in ("event_type", "source_ip", "severity", "threat",
                    "duration_ms", "status_code", "endpoint"):
            val = r.__dict__.get(key)
            if val is not None:
                record[key] = val

        # Traceback em caso de exceção
        if r.exc_info:
            record["exception"] = self.formatException(r.exc_info)

        return json.dumps(record, ensure_ascii=False, default=str)

h = logging.StreamHandler()
h.setFormatter(JSONFormatter())
logging.basicConfig(handlers=[h], level=logging.INFO, force=True)
logger = logging.getLogger("ids.api")

# SensitiveDataFilter — instalado após importar security (mais abaixo)
# A instalação real acontece em _install_sensitive_filter() chamado no final do setup

# ── Hostname real da máquina ──────────────────────────────────────
def _get_real_hostname() -> str:
    try:
        import subprocess
        hn = subprocess.check_output("hostname", shell=True, text=True).strip()
        if hn and hn.lower() not in ("new", "localhost", ""):
            return hn
    except Exception:
        pass
    try:
        import socket
        hn = socket.gethostname()
        if hn and hn.lower() not in ("new", "localhost", ""):
            return hn
    except Exception:
        pass
    return "netguard-host"

REAL_HOSTNAME = get_hostname()
logger.info("Hostname detectado: %s", REAL_HOSTNAME)

# ── Audit log (JSON estruturado) ──────────────────────────────────
_audit_logger = logging.getLogger("netguard.audit")
_audit_file   = os.environ.get("IDS_AUDIT_LOG", "netguard_audit.log")
if not _audit_logger.handlers:
    _ah = logging.FileHandler(_audit_file, encoding="utf-8")
    _ah.setFormatter(JSONFormatter())   # mesmo formato JSON estruturado
    _audit_logger.addHandler(_ah)
    _audit_logger.setLevel(logging.INFO)
    _audit_logger.propagate = False

def audit(action: str, actor: str = "system", ip: str = "-", detail: str = ""):
    """Registra evento no audit log em JSON estruturado."""
    _audit_logger.info(
        action,
        extra={"event_type": "audit", "actor": actor, "source_ip": ip, "detail": detail}
    )


_WELCOME_TICKET_TTL = int(os.environ.get("IDS_WELCOME_TICKET_TTL", "900"))
try:
    _FREE_PREVIEW_MINUTES = max(1, min(60, int(os.environ.get("IDS_FREE_PREVIEW_MINUTES", "15"))))
except ValueError:
    _FREE_PREVIEW_MINUTES = 15
_FREE_PREVIEW_SECONDS = _FREE_PREVIEW_MINUTES * 60
_welcome_ticket_lock = threading.Lock()
_welcome_tickets = {}


def _purge_welcome_tickets(now: float | None = None):
    now = now if now is not None else time.time()
    expired = [
        ticket for ticket, payload in _welcome_tickets.items()
        if payload.get("expires_at", 0) <= now
    ]
    for ticket in expired:
        _welcome_tickets.pop(ticket, None)


def _issue_welcome_ticket(payload: dict) -> str:
    now = time.time()
    ticket = secrets.token_urlsafe(24)
    repo_obj = globals().get("repo")
    if repo_obj and hasattr(repo_obj, "save_onboarding_ticket"):
        if repo_obj.save_onboarding_ticket(ticket, payload, _WELCOME_TICKET_TTL):
            return ticket
    with _welcome_ticket_lock:
        _purge_welcome_tickets(now)
        _welcome_tickets[ticket] = {**payload, "expires_at": now + _WELCOME_TICKET_TTL}
    return ticket


def _consume_welcome_ticket(ticket: str) -> dict | None:
    if not ticket:
        return None
    repo_obj = globals().get("repo")
    if repo_obj and hasattr(repo_obj, "consume_onboarding_ticket"):
        payload = repo_obj.consume_onboarding_ticket(ticket)
        if payload is not None:
            return payload
    now = time.time()
    with _welcome_ticket_lock:
        _purge_welcome_tickets(now)
        payload = _welcome_tickets.pop(ticket, None)
    if not payload:
        return None
    payload.pop("expires_at", None)
    return payload


def _build_welcome_context(*, demo: bool, token: str, name: str, plan_label: str,
                           server_url: str) -> dict:
    return {
        "demo": demo,
        "token": token,
        "name": name,
        "plan_label": plan_label,
        "server_url": server_url,
    }


def _render_welcome_page(**context):
    from flask import make_response, render_template

    resp = make_response(render_template("welcome.html", **context))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


def _clear_preview_cookies(resp):
    for cookie_name in ("netguard_preview_mode", "netguard_preview_expires"):
        resp.delete_cookie(cookie_name)
    return resp


def _apply_free_preview_cookies(resp, *, preview_token: str, seconds: int):
    expires_at = int(time.time()) + seconds
    resp.set_cookie(
        "netguard_token",
        preview_token,
        httponly=True,
        samesite="Lax",
        max_age=seconds,
        secure=_HTTPS_ONLY,
    )
    resp.set_cookie(
        "netguard_preview_mode",
        "free",
        httponly=False,
        samesite="Lax",
        max_age=seconds,
        secure=_HTTPS_ONLY,
    )
    resp.set_cookie(
        "netguard_preview_expires",
        str(expires_at),
        httponly=False,
        samesite="Lax",
        max_age=seconds,
        secure=_HTTPS_ONLY,
    )
    return resp


def _ensure_demo_access_token(*, min_events: int = 50, reason: str = "demo") -> str | None:
    if os.environ.get("IDS_DEMO_DISABLED", "false").lower() == "true":
        return None
    try:
        from demo_seed import seed_demo, DEMO_TOKEN, DEMO_TENANT_ID
        try:
            existing = repo.get_tenant_by_token(DEMO_TOKEN)
            event_count = repo.count(tenant_id=DEMO_TENANT_ID) if existing else 0
        except Exception:
            existing = None
            event_count = 0
        if not existing or event_count < min_events:
            seed_demo(repo, n_events=350, verbose=False)
            existing = repo.get_tenant_by_token(DEMO_TOKEN)
            logger.info("Demo seed criado/refeito | reason=%s | ip=%s | events_before=%d",
                        reason, request.remote_addr, event_count)
        if not existing:
            logger.warning("Demo token indisponivel apos seed | reason=%s", reason)
            return None
        audit("DEMO_ACCESS", ip=request.remote_addr or "-",
              detail=f"tenant={DEMO_TENANT_ID} events={event_count} reason={reason}")
        return DEMO_TOKEN
    except Exception as exc:
        logger.warning("Demo seed falhou (%s): %s", reason, exc)
        return None


def _resolve_tenant_id(fallback: str = None) -> str:
    """
    Resolve o tenant_id da requisição atual.
    Prioridade: fallback param → token/header/cookie → 'default'
    """
    if fallback:
        return fallback
    try:
        token = _extract_token()
        if token and AUTH_MODULE_OK:
            result = verify_any_token(token, repo)
            tenant = result.get("tenant")
            if tenant:
                t = dict(tenant) if not isinstance(tenant, dict) else tenant
                tid = t.get("tenant_id")
                if tid:
                    return tid
    except Exception:
        pass
    return "default"


def _resolve_tenant_with_role() -> tuple[str, str]:
    """
    Resolve (tenant_id, role) da requisição atual.

    Lógica de prioridade:
      1. AUTH_ENABLED=False → modo local single-user → admin automático
      2. Token de admin (arquivo .netguard_token) → admin
      3. Token ng_ de tenant SaaS → lê role do banco
      4. Sem token → viewer (apenas endpoints públicos)
    """
    try:
        token = _extract_token()
        if token and AUTH_MODULE_OK:
            result = verify_any_token(token, repo)
            if result.get("valid"):
                if result.get("type") == "admin":
                    return "admin", "admin"
                tenant = result.get("tenant")
                if tenant:
                    t    = dict(tenant) if not isinstance(tenant, dict) else tenant
                    tid  = t.get("tenant_id", "default")
                    role = t.get("role", "analyst")
                    return tid, role
    except Exception:
        pass
    # Modo local (AUTH_ENABLED=False): usuário único, acesso total
    if not AUTH_ENABLED:
        return "admin", "admin"
    return "default", "viewer"


# ── App ───────────────────────────────────────────────────────────
app = Flask(__name__)

# ── Limites globais de request ────────────────────────────────────
# Previne DoS por upload de payload gigante (padrão Flask: 16 MB)
app.config["MAX_CONTENT_LENGTH"] = int(
    os.environ.get("MAX_CONTENT_LENGTH", str(5 * 1024 * 1024))  # 5 MB
)

# ── Security module ───────────────────────────────────────────────
try:
    from security import (
        hash_token, verify_token,
        get_bf_guard,
        require_role,
        mask_sensitive, SensitiveDataFilter,
        validate_redirect_url, safe_filename, sanitize_csv_cell,
        SESSION_MAX_AGE_SECONDS,
        rotate_token,
    )
    SECURITY_OK = True
except Exception as _sec_err:
    SECURITY_OK = False
    print(f"[WARN] Security module: {_sec_err}")
    # No-op fallbacks para não quebrar o app
    def hash_token(t): return t          # noqa
    def verify_token(t, h): return t == h  # noqa
    def require_role(*r): return lambda f: f  # noqa
    def mask_sensitive(t): return t      # noqa
    def validate_redirect_url(u, **_): return u or "/"  # noqa
    def safe_filename(f, d="download"): return os.path.basename(f) if f else d  # noqa
    def sanitize_csv_cell(v): return v   # noqa
    def get_bf_guard(**_): return None   # noqa
    SESSION_MAX_AGE_SECONDS = 8 * 3600  # noqa

# ── SensitiveDataFilter — instala em todos os handlers de logging ──
if SECURITY_OK:
    _sdf = SensitiveDataFilter()
    for _handler in logging.root.handlers:
        _handler.addFilter(_sdf)
    # Garante também nos loggers nomeados usados pelo app
    for _log_name in ("ids.api", "netguard.audit", "netguard.security",
                      "ids.sigma", "werkzeug"):
        _named = logging.getLogger(_log_name)
        for _h in _named.handlers:
            _h.addFilter(_sdf)
    logger.info("SensitiveDataFilter instalado em todos os handlers de logging")

# ── CORS — whitelist configurável via env (não mais wildcard) ─────
_cors_origins_raw = os.environ.get("IDS_CORS_ORIGINS", "")
_cors_origins = (
    [o.strip() for o in _cors_origins_raw.split(",") if o.strip()]
    if _cors_origins_raw
    else ["http://localhost:5000", "http://127.0.0.1:5000"]
)
CORS(app, resources={r"/api/*": {"origins": _cors_origins}})

# ── Security headers via Flask-Talisman (se disponível) ──────────
_HTTPS_ONLY = os.environ.get("HTTPS_ONLY", "false").lower() == "true"
try:
    from flask_talisman import Talisman
    Talisman(
        app,
        force_https=_HTTPS_ONLY,
        strict_transport_security=_HTTPS_ONLY,
        strict_transport_security_max_age=31536000,
        content_security_policy={
            "default-src": "'self'",
            "script-src":  "'self' 'unsafe-inline' https://js.stripe.com https://cdnjs.cloudflare.com",
            "style-src":   "'self' 'unsafe-inline' https://fonts.googleapis.com",
            "font-src":    "'self' https://fonts.gstatic.com",
            "img-src":     "'self' data:",
            "frame-src":   "https://js.stripe.com",
            "connect-src": "'self'",
        },
        x_frame_options="DENY",
        x_content_type_options=True,
        referrer_policy="strict-origin-when-cross-origin",
        session_cookie_secure=_HTTPS_ONLY,
        session_cookie_http_only=True,
    )
    logger.info("Flask-Talisman ativo | HTTPS_ONLY=%s", _HTTPS_ONLY)
except ImportError:
    logger.warning("flask-talisman não instalado — headers de segurança desativados. "
                   "Instale com: pip install flask-talisman")

# ── Rate Limiting via Flask-Limiter (se disponível) ──────────────
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address

    def _skip_rate_limit() -> bool:
        return bool(app.config.get("TESTING"))

    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["600 per minute"],  # limite global
        storage_uri="memory://",
        headers_enabled=True,                # X-RateLimit-* headers
        default_limits_exempt_when=_skip_rate_limit,
    )
    # Atalhos de decorator reutilizáveis
    _limit_login    = limiter.limit("10 per minute", exempt_when=_skip_rate_limit)
    _limit_validate = limiter.limit("10 per minute", exempt_when=_skip_rate_limit)
    _limit_trial    = limiter.limit("3 per hour", exempt_when=_skip_rate_limit)
    _limit_contact  = limiter.limit("5 per hour", exempt_when=_skip_rate_limit)
    _limit_report   = limiter.limit("5 per minute", exempt_when=_skip_rate_limit)
    _limit_ioc_check= limiter.limit("60 per minute", exempt_when=_skip_rate_limit)
    _limit_train    = limiter.limit("2 per minute", exempt_when=_skip_rate_limit)
    logger.info("Flask-Limiter ativo | default=600/min")
except ImportError:
    logger.warning("flask-limiter não instalado — rate limiting desativado. "
                   "Instale com: pip install flask-limiter")
    # Fallback: decorators que não fazem nada
    class _NoopLimiter:
        def limit(self, *a, **kw):
            def decorator(f): return f
            return decorator
        def exempt(self, f): return f
    limiter       = _NoopLimiter()
    _limit_login  = _limit_validate = _limit_trial = _limit_contact = _noop = limiter.limit("")
    _limit_report = _limit_ioc_check = _limit_train = _noop

# ── Whitelist ─────────────────────────────────────────────────────
WHITELIST = ["127.0.0.1","::1","192.168.15.1","192.168.15.2"]
extras = os.environ.get("IDS_WHITELIST_IPS","")
if extras:
    WHITELIST += [ip.strip() for ip in extras.split(",") if ip.strip()]

AUTO_BLOCK = os.environ.get("IDS_AUTO_BLOCK","false").lower() == "true"

ids = IDSEngine(
    db_path=os.environ.get("IDS_DB_PATH","ids_detections.db"),
    whitelist_ips=WHITELIST,
    auto_block=AUTO_BLOCK,
)
log_proc = LogProcessor()

# ── Per-tenant IDSEngine cache ────────────────────────────────────
# Cada tenant recebe seu próprio banco ids_detections_<tid>.db
# garantindo isolamento total de dados entre clientes.
_ids_engines: dict = {}
_ids_lock    = threading.Lock()
_IDS_BASE_PATH = os.environ.get("IDS_DB_PATH", "ids_detections.db")

def _get_ids(tid: str = None) -> "IDSEngine":
    """
    Retorna o IDSEngine do tenant `tid`.
    - tid None / 'default' → instância global (retrocompatibilidade)
    - qualquer outro tid   → instância isolada com DB próprio (criada sob demanda)
    """
    if not tid or tid == "default":
        return ids
    with _ids_lock:
        if tid not in _ids_engines:
            db_dir  = os.path.dirname(_IDS_BASE_PATH) or "."
            db_name = f"ids_detections_{tid[:36].replace('-','')}.db"
            _ids_engines[tid] = IDSEngine(
                db_path      = os.path.join(db_dir, db_name),
                whitelist_ips= WHITELIST,
                auto_block   = AUTO_BLOCK,
            )
        return _ids_engines[tid]

# ── Event Repository (multi-tenant storage) ───────────────────────
from storage.event_repository import EventRepository
repo = EventRepository()
app._repo = repo

# ── Auth ──────────────────────────────────────────────────────────
# Nota: auth() importado de auth.py (token-based) tem prioridade.
# API_KEY é um segundo mecanismo legado via header X-API-Key.
API_KEY = os.environ.get("IDS_API_KEY","")

def _api_key_auth(f):
    """Auth legado por X-API-Key (usado em endpoints de agente externo)."""
    @functools.wraps(f)
    def d(*a,**kw):
        if not API_KEY: return f(*a,**kw)
        k = request.headers.get("X-API-Key") or request.args.get("api_key")
        if k != API_KEY: return jsonify({"error":"Unauthorized"}),401
        return f(*a,**kw)
    return d

# ── DNS cache (non-blocking, thread-pool resolver) ─────────────────
_dns_cache: dict = {}
_dns_lock = threading.Lock()

def _init_dns_executor():
    from concurrent.futures import ThreadPoolExecutor
    return ThreadPoolExecutor(max_workers=6, thread_name_prefix="ng-dns")

_dns_executor = _init_dns_executor()

def resolve_ip(ip: str) -> str:
    """Non-blocking DNS reverse lookup.
    Returns cached hostname immediately; if not cached, submits resolution
    to a thread pool and returns the IP string — caller gets the real hostname
    on the next cache hit (next request cycle).
    """
    with _dns_lock:
        cached = _dns_cache.get(ip)
        if cached is not None:
            return cached

    def _do_resolve(addr: str):
        try:
            host = socket.gethostbyaddr(addr)[0]
        except Exception:
            host = addr
        with _dns_lock:
            _dns_cache[addr] = host

    try:
        _dns_executor.submit(_do_resolve, ip)
    except Exception:
        pass
    return ip  # return raw IP now; hostname available on next hit

# ── TTL cache with stale-while-revalidate ──────────────────────────
# Fresh window  → return immediately, no refresh triggered
# Stale window  → return old data immediately, trigger bg refresh
# Beyond stale  → data treated as absent (forces sync compute)
_GRAPH_CACHE_TTL   = 30.0   # seconds until graph snapshot is stale
_GRAPH_STALE_TTL   = 120.0  # seconds until stale graph is discarded
_GEO_CACHE_TTL     = 60.0   # seconds until geo snapshot is stale
_GEO_STALE_TTL     = 300.0  # seconds until stale geo is discarded

_graph_cache: dict = {}
_geo_cache: dict   = {}
_graph_cache_lock  = threading.Lock()
_geo_cache_lock    = threading.Lock()

# Tracks which tenant bg-refresh jobs are in-flight
_bg_running: set        = set()
_bg_running_lock        = threading.Lock()

def _ttl_cache_get(cache: dict, lock: threading.Lock, key: str, ttl: float):
    """Legacy helper — returns data only within fresh window."""
    now = time.time()
    with lock:
        entry = cache.get(key)
        if entry and now - entry["ts"] < ttl:
            return entry["data"]
    return None

def _ttl_cache_get_swr(cache: dict, lock: threading.Lock, key: str,
                       fresh_ttl: float, stale_ttl: float):
    """Stale-While-Revalidate: returns (data, is_stale).
    data is None only when no entry exists or entry is beyond stale_ttl.
    """
    now = time.time()
    with lock:
        entry = cache.get(key)
    if not entry:
        return None, False
    age = now - entry["ts"]
    if age < fresh_ttl:
        return entry["data"], False   # fresh — serve as-is
    if age < stale_ttl:
        return entry["data"], True    # stale but usable
    return None, False                # too old — discard

def _ttl_cache_set(cache: dict, lock: threading.Lock, key: str, data):
    with lock:
        cache[key] = {"ts": time.time(), "data": data}

def _trigger_bg_refresh(job_key: str, fn, *args):
    """Launch fn(*args) in a daemon thread if not already running for job_key."""
    with _bg_running_lock:
        if job_key in _bg_running:
            return
        _bg_running.add(job_key)

    def _run():
        try:
            fn(*args)
        except Exception as _exc:
            logging.getLogger("netguard.cache").warning("bg refresh %s failed: %s", job_key, _exc)
        finally:
            with _bg_running_lock:
                _bg_running.discard(job_key)

    threading.Thread(target=_run, daemon=True, name=f"bg-{job_key}").start()

# ── Descoberta de dispositivos ────────────────────────────────────
_dispositivos: list = []
_ultimo_scan: float = 0.0

def scan_rede_local(rede: str = "192.168.15.0/24") -> list:
    global _dispositivos, _ultimo_scan
    now = time.time()
    if now - _ultimo_scan < 60 and _dispositivos:
        return _dispositivos
    dispositivos = {}
    try:
        r = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
        for linha in r.stdout.split("\n"):
            partes = linha.strip().split()
            if len(partes) >= 3:
                ip = partes[0]; mac = partes[1]
                try:
                    addr = ipaddress.ip_address(ip)
                    if addr in ipaddress.ip_network(rede, strict=False):
                        if mac not in ("ff-ff-ff-ff-ff-ff","ff:ff:ff:ff:ff:ff"):
                            dispositivos[ip] = {
                                "ip": ip, "mac": mac.upper(), "hostname": "",
                                "status": "online", "tipo": _classificar_dispositivo(ip, mac),
                            }
                except Exception: pass
    except Exception as e:
        logger.warning("ARP scan erro: %s", e)

    def ping_ip(ip_str):
        try:
            r2 = subprocess.run(["ping","-n","1","-w","300",ip_str], capture_output=True, timeout=2)
            if r2.returncode == 0 and ip_str not in dispositivos:
                dispositivos[ip_str] = {"ip":ip_str,"mac":"—","hostname":"","status":"online","tipo":"dispositivo"}
        except Exception: pass

    net = ipaddress.ip_network(rede, strict=False)
    threads = [threading.Thread(target=ping_ip, args=(str(h),), daemon=True) for h in list(net.hosts())[:254]]
    for t in threads: t.start()
    for t in threads: t.join(timeout=0.5)

    def resolver_hostnames():
        for ip, d in list(dispositivos.items()):
            if d["hostname"] == "": d["hostname"] = resolve_ip(ip)
    threading.Thread(target=resolver_hostnames, daemon=True).start()

    gw = rede.replace("0/24","1"); me = rede.replace("0/24","2")
    if gw in dispositivos:
        dispositivos[gw]["tipo"] = "gateway"
        dispositivos[gw]["hostname"] = dispositivos[gw]["hostname"] or "Gateway/Roteador"
    if me in dispositivos:
        dispositivos[me]["tipo"] = "local"
        dispositivos[me]["hostname"] = dispositivos[me]["hostname"] or "Este computador"

    # Enrich with open ports for local IPs
    def enrich_device(d):
        ip = d["ip"]
        # Try to get open ports via nmap-style connect scan on common ports
        d["open_ports"] = []
        d["services"]   = []
        common = [21,22,23,25,53,80,110,135,139,143,443,445,3389,8080,8443]
        for port in common:
            try:
                s = __import__('socket').socket(__import__('socket').AF_INET, __import__('socket').SOCK_STREAM)
                s.settimeout(0.15)
                result = s.connect_ex((ip, port))
                s.close()
                if result == 0:
                    d["open_ports"].append(port)
                    svc_map = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
                               110:"POP3",135:"RPC",139:"NetBIOS",143:"IMAP",443:"HTTPS",
                               445:"SMB",3389:"RDP",8080:"HTTP-Alt",8443:"HTTPS-Alt"}
                    d["services"].append(svc_map.get(port, str(port)))
            except Exception:
                pass
        # MAC vendor lookup (first 3 octets)
        mac = d.get("mac","")
        if mac and mac != "—":
            prefix = mac.replace("-",":").upper()[:8]
            vendor_map = {
                "00:50:56":"VMware","00:0C:29":"VMware","00:1C:42":"Parallels",
                "B8:27:EB":"Raspberry Pi","DC:A6:32":"Raspberry Pi",
                "E4:5F:01":"Raspberry Pi","28:CD:C1":"Apple","3C:22:FB":"Apple",
                "AC:BC:32":"Apple","00:1A:11":"Google","94:EB:2C":"TP-Link",
                "C4:E9:84":"TP-Link","50:C7:BF":"TP-Link","78:11:DC":"Huawei",
                "00:46:4B":"Huawei","54:89:98":"Huawei","B4:FB:E4":"ASUSTek",
                "04:D9:F5":"ASUSTek","10:78:D2":"ASUSTek","00:21:CC":"Dell",
                "F4:8E:38":"Dell","18:66:DA":"Dell","00:25:90":"Dell",
                "00:50:F2":"Microsoft","28:18:78":"Microsoft","00:15:5D":"Microsoft",
                "00:1B:21":"Intel","8C:8D:28":"Intel","A0:36:9F":"Intel",
                "00:23:AE":"Cisco","00:1E:F7":"Cisco","CC:46:D6":"Cisco",
            }
            d["vendor"] = vendor_map.get(prefix, "")

    # Run enrichment in parallel threads
    enrich_threads = [threading.Thread(target=enrich_device, args=(d,), daemon=True)
                      for d in dispositivos.values()]
    for t in enrich_threads: t.start()
    for t in enrich_threads: t.join(timeout=2.0)

    _dispositivos = sorted(dispositivos.values(), key=lambda x: [int(p) for p in x["ip"].split(".")])
    _ultimo_scan = now
    logger.info("Scan de rede: %d dispositivos encontrados", len(_dispositivos))
    return _dispositivos

def _classificar_dispositivo(ip: str, mac: str) -> str:
    mac_clean = mac.replace("-","").replace(":","").upper()
    oui = mac_clean[:6] if len(mac_clean) >= 6 else ""
    try:
        if int(mac_clean[1], 16) & 0x2: return "celular"
    except Exception: pass
    oui_map = {
        "900A62":"gateway","E8744A":"gateway","006755":"gateway",
        "001CB3":"apple","A45E60":"apple","F0B429":"apple","3C0754":"apple",
        "ACDE48":"apple","F0DCE2":"apple","8866A5":"apple","DC2B2A":"apple",
        "001632":"samsung","8C71F8":"samsung","E8D0FC":"samsung","F45298":"samsung",
        "F4F5D8":"google","54607E":"google","1C62B8":"google",
        "F0272D":"amazon","A002DC":"amazon","FC65DE":"amazon","74C246":"amazon",
        "286C07":"xiaomi","9C99A0":"xiaomi","F8A45F":"xiaomi",
        "B0487A":"tplink","C46E1F":"tplink","F8D111":"tplink","E8DE27":"tplink",
        "8C8D28":"pc","3413E8":"pc","A4C3F0":"pc","141416":"pc","A0A4C5":"pc",
        "00E04C":"pc","EC086B":"pc","145D34":"pc",
    }
    tipo = oui_map.get(oui, "dispositivo")
    if ip.endswith(".1"): tipo = "gateway"
    return tipo

# ── Sistema: info de processos/rede via psutil ────────────────────
def get_system_info() -> dict:
    """Coleta métricas detalhadas do sistema usando psutil."""
    try:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('C:\\') if os.name == 'nt' else psutil.disk_usage('/')
        net_io = psutil.net_io_counters()
        boot = psutil.boot_time()
        uptime_s = int(time.time() - boot)
        uptime = f"{uptime_s//3600}h {(uptime_s%3600)//60}m"

        # Top processes by CPU
        procs = []
        for p in sorted(psutil.process_iter(['pid','name','cpu_percent','memory_percent','status']),
                        key=lambda x: x.info.get('cpu_percent') or 0, reverse=True)[:15]:
            try:
                try:
                    nconns = len(p.net_connections())
                except Exception:
                    nconns = 0
                procs.append({
                    "pid":    p.info['pid'],
                    "name":   p.info['name'],
                    "cpu":    round(p.info.get('cpu_percent') or 0, 1),
                    "mem":    round(p.info.get('memory_percent') or 0, 1),
                    "status": p.info.get('status','?'),
                    "conns":  nconns,
                })
            except Exception: pass

        # Network interfaces
        interfaces = []
        for name, addrs in psutil.net_if_addrs().items():
            stats = psutil.net_if_stats().get(name)
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    interfaces.append({
                        "name":  name,
                        "ip":    addr.address,
                        "mask":  addr.netmask,
                        "speed": stats.speed if stats else 0,
                        "up":    stats.isup if stats else False,
                    })

        # Open listening ports
        listening = []
        for conn in psutil.net_connections(kind='tcp'):
            if conn.status == 'LISTEN':
                try:
                    proc = psutil.Process(conn.pid).name() if conn.pid else '?'
                except Exception:
                    proc = f'pid:{conn.pid}'
                listening.append({
                    "port": conn.laddr.port,
                    "addr": conn.laddr.ip,
                    "pid":  conn.pid,
                    "process": proc,
                })
        listening.sort(key=lambda x: x['port'])

        return {
            "cpu_percent":   cpu,
            "mem_percent":   mem.percent,
            "mem_used_mb":   round(mem.used/1024/1024),
            "mem_total_mb":  round(mem.total/1024/1024),
            "disk_percent":  disk.percent,
            "disk_free_gb":  round(disk.free/1024/1024/1024, 1),
            "disk_total_gb": round(disk.total/1024/1024/1024, 1),
            "net_sent_mb":   round(net_io.bytes_sent/1024/1024, 1),
            "net_recv_mb":   round(net_io.bytes_recv/1024/1024, 1),
            "net_packets_sent": net_io.packets_sent,
            "net_packets_recv": net_io.packets_recv,
            "uptime":        uptime,
            "boot_time":     datetime.fromtimestamp(boot).isoformat(),
            "processes":     procs,
            "interfaces":    interfaces,
            "listening":     listening,
        }
    except Exception as e:
        logger.warning("System info error: %s", e)
        return {"error": str(e)}

# ── Monitor state ─────────────────────────────────────────────────
monitor_status = {
    "rodando":False,"ciclo":0,"ultimo_ciclo":None,
    "event_log":"aguardando","conexoes":"aguardando","processos":"aguardando",
    "captura":"iniciando",
}
conexoes_ativas: list = []

# ── Apps confiáveis ───────────────────────────────────────────────
BROWSERS_E_APPS = {
    "brave.exe","chrome.exe","firefox.exe","msedge.exe",
    "opera.exe","vivaldi.exe","chromium.exe","iexplore.exe",
    "svchost.exe","system","lsass.exe","services.exe","explorer.exe",
    "wininit.exe","winlogon.exe","taskhostw.exe","sihost.exe",
    "runtimebroker.exe","searchhost.exe","fontdrvhost.exe",
    "applicationframehost.exe","shellexperiencehost.exe",
    "wuauclt.exe","musnotification.exe","wsappx.exe",
    "onedrive.exe","teams.exe","slack.exe","discord.exe",
    "spotify.exe","zoom.exe","skype.exe","outlook.exe",
    "code.exe","cursor.exe","windowsterminal.exe",
    "python.exe","pythonw.exe","node.exe","git.exe",
    "dropbox.exe","googledrivefs.exe","steam.exe",
    "obs64.exe","vlc.exe","microsoftedgeupdate.exe",
    "steam.exe","steamwebhelper.exe","steamservice.exe","gameoverlayui.exe",
    "mpdefendercoreservice.exe","mpdefendercoreserv.exe","msmpeng.exe","nissrv.exe",
    "securityhealthsystray.exe","securityhealthservice.exe",
    "msedgewebview2.exe","webview2.exe",
    "claude.exe","notion.exe","figma.exe","linear.exe",
    "whatsapp.exe","signal.exe","telegram.exe",
    "postman.exe","insomnia.exe","1password.exe",
    "winstore.app.exe","winstoredraftapp.exe","microsoftstore.exe","widgets.exe",
    "msMpEng.exe","nisssrv.exe","securityhealthservice.exe",
    "csrss.exe","smss.exe","spoolsv.exe","RuntimeBroker.exe",
    "Teams.exe","Slack.exe","discord.exe",
}

PROCESSOS_SUSPEITOS = [
    "mimikatz","meterpreter","netcat","ncat","nc.exe",
    "pwdump","fgdump","wce.exe","gsecdump","procdump",
    "psexec","wmiexec","dcsync","bloodhound",
    "cobaltstrike","cobalt_strike","beacon.exe",
]

PORTAS_SUSPEITAS = {
    4444,1337,31337,8888,9001,9002,6666,6667,6668,1234,
    5555,7777,8989,12345,54321,65535,1111,2222,3333,
}

PORTAS_LEGITIMAS = {
    80,443,8080,8443,53,22,3389,21,25,587,465,993,995,
    110,143,389,636,3306,5432,1433,27017,6379,5672,
    5000,3000,8000,4200,9200,5601,8888,
}

REDE_LOCAL = "192.168.15."

_conexoes_vistas:   set = set()
_processos_alertados: set = set()
_pid_cache: dict = {}
_pid_cache_time: float = 0.0

# Locks para thread safety nos sets/dicts globais modificados por threads de monitor
_conexoes_lock    = threading.Lock()
_processos_lock   = threading.Lock()
_pid_cache_lock   = threading.Lock()

def get_pid_name_cached(pid) -> str:
    global _pid_cache, _pid_cache_time
    now = time.time()
    with _pid_cache_lock:
        if now - _pid_cache_time > 30:
            try:
                _pid_cache = get_pid_name_map()
                _pid_cache_time = now
            except Exception:
                pass
        return _pid_cache.get(str(pid), "")

def ip_ok(ip: str) -> bool:
    return ip.startswith(REDE_LOCAL) or ip in ("127.0.0.1","::1","0.0.0.0")

# ── Input sanitization ────────────────────────────────────────────
import html as _html
_DANGEROUS_PATTERNS = re.compile(
    r'(<\s*script|javascript\s*:|on\w+\s*=|data\s*:\s*text/html|'
    r'union\s+select|drop\s+table|insert\s+into|delete\s+from|'
    r'--\s|/\*|\*/|xp_cmdshell)',
    re.IGNORECASE,
)

def sanitize(value, max_len: int = 512, label: str = "input") -> str:
    """Sanitiza string de entrada: escapa HTML, bloqueia padrões perigosos."""
    if value is None:
        return ""
    s = str(value)[:max_len]
    if _DANGEROUS_PATTERNS.search(s):
        logger.warning("sanitize: padrão suspeito em %s: %.80r", label, s)
        s = _DANGEROUS_PATTERNS.sub("", s)
    return _html.escape(s, quote=True)


def has_dangerous_input(value) -> bool:
    if value is None:
        return False
    return bool(_DANGEROUS_PATTERNS.search(str(value)))

def sanitize_ip(value) -> str:
    """Valida e retorna IP limpo ou '' se inválido."""
    if not value:
        return ""
    s = str(value).strip()[:45]
    try:
        import ipaddress as _ip
        return str(_ip.ip_address(s))
    except ValueError:
        return ""

# ── Threat Intelligence Cache (TTL 1h) ───────────────────────────
_TI_CACHE: dict = {}          # ip -> {"data": ..., "ts": float}
_TI_CACHE_TTL = 3600          # segundos
_TI_CACHE_MAX = 2000          # evita crescimento ilimitado
_ti_cache_lock = threading.Lock()

def _ti_lookup_ip(ip: str) -> dict:
    """Consulta threat intel com cache TTL de 1h.
    Evita chamadas repetidas a APIs externas (VirusTotal, AbuseIPDB).
    NOTA: nome com _ para não colidir com a Flask route ti_lookup().
    """
    now = time.time()
    with _ti_cache_lock:
        entry = _TI_CACHE.get(ip)
        if entry and now - entry["ts"] < _TI_CACHE_TTL:
            return entry["data"]   # cache hit

    # cache miss — consulta a API
    result = {"score": 0, "categoria": "ok"}
    try:
        from threat_intel import intel as _ti
        result = _ti.analisar(ip) or result
    except Exception:
        pass

    with _ti_cache_lock:
        # evict entradas antigas se cache muito grande
        if len(_TI_CACHE) >= _TI_CACHE_MAX:
            oldest = sorted(_TI_CACHE, key=lambda k: _TI_CACHE[k]["ts"])
            for k in oldest[:200]:
                del _TI_CACHE[k]
        _TI_CACHE[ip] = {"data": result, "ts": now}

    return result

@app.route("/api/threat-cache/stats")
@auth
def ti_cache_stats():
    """Retorna estatísticas do cache de threat intelligence."""
    with _ti_cache_lock:
        n = len(_TI_CACHE)
        oldest = min((_TI_CACHE[k]["ts"] for k in _TI_CACHE), default=0)
    return jsonify({
        "cached_ips": n,
        "max_size":   _TI_CACHE_MAX,
        "ttl_seconds": _TI_CACHE_TTL,
        "oldest_entry_age": round(time.time() - oldest) if oldest else 0,
    })

def analisar(log: str, ip: str = None, field: str = "raw", origem: str = "", tenant_id: str = None):
    ctx = {"field": field}
    if origem: ctx["origem"] = origem
    _ids_inst = _get_ids(tenant_id or _resolve_tenant_id())
    eventos = _ids_inst.analyze(log, ip, ctx)

    # Threat Intel — checar IP contra feeds TI (não bloqueia pipeline)
    if TI_AVAILABLE and ip and ip not in ("—", ""):
        try:
            match = _get_ti_feed().lookup(ip, tenant_id=tenant_id or "global")
            if match:
                from ids_engine import Detection
                ti_evt = Detection(
                    threat_name=f"[TI] {match['threat_type'] or match['source']} — {ip}",
                    severity="critical" if match["severity"] == "critical" else "high",
                    source_ip=ip,
                    log_entry=log[:300],
                    method="threat_intel",
                    confidence=match["confidence"] / 100.0,
                )
                if hasattr(ti_evt, "mitre_tactic"):
                    ti_evt.mitre_tactic = "command_and_control"
                eventos.append(ti_evt)
        except Exception:
            pass

    # OWASP CRS — análise de payload web
    if owasp_engine and field in ("url","body","query_string","raw","apache"):
        owasp_matches = owasp_engine.analyze(log)
        for om in owasp_matches:
            already = any(e.threat_name == om.title for e in eventos)
            if not already:
                log_ao_vivo({
                    "type":   "owasp",
                    "sev":    om.severity,
                    "threat": f"[OWASP {om.rule_id}] {om.title}",
                    "ip":     ip or "—",
                    "msg":    f"{om.category} · {om.evidence[:60]}",
                })

    # Sigma Rules — análise adicional
    if sigma_engine:
        sigma_matches = sigma_engine.match(log, ctx)
        for rule in sigma_matches:
            # Evita duplicata com detecções do IDS
            already = any(e.threat_name == rule.title for e in eventos)
            if not already:
                # Injeta como detecção sintética
                from ids_engine import Detection  # noqa: F401
                try:
                    fake_ctx = {"field": field, "sigma": True}
                    synthetic = _ids_inst.analyze(
                        f"SIGMA:{rule.id} {log[:200]}", ip,
                        {"field": field, "sigma_rule": rule.title}
                    )
                    if not synthetic:
                        # Cria entrada de log direto
                        log_ao_vivo({
                            "type": "sigma",
                            "sev":  rule.level,
                            "threat": f"[Sigma] {rule.title}",
                            "ip":   ip or "—",
                            "msg":  rule.description,
                        })
                except Exception:
                    pass

    for e in eventos:
        logger.warning("DETECÇÃO | %s | sev=%s | ip=%s | %s", e.threat_name, e.severity, ip, log[:80])
        # Feed Fail2Ban
        if F2B_AVAILABLE and fail2ban and ip:
            try:
                ban = fail2ban.ingest({
                    "source_ip":   ip,
                    "threat_name": e.threat_name,
                    "severity":    e.severity,
                    "method":      "ids",
                    "timestamp":   _utc_iso(),
                })
                if ban:
                    log_ao_vivo({
                        "type": "fail2ban",
                        "sev":  "high",
                        "threat": f"🚫 BAN: {ip} ({ban.jail_label})",
                        "ip":   ip,
                        "msg":  f"Banido após {ban.count} tentativas — expira: {ban.time_remaining()}",
                    })
                    logger.warning("FAIL2BAN | ip=%s | jail=%s | count=%d", ip, ban.jail, ban.count)
            except Exception as _fe:
                pass

        # Feed kill chain correlator
        if kc_correlator and ip:
            try:
                kc_correlator.ingest({
                    "source_ip":     ip,
                    "threat_name":   e.threat_name,
                    "severity":      e.severity,
                    "mitre_tactic":  e.mitre_tactic if hasattr(e,'mitre_tactic') else "",
                    "mitre_technique": e.mitre_technique if hasattr(e,'mitre_technique') else "",
                    "method":        "ids",
                    "log_entry":     log[:200],
                    "confidence":    e.confidence if hasattr(e,'confidence') else 1.0,
                    "timestamp":     _utc_iso(),
                })
            except Exception:
                pass

        # Webhook dispatch — envia alerta em background
        if WEBHOOK_AVAILABLE:
            try:
                _get_webhook_engine().dispatch({
                    "severity":   e.severity,
                    "threat":     e.threat_name,
                    "event_type": "detection",
                    "source_ip":  ip or "—",
                    "hostname":   os.environ.get("COMPUTERNAME", "netguard-host"),
                    "timestamp":  _utc_iso(),
                    "details":    {"raw": log[:300]},
                })
            except Exception:
                pass

        # Incident Response Playbook — auto-trigger em detecções críticas
        if PLAYBOOK_AVAILABLE and e.severity in ("critical", "high"):
            try:
                _get_playbook_engine().auto_trigger({
                    "threat_name":     e.threat_name,
                    "severity":        e.severity,
                    "source_ip":       ip or "",
                    "mitre_tactic":    e.mitre_tactic if hasattr(e, "mitre_tactic") else "",
                    "log_entry":       log[:400],
                    "timestamp":       _utc_iso(),
                }, tenant_id=tenant_id or "default")
            except Exception:
                pass

        # Forensics Snapshot — captura automática em alertas críticos
        if FORENSICS_AVAILABLE and e.severity == "critical":
            try:
                _get_forensics_engine().capture_async(
                    trigger_type="alert",
                    trigger_event={
                        "threat_name": e.threat_name,
                        "source_ip":   ip or "",
                        "log_entry":   log[:400],
                    },
                    severity="critical",
                    tenant_id=tenant_id or "default",
                )
            except Exception:
                pass

    # MITRE ATT&CK — mapeia log para técnicas e registra hits
    if MITRE_AVAILABLE and log:
        try:
            me = _get_mitre_engine()
            techniques = me.map_event(log)
            if techniques:
                me.record_hit({"raw": log[:300], "source_ip": ip or "", "origem": origem}, techniques)
        except Exception:
            pass

    return eventos

# ── Monitor: Event Log ────────────────────────────────────────────
def checar_event_log():
    try:
        events = get_security_events(seconds_back=35)
        count  = 0
        for ev in events:
            msg = f"EventID={ev.get('event_id','')} {ev.get('message','')}"
            analisar(msg, "127.0.0.1", "syslog", ev.get("source", "event_log"))
            count += 1
        monitor_status["event_log"] = f"{count} eventos novos" if count else "sem eventos novos"
    except Exception as e:
        monitor_status["event_log"] = f"erro: {e}"

# ── Monitor: Conexões ─────────────────────────────────────────────
def checar_conexoes():
    try:
        conns_raw  = platform_get_connections()
        sus=0; total=0; info_conexoes=[]; conn_map={}

        for conn_entry in conns_raw:
            ip_r      = conn_entry.get("ip", "")
            porta     = conn_entry.get("port", 0)
            proc_nome = conn_entry.get("process", "")
            total    += 1

            is_trusted = any(b in proc_nome for b in [x.lower() for x in BROWSERS_E_APPS])

            # Popula mapa de conexões
            if proc_nome not in conn_map:
                conn_map[proc_nome] = {
                    "process": proc_nome,
                    "connections": [],
                    "trusted": is_trusted,
                }
            conn_map[proc_nome]["connections"].append({
                "dst_ip":    ip_r,
                "dst_port":  porta,
                "local_port": conn_entry.get("local_port", 0),
                "hostname":  resolve_ip(ip_r) if not ip_r.startswith("127.") else "localhost",
            })

            if ip_ok(ip_r) or ip_r.startswith("127."): continue

            chave = f"{ip_r}:{porta}:{proc_nome}"
            with _conexoes_lock:
                nova_suspeita  = porta in PORTAS_SUSPEITAS and chave not in _conexoes_vistas
                nova_externa   = (not ip_r.startswith(REDE_LOCAL) and porta not in PORTAS_LEGITIMAS
                                  and porta < 1024 and not is_trusted and chave not in _conexoes_vistas)
                if nova_suspeita or nova_externa:
                    _conexoes_vistas.add(chave)
            if nova_suspeita:
                analisar(f"SUSPICIOUS CONNECTION DST={ip_r} DPT={porta} PROC={proc_nome}", ip_r, "firewall")
                sus += 1
            elif nova_externa:
                analisar(f"EXTERNAL CONNECTION DST={ip_r} DPT={porta} PROC={proc_nome}", ip_r, "firewall")
                sus += 1

            if not is_trusted and not ip_ok(ip_r):
                info_conexoes.append(f"{proc_nome}→{ip_r}:{porta}")

        global conexoes_ativas
        conexoes_ativas = sorted(conn_map.values(), key=lambda x: (x["trusted"], x["process"]))
        resumo = f"{total} ativas | {sus} suspeitas"
        if info_conexoes: resumo += f" | {', '.join(info_conexoes[:3])}"
        monitor_status["conexoes"] = resumo
    except Exception as e:
        monitor_status["conexoes"] = f"erro: {e}"

# ── Monitor: Processos ────────────────────────────────────────────
def checar_processos():
    try:
        procs = get_processes()
        found = []
        for p in procs:
            nome = p.get("name", "").lower()
            pid  = str(p.get("pid", "?"))
            for s in PROCESSOS_SUSPEITOS:
                if s.lower() in nome:
                    with _processos_lock:
                        novo = nome not in _processos_alertados
                        if novo:
                            _processos_alertados.add(nome)
                    if novo:
                        analisar(f"Suspicious process running: {nome} PID={pid}", "127.0.0.1", "command", "process_monitor")
                        found.append(nome)
        monitor_status["processos"] = f"suspeitos: {found}" if found else "nenhum suspeito"
    except Exception as e:
        monitor_status["processos"] = f"erro: {e}"

def loop_monitor(intervalo=30):
    monitor_status["rodando"] = True
    logger.info("Monitor iniciado (intervalo=%ds)", intervalo)
    while monitor_status["rodando"]:
        monitor_status["ciclo"] += 1
        monitor_status["ultimo_ciclo"] = datetime.now().strftime('%H:%M:%S')
        with app.app_context():
            checar_event_log()
            checar_conexoes()
            checar_processos()
        logger.info("Ciclo #%d | evlog=%s | rede=%s | proc=%s",
                    monitor_status["ciclo"],
                    monitor_status["event_log"],
                    monitor_status["conexoes"],
                    monitor_status["processos"])

        # ── Detection Engine — analisa snapshot do sistema ────────
        if DE_AVAILABLE and detection_engine:
            logger.debug("SOC snapshot: procs=%d ports=%d", len(conexoes_ativas or []), 0)
            try:
                # Coleta processos
                procs_snapshot = []
                if PSUTIL_OK:
                    for p in psutil.process_iter(['pid','name','cpu_percent','memory_percent','exe']):
                        try:
                            procs_snapshot.append({
                                "name": p.info['name'],
                                "pid":  p.info['pid'],
                                "cpu":  p.info.get('cpu_percent') or 0,
                                "mem":  p.info.get('memory_percent') or 0,
                                "exe":  (p.info.get('exe') or '')[:120],
                            })
                        except Exception:
                            pass

                # Coleta portas
                ports_snapshot = []
                if PSUTIL_OK:
                    for conn in psutil.net_connections(kind='inet'):
                        if conn.status == 'LISTEN':
                            ports_snapshot.append({
                                "port":    conn.laddr.port,
                                "proto":   "tcp",
                                "addr":    str(conn.laddr.ip),
                                "process": get_pid_name_cached(str(conn.pid)) if conn.pid else "",
                            })

                # Coleta conexões ativas (flat list) — também via psutil para IPs externos
                conns_snapshot = []
                # De conexoes_ativas (já processadas pelo checar_conexoes)
                for proc_data in conexoes_ativas:
                    for conn in proc_data.get("connections", []):
                        conns_snapshot.append({
                            "process":  proc_data["process"],
                            "dst_ip":   conn.get("dst_ip",""),
                            "dst_port": conn.get("dst_port",0),
                        })
                # Também via psutil diretamente para garantir cobertura
                if PSUTIL_OK and not conns_snapshot:
                    try:
                        for conn in psutil.net_connections(kind='inet'):
                            if conn.status == 'ESTABLISHED' and conn.raddr:
                                pname = get_pid_name_cached(str(conn.pid)) if conn.pid else "system"
                                conns_snapshot.append({
                                    "process": pname,
                                    "dst_ip":  conn.raddr.ip,
                                    "dst_port": conn.raddr.port,
                                })
                    except Exception:
                        pass

                # Run sync for immediate results + async via queue
                try:
                    events = detection_engine.analyze(
                        processes   = procs_snapshot,
                        ports       = ports_snapshot,
                        connections = conns_snapshot,
                    )
                    if events:
                        logger.info("SOC | %d eventos gerados no ciclo", len(events))
                        # Feed lateral movement detector
                        if LATERAL_AVAILABLE and _lateral_detector:
                            try:
                                h_id = detection_engine.host_id
                                for ev in events:
                                    ed = ev.to_dict() if hasattr(ev,'to_dict') else dict(ev)
                                    lm_alerts = _lateral_detector.ingest(ed, host_id=h_id)
                                    for la in lm_alerts:
                                        log_ao_vivo({
                                            "type":   "lateral_movement",
                                            "sev":    la.severity.lower(),
                                            "threat": la.rule_name,
                                            "ip":     la.source_ip,
                                            "msg":    la.description[:80],
                                        })
                            except Exception: pass

                    # Feed ML baseline EVERY cycle (not just when events fire)
                    if ML_AVAILABLE and _ml_baseline:
                        try:
                            ml_alert = _ml_baseline.add_sample({
                                "processes":   procs_snapshot,
                                "connections": conns_snapshot,
                                "ports":       ports_snapshot,
                            })
                            if ml_alert:
                                log_ao_vivo({
                                    "type":   "ml_anomaly",
                                    "sev":    ml_alert["severity"].lower(),
                                    "threat": ml_alert["rule_name"],
                                    "ip":     ml_alert["host_id"],
                                    "msg":    ml_alert["description"][:80],
                                })
                                logger.warning("ML ANOMALY | %s", ml_alert["description"][:80])
                        except Exception: pass

                    if events:
                        # Feed correlation engine
                        if CORR_AVAILABLE and _corr_engine:
                            try:
                                def _fix_host(ed):
                                    if ed.get("host_id","").lower() in ("new","localhost",""):
                                        ed["host_id"] = _corr_engine.host_id
                                    return ed
                                corr_alerts = _corr_engine.ingest_batch([
                                    _fix_host(ev.to_dict() if hasattr(ev,'to_dict') else dict(ev))
                                    for ev in events
                                ])
                                if corr_alerts:
                                    logger.warning("CORR | %d padrões detectados", len(corr_alerts))
                            except Exception as _ca: pass
                        # Feed risk engine + auto block
                        if RISK_AVAILABLE and risk_engine:
                            try:
                                for ev in events:
                                    ed = ev.to_dict() if hasattr(ev,'to_dict') else dict(ev)
                                    # Fix hostname
                                    if ed.get("host_id","").lower() in ("new","localhost",""):
                                        ed["host_id"] = REAL_HOSTNAME
                                    risk_engine.ingest_event(ed)
                            except Exception: pass
                except Exception as _sync_e:
                    logger.debug("SOC sync analyze: %s", _sync_e)
                    detection_engine.enqueue_snapshot({
                        "processes":   procs_snapshot,
                        "ports":       ports_snapshot,
                        "connections": conns_snapshot,
                    })
            except Exception as _de_e:
                logger.debug("Detection engine snapshot error: %s", _de_e)

        # Alimenta o terminal ao vivo
        try:
            log_ao_vivo({
                "type": "monitor",
                "msg":  f"Ciclo #{monitor_status['ciclo']} · {monitor_status['event_log']} · {monitor_status['conexoes']}",
                "ip":   "127.0.0.1",
            })
        except Exception:
            pass
        time.sleep(intervalo)

# ── Middleware ────────────────────────────────────────────────────
@app.before_request
def before():
    from flask import g
    request._t  = time.monotonic()
    rid = request.headers.get("X-Request-ID") or _uuid_mod.uuid4().hex[:16]
    request._rid = rid
    _request_ctx.request_id = rid
    g._repo = repo
    # Resolve tenant + role e expõe via flask.g (para require_role() funcionar)
    _tid, _role = _resolve_tenant_with_role()
    _request_ctx.tenant_id = _tid
    g.tenant_id   = _tid
    g.tenant_role = _role

@app.after_request
def after(resp):
    ms  = round((time.monotonic() - request._t) * 1000, 2)
    rid = getattr(request, "_rid", "-")
    resp.headers["X-Request-Time-ms"] = str(ms)
    resp.headers["X-Request-ID"]      = rid
    # Loga cada request com métricas estruturadas
    if not request.path.startswith("/api/events/stream"):  # evita flood do SSE
        logger.info(
            "%s %s %s",
            request.method, request.path, resp.status_code,
            extra={
                "endpoint":    request.path,
                "method":      request.method,
                "status_code": resp.status_code,
                "duration_ms": ms,
                "source_ip":   request.remote_addr,
            }
        )
    return resp

# ── API routes ────────────────────────────────────────────────────

@app.route("/api/detections")
@auth
def get_detections():
    _ids = _get_ids(_resolve_tenant_id())
    rows = _ids.get_detections(
        limit=min(request.args.get("limit",100,int),500),
        offset=request.args.get("offset",0,int),
        severity=sanitize(request.args.get("severity"), max_len=20, label="severity"),
        status=sanitize(request.args.get("status"), max_len=30, label="status"),
        source_ip=sanitize_ip(request.args.get("source_ip")),
    )
    return jsonify({"total":_ids.store.count_total(),"returned":len(rows),"detections":rows})

@app.route("/api/detections/<did>")
@auth
def get_detection(did):
    _ids = _get_ids(_resolve_tenant_id())
    for r in _ids.store.query(limit=10000):
        if r["detection_id"]==did: return jsonify(r)
    return jsonify({"error":"not found"}),404

@app.route("/api/detections/<did>/status",methods=["PATCH"])
@auth
@require_role("analyst", "admin")
def update_status(did):
    _ids = _get_ids(_resolve_tenant_id())
    body = request.get_json(force=True) or {}
    status = sanitize(body.get("status"), max_len=30, label="status")
    if status not in {"active","investigating","resolved","false_positive"}:
        return jsonify({"error":"status invalido"}),400
    note = sanitize(body.get("analyst_note",""), max_len=1000, label="analyst_note")
    ok = _ids.update_status(did, status, note)
    return (jsonify({"success":True,"detection_id":did,"new_status":status})
            if ok else jsonify({"error":"not found"}),404)

@app.route("/api/analyze",methods=["POST"])
@app.route("/api/detect",methods=["POST"])
@auth
def analyze():
    body = request.get_json(force=True) or {}
    log  = (body.get("log") or body.get("log_line") or "").strip()
    if not log: return jsonify({"error":"log obrigatorio"}),400
    if len(log)>10000: return jsonify({"error":"log muito longo"}),413
    field = sanitize(body.get("field","raw"), max_len=30, label="field")
    src_ip = sanitize_ip(body.get("source_ip"))
    events = _get_ids(_resolve_tenant_id()).analyze(log, src_ip or None, {"field": field})

    # OWASP CRS analysis
    owasp_matches = []
    if owasp_engine:
        for om in owasp_engine.analyze(log):
            owasp_matches.append({
                "threat_name":   f"[OWASP] {om.title}",
                "description":   om.description,
                "severity":      om.severity,
                "mitre_tactic":  om.category,
                "mitre_technique": om.cwe,
                "method":        "owasp_crs",
                "confidence":    0.9,
                "log_entry":     log[:200],
                "source_ip":     body.get("source_ip",""),
                "rule_id":       om.rule_id,
                "owasp_ref":     om.owasp_ref,
                "evidence":      om.evidence,
                "remediation":   om.remediation,
            })

    # Also run Sigma
    sigma_matches = []
    if sigma_engine:
        for rule in sigma_engine.match(log):
            sigma_matches.append({
                "id":            rule.id,
                "threat_name":   f"[Sigma] {rule.title}",
                "description":   rule.description,
                "severity":      rule.level,
                "mitre_tactic":  rule.mitre_tactic,
                "mitre_technique": rule.mitre_technique,
                "method":        "sigma",
                "confidence":    0.85,
                "log_entry":     log[:200],
                "source_ip":     body.get("source_ip",""),
            })

    all_detections = [e.to_dict() for e in events] + sigma_matches + owasp_matches
    return jsonify({
        "analyzed":       log[:200],
        "threats_found":  len(all_detections),
        "detections":     all_detections,
        "sigma_matches":  len(sigma_matches),
        "owasp_matches":  len(owasp_matches),
        "ids_matches":    len(events),
    })

@app.route("/api/statistics")
@auth
def statistics():
    return jsonify(_get_ids(_resolve_tenant_id()).get_statistics())

@app.route("/api/export")
@auth
def export():
    fmt  = request.args.get("format","json")
    data = _get_ids(_resolve_tenant_id()).export(fmt)
    ct   = "text/csv" if fmt=="csv" else "application/json"
    fn   = safe_filename(f"ids_export.{fmt}")  # protege contra path traversal
    return Response(data,mimetype=ct,headers={"Content-Disposition":f"attachment;filename={fn}"})

@app.route("/api/block",methods=["POST"])
@auth
@require_role("analyst", "admin")
def block_ip():
    _ids = _get_ids(_resolve_tenant_id())
    body   = request.get_json(force=True) or {}
    ip     = body.get("ip","").strip()
    reason = body.get("reason","Manual via API")
    if not ip: return jsonify({"error":"ip obrigatorio"}),400
    if ip in _ids.whitelist_ips:
        return jsonify({"error":"IP esta na whitelist — nao pode bloquear"}),409
    ok = _ids.block_ip(ip, reason)
    return jsonify({"success":ok,"ip":ip,"reason":reason,
                    "note":"Requer privilégio de Administrador" if not ok else ""})

@app.route("/api/block",methods=["GET"])
@auth
def list_blocks():
    return jsonify({"blocked_ips":_get_ids(_resolve_tenant_id()).blocker.list_blocked()})

@app.route("/api/block/<ip>",methods=["DELETE"])
@auth
@require_role("analyst", "admin")
def unblock_ip(ip):
    ok = _get_ids(_resolve_tenant_id()).unblock_ip(ip)
    return jsonify({"success":ok,"ip":ip})


# ── Device enrichment helpers ──────────────────────────────────────

OUI_VENDOR_MAP = {
    "900A62":"Huawei","E8744A":"Huawei","006755":"Huawei","C8E2A4":"Huawei",
    "001CB3":"Apple","A45E60":"Apple","F0B429":"Apple","3C0754":"Apple",
    "ACDE48":"Apple","8C85C1":"Apple","F8A45F":"Xiaomi","286C07":"Xiaomi",
    "001632":"Samsung","8C71F8":"Samsung","E8D0FC":"Samsung",
    "F4F5D8":"Google","54607E":"Google","1C62B8":"Google",
    "F0272D":"Amazon","A002DC":"Amazon","FC65DE":"Amazon",
    "9CEB5A":"ASUS","F8AB05":"ASUS","1062E5":"Intel","8086F2":"Intel",
    "000C29":"VMware","005056":"VMware","001C14":"VMware",
    "B827EB":"Raspberry Pi","DC:A6:32":"Raspberry Pi",
    "708BCD":"Microsoft","3C1867":"Microsoft","0026B9":"Dell",
    "00259C":"Dell","1866DA":"HP","A0D3C1":"HP",
    "3417EB":"Realtek","A4AE12":"Realtek","04BFD0":"LG",
    "B4EED4":"LG","0CF3EE":"Intelbras","88548D":"Intelbras",
}

COMMON_PORT_SERVICES = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS", 445:"SMB",
    3389:"RDP", 8080:"HTTP-Alt", 8443:"HTTPS-Alt", 3306:"MySQL",
    5432:"PostgreSQL", 6379:"Redis", 27017:"MongoDB",
    5000:"Flask/Dev", 8888:"Jupyter", 4000:"Dev",
}

def _oui_vendor(mac: str) -> str:
    """Retorna fabricante do dispositivo pelo OUI do MAC."""
    if not mac or mac == "—":
        return "Desconhecido"
    clean = mac.replace("-","").replace(":","").upper()
    oui = clean[:6] if len(clean) >= 6 else ""
    return OUI_VENDOR_MAP.get(oui, "Desconhecido")

def _scan_device_ports(ip: str) -> list:
    """
    Verifica portas abertas num dispositivo local via conexões netstat.
    Rápido — não faz scan TCP real, usa apenas o estado da rede atual.
    """
    if not ip or ip == "192.168.15.2":  # própria máquina
        try:
            if PSUTIL_OK:
                ports = []
                for conn in psutil.net_connections(kind='inet'):
                    if conn.status == 'LISTEN' and conn.laddr:
                        p = conn.laddr.port
                        if p not in ports:
                            ports.append(p)
                return sorted(ports)[:20]
        except Exception:
            pass
        return []
    # Para outros dispositivos: tenta conexões TCP rápidas nas portas comuns
    open_ports = []
    check_ports = [22, 80, 443, 445, 3389, 8080, 21, 23, 25, 53]
    def check_port(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            result = s.connect_ex((ip, port))
            s.close()
            if result == 0:
                open_ports.append(port)
        except Exception:
            pass
    threads = [threading.Thread(target=check_port, args=(p,), daemon=True) for p in check_ports]
    for t in threads: t.start()
    for t in threads: t.join(timeout=1.0)
    return sorted(open_ports)

def _ping_latency(ip: str) -> float:
    """Retorna latência em ms via ping. Retorna -1 se falhar."""
    return platform_ping(ip, timeout_ms=500)

def _infer_services(ports: list) -> list:
    """Infere serviços pelo número de porta."""
    return [
        {"port": p, "service": COMMON_PORT_SERVICES.get(p, f"port/{p}")}
        for p in (ports or [])
    ]

@app.route("/api/devices")
@auth
def get_devices():
    dispositivos = scan_rede_local("192.168.15.0/24")
    # Enrich each device with extra info
    enriched = []
    for d in dispositivos:
        dev = dict(d)
        ip = dev.get("ip","")
        mac = dev.get("mac","")
        # OUI vendor lookup
        dev["vendor"] = _oui_vendor(mac)
        # Open ports via netstat (fast, local)
        dev["open_ports"] = _scan_device_ports(ip)
        # Latency via ping
        dev["latency_ms"] = _ping_latency(ip)
        # Services inferred from ports
        dev["services"] = _infer_services(dev["open_ports"])
        enriched.append(dev)
    return jsonify({
        "devices":   enriched,
        "total":     len(enriched),
        "rede":      "192.168.15.0/24",
        "timestamp": _utc_iso(),
    })

@app.route("/api/connections")
@auth
def get_connections():
    """Conexões ativas mapeadas por processo (com DNS e hostname)."""
    return jsonify({
        "connections": conexoes_ativas,
        "total":       len(conexoes_ativas),
        "timestamp":   _utc_iso(),
    })

@app.route("/api/system")
@auth
def system_info():
    if not PSUTIL_OK:
        return jsonify({"error": "psutil não instalado. Execute: pip install psutil"}), 503
    """Métricas detalhadas do sistema: CPU, RAM, disco, processos, portas abertas."""
    return jsonify(get_system_info())

@app.route("/api/processes")
@auth
def list_processes():
    if not PSUTIL_OK:
        return jsonify({"error": "psutil não instalado"}), 503
    """Lista todos os processos com CPU, RAM, conexões e classificação."""
    try:
        procs = []
        for p in psutil.process_iter(['pid','name','cpu_percent','memory_percent',
                                       'status','username','exe']):
            try:
                name = (p.info['name'] or '').lower()
                trusted = any(b in name for b in [x.lower() for x in BROWSERS_E_APPS])
                suspicious = any(s.lower() in name for s in PROCESSOS_SUSPEITOS)
                try:
                    nconns = len(p.net_connections())
                except Exception:
                    nconns = 0
                procs.append({
                    "pid":        p.info['pid'],
                    "name":       p.info['name'],
                    "cpu":        round(p.info.get('cpu_percent') or 0, 1),
                    "mem":        round(p.info.get('memory_percent') or 0, 1),
                    "status":     p.info.get('status','?'),
                    "user":       (p.info.get('username') or '?').split('\\')[-1],
                    "conns":      nconns,
                    "trusted":    trusted,
                    "suspicious": suspicious,
                    "exe":        (p.info.get('exe') or '')[:80],
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied): pass
        procs.sort(key=lambda x: x['cpu'], reverse=True)
        return jsonify({"total": len(procs), "processes": procs})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/ports")
@auth
def list_ports():
    if not PSUTIL_OK:
        return jsonify({"error": "psutil não instalado"}), 503
    """Lista todas as portas abertas (LISTEN) com processo responsável."""
    try:
        listening = []
        for conn in psutil.net_connections(kind='inet'):
            if conn.status in ('LISTEN',''):
                try:
                    proc = psutil.Process(conn.pid).name() if conn.pid else '?'
                except Exception:
                    proc = f'pid:{conn.pid}'
                listening.append({
                    "port":     conn.laddr.port,
                    "addr":     conn.laddr.ip,
                    "proto":    "tcp" if conn.type == 1 else "udp",
                    "pid":      conn.pid,
                    "process":  proc,
                    "suspicious": conn.laddr.port in PORTAS_SUSPEITAS,
                })
        listening.sort(key=lambda x: x['port'])
        return jsonify({"total": len(listening), "ports": listening})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Live log buffer ──────────────────────────────────────────────
from collections import deque
_live_log: deque = deque(maxlen=200)
_live_log_lock = threading.Lock()

# SSE — fila de subscribers para streaming em tempo real
import queue as _queue
_sse_subscribers: list = []
_sse_lock = threading.Lock()

def _sse_broadcast(data: dict):
    """Envia evento SSE para todos os clientes conectados."""
    payload = json.dumps(data, ensure_ascii=False)
    dead = []
    with _sse_lock:
        for q in _sse_subscribers:
            try:
                q.put_nowait(payload)
            except _queue.Full:
                dead.append(q)
        for q in dead:
            _sse_subscribers.remove(q)

def log_ao_vivo(entry: dict):
    """Adiciona entrada ao buffer de log ao vivo e transmite via SSE."""
    entry["ts"] = datetime.now().strftime('%H:%M:%S.%f')[:12]
    with _live_log_lock:
        _live_log.append(entry)
    _sse_broadcast(entry)  # push em tempo real para clientes SSE

# Integra analisar com o live log — wrapper sem redefinir o nome
def _analisar_com_live_log(log: str, ip: str = None, field: str = "raw", origem: str = ""):
    """Chama analisar() e alimenta o buffer de log ao vivo com as detecções."""
    eventos = analisar(log, ip, field, origem)
    if eventos:
        for e in eventos:
            log_ao_vivo({
                "type":    "detection",
                "sev":     e.severity,
                "threat":  e.threat_name,
                "ip":      ip or "—",
                "msg":     log[:80],
            })
    return eventos

@app.route("/api/live-log")
@auth
def live_log():
    """Retorna buffer de log ao vivo (últimas 200 entradas)."""
    with _live_log_lock:
        entries = list(_live_log)
    return jsonify({
        "entries":   entries,
        "total":     len(entries),
        "timestamp": _utc_iso(),
    })

@app.route("/api/events/stream")
@auth
def events_stream():
    """Server-Sent Events — push de detecções em tempo real sem polling.

    Uso no cliente:
        const es = new EventSource('/api/events/stream');
        es.onmessage = e => console.log(JSON.parse(e.data));
    """
    q: _queue.Queue = _queue.Queue(maxsize=100)
    with _sse_lock:
        _sse_subscribers.append(q)

    # Envia snapshot inicial do buffer
    with _live_log_lock:
        snapshot = list(_live_log)

    def generate():
        try:
            # Heartbeat inicial + snapshot
            yield "event: connected\ndata: {\"status\":\"ok\"}\n\n"
            for entry in snapshot[-20:]:  # últimas 20 entradas
                yield f"data: {json.dumps(entry, ensure_ascii=False)}\n\n"
            # Stream contínuo
            while True:
                try:
                    payload = q.get(timeout=25)
                    yield f"data: {payload}\n\n"
                except _queue.Empty:
                    yield ": heartbeat\n\n"  # mantém conexão viva
        except GeneratorExit:
            pass
        finally:
            with _sse_lock:
                try:
                    _sse_subscribers.remove(q)
                except ValueError:
                    pass

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":   "no-cache",
            "X-Accel-Buffering": "no",   # desabilita buffer do nginx
            "Connection":      "keep-alive",
        },
    )

def _compute_graph_data(tenant_id: str) -> dict:
    """Compute connection graph snapshot and write to cache. Safe to call from bg thread."""
    live = []
    try:
        r = subprocess.run(["netstat", "-n", "-o"], capture_output=True, text=True, timeout=8)
        conn_map = {}
        for linha in r.stdout.strip().split("\n"):
            if "ESTABLISHED" not in linha:
                continue
            p = linha.split()
            if len(p) < 5:
                continue
            end = p[2]
            if ":" not in end:
                continue
            idx  = end.rfind(":")
            ip2  = end[:idx].strip("[]")
            try:
                porta2 = int(end[idx + 1:])
                pid2   = p[4]
            except Exception:
                continue
            proc2 = get_pid_name_cached(pid2) or f"pid:{pid2}"
            if proc2 not in conn_map:
                conn_map[proc2] = {
                    "process":     proc2,
                    "connections": [],
                    "trusted":     any(b in proc2 for b in [x.lower() for x in BROWSERS_E_APPS]),
                }
            # resolve_ip is non-blocking: returns cached hostname or raw IP
            conn_map[proc2]["connections"].append({
                "dst_ip":   ip2,
                "dst_port": porta2,
                "hostname": resolve_ip(ip2) if not ip2.startswith("127.") else "localhost",
            })
        live = list(conn_map.values())
    except Exception:
        live = conexoes_ativas  # fallback to monitor cache

    nodes: dict  = {}
    edges: list  = []
    seen_edges   = set()

    for proc_data in live:
        proc    = proc_data["process"]
        trusted = proc_data["trusted"]
        pid     = f"proc:{proc}"
        if pid not in nodes:
            nodes[pid] = {
                "id":      pid,
                "label":   proc,
                "type":    "process",
                "trusted": trusted,
                "conns":   len(proc_data["connections"]),
            }
        for conn in proc_data.get("connections", []):
            ip   = conn["dst_ip"]
            port = conn["dst_port"]
            hn   = conn.get("hostname", ip)
            iid  = f"ip:{ip}"
            if iid not in nodes:
                r2 = _ti_lookup_ip(ip)
                nodes[iid] = {
                    "id":       iid,
                    "label":    hn if hn != ip else ip,
                    "ip":       ip,
                    "type":     "ip",
                    "score":    r2.get("score", 0),
                    "cat":      r2.get("categoria", "ok"),
                    "hostname": hn,
                }
            eid = f"{pid}->{iid}:{port}"
            if eid not in seen_edges:
                seen_edges.add(eid)
                edges.append({"source": pid, "target": iid, "port": port})

    payload = {
        "nodes":     list(nodes.values()),
        "edges":     edges,
        "timestamp": _utc_iso(),
        "cached":    False,
    }
    _ttl_cache_set(_graph_cache, _graph_cache_lock, tenant_id, payload)
    return payload


@app.route("/api/graph")
@auth
def connection_graph():
    tenant_id = _resolve_tenant_id()

    data, is_stale = _ttl_cache_get_swr(
        _graph_cache, _graph_cache_lock, tenant_id,
        _GRAPH_CACHE_TTL, _GRAPH_STALE_TTL
    )
    if data is not None:
        if is_stale:
            # Return stale immediately, refresh in background
            _trigger_bg_refresh(f"graph:{tenant_id}", _compute_graph_data, tenant_id)
        resp        = dict(data)
        resp["cached"] = True
        resp["stale"]  = is_stale
        return jsonify(resp)

    # No cache at all (first request) — compute synchronously
    payload = _compute_graph_data(tenant_id)
    payload["cached"] = False
    payload["stale"]  = False
    return jsonify(payload)


# ── SOC Engine initialization (after log_ao_vivo is defined) ────────
if SOC_IMPORT_OK:
    try:
        def _soc_alert_live(event):
            try:
                log_ao_vivo({
                    "type":   "detection",
                    "sev":    event.severity.lower() if hasattr(event.severity, 'lower') else str(event.severity).lower(),
                    "threat": f"[{event.rule_id}] {event.rule_name}",
                    "ip":     event.details.get("source_ip", event.host_id),
                    "msg":    (event.raw[:80] if event.raw else str(event.details)[:80]),
                })
            except Exception:
                pass
            logger.warning("SOC ENGINE | rule=%s | sev=%s | %s",
                           event.rule_id, event.severity, event.rule_name)

        _db_path = os.environ.get("IDS_DB_PATH",
                      str(pathlib.Path(__file__).parent / "netguard_soc.db"))
        detection_engine = SOCEngine(
            db_path        = _db_path,
            alert_callback = _soc_alert_live,
            host_id        = REAL_HOSTNAME,
        )
        detection_engine.start()
        # Migrate legacy host_id='new' in DB
        try:
            detection_engine.storage._migrate(detection_engine.host_id)
        except Exception: pass
        DE_AVAILABLE = True
        logger.info("SOC Engine OK | 12 regras ativas")
        # Init Threat Hunter
        if HUNTER_AVAILABLE:
            try:
                _db = os.environ.get("IDS_DB_PATH",
                      str(pathlib.Path(__file__).parent / "netguard_soc.db"))
                _threat_hunter = ThreatHunter(db_path=_db)
                logger.info("ThreatHunter iniciado | db=%s", _db)
            except Exception as _th_init:
                logger.warning("ThreatHunter init: %s", _th_init)

        # Init ML baseline
        if ML_AVAILABLE:
            try:
                _ml_baseline = MLBaseline(
                    host_id     = detection_engine.host_id,
                    min_samples = 30,
                    contamination = 0.05,
                )
                logger.info("ML Baseline iniciado | min_samples=30")
            except Exception as _ml_init_err:
                logger.warning("ML Baseline init: %s", _ml_init_err)

        # Init correlation engine
        if CORR_AVAILABLE:
            try:
                _hn = detection_engine.host_id
                _corr_engine = get_correlation_engine(
                    host_id  = _hn,
                    callback = _on_correlation,
                )
                logger.info("Correlation Engine OK | 5 regras ativas | host=%s", _hn)
            except Exception as _corr_err:
                logger.warning("Correlation Engine init: %s", _corr_err)
    except Exception as _soc_init_err:
        detection_engine = None
        DE_AVAILABLE = False
        logger.warning("SOC Engine init failed: %s", _soc_init_err)


@app.route("/api/enrich/<ip>")
@auth
def enrich_ip_route(ip):
    """Enriquece um IP com o engine atual e faz fallback para o legado."""
    if ENRICH_AVAILABLE and _enrichment:
        try:
            data = _enrichment.enrich(ip)
            return jsonify(data)
        except Exception:
            pass

    result = enrich_ip(ip)
    return jsonify(result)

@app.route("/api/threatfox/<ip>")
@auth
def threatfox_check(ip):
    """Consulta ThreatFox por IOCs do IP (sem chave de API)."""
    result = check_threatfox_ip(ip)
    return jsonify(result)

@app.route("/api/sigma/stats")
@auth
def sigma_stats():
    """Estatísticas do Sigma Rules Engine."""
    if not sigma_engine:
        return jsonify({"error": "Sigma não disponível"}), 503
    return jsonify({
        "engine":   "SigmaHQ compatible",
        "rules":    sigma_engine.stats(),
        "builtin":  True,
        "external": False,
    })

@app.route("/api/sigma/analyze", methods=["POST"])
@auth
def sigma_analyze():
    """Analisa um log contra todas as regras Sigma."""
    if not sigma_engine:
        return jsonify({"error": "Sigma não disponível"}), 503
    body = request.get_json(force=True) or {}
    log  = body.get("log", "").strip()
    if not log:
        return jsonify({"error": "log obrigatório"}), 400
    matches = sigma_engine.match(log)
    return jsonify({
        "log":          log[:200],
        "matches":      len(matches),
        "rules_matched": [{
            "id":          r.id,
            "title":       r.title,
            "level":       r.level,
            "description": r.description,
            "mitre_tactic": r.mitre_tactic,
            "mitre_technique": r.mitre_technique,
        } for r in matches],
    })

# ── Fail2Ban API ──────────────────────────────────────────────────

# ── Detection Engine API ──────────────────────────────────────────

# ── Honeypot API ──────────────────────────────────────────────────

@app.route("/api/honeypot/status")
@auth
def honeypot_status():
    if not HONEYPOT_AVAILABLE or not _honeypot:
        return jsonify({"available": False, "running": False})
    s = _honeypot.stats()
    return jsonify({"available": True, "running": True, **s})

@app.route("/api/honeypot/captures")
@auth
def honeypot_captures():
    if not HONEYPOT_AVAILABLE or not _honeypot:
        return jsonify({"available": False, "captures": []})
    limit = int(request.args.get("limit", 100))
    return jsonify({
        "available": True,
        "captures": _honeypot.get_captures(limit),
        "stats": _honeypot.stats(),
    })

@app.route("/api/honeypot/start", methods=["POST"])
@auth
def honeypot_start():
    if not HONEYPOT_AVAILABLE or not _honeypot:
        return jsonify({"error": "indisponível"}), 503
    data = request.get_json(force=True) or {}
    ports = data.get("ports", None)
    try:
        _honeypot.start(ports)
        return jsonify({"ok": True, "stats": _honeypot.stats()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/honeypot/stop", methods=["POST"])
@auth
def honeypot_stop():
    if not HONEYPOT_AVAILABLE or not _honeypot:
        return jsonify({"error": "indisponível"}), 503
    _honeypot.stop()
    return jsonify({"ok": True})

@app.route("/api/honeypot/demo", methods=["POST"])
@auth
def honeypot_demo():
    if not HONEYPOT_AVAILABLE or not _honeypot:
        return jsonify({"error": "indisponível"}), 503
    captures = _honeypot.inject_demo()
    return jsonify({"injected": len(captures), "captures": captures})

# ── DNS Monitor API ───────────────────────────────────────────────

@app.route("/api/dns/alerts")
@auth
def dns_alerts():
    if not DNS_AVAILABLE or not _dns_monitor:
        return jsonify({"available": False, "alerts": []})
    limit = int(request.args.get("limit", 100))
    return jsonify({
        "available": True,
        "alerts": _dns_monitor.get_alerts(limit),
        "stats": _dns_monitor.stats(),
    })

@app.route("/api/dns/analyze", methods=["POST"])
@auth
def dns_analyze():
    if not DNS_AVAILABLE or not _dns_monitor:
        return jsonify({"error": "indisponível"}), 503
    data = request.get_json(force=True) or {}
    domain = data.get("domain", "").strip()
    qtype = data.get("type", "A")
    if not domain:
        return jsonify({"error": "domain obrigatório"}), 400
    result = _dns_monitor.analyze_domain(domain, qtype)
    return jsonify(result)

@app.route("/api/dns/demo", methods=["POST"])
@auth
def dns_demo():
    if not DNS_AVAILABLE or not _dns_monitor:
        return jsonify({"error": "indisponível"}), 503
    alerts = _dns_monitor.inject_demo()
    return jsonify({"injected": len(alerts), "alerts": alerts})

@app.route("/api/dns/stats")
@auth
def dns_stats():
    if not DNS_AVAILABLE or not _dns_monitor:
        return jsonify({"available": False})
    return jsonify(_dns_monitor.stats())

# ── IP Enrichment API (Shodan + WHOIS) ────────────────────────────

@app.route("/api/enrich/bulk", methods=["POST"])
@auth
def enrich_bulk():
    if not ENRICH_AVAILABLE or not _enrichment:
        return jsonify({"error": "indisponível"}), 503
    data = request.get_json(force=True) or {}
    ips = data.get("ips", [])[:20]
    results = _enrichment.bulk_enrich(ips)
    return jsonify({"results": results, "count": len(results)})

@app.route("/api/enrichment/stats")
@auth
def enrichment_stats():
    if not ENRICH_AVAILABLE or not _enrichment:
        return jsonify({"available": False})
    return jsonify(_enrichment.stats())

# ── Threat Hunting API ────────────────────────────────────────────

@app.route("/api/hunt", methods=["POST"])
@auth
def hunt():
    if not HUNTER_AVAILABLE or not _threat_hunter:
        return jsonify({"error":"indisponível"}), 503
    data    = request.get_json(force=True) or {}
    query   = data.get("query","")
    limit   = min(int(data.get("limit",200)), 500)
    hours   = min(int(data.get("hours",24)), 168)
    host_id = data.get("host_id","")
    result  = _threat_hunter.hunt(query, limit=limit, hours=hours, host_id=host_id)
    return jsonify(result)

@app.route("/api/hunt/validate", methods=["POST"])
@auth
def hunt_validate():
    if not HUNTER_AVAILABLE or not _threat_hunter:
        return jsonify({"error":"indisponível"}), 503
    data  = request.get_json(force=True) or {}
    query = data.get("query","")
    return jsonify(_threat_hunter.validate(query))

@app.route("/api/hunt/suggestions")
@auth
def hunt_suggestions():
    if not HUNTER_AVAILABLE or not _threat_hunter:
        return jsonify({"suggestions":[]})
    return jsonify({"suggestions": _threat_hunter.suggest_queries()})

# ── Lateral Movement API ───────────────────────────────────────────

@app.route("/api/lateral/alerts")
@auth
def lateral_alerts():
    if not LATERAL_AVAILABLE or not _lateral_detector:
        return jsonify({"available":False,"alerts":[]})
    limit = int(request.args.get("limit",100))
    return jsonify({
        "available": True,
        "alerts":    _lateral_detector.get_alerts(limit),
        "stats":     _lateral_detector.stats(),
    })

@app.route("/api/lateral/demo", methods=["POST"])
@auth
def lateral_demo():
    if not LATERAL_AVAILABLE or not _lateral_detector:
        return jsonify({"error":"indisponível"}), 503
    alerts = _lateral_detector.inject_demo()
    return jsonify({"injected": len(alerts),
                    "alerts": [a.to_dict() for a in alerts]})

@app.route("/api/lateral/stats")
@auth
def lateral_stats():
    if not LATERAL_AVAILABLE or not _lateral_detector:
        return jsonify({"available":False})
    return jsonify(_lateral_detector.stats())

# ── YARA API ───────────────────────────────────────────────────────

@app.route("/api/yara/scan", methods=["POST"])
@auth
def yara_scan():
    if not YARA_AVAILABLE or not _yara_engine:
        return jsonify({"error":"indisponível"}), 503
    data    = request.get_json(force=True) or {}
    content = data.get("content","")
    context = data.get("context","api")
    if not content:
        return jsonify({"error":"content obrigatório"}), 400
    matches = _yara_engine.scan_string(content, context)
    return jsonify({
        "matches":     [m.to_dict() for m in matches],
        "match_count": len(matches),
        "scanned":     len(content),
    })

@app.route("/api/yara/scan-process", methods=["POST"])
@auth
def yara_scan_process():
    if not YARA_AVAILABLE or not _yara_engine:
        return jsonify({"error":"indisponível"}), 503
    proc = request.get_json(force=True) or {}
    matches = _yara_engine.scan_process(proc)
    return jsonify({
        "matches":     [m.to_dict() for m in matches],
        "match_count": len(matches),
        "process":     proc.get("name",""),
    })

@app.route("/api/yara/stats")
@auth
def yara_stats():
    if not YARA_AVAILABLE or not _yara_engine:
        return jsonify({"available":False})
    return jsonify(_yara_engine.stats())

# ── Agent Push API ────────────────────────────────────────────────

@app.route("/api/agent/push", methods=["POST"])
@auth
def agent_push():
    """Recebe snapshot de um agente distribuído."""
    try:
        data    = request.get_json(force=True)
        host_id = data.get("host_id","unknown")
        procs   = data.get("processes",[])
        conns   = data.get("connections",[])
        ports   = data.get("ports",[])

        # Feed SOC engine com dados do agente
        if DE_AVAILABLE and detection_engine:
            try:
                events = detection_engine.analyze(
                    processes=procs, ports=ports, connections=conns
                )
                if events and RISK_AVAILABLE and risk_engine:
                    for ev in events:
                        ed = ev.to_dict() if hasattr(ev,"to_dict") else dict(ev)
                        ed["host_id"] = host_id
                        risk_engine.ingest_event(ed)
            except Exception: pass

        # Feed ML baseline
        if ML_AVAILABLE and _ml_baseline:
            try:
                _ml_baseline.add_sample({"processes":procs,"connections":conns,"ports":ports})
            except Exception: pass

        logger.info("Agent push | host=%s | procs=%d conns=%d ports=%d",
                    host_id, len(procs), len(conns), len(ports))
        return jsonify({"status":"ok","host_id":host_id,"received":{
            "processes": len(procs), "connections": len(conns), "ports": len(ports)
        }})
    except Exception as e:
        logger.error("Agent push error: %s", e)
        return jsonify({"error":str(e)}), 400

@app.route("/api/agent/status")
@auth
def agent_status():
    """Lista agentes que fizeram push recentemente."""
    if not RISK_AVAILABLE or not risk_engine:
        return jsonify({"agents":[]})
    hosts = risk_engine.get_all_hosts()
    return jsonify({"agents": hosts, "total": len(hosts)})

# ── Auto Block API ─────────────────────────────────────────────────

@app.route("/api/autoblock/status")
@auth
def autoblock_status():
    if not AUTOBLOCK_AVAILABLE:
        return jsonify({"available":False}), 200
    return jsonify({**auto_block.stats(), "blocks": auto_block.get_blocks()})

@app.route("/api/autoblock/blocks")
@auth
def autoblock_blocks():
    if not AUTOBLOCK_AVAILABLE:
        return jsonify({"blocks":[]}), 200
    return jsonify({"blocks": auto_block.get_blocks(),
                    "history": auto_block.get_history(20)})

@app.route("/api/autoblock/block", methods=["POST"])
@auth
def autoblock_manual_block():
    if not AUTOBLOCK_AVAILABLE:
        return jsonify({"error":"indisponível"}), 503
    data  = request.get_json(force=True) or {}
    ip    = data.get("ip","")
    score = int(data.get("score",100))
    reason= data.get("reason","Manual block")
    if not ip:
        return jsonify({"error":"ip obrigatório"}), 400
    rec = auto_block.block(ip, score, reason)
    return jsonify({"status":"blocked","record": rec.to_dict() if rec else None})

@app.route("/api/autoblock/unblock/<ip>", methods=["POST"])
@auth
def autoblock_unblock(ip):
    if not AUTOBLOCK_AVAILABLE:
        return jsonify({"error":"indisponível"}), 503
    ok = auto_block.unblock(ip)
    return jsonify({"status":"unblocked" if ok else "error","ip":ip})

@app.route("/api/autoblock/config", methods=["POST"])
@auth
def autoblock_config():
    if not AUTOBLOCK_AVAILABLE:
        return jsonify({"error":"indisponível"}), 503
    data = request.get_json(force=True) or {}
    if "threshold" in data:
        auto_block.set_threshold(int(data["threshold"]))
    if "enabled" in data:
        auto_block.set_enabled(bool(data["enabled"]))
    return jsonify(auto_block.stats())

# ── ML Baseline API ───────────────────────────────────────────────

@app.route("/api/ml/stats")
@auth
def ml_stats():
    if not ML_AVAILABLE or not _ml_baseline:
        return jsonify({"available": False, "reason": "scikit-learn não instalado"}), 200
    return jsonify(_ml_baseline.stats())

@app.route("/api/ml/reset", methods=["POST"])
@auth
def ml_reset():
    if not ML_AVAILABLE or not _ml_baseline:
        return jsonify({"error": "indisponível"}), 503
    _ml_baseline.reset()
    return jsonify({"status": "reset", "message": "Baseline ML reiniciado"})

# ── VirusTotal API ─────────────────────────────────────────────────

@app.route("/api/vt/lookup/<file_hash>")
@auth
def vt_lookup(file_hash):
    if not VT_AVAILABLE or not _vt_client:
        return jsonify({"error": "indisponível"}), 503
    result = _vt_client.lookup_hash(file_hash)
    if not result:
        return jsonify({"error": "lookup falhou"}), 503
    return jsonify(result)

@app.route("/api/vt/stats")
@auth
def vt_stats():
    if not VT_AVAILABLE or not _vt_client:
        return jsonify({"available": False}), 200
    return jsonify(_vt_client.stats())

# ── Correlation Engine API ────────────────────────────────────────

@app.route("/api/correlation/alerts")
@auth
def correlation_alerts():
    if not CORR_AVAILABLE or not _corr_engine:
        return jsonify({"alerts": [], "error": "Correlation Engine indisponível"}), 200
    limit = int(request.args.get("limit", 100))
    return jsonify({
        "alerts": _corr_engine.get_alerts(limit),
        "stats":  _corr_engine.get_stats(),
    })

@app.route("/api/correlation/stats")
@auth
def correlation_stats():
    if not CORR_AVAILABLE or not _corr_engine:
        return jsonify({"error": "indisponível"}), 503
    return jsonify(_corr_engine.get_stats())

@app.route("/api/correlation/demo", methods=["POST"])
@auth
def correlation_demo():
    if not CORR_AVAILABLE or not _corr_engine:
        return jsonify({"error": "indisponível"}), 503
    alerts = _corr_engine.inject_demo()
    return jsonify({"triggered": len(alerts),
                    "alerts": [a.to_dict() for a in alerts]})

# ── Risk Score API ────────────────────────────────────────────────

@app.route("/api/risk/hosts")
@auth
def risk_hosts():
    if not RISK_AVAILABLE:
        return jsonify({"error": "Risk Engine indisponível"}), 503
    return jsonify({"hosts": risk_engine.get_all_hosts(),
                    "summary": risk_engine.get_summary()})

@app.route("/api/risk/host/<host_id>")
@auth
def risk_host(host_id):
    if not RISK_AVAILABLE:
        return jsonify({"error": "Risk Engine indisponível"}), 503
    data = risk_engine.get_host(host_id)
    if not data:
        return jsonify({"error": "Host não encontrado"}), 404
    return jsonify(data)

@app.route("/api/risk/report/<host_id>")
@auth
def risk_report(host_id):
    if not RISK_AVAILABLE:
        return jsonify({"error": "Risk Engine indisponível"}), 503
    return jsonify(risk_engine.generate_report(host_id))

@app.route("/api/risk/summary")
@auth
def risk_summary():
    if not RISK_AVAILABLE:
        return jsonify({"error": "Risk Engine indisponível"}), 503
    return jsonify(risk_engine.get_summary())

@app.route("/api/soc/events")
@auth
def soc_events():
    """Lista eventos do Detection Engine."""
    if not DE_AVAILABLE:
        return jsonify({"error": "Detection Engine indisponível"}), 503
    limit    = min(int(request.args.get("limit", 100)), 500)
    offset   = int(request.args.get("offset", 0))
    severity = request.args.get("severity")
    etype    = request.args.get("event_type")
    since    = request.args.get("since")
    events   = detection_engine.get_events(
        limit=limit, offset=offset,
        severity=severity, event_type=etype, since=since
    )
    return jsonify({"events": events, "total": len(events)})

@app.route("/api/soc/stats")
@auth
def soc_stats():
    """Estatísticas do Detection Engine."""
    if not DE_AVAILABLE:
        return jsonify({"error": "Detection Engine indisponível"}), 503
    return jsonify({**detection_engine.get_stats(), "available": True})

@app.route("/api/soc/analyze", methods=["POST"])
@auth
def soc_analyze_web():
    """Analisa payload web contra regras R10/R11/R12."""
    if not DE_AVAILABLE:
        return jsonify({"error": "Detection Engine indisponível"}), 503
    body       = request.get_json(force=True) or {}
    payload    = body.get("payload","")
    source_ip  = body.get("source_ip","")
    user_agent = body.get("user_agent","")
    events     = detection_engine.analyze_web_payload(
        payload=payload, source_ip=source_ip, user_agent=user_agent
    )
    return jsonify({
        "events_generated": len(events),
        "events": [e.to_dict() for e in events],
    })

@app.route("/api/fail2ban/status")
@auth
def f2b_status():
    if not F2B_AVAILABLE:
        return jsonify({"error": "Fail2Ban não disponível"}), 503
    return jsonify({**fail2ban.stats(), "available": True})

@app.route("/api/fail2ban/bans")
@auth
def f2b_bans():
    if not F2B_AVAILABLE:
        return jsonify({"error": "Fail2Ban não disponível"}), 503
    return jsonify({
        "bans":      fail2ban.get_active_bans(),
        "history":   fail2ban.get_history(limit=50),
        "timestamp": _utc_iso(),
    })

@app.route("/api/fail2ban/unban/<ip>", methods=["POST"])
@auth
def f2b_unban(ip):
    if not F2B_AVAILABLE:
        return jsonify({"error": "Fail2Ban não disponível"}), 503
    ok = fail2ban.unban(ip, reason="manual_dashboard")
    return jsonify({"success": ok, "ip": ip})

@app.route("/api/fail2ban/ban", methods=["POST"])
@auth
def f2b_manual_ban():
    if not F2B_AVAILABLE:
        return jsonify({"error": "Fail2Ban não disponível"}), 503
    body = request.get_json(force=True) or {}
    ip   = body.get("ip","").strip()
    jail = body.get("jail","brute-force")
    if not ip:
        return jsonify({"error": "ip obrigatório"}), 400
    # Inject fake detections to trigger ban
    jail_cfg = F2B_JAILS.get(jail, {})
    for _ in range(jail_cfg.get("maxretry", 5)):
        fail2ban.ingest({
            "source_ip":   ip,
            "threat_name": jail_cfg.get("triggers",["Brute Force"])[0],
            "severity":    "high",
        })
    return jsonify({"success": True, "ip": ip, "jail": jail})

@app.route("/api/fail2ban/whitelist", methods=["GET"])
@auth
def f2b_whitelist_get():
    if not F2B_AVAILABLE:
        return jsonify({"error": "Fail2Ban não disponível"}), 503
    return jsonify({"whitelist": sorted(fail2ban.whitelist)})

@app.route("/api/fail2ban/whitelist", methods=["POST"])
@auth
def f2b_whitelist_add():
    if not F2B_AVAILABLE:
        return jsonify({"error": "Fail2Ban não disponível"}), 503
    body = request.get_json(force=True) or {}
    ip = body.get("ip","").strip()
    if ip:
        fail2ban.add_whitelist(ip)
    return jsonify({"success": True, "ip": ip})

@app.route("/api/fail2ban/whitelist/<ip>", methods=["DELETE"])
@auth
def f2b_whitelist_remove(ip):
    if not F2B_AVAILABLE:
        return jsonify({"error": "Fail2Ban não disponível"}), 503
    fail2ban.remove_whitelist(ip)
    return jsonify({"success": True, "ip": ip})

@app.route("/api/fail2ban/toggle", methods=["POST"])
@auth
def f2b_toggle():
    if not F2B_AVAILABLE:
        return jsonify({"error": "Fail2Ban não disponível"}), 503
    body = request.get_json(force=True) or {}
    enabled = body.get("enabled", True)
    fail2ban.set_enabled(enabled)
    return jsonify({"success": True, "enabled": enabled})

@app.route("/api/killchain/incidents")
@auth
def kc_incidents():
    """Lista incidentes de Kill Chain ativos."""
    if not KC_AVAILABLE:
        return jsonify({"error": "Kill Chain não disponível"}), 503
    min_e = int(request.args.get("min_events", 2))
    return jsonify({
        "incidents":  kc_correlator.get_incidents(min_events=min_e),
        "stats":      kc_correlator.stats(),
        "timestamp":  _utc_iso(),
    })

@app.route("/api/killchain/report/<ip>")
@auth
def kc_report(ip):
    """Gera Incident Report completo para um IP."""
    if not KC_AVAILABLE:
        return jsonify({"error": "Kill Chain não disponível"}), 503
    report = kc_correlator.generate_report(ip)
    return jsonify(report)

@app.route("/api/killchain/stats")
@auth
def kc_stats():
    if not KC_AVAILABLE:
        return jsonify({"error": "Kill Chain não disponível"}), 503
    return jsonify({**kc_correlator.stats(), "available": True})

@app.route("/api/killchain/inject", methods=["POST"])
@auth
def kc_inject():
    """Injeta evento manual no correlador (para demo/teste)."""
    if not KC_AVAILABLE:
        return jsonify({"error": "Kill Chain não disponível"}), 503
    body = request.get_json(force=True) or {}
    kc_correlator.ingest({**body, "timestamp": _utc_iso()})
    return jsonify({"ok": True})

@app.route("/api/owasp/stats")
@auth
def owasp_stats():
    if not OWASP_AVAILABLE:
        return jsonify({"error": "OWASP não disponível"}), 503
    return jsonify({**owasp_engine.stats(), "available": True})

@app.route("/api/owasp/analyze", methods=["POST"])
@auth
def owasp_analyze():
    if not OWASP_AVAILABLE:
        return jsonify({"error": "OWASP não disponível"}), 503
    body = request.get_json(force=True) or {}
    log  = body.get("log","").strip()
    hdrs = body.get("headers",{})
    if not log and not hdrs:
        return jsonify({"error": "log ou headers obrigatório"}), 400
    payload_matches = owasp_engine.analyze(log) if log else []
    header_matches  = owasp_engine.analyze_headers(hdrs) if hdrs else []
    all_m = payload_matches + header_matches
    return jsonify({
        "payload_matches": len(payload_matches),
        "header_matches":  len(header_matches),
        "total":           len(all_m),
        "results": [{
            "rule_id":     m.rule_id,
            "category":    m.category,
            "owasp_ref":   m.owasp_ref,
            "title":       m.title,
            "severity":    m.severity,
            "evidence":    m.evidence,
            "cwe":         m.cwe,
            "remediation": m.remediation,
        } for m in all_m],
    })

@app.route("/api/owasp/payloads")
@auth
def owasp_payloads():
    """Retorna payloads do OWASP Testing Guide."""
    return jsonify({
        "attack_types": list(TESTING_PAYLOADS.keys()),
        "payloads":     TESTING_PAYLOADS,
        "total":        sum(len(v) for v in TESTING_PAYLOADS.values()),
    })

@app.route("/api/feeds/stats")
@auth
def feeds_stats():
    """Status dos threat feeds."""
    if not FEEDS_AVAILABLE:
        return jsonify({"available": False})
    s = feed_stats()
    s["available"] = True
    s["abuseipdb_key_set"] = bool(os.environ.get("IDS_ABUSEIPDB_KEY"))
    return jsonify(s)

def _is_private_ip(ip: str) -> bool:
    return (not ip or ip.startswith("127.") or ip.startswith("192.168.")
            or ip.startswith("10.") or ip.startswith("172."))

def _compute_geo_data(tenant_id: str) -> dict:
    """Compute geo snapshot and write to cache. Safe to call from bg thread."""
    try:
        from geo_ip import lookup
    except ImportError:
        return {"error": "geo_ip module not found", "points": [], "total": 0}

    seen: dict = {}

    # Live connections (cross-platform)
    try:
        for c in platform_get_connections():
            ip = c.get("ip", "")
            if _is_private_ip(ip) or ip in seen:
                continue
            geo = lookup(ip)
            if not geo.get("private"):
                seen[ip] = {
                    "ip":       ip,
                    "country":  geo["country"],
                    "city":     geo["city"],
                    "lat":      geo["lat"],
                    "lon":      geo["lon"],
                    "flag":     geo["flag"],
                    "org":      geo["org"],
                    "process":  c.get("process", ""),
                    "port":     c.get("port", 0),
                    # Non-blocking: returns cached hostname or raw IP
                    "hostname": resolve_ip(ip),
                }
    except Exception:
        pass

    # IPs from detections (tenant-scoped)
    try:
        for det in _get_ids(tenant_id).get_detections(limit=100):
            ip = det.get("source_ip", "")
            if _is_private_ip(ip) or ip in seen:
                continue
            geo = lookup(ip)
            if not geo.get("private"):
                seen[ip] = {
                    "ip":       ip,
                    "country":  geo["country"],
                    "city":     geo["city"],
                    "lat":      geo["lat"],
                    "lon":      geo["lon"],
                    "flag":     geo["flag"],
                    "org":      geo["org"],
                    "process":  "detection",
                    "threat":   det.get("threat_name", ""),
                    "severity": det.get("severity", ""),
                    "port":     0,
                    "hostname": ip,
                }
    except Exception:
        pass

    payload = {
        "points":    list(seen.values()),
        "total":     len(seen),
        "timestamp": _utc_iso(),
        "cached":    False,
    }
    _ttl_cache_set(_geo_cache, _geo_cache_lock, tenant_id, payload)
    return payload


@app.route("/api/geo")
@auth
def geo_ips():
    tenant_id = _resolve_tenant_id()

    data, is_stale = _ttl_cache_get_swr(
        _geo_cache, _geo_cache_lock, tenant_id,
        _GEO_CACHE_TTL, _GEO_STALE_TTL
    )
    if data is not None:
        if is_stale:
            _trigger_bg_refresh(f"geo:{tenant_id}", _compute_geo_data, tenant_id)
        resp           = dict(data)
        resp["cached"] = True
        resp["stale"]  = is_stale
        return jsonify(resp)

    # No cache — first request, compute synchronously
    try:
        from geo_ip import lookup as _geo_lookup  # noqa: F401
    except ImportError:
        return jsonify({"error": "geo_ip module not found"}), 500

    payload = _compute_geo_data(tenant_id)
    payload["cached"] = False
    payload["stale"]  = False
    return jsonify(payload)


# ── /metrics — Prometheus Exposition Format ───────────────────────
_metrics_start_time = time.time()

@app.route("/metrics")
def prometheus_metrics():
    """
    Endpoint de métricas no formato Prometheus Text Exposition.
    Compatível com Prometheus scrape, Grafana, VictoriaMetrics, etc.

    Scrape config (prometheus.yml):
      - job_name: 'netguard'
        static_configs:
          - targets: ['localhost:5000']
        metrics_path: '/metrics'
    """
    lines = []

    def g(name, desc, type_="gauge"):
        lines.append(f"# HELP {name} {desc}")
        lines.append(f"# TYPE {name} {type_}")

    def m(name, value, labels=None):
        if value is None:
            return
        lbl = ""
        if labels:
            pairs = ",".join(f'{k}="{v}"' for k, v in labels.items())
            lbl = "{" + pairs + "}"
        lines.append(f"{name}{lbl} {value}")

    uptime = time.time() - _metrics_start_time

    # ── Info / Uptime ─────────────────────────────────────────────
    g("netguard_info", "Informações estáticas do NetGuard IDS", "gauge")
    m("netguard_info", 1, {"version": "3.0", "host": REAL_HOSTNAME})

    g("netguard_uptime_seconds", "Tempo em segundos desde o início do servidor", "counter")
    m("netguard_uptime_seconds", round(uptime, 2))

    # ── IDS Detections ────────────────────────────────────────────
    try:
        detections = ids.get_detections(limit=10000)
        g("netguard_ids_detections_total", "Total de detecções do IDS Engine", "counter")
        m("netguard_ids_detections_total", len(detections))

        sev_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for d in detections:
            sev = (d.get("severity") or "LOW").upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        g("netguard_ids_detections_by_severity", "Detecções do IDS por severidade", "gauge")
        for sev, count in sev_counts.items():
            m("netguard_ids_detections_by_severity", count, {"severity": sev})
    except Exception:
        pass

    # ── SOC Engine ────────────────────────────────────────────────
    try:
        if SOC_IMPORT_OK and detection_engine:
            soc_stats = detection_engine.get_stats() if hasattr(detection_engine, "get_stats") else {}
            g("netguard_soc_events_total", "Total de eventos gerados pelo SOC Engine", "counter")
            m("netguard_soc_events_total", soc_stats.get("total_events", 0))

            g("netguard_soc_rules_active", "Regras ativas no SOC Engine", "gauge")
            m("netguard_soc_rules_active", soc_stats.get("rules_active", 0))
    except Exception:
        pass

    # ── Correlation Engine ────────────────────────────────────────
    try:
        if CORR_AVAILABLE and _corr_engine:
            corr_stats = _corr_engine.get_stats()
            g("netguard_correlation_alerts_total", "Total de alertas de correlação detectados", "counter")
            m("netguard_correlation_alerts_total", corr_stats.get("total", 0))

            g("netguard_correlation_alerts_by_rule", "Alertas de correlação por regra", "gauge")
            for rule_id, count in corr_stats.get("by_rule", {}).items():
                m("netguard_correlation_alerts_by_rule", count, {"rule": rule_id})

            g("netguard_correlation_alerts_by_severity", "Alertas de correlação por severidade", "gauge")
            for sev, count in corr_stats.get("by_severity", {}).items():
                m("netguard_correlation_alerts_by_severity", count, {"severity": sev})

            g("netguard_correlation_suspicious_procs", "Processos suspeitos rastreados pelo correlator", "gauge")
            m("netguard_correlation_suspicious_procs", corr_stats.get("suspicious_procs", 0))

            g("netguard_correlation_beacons_tracked", "IPs de beaconing rastreados", "gauge")
            m("netguard_correlation_beacons_tracked", corr_stats.get("tracked_beacons", 0))
    except Exception:
        pass

    # ── Risk Engine ───────────────────────────────────────────────
    try:
        if RISK_AVAILABLE and risk_engine:
            risk_summary = risk_engine.get_summary()
            g("netguard_risk_hosts_total", "Total de hosts monitorados pelo Risk Engine", "gauge")
            m("netguard_risk_hosts_total", risk_summary.get("total_hosts", 0))

            g("netguard_risk_hosts_by_level", "Hosts por nível de risco", "gauge")
            for level in ("critical", "high", "medium", "low"):
                m("netguard_risk_hosts_by_level", risk_summary.get(f"{level}_hosts", 0), {"level": level.upper()})

            g("netguard_risk_score_max", "Risk score máximo entre todos os hosts", "gauge")
            m("netguard_risk_score_max", risk_summary.get("max_score", 0))

            g("netguard_risk_score_avg", "Risk score médio entre todos os hosts", "gauge")
            m("netguard_risk_score_avg", risk_summary.get("avg_score", 0))

            g("netguard_risk_score", "Risk score individual por host", "gauge")
            for host in risk_engine.get_all_hosts():
                m("netguard_risk_score", host.get("score", 0), {"host": host.get("host_id", "unknown")})
    except Exception:
        pass

    # ── Fail2Ban ──────────────────────────────────────────────────
    try:
        if F2B_AVAILABLE and fail2ban:
            f2b_status = fail2ban.get_status() if hasattr(fail2ban, "get_status") else {}
            g("netguard_fail2ban_banned_total", "Total de IPs banidos pelo Fail2Ban", "gauge")
            m("netguard_fail2ban_banned_total", f2b_status.get("total_banned", 0))

            g("netguard_fail2ban_jails_active", "Jails ativos no Fail2Ban", "gauge")
            m("netguard_fail2ban_jails_active", f2b_status.get("active_jails", len(F2B_JAILS)))

            g("netguard_fail2ban_bans_by_jail", "Bans por jail do Fail2Ban", "gauge")
            for jail_name, jail_data in f2b_status.get("jails", {}).items():
                count = jail_data.get("banned", 0) if isinstance(jail_data, dict) else 0
                m("netguard_fail2ban_bans_by_jail", count, {"jail": jail_name})
    except Exception:
        pass

    # ── Kill Chain ────────────────────────────────────────────────
    try:
        if KC_AVAILABLE and kc_correlator:
            incidents = kc_correlator.get_incidents() if hasattr(kc_correlator, "get_incidents") else []
            g("netguard_killchain_incidents_total", "Total de incidentes na Kill Chain", "gauge")
            m("netguard_killchain_incidents_total", len(incidents))
    except Exception:
        pass

    # ── Sistema (psutil) ──────────────────────────────────────────
    try:
        if PSUTIL_OK and psutil:
            g("netguard_system_cpu_percent", "Uso de CPU do sistema (%)", "gauge")
            m("netguard_system_cpu_percent", psutil.cpu_percent(interval=0.1))

            vm = psutil.virtual_memory()
            g("netguard_system_memory_percent", "Uso de memória RAM do sistema (%)", "gauge")
            m("netguard_system_memory_percent", round(vm.percent, 1))

            g("netguard_system_memory_used_bytes", "Memória RAM usada em bytes", "gauge")
            m("netguard_system_memory_used_bytes", vm.used)

            disk = psutil.disk_usage("/")
            g("netguard_system_disk_percent", "Uso de disco do sistema (%)", "gauge")
            m("netguard_system_disk_percent", round(disk.percent, 1))

            g("netguard_system_processes_total", "Total de processos em execução", "gauge")
            m("netguard_system_processes_total", len(list(psutil.process_iter())))

            net_io = psutil.net_io_counters()
            g("netguard_system_net_bytes_sent_total", "Total de bytes enviados pela rede", "counter")
            m("netguard_system_net_bytes_sent_total", net_io.bytes_sent)

            g("netguard_system_net_bytes_recv_total", "Total de bytes recebidos pela rede", "counter")
            m("netguard_system_net_bytes_recv_total", net_io.bytes_recv)

            try:
                conns = psutil.net_connections(kind="inet")
                g("netguard_system_connections_active", "Conexões de rede ativas (ESTABLISHED)", "gauge")
                m("netguard_system_connections_active",
                  sum(1 for c in conns if c.status == "ESTABLISHED"))
            except Exception:
                pass
    except Exception:
        pass

    # ── Scrape metadata ───────────────────────────────────────────
    g("netguard_scrape_timestamp_seconds", "Timestamp Unix do último scrape", "gauge")
    m("netguard_scrape_timestamp_seconds", round(time.time(), 3))

    output = "\n".join(lines) + "\n"
    return Response(output, mimetype="text/plain; version=0.0.4; charset=utf-8")


# ══════════════════════════════════════════════════════════════════
#  BILLING — Stripe SaaS routes
# ══════════════════════════════════════════════════════════════════

@app.route("/health")
@app.route("/api/health")
def health():
    """
    Health check — status de todos os subsistemas.
    Erros internos retornam JSON opaco com request_id (sem traceback na resposta).
    """
    import uuid as _uuid
    req_id = _uuid.uuid4().hex[:12]
    try:
        resp, code = _health_inner()
        data = resp.get_json()
        data["request_id"] = req_id
        return jsonify(data), code
    except Exception as _ex:
        import traceback as _tb
        logger.error("health error [%s]: %s\n%s", req_id, _ex, _tb.format_exc())
        return jsonify({
            "status":     "error",
            "request_id": req_id,
            "error":      "internal_error",  # opaco — sem detalhes para o cliente
        }), 500


def _health_inner():
    """Usado por Docker healthcheck, load balancers e make health.
    HTTP 200 = tudo OK | HTTP 503 = algum subsistema critico down.
    """
    from datetime import timezone as _tz
    import time as _time  # noqa: F401

    # ── Banco de dados ─────────────────────────────────────────────
    try:
        stats = repo.stats()
        db_ok = True
        db_info = f"ok | {stats.get('total', 0)} eventos"
    except Exception as _e:
        db_ok = False
        db_info = f"erro: {_e}"

    # ── DB Adapter backend ─────────────────────────────────────────
    try:
        from storage.event_repository import USE_POSTGRES as _USE_STORAGE_PG
        db_backend = "postgresql" if _USE_STORAGE_PG else "sqlite"
    except Exception:
        db_backend = "sqlite"

    # ── Monitor loop ───────────────────────────────────────────────
    monitor_disabled = monitor_status.get("captura") == "desativada"
    monitor_ok  = monitor_status.get("rodando", False) or monitor_disabled
    monitor_info = (
        "desativado"
        if monitor_disabled else
        f"ciclo #{monitor_status.get('ciclo', 0)} | "
        f"ultimo={monitor_status.get('ultimo_ciclo', 'nunca')}"
        if monitor_status.get("rodando", False) else "parado"
    )

    # ── Captura de pacotes ─────────────────────────────────────────
    captura_info = monitor_status.get("captura", "desconhecido")
    captura_ok   = "indisponivel" not in captura_info and "erro" not in captura_info.lower()

    # ── IDS Engine ─────────────────────────────────────────────────
    try:
        ids_ok   = ids is not None
        ids_info = f"ok | {ids.store.count_total()} detecções" if ids_ok else "não inicializado"
    except Exception:
        ids_ok   = False
        ids_info = "erro"

    # ── Fail2Ban ───────────────────────────────────────────────────
    try:
        from fail2ban_engine import Fail2BanEngine  # noqa: F401
        f2b_ok   = True
        f2b_info = "ok"
    except Exception:
        f2b_ok   = False
        f2b_info = "não disponível"

    # ── Threat Feeds ──────────────────────────────────────────────
    try:
        feeds_ok   = True
        feeds_info = "ok"
    except Exception:
        feeds_ok   = False
        feeds_info = "não disponível"

    # ── Billing ───────────────────────────────────────────────────
    billing_info = "stripe ativo" if (BILLING_OK and billing_active()) else "modo demo (sem Stripe)"

    # ── Status geral ──────────────────────────────────────────────
    critical_ok = db_ok and monitor_ok
    overall     = "healthy" if critical_ok else "degraded"

    tid = _resolve_tenant_id()
    try:
        from demo_seed import DEMO_TENANT_ID
        is_demo = (tid == DEMO_TENANT_ID)
    except Exception:
        is_demo = False

    payload = {
        "status":    overall,
        "timestamp": datetime.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "version":   "3.0",
        "uptime_cycles": monitor_status.get("ciclo", 0),
        "demo_mode": is_demo,
        "tenant_id": tid,
        "db_backend": db_backend,
        "subsystems": {
            "database":    db_info,
            "monitor":     monitor_info,
            "packet_capture": captura_info,
            "ids_engine":  ids_info,
            "fail2ban":    f2b_info,
            "billing":     billing_info,
        },
        "connections_active": len(conexoes_ativas),
    }

    status_code = 200 if critical_ok else 503
    return jsonify(payload), status_code  # retornado como tupla para health()


@app.route("/login")
def login_page():
    """Página de login com token de API."""
    from flask import render_template
    # Se já tem cookie válido, redireciona direto pro dashboard
    if AUTH_ENABLED:
        token = request.cookies.get("netguard_token", "")
        if token:
            result = verify_any_token(token, repo)
            if result["valid"]:
                from flask import redirect as _redir
                _next = validate_redirect_url(request.args.get("next", "/dashboard"))
                return _redir(_next)
    return render_template("login.html")


@app.route("/api/auth/login", methods=["POST"])
@_limit_login
def auth_login():
    """
    Endpoint de login — valida token (admin ou tenant) e define cookie de sessão.
    Seta cookie httponly válido por 8h.
    Rate limit: 10 tentativas por IP por janela de 60 segundos.
    """
    from flask import make_response

    ip = request.remote_addr or "unknown"

    # ── BruteForceGuard — lockout escalonado persistido em SQLite ────
    # Thresholds: 3 erros→5min, 5→15min, 10→1h, 20→24h
    _bf_db   = os.environ.get("IDS_BF_DB", "netguard_security.db")
    _bf      = get_bf_guard(_bf_db)
    if _bf and _bf.is_locked(ip):
        remaining = _bf.lockout_remaining(ip)
        count     = _bf.failure_count(ip)
        logger.warning("Login bloqueado (BruteForce) | ip=%s | restam=%ds", ip, remaining)
        audit("LOGIN_BLOCKED", actor="brute_force_guard", ip=ip,
              detail=f"lockout_remaining={remaining}s count={count}")
        # Notifica operações apenas nos thresholds graves (10+ falhas)
        if count >= 10:
            _notify("BRUTE_FORCE_ALERT", ip=ip, count=count, duration_s=remaining)
        return jsonify({
            "valid": False,
            "error": f"Conta bloqueada por excesso de tentativas. Tente novamente em {remaining}s.",
        }), 429

    data  = request.get_json(silent=True) or {}
    token = data.get("token", "").strip()
    if not token:
        return jsonify({"valid": False, "error": "Token ausente"}), 400

    result = verify_any_token(token, repo)
    if not result["valid"]:
        if _bf:
            _bf.record_failure(ip)
            failures = _bf.failure_count(ip)
            logger.warning("Login falhou | ip=%s | token=%s… | tentativas=%d",
                           ip, token[:8], failures)
        else:
            logger.warning("Login falhou | ip=%s | token=%s…", ip, token[:8])
        audit("LOGIN_FAIL", actor="unknown", ip=ip, detail=f"token_prefix={token[:8]}")
        return jsonify({"valid": False, "error": "Token inválido"}), 401

    # Login OK — reseta contador de falhas
    if _bf:
        _bf.reset(ip)

    tenant_id = (result.get("tenant") or {}).get("tenant_id", "-")
    logger.info("Login OK | ip=%s | type=%s", ip, result["type"])
    audit("LOGIN_OK", actor=tenant_id, ip=ip, detail=f"type={result['type']}")
    resp = make_response(jsonify({
        "valid":  True,
        "type":   result["type"],
        "tenant": result.get("tenant"),
    }))
    _clear_preview_cookies(resp)
    resp.set_cookie(
        "netguard_token",
        token,
        httponly=True,
        samesite="Lax",
        max_age=8 * 3600,
        secure=_HTTPS_ONLY,  # True automaticamente quando HTTPS_ONLY=true
    )
    return resp


@app.route("/api/auth/free-preview", methods=["POST"])
@_limit_login
def auth_free_preview():
    """
    Inicia uma sessÃ£o curta de avaliaÃ§Ã£o com expiraÃ§Ã£o automÃ¡tica.
    O token real continua fora da URL e a experiÃªncia pode usar dados demo.
    """
    from flask import make_response

    data = request.get_json(silent=True) or {}
    token = data.get("token", "").strip()
    if not token:
        return jsonify({"valid": False, "error": "Token ausente"}), 400

    result = verify_any_token(token, repo)
    if not result["valid"]:
        return jsonify({"valid": False, "error": "Token invÃ¡lido"}), 401

    tenant = result.get("tenant") or {}
    preview_token = _ensure_demo_access_token(reason="free_preview") or token
    source = "demo" if preview_token != token else "tenant"
    actor = tenant.get("tenant_id", result.get("type", "unknown"))

    logger.info("Free preview iniciado | ip=%s | actor=%s | seconds=%d | source=%s",
                request.remote_addr or "unknown", actor, _FREE_PREVIEW_SECONDS, source)
    audit("FREE_PREVIEW_START", actor=actor, ip=request.remote_addr or "-",
          detail=f"seconds={_FREE_PREVIEW_SECONDS} source={source}")

    resp = make_response(jsonify({
        "valid": True,
        "mode": "free_preview",
        "minutes": _FREE_PREVIEW_MINUTES,
        "redirect_to": "/dashboard",
        "uses_demo_data": source == "demo",
    }))
    _clear_preview_cookies(resp)
    _apply_free_preview_cookies(resp, preview_token=preview_token, seconds=_FREE_PREVIEW_SECONDS)
    return resp


@app.route("/api/me")
@auth
def api_me():
    """
    Retorna dados do tenant autenticado: id, plano, role, e flags de acesso.
    Usado pelo dashboard para decidir quais abas/features mostrar.

    Resposta:
        {
          "tenant_id": "...",
          "name": "...",
          "plan": "pro",           // free | pro | business | enterprise
          "role": "admin",         // admin | analyst | viewer
          "is_paid": true,         // plano != free
          "is_admin": true,        // role == admin
          "can_see_admin_tab": true // is_paid && is_admin
        }
    """
    # Modo local (AUTH_ENABLED=False) → admin automático
    if not AUTH_ENABLED:
        return jsonify({
            "tenant_id":         "admin",
            "name":              "Administrador Local",
            "plan":              "enterprise",
            "role":              "admin",
            "is_paid":           True,
            "is_admin":          True,
            "can_see_admin_tab": True,
        })

    token = request.cookies.get("netguard_token", "") or \
            request.headers.get("X-API-Token", "") or \
            request.headers.get("Authorization", "").removeprefix("Bearer ").strip()

    # Admin token (arquivo .netguard_token)
    result = verify_any_token(token, repo)
    if result.get("type") == "admin":
        return jsonify({
            "tenant_id":       "admin",
            "name":            "Administrador",
            "plan":            "enterprise",
            "role":            "admin",
            "is_paid":         True,
            "is_admin":        True,
            "can_see_admin_tab": True,
        })

    tenant = result.get("tenant")
    if not tenant:
        return jsonify({"error": "Não autenticado"}), 401

    t = dict(tenant) if not isinstance(tenant, dict) else tenant
    plan    = t.get("plan", "free")
    role    = t.get("role", "analyst")
    is_paid = plan in ("pro", "business", "enterprise")
    is_adm  = role == "admin"

    return jsonify({
        "tenant_id":         t.get("tenant_id", ""),
        "name":              t.get("name", ""),
        "plan":              plan,
        "role":              role,
        "is_paid":           is_paid,
        "is_admin":          is_adm,
        "can_see_admin_tab": is_paid and is_adm,
    })


@app.route("/logout")
def logout():
    """Limpa cookie de sessão e redireciona para login."""
    from flask import make_response, redirect as _redir
    resp = make_response(_redir("/login"))
    resp.delete_cookie("netguard_token")
    _clear_preview_cookies(resp)
    logger.info("Logout | ip=%s", request.remote_addr)
    audit("LOGOUT", ip=request.remote_addr or "-")
    return resp


@app.route("/api/auth/validate", methods=["POST"])
@_limit_validate
def auth_validate():
    """Valida token e retorna dados do tenant (sem setar cookie)."""
    data  = request.get_json(silent=True) or {}
    token = data.get("token", "").strip()
    if not token:
        return jsonify({"valid": False, "error": "Token ausente"}), 400
    result = verify_any_token(token, repo)
    if result["valid"]:
        return jsonify({
            "valid":  True,
            "type":   result["type"],
            "tenant": result.get("tenant"),
        })
    return jsonify({"valid": False, "error": "Token inválido"}), 401


@app.route("/api/auth/rotate", methods=["POST"])
@auth
@csrf_protect
@require_role("admin")
def rotate_token_endpoint():
    """
    Rotaciona o token de API do tenant autenticado.

    Segurança:
    - Requer role=admin (apenas o owner do tenant pode rotacionar)
    - Token antigo é invalidado atomicamente no banco
    - Novo token retornado apenas nesta resposta (one-time display)
    - Cookie é atualizado automaticamente

    Returns:
        200: { "new_token": "ng_...", "rotated_at": "<iso>" }
        403: role insuficiente
        500: erro interno
    """
    from flask import g, make_response
    from datetime import datetime, timezone

    ip = request.remote_addr or "unknown"
    try:
        tenant_id = getattr(g, "tenant_id", None) or _resolve_tenant_id()
        if not tenant_id or tenant_id == "default":
            return jsonify({"error": "Tenant não identificado"}), 400

        old_token = request.cookies.get("netguard_token", "")

        # Gera novo token + hash via rotate_token()
        if BILLING_OK:
            new_token, new_hash = rotate_token(old_token, generate_api_token)
        else:
            import secrets, base64
            _gen = lambda: "ng_" + base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()  # noqa
            new_token, new_hash = rotate_token(old_token, _gen)

        # Persiste atomicamente no banco
        repo.update_tenant_token(tenant_id, new_token, new_hash)

        audit("TOKEN_ROTATED", actor=tenant_id, ip=ip,
              detail=f"old_prefix={old_token[:8]} new_prefix={new_token[:8]}")
        logger.info("Token rotacionado | tenant=%s | ip=%s", tenant_id, ip)

        rotated_at = datetime.now(timezone.utc).isoformat()
        resp = make_response(jsonify({
            "new_token":  new_token,
            "rotated_at": rotated_at,
            "message":    "Salve este token agora — não será exibido novamente.",
        }))
        # Atualiza cookie com novo token
        resp.set_cookie(
            "netguard_token",
            new_token,
            httponly=True,
            samesite="Lax",
            max_age=8 * 3600,
            secure=_HTTPS_ONLY,
        )
        return resp

    except Exception as exc:
        logger.error("Erro ao rotacionar token | tenant=%s | err=%s", tenant_id, exc)
        return jsonify({"error": "Erro interno ao rotacionar token"}), 500


@app.route("/pricing")
def pricing():
    """Página pública de planos e preços."""
    from flask import render_template
    cancelled     = request.args.get("cancelled") == "1"
    contact_ok    = request.args.get("contact") == "ok"
    error         = request.args.get("error", "")
    upgrade       = request.args.get("upgrade", "")
    contact_email = CONTACT_EMAIL if BILLING_OK else "contato@netguard.io"
    stripe_active = BILLING_OK and billing_active()
    return render_template(
        "pricing.html",
        cancelled     = cancelled,
        contact_ok    = contact_ok,
        error         = error,
        upgrade       = upgrade,
        contact_email = contact_email,
        plans         = PLANS if BILLING_OK else {},
        stripe_active = stripe_active,
    )


@app.route("/trial", methods=["POST"])
@_limit_trial
def trial():
    """
    Registra um novo tenant no plano Free ou Pro sem exigir cartão.
    Body (JSON ou form): name, email, company, plan (opcional, default 'pro').
    Cria o tenant diretamente e redireciona para /welcome em modo demo.
    """
    from flask import redirect
    import uuid

    if request.is_json:
        data = request.get_json(silent=True) or {}
    else:
        data = request.form

    if any(has_dangerous_input(data.get(field, "")) for field in ("name", "email", "company")):
        if request.is_json:
            return jsonify({"error": "Entrada inválida"}), 400
        return redirect("/pricing?error=missing_fields")

    name    = sanitize(data.get("name", "").strip(),    100, "name")
    email   = sanitize(data.get("email", "").strip(),   200, "email")
    company = sanitize(data.get("company", "").strip(), 200, "company")
    plan_key = data.get("plan", "pro")

    if plan_key not in ("free", "pro"):
        plan_key = "pro"

    if not name or not email:
        if request.is_json:
            return jsonify({"error": "Nome e e-mail são obrigatórios"}), 400
        return redirect(f"/pricing?error=missing_fields")

    token     = generate_api_token()
    plan_info = get_plan(plan_key)
    tenant_id = str(uuid.uuid4())

    try:
        repo.create_tenant(
            tenant_id = tenant_id,
            name      = company or name,
            token     = token,
            plan      = plan_key,
            max_hosts = plan_info["max_hosts"],
        )
        logger.info("Trial tenant criado: %s | plan=%s | email=%s", tenant_id, plan_key, email)
        audit("TENANT_TRIAL", actor=email,
              ip=request.remote_addr or "-",
              detail=f"plan={plan_key} company={company} tenant_id={tenant_id}")
    except Exception as exc:
        logger.error("Erro ao criar trial tenant: %s", exc)
        if request.is_json:
            return jsonify({"error": "Falha ao criar conta"}), 500
        return redirect("/pricing?error=server")

    # E-mail de boas-vindas — assíncrono, falha silenciosa
    send_welcome(
        name    = name,
        email   = email,
        token   = token,
        plan    = plan_key,
        app_url = request.host_url.rstrip("/"),
    )

    # Notificação Telegram/Slack — assíncrona, falha silenciosa
    _notify("TRIAL_CREATED", name=name, email=email,
            company=company, plan=plan_key, tenant_id=tenant_id)

    if request.is_json:
        welcome_ticket = _issue_welcome_ticket(_build_welcome_context(
            demo=True,
            token=token,
            name=name,
            plan_label=plan_info["name"],
            server_url=request.host_url.rstrip("/"),
        ))
        return jsonify({
            "ok": True,
            "token": token,
            "tenant_id": tenant_id,
            "plan": plan_key,
            "welcome_url": f"{request.host_url.rstrip('/')}/welcome?onboarding={welcome_ticket}",
        })

    welcome_ticket = _issue_welcome_ticket(_build_welcome_context(
        demo=True,
        token=token,
        name=name,
        plan_label=plan_info["name"],
        server_url=request.host_url.rstrip("/"),
    ))
    return redirect(f"/welcome?onboarding={welcome_ticket}", code=303)


@app.route("/contact", methods=["POST"])
@_limit_contact
def contact():
    """
    Recebe formulário de contato para Enterprise/MSSP.
    Registra o lead no audit log e retorna confirmação.
    Opcionalmente envia e-mail se SMTP estiver configurado (futuro).
    """
    if request.is_json:
        data = request.get_json(silent=True) or {}
    else:
        data = request.form

    if any(has_dangerous_input(data.get(field, "")) for field in ("name", "email", "company", "message")):
        if request.is_json:
            return jsonify({"error": "Entrada inválida"}), 400
        return redirect("/pricing?error=missing_fields")

    name    = sanitize(data.get("name", "").strip(),    100, "name")
    email   = sanitize(data.get("email", "").strip(),   200, "email")
    company = sanitize(data.get("company", "").strip(), 200, "company")
    plan    = data.get("plan", "enterprise")
    message = sanitize(data.get("message", "").strip(), 2000, "message")

    if not name or not email:
        if request.is_json:
            return jsonify({"error": "Nome e e-mail são obrigatórios"}), 400
        return redirect("/pricing?error=missing_fields")

    logger.info("Contato Enterprise/MSSP: email=%s company=%s plan=%s", email, company, plan)
    audit("CONTACT_LEAD", actor=email,
          ip=request.remote_addr or "-",
          detail=f"plan={plan} company={company} msg_len={len(message)}")

    # Confirmação para o lead — assíncrona, falha silenciosa
    send_contact_confirmation(name=name, email=email, plan=plan)

    if request.is_json:
        return jsonify({
            "ok": True,
            "message": "Recebemos seu contato! Nossa equipe retornará em até 1 dia útil.",
        })

    return redirect("/pricing?contact=ok")


@app.route("/checkout", methods=["POST"])
def checkout():
    """
    Inicia sessão de checkout no Stripe (modo produção) ou cria tenant demo.

    Modo Stripe  → redireciona para checkout.stripe.com
    Modo demo    → cria tenant direto e redireciona para /welcome
    """
    from flask import redirect
    import traceback as _tb
    import uuid as _uuid

    # Funções de fallback quando billing.py não está disponível
    def _gen_token():
        import secrets as _s
        return "ng_" + _s.token_urlsafe(32)

    _MAX_HOSTS = {"free": 1, "pro": 20, "enterprise": 9999, "mssp": 9999}

    try:
        if any(has_dangerous_input(request.form.get(field, "")) for field in ("plan", "email", "name", "company")):
            return redirect("/pricing?error=missing_fields")
        plan    = sanitize(request.form.get("plan",    "pro").strip(),   20,  "plan")
        email   = sanitize(request.form.get("email",   "").strip(),      200, "email")
        name    = sanitize(request.form.get("name",    "").strip(),      100, "name")
        company = sanitize(request.form.get("company", "").strip(),      200, "company")

        if plan not in ("free", "pro", "enterprise", "mssp"):
            plan = "pro"

        if not email or not name:
            return redirect("/pricing?error=missing_fields")

        # Só usa Stripe se: billing ok + key configurada + price_id do plano configurado
        stripe_on = False
        if BILLING_OK and billing_active():
            _plan_cfg = get_plan(plan)
            if _plan_cfg.get("price_id"):   # price_id vazio → modo demo
                stripe_on = True

        if not stripe_on:
            # ── Modo demo / sem Stripe ──────────────────────────────
            token     = generate_api_token() if BILLING_OK else _gen_token()
            max_hosts = (get_plan(plan)["max_hosts"] if BILLING_OK
                         else _MAX_HOSTS.get(plan, 1))
            tenant_id = str(_uuid.uuid4())

            repo.create_tenant(
                tenant_id = tenant_id,
                name      = company or name,
                token     = token,
                plan      = plan,
                max_hosts = max_hosts,
            )
            audit("TENANT_CHECKOUT_DEMO", actor=email, ip=request.remote_addr or "-",
                  detail=f"plan={plan} company={company} tenant_id={tenant_id}")
            _notify("TRIAL_CREATED", name=name, email=email,
                    company=company, plan=plan, tenant_id=tenant_id)
            send_welcome(name=name, email=email, token=token, plan=plan,
                         app_url=request.host_url.rstrip("/"))
            welcome_ticket = _issue_welcome_ticket(_build_welcome_context(
                demo=True,
                token=token,
                name=name,
                plan_label=get_plan(plan)["name"] if BILLING_OK else plan.upper(),
                server_url=request.host_url.rstrip("/"),
            ))
            return redirect(f"/welcome?onboarding={welcome_ticket}", code=303)

        # ── Modo Stripe real ────────────────────────────────────────
        url = create_checkout_session(plan, email, name, company)
        if not url:
            logger.error("Stripe checkout falhou: plan=%s email=%s", plan, email)
            return redirect("/pricing?error=checkout_failed")

        audit("CHECKOUT_START", actor=email, ip=request.remote_addr or "-",
              detail=f"plan={plan} company={company} mode=stripe")
        return redirect(url)

    except Exception as _exc:
        logger.error("checkout() exception: %s\n%s", _exc, _tb.format_exc())
        return redirect("/pricing?error=server")


@app.route("/welcome")
def welcome():
    """
    Página de boas-vindas pós-pagamento.
    Dois modos:
      ?onboarding=<ticket> → mostra onboarding seguro de uso único
      ?session_id=cs_...   → pagamento real via Stripe
      ?demo=1&...          → fluxo legado descontinuado por segurança
    """
    from flask import redirect

    onboarding = request.args.get("onboarding", "").strip()
    if onboarding:
        payload = _consume_welcome_ticket(onboarding)
        if not payload:
            return redirect("/pricing?error=welcome_expired")
        return _render_welcome_page(**payload)

    demo       = request.args.get("demo") == "1"
    session_id = request.args.get("session_id", "")

    if demo:
        logger.warning("Onboarding demo legado bloqueado | ip=%s", request.remote_addr or "-")
        audit("WELCOME_LEGACY_BLOCKED", ip=request.remote_addr or "-",
              detail="legacy demo query rejected")
        return redirect("/pricing?error=welcome_expired", code=303)

    # Pagamento real: busca dados no Stripe
    if not session_id:
        return redirect("/pricing")

    if not BILLING_OK:
        return jsonify({"error": "Billing não configurado"}), 500

    stripe_session = retrieve_checkout_session(session_id)
    if not stripe_session:
        return jsonify({"error": "Sessão de checkout inválida"}), 400

    meta      = stripe_session.get("metadata", {})
    plan_key  = meta.get("plan", "pro")
    name      = meta.get("name", "")
    email     = meta.get("email", "")
    plan_info = get_plan(plan_key)
    token     = generate_api_token()

    stripe_customer_id      = (stripe_session.get("customer") or {}).get("id", "")
    stripe_subscription_id  = (stripe_session.get("subscription") or {}).get("id", "")

    existing = None
    if stripe_subscription_id and hasattr(repo, "get_tenant_by_stripe_subscription_id"):
        existing = repo.get_tenant_by_stripe_subscription_id(stripe_subscription_id)
    if not existing and stripe_customer_id and hasattr(repo, "get_tenant_by_stripe_customer_id"):
        existing = repo.get_tenant_by_stripe_customer_id(stripe_customer_id)
    if existing:
        logger.info("Stripe session já provisionada | customer=%s | subscription=%s",
                    stripe_customer_id, stripe_subscription_id)
        return redirect("/login?provisioned=1")

    tenant_id = str(uuid.uuid4())
    try:
        repo.create_tenant(
            tenant_id = tenant_id,
            name      = name or email,
            token     = token,
            plan      = plan_key,
            max_hosts = plan_info["max_hosts"],
            stripe_customer_id = stripe_customer_id,
            stripe_subscription_id = stripe_subscription_id,
        )
        logger.info("Tenant criado via Stripe: %s | plan=%s | cust=%s",
                    tenant_id, plan_key, stripe_customer_id)
        audit("TENANT_CREATE", actor=email or tenant_id,
              ip=request.remote_addr or "-",
              detail=f"plan={plan_key} mode=stripe stripe_customer={stripe_customer_id} tenant_id={tenant_id}")
    except Exception as exc:
        logger.error("Erro ao criar tenant: %s", exc)

    welcome_ticket = _issue_welcome_ticket(_build_welcome_context(
        demo=False,
        token=token,
        name=name,
        plan_label=plan_info["name"],
        server_url=request.host_url.rstrip("/"),
    ))
    return redirect(f"/welcome?onboarding={welcome_ticket}", code=303)


@app.route("/billing/portal")
@auth
@require_role("admin")
def billing_portal():
    """Redireciona para o portal de auto-atendimento do Stripe."""
    from flask import redirect, g as _g
    # Tenant identificado via g.tenant_id injetado pelo before_request
    tenant = repo.get_tenant_by_id(getattr(_g, "tenant_id", None))
    if not tenant:
        return jsonify({"error": "Tenant não encontrado"}), 404

    stripe_customer_id = tenant.get("stripe_customer_id", "")
    if not stripe_customer_id:
        return jsonify({"error": "Tenant sem customer Stripe — use o portal demo"}), 400

    url = create_portal_session(stripe_customer_id)
    if not url:
        return jsonify({"error": "Falha ao criar sessão do portal"}), 500

    return redirect(url)


@app.route("/stripe/webhook", methods=["POST"])
def stripe_webhook():
    """
    Webhook handler do Stripe.
    Eventos tratados:
      checkout.session.completed     → tenant já criado em /welcome; log apenas
      invoice.paid                   → confirma renovação
      customer.subscription.deleted  → desativa tenant
      customer.subscription.updated  → atualiza plano
    """
    import uuid  # noqa: F401
    payload    = request.get_data()
    sig_header = request.headers.get("Stripe-Signature", "")

    if not BILLING_OK:
        return jsonify({"error": "Billing não configurado"}), 500

    event = handle_webhook(payload, sig_header)
    if event is None:
        return jsonify({"error": "Webhook inválido"}), 400

    etype = event.get("type", "")
    data  = event["data"]["object"]

    if etype == "checkout.session.completed":
        # Tenant já criado em /welcome — apenas log
        meta = data.get("metadata", {})
        logger.info("Stripe checkout.session.completed | plan=%s | email=%s",
                    meta.get("plan"), meta.get("email"))

    elif etype == "invoice.paid":
        customer_id = data.get("customer", "")
        logger.info("Stripe invoice.paid | customer=%s — assinatura ativa", customer_id)
        # Reativa tenant se estava suspenso
        try:
            repo._exec_sql(
                "UPDATE tenants SET active=? WHERE stripe_customer_id=?",
                (1, customer_id)
            )
        except Exception:
            pass

    elif etype == "customer.subscription.deleted":
        customer_id = data.get("customer", "")
        logger.warning("Stripe subscription.deleted | customer=%s — desativando tenant", customer_id)
        try:
            repo._exec_sql(
                "UPDATE tenants SET active=? WHERE stripe_customer_id=?",
                (0, customer_id)
            )
        except Exception:
            pass

    elif etype == "customer.subscription.updated":
        customer_id = data.get("customer", "")
        # Descobre novo plano pelo price metadata
        items    = data.get("items", {}).get("data", [])
        price_id = items[0]["price"]["id"] if items else ""
        new_plan = next(
            (k for k, v in PLANS.items() if v.get("price_id") == price_id),
            None
        ) if BILLING_OK else None
        if new_plan:
            plan_info = get_plan(new_plan)
            try:
                repo._exec_sql(
                    "UPDATE tenants SET plan=?, max_hosts=? WHERE stripe_customer_id=?",
                    (new_plan, plan_info["max_hosts"], customer_id)
                )
                logger.info("Plano atualizado: customer=%s → %s", customer_id, new_plan)
            except Exception:
                pass

    return jsonify({"received": True}), 200


# ── Demo ──────────────────────────────────────────────────────────

@app.route("/demo")
def demo_access():
    """
    Acesso direto ao ambiente de demonstração.
    Cria o tenant demo (se não existir), seta cookie e redireciona ao dashboard.
    Desative com IDS_DEMO_DISABLED=true em produção.
    """
    from flask import make_response, redirect as _redir  # noqa: F401
    if os.environ.get("IDS_DEMO_DISABLED", "false").lower() == "true":
        return redirect("/pricing")

    demo_token = _ensure_demo_access_token(reason="demo_route")
    if not demo_token:
        try:
            from demo_seed import DEMO_TOKEN as _DEMO_TOKEN
            demo_token = _DEMO_TOKEN
        except Exception:
            demo_token = "ng_DEMO00000000000000000000000000"

    dashboard_path = pathlib.Path(__file__).parent / "dashboard.html"
    if not dashboard_path.exists():
        return redirect("/login")

    html = dashboard_path.read_text(encoding="utf-8")
    resp = make_response(html, 200)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    _set_no_cache_headers(resp)
    _clear_preview_cookies(resp)
    resp.set_cookie(
        "netguard_token", demo_token,
        httponly=True, samesite="Lax",
        max_age=4 * 3600,
        secure=_HTTPS_ONLY,
    )
    return resp


@app.route("/demo/reset", methods=["POST"])
def demo_reset():
    """Recria os dados de demo do zero (útil para apresentações)."""
    if os.environ.get("IDS_DEMO_DISABLED", "false").lower() == "true":
        return jsonify({"error": "Demo desativado"}), 403
    try:
        from demo_seed import seed_demo, clear_demo, DEMO_TOKEN  # noqa: F401
        clear_demo(repo, verbose=False)
        result = seed_demo(repo, n_events=350, verbose=False)
        audit("DEMO_RESET", ip=request.remote_addr or "-")
        return jsonify({"ok": True, "events": result["events"]})
    except Exception as exc:
        logger.error("Demo reset falhou: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ── Alertas por e-mail ────────────────────────────────────────────

@app.route("/api/alerts/test", methods=["POST"])
@require_session
def alerts_test():
    """
    Envia um e-mail de teste para verificar a configuração SMTP.

    Body JSON:
        { "email": "destino@empresa.com", "name": "Empresa Teste" }

    Variáveis de ambiente necessárias:
        ALERT_EMAIL_ENABLED=true
        SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS
    """
    from alerts.email_alert import get_alert_manager, ALERT_ENABLED, SMTP_USER  # noqa: F401

    if not ALERT_ENABLED:
        return jsonify({
            "ok": False,
            "error": "Alertas desativados. Defina ALERT_EMAIL_ENABLED=true e configure SMTP_USER/SMTP_PASS.",
        }), 400

    data    = request.get_json(silent=True) or {}
    to_mail = data.get("email", "").strip()
    name    = data.get("name", "Empresa Teste")

    if not to_mail:
        return jsonify({"ok": False, "error": "Campo 'email' obrigatório"}), 400

    try:
        get_alert_manager().send_test(to_mail, tenant_name=name)
        audit("ALERT_TEST", actor=to_mail, ip=request.remote_addr or "-",
              detail=f"to={to_mail}")
        return jsonify({"ok": True, "message": f"E-mail de teste enviado para {to_mail}"})
    except Exception as exc:
        logger.error("Teste de alerta falhou: %s", exc)
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/alerts/status")
@require_session
def alerts_status():
    """Retorna status atual da configuração de alertas."""
    from alerts.email_alert import ALERT_ENABLED, SMTP_HOST, SMTP_PORT, SMTP_USER, ALERT_SEVERITIES, RATE_LIMIT_SEC
    return jsonify({
        "enabled":       ALERT_ENABLED,
        "smtp_host":     SMTP_HOST,
        "smtp_port":     SMTP_PORT,
        "smtp_user":     SMTP_USER if SMTP_USER else "(não configurado)",
        "severities":    sorted(ALERT_SEVERITIES),
        "rate_limit_s":  RATE_LIMIT_SEC,
        "configured":    bool(SMTP_USER and ALERT_ENABLED),
    })


# ── Relatório PDF mensal ──────────────────────────────────────────

@app.route("/api/report/monthly")
@require_session
def report_monthly():
    """
    Gera e baixa o relatório mensal em PDF.

    Query params:
      month       YYYY-MM (default: mês anterior)
      tenant_id   ID do tenant (default: tenant do cookie)
      name        Nome do cliente no relatório
      company     Nome do parceiro/MSSP no relatório
    """
    try:
        from reports.pdf_report import generate_monthly_report
    except ImportError as exc:
        logger.error("reportlab não instalado: %s", exc)
        return jsonify({
            "error": "Módulo de relatório não disponível. "
                     "Instale com: pip install reportlab"
        }), 503

    month   = request.args.get("month")
    name    = request.args.get("name", "Cliente")
    company = request.args.get("company", "NetGuard IDS")

    # Detecta tenant do cookie — usa query param como fallback
    tenant_id = _resolve_tenant_id(request.args.get("tenant_id"))

    try:
        pdf_bytes = generate_monthly_report(
            repo,
            tenant_id   = tenant_id,
            month       = month,
            tenant_name = name,
            company_name= company,
        )
    except Exception as exc:
        logger.error("Erro ao gerar relatório PDF: %s", exc)
        return jsonify({"error": f"Falha ao gerar relatório: {exc}"}), 500

    from datetime import datetime as _dt
    label    = month or _dt.now().strftime("%Y-%m")
    filename = f"netguard-relatorio-{label}.pdf"

    audit("REPORT_DOWNLOAD", ip=request.remote_addr or "-",
          detail=f"tenant={tenant_id} month={label}")

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )


@app.route("/api/report/monthly/preview")
@require_session
def report_monthly_preview():
    """Mesmo que /api/report/monthly mas exibe inline (para preview no browser)."""
    try:
        from reports.pdf_report import generate_monthly_report
    except ImportError:
        return jsonify({"error": "reportlab não instalado"}), 503

    month     = request.args.get("month")
    name      = request.args.get("name", "Cliente")
    company   = request.args.get("company", "NetGuard IDS")
    tenant_id = _resolve_tenant_id(request.args.get("tenant_id"))

    try:
        pdf_bytes = generate_monthly_report(
            repo, tenant_id=tenant_id, month=month,
            tenant_name=name, company_name=company,
        )
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": "inline"},
    )


# ═══════════════════════════════════════════════════════════════════
# ── IOC Manager API ────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════
try:
    from ioc_manager import get_ioc_manager
    IOC_AVAILABLE = True
except Exception as _ioc_err:
    IOC_AVAILABLE = False
    print(f"[WARN] IOC Manager: {_ioc_err}")


def _get_ioc_mgr():
    tid = _resolve_tenant_id()
    db  = os.environ.get("IDS_DB_PATH", "netguard_events.db")
    return get_ioc_manager(db_path=db, tenant_id=tid)


@app.route("/api/ioc", methods=["GET"])
@auth
def ioc_list():
    """Lista IOCs do tenant atual."""
    if not IOC_AVAILABLE:
        return jsonify({"error": "IOC Manager não disponível"}), 503
    ioc_type   = request.args.get("type", "")
    active_only = request.args.get("active", "true").lower() == "true"
    limit  = min(int(request.args.get("limit", 500)), 2000)
    offset = int(request.args.get("offset", 0))
    mgr    = _get_ioc_mgr()
    iocs   = mgr.list_iocs(ioc_type=ioc_type, active_only=active_only,
                            limit=limit, offset=offset)
    stats  = mgr.count_iocs()
    return jsonify({"iocs": iocs, "stats": stats, "count": len(iocs)})


@app.route("/api/ioc", methods=["POST"])
@auth
@csrf_protect
@require_role("analyst", "admin")
def ioc_add():
    """Adiciona um IOC manualmente."""
    if not IOC_AVAILABLE:
        return jsonify({"error": "IOC Manager não disponível"}), 503
    data = request.get_json(force=True) or {}
    value = (data.get("value") or "").strip()
    if not value:
        return jsonify({"error": "Campo 'value' é obrigatório"}), 400
    try:
        mgr = _get_ioc_mgr()
        ioc = mgr.add_ioc(
            value=value,
            ioc_type=data.get("ioc_type", ""),
            threat_name=data.get("threat_name", "Custom IOC"),
            confidence=int(data.get("confidence", 80)),
            source=data.get("source", "manual"),
            tags=data.get("tags", []),
            notes=data.get("notes", ""),
        )
        return jsonify({"ok": True, "ioc": ioc}), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error("IOC add error: %s", e)
        return jsonify({"error": "Erro interno"}), 500


@app.route("/api/ioc/<ioc_id>", methods=["DELETE"])
@auth
@csrf_protect
@require_role("analyst", "admin")
def ioc_delete(ioc_id):
    """Remove um IOC."""
    if not IOC_AVAILABLE:
        return jsonify({"error": "IOC Manager não disponível"}), 503
    mgr = _get_ioc_mgr()
    ok  = mgr.delete_ioc(ioc_id)
    return jsonify({"ok": ok}), (200 if ok else 404)


@app.route("/api/ioc/<ioc_id>/toggle", methods=["POST"])
@auth
@csrf_protect
@require_role("analyst", "admin")
def ioc_toggle(ioc_id):
    """Ativa ou desativa um IOC."""
    if not IOC_AVAILABLE:
        return jsonify({"error": "IOC Manager não disponível"}), 503
    data   = request.get_json(force=True) or {}
    active = bool(data.get("active", True))
    mgr    = _get_ioc_mgr()
    ok     = mgr.toggle_ioc(ioc_id, active)
    return jsonify({"ok": ok})


@app.route("/api/ioc/import", methods=["POST"])
@auth
@csrf_protect
@require_role("analyst", "admin")
def ioc_import():
    """Importa IOCs via CSV (multipart/form-data ou raw bytes)."""
    if not IOC_AVAILABLE:
        return jsonify({"error": "IOC Manager não disponível"}), 503
    if "file" in request.files:
        csv_bytes = request.files["file"].read()
    else:
        csv_bytes = request.get_data()
    if not csv_bytes:
        return jsonify({"error": "Nenhum arquivo enviado"}), 400
    threat   = request.args.get("threat_name", "Imported IOC")
    conf     = int(request.args.get("confidence", 80))
    mgr      = _get_ioc_mgr()
    result   = mgr.import_csv(csv_bytes, default_threat=threat,
                               default_confidence=conf)
    return jsonify(result), 200


@app.route("/api/ioc/export", methods=["GET"])
@auth
def ioc_export():
    """Exporta IOCs como CSV."""
    if not IOC_AVAILABLE:
        return jsonify({"error": "IOC Manager não disponível"}), 503
    mgr      = _get_ioc_mgr()
    csv_data = mgr.export_csv()
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=netguard_iocs.csv"}
    )


@app.route("/api/ioc/hits", methods=["GET"])
@auth
def ioc_hits():
    """Lista hits recentes de IOCs."""
    if not IOC_AVAILABLE:
        return jsonify({"hits": []}), 200
    limit = min(int(request.args.get("limit", 50)), 200)
    mgr   = _get_ioc_mgr()
    hits  = mgr.recent_hits(limit=limit)
    return jsonify({"hits": hits, "count": len(hits)})


@app.route("/api/ioc/check", methods=["POST"])
@auth
@_limit_ioc_check
def ioc_check():
    """Verifica um valor (IP/domínio/hash) contra a lista de IOCs."""
    if not IOC_AVAILABLE:
        return jsonify({"hits": []}), 200
    data = request.get_json(force=True) or {}
    mgr  = _get_ioc_mgr()
    hits = mgr.check_all(
        ip=data.get("ip", ""),
        domain=data.get("domain", ""),
        file_hash=data.get("hash", ""),
    )
    return jsonify({"hits": hits, "matched": len(hits) > 0})


# ═══════════════════════════════════════════════════════════════════
# ── ML Anomaly API ─────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════
try:
    from engine.ml_anomaly import MLAnomalyEngine
    _ml_anomaly_engines: dict = {}
    ML_ANOMALY_AVAILABLE = True
except Exception as _mla_err:
    ML_ANOMALY_AVAILABLE = False
    _ml_anomaly_engines  = {}
    print(f"[WARN] ML Anomaly: {_mla_err}")


def _get_ml_anomaly():
    tid = _resolve_tenant_id()
    if tid not in _ml_anomaly_engines:
        repo = getattr(app, "_repo", None)
        _ml_anomaly_engines[tid] = MLAnomalyEngine(repo=repo, tenant_id=tid)
    return _ml_anomaly_engines[tid]


@app.route("/api/ml/anomaly/status", methods=["GET"])
@auth
def ml_anomaly_status():
    if not ML_ANOMALY_AVAILABLE:
        return jsonify({"available": False, "message": "scikit-learn não instalado"}), 200
    eng = _get_ml_anomaly()
    return jsonify(eng.status())


@app.route("/api/ml/anomaly/train", methods=["POST"])
@auth
@csrf_protect
@_limit_train
def ml_anomaly_train():
    if not ML_ANOMALY_AVAILABLE:
        return jsonify({"error": "scikit-learn não disponível"}), 503
    data     = request.get_json(force=True) or {}
    days_back = int(data.get("days_back", 30))
    eng      = _get_ml_anomaly()
    result   = eng.train(days_back=days_back)
    return jsonify(result)


@app.route("/api/ml/anomaly/detect", methods=["GET"])
@auth
def ml_anomaly_detect():
    if not ML_ANOMALY_AVAILABLE:
        return jsonify({"anomalies": []}), 200
    eng       = _get_ml_anomaly()
    anomalies = eng.get_anomalies(limit=50)
    return jsonify({"anomalies": anomalies, "count": len(anomalies),
                    "trained": eng._trained})


@app.route("/api/ml/anomaly/reset", methods=["POST"])
@auth
@csrf_protect
def ml_anomaly_reset():
    if not ML_ANOMALY_AVAILABLE:
        return jsonify({"ok": False}), 503
    eng = _get_ml_anomaly()
    eng.reset()
    return jsonify({"ok": True, "message": "ML Anomaly Engine resetado"})


# ═══════════════════════════════════════════════════════════════════
# ── Compliance Report API ──────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════
@app.route("/api/report/compliance")
@require_session
@_limit_report
def report_compliance():
    """Gera relatório de conformidade (SOC 2 / PCI DSS / HIPAA) em PDF."""
    try:
        from reports.compliance_report import generate_compliance_report
    except ImportError as e:
        return jsonify({"error": f"reportlab não instalado: {e}"}), 503

    framework  = request.args.get("framework", "soc2").lower()
    month      = request.args.get("month", "")
    org_name   = request.args.get("org", "Organização")
    tenant_id  = _resolve_tenant_id(request.args.get("tenant_id"))
    as_inline  = request.args.get("inline", "false").lower() == "true"

    try:
        repo = getattr(app, "_repo", None)
        pdf_bytes = generate_compliance_report(
            repo=repo,
            tenant_id=tenant_id,
            framework=framework,
            month=month,
            org_name=org_name,
        )
    except Exception as e:
        logger.error("Compliance report error: %s", e)
        return jsonify({"error": str(e)}), 500

    fw_labels = {"soc2": "SOC2", "pci": "PCI-DSS", "hipaa": "HIPAA"}
    fw_label  = fw_labels.get(framework, framework.upper())
    if not month:
        from datetime import datetime, timezone
        month = datetime.now(timezone.utc).strftime("%Y-%m")
    filename = f"NetGuard-{fw_label}-{month}.pdf"

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": (
                "inline" if as_inline else f'attachment; filename="{filename}"'
            )
        },
    )


# ═══════════════════════════════════════════════════════════════════
# ── Custom Rules API ───────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════
try:
    from custom_rules import get_custom_rule_engine
    CUSTOM_RULES_AVAILABLE = True
except Exception as _cr_err:
    CUSTOM_RULES_AVAILABLE = False
    print(f"[WARN] Custom Rules: {_cr_err}")


def _get_cr_engine():
    tid = _resolve_tenant_id()
    db  = os.environ.get("IDS_DB_PATH", "netguard_events.db")
    return get_custom_rule_engine(db_path=db, tenant_id=tid)


@app.route("/api/rules/custom", methods=["GET"])
@auth
def custom_rules_list():
    if not CUSTOM_RULES_AVAILABLE:
        return jsonify({"rules": [], "stats": {}}), 200
    eng   = _get_cr_engine()
    rules = eng.list_rules()
    stats = eng.stats()
    return jsonify({"rules": rules, "stats": stats, "count": len(rules)})


@app.route("/api/rules/custom", methods=["POST"])
@auth
@csrf_protect
@require_role("analyst", "admin")
def custom_rules_create():
    if not CUSTOM_RULES_AVAILABLE:
        return jsonify({"error": "Custom Rules não disponível"}), 503
    data = request.get_json(force=True) or {}
    try:
        eng  = _get_cr_engine()
        rule = eng.create_rule(
            name=data.get("name", ""),
            conditions=data.get("conditions", []),
            logic=data.get("logic", "AND"),
            severity=data.get("severity", "MEDIUM"),
            description=data.get("description", ""),
            tags=data.get("tags", []),
        )
        return jsonify({"ok": True, "rule": rule}), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error("Custom rule create error: %s", e)
        return jsonify({"error": "Erro interno"}), 500


@app.route("/api/rules/custom/<rule_id>", methods=["GET"])
@auth
def custom_rules_get(rule_id):
    if not CUSTOM_RULES_AVAILABLE:
        return jsonify({"error": "não disponível"}), 503
    eng  = _get_cr_engine()
    rule = eng.get_rule(rule_id)
    if not rule:
        return jsonify({"error": "Regra não encontrada"}), 404
    return jsonify(rule)


@app.route("/api/rules/custom/<rule_id>", methods=["PUT"])
@auth
@csrf_protect
@require_role("analyst", "admin")
def custom_rules_update(rule_id):
    if not CUSTOM_RULES_AVAILABLE:
        return jsonify({"error": "não disponível"}), 503
    data = request.get_json(force=True) or {}
    try:
        eng  = _get_cr_engine()
        rule = eng.update_rule(rule_id, **data)
        if not rule:
            return jsonify({"error": "Regra não encontrada"}), 404
        return jsonify({"ok": True, "rule": rule})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/rules/custom/<rule_id>", methods=["DELETE"])
@auth
@csrf_protect
@require_role("analyst", "admin")
def custom_rules_delete(rule_id):
    if not CUSTOM_RULES_AVAILABLE:
        return jsonify({"error": "não disponível"}), 503
    eng = _get_cr_engine()
    ok  = eng.delete_rule(rule_id)
    return jsonify({"ok": ok}), (200 if ok else 404)


@app.route("/api/rules/custom/<rule_id>/toggle", methods=["POST"])
@auth
@csrf_protect
@require_role("analyst", "admin")
def custom_rules_toggle(rule_id):
    if not CUSTOM_RULES_AVAILABLE:
        return jsonify({"error": "não disponível"}), 503
    data    = request.get_json(force=True) or {}
    enabled = bool(data.get("enabled", True))
    eng     = _get_cr_engine()
    rule    = eng.toggle_rule(rule_id, enabled)
    return jsonify({"ok": rule is not None, "rule": rule})


@app.route("/api/rules/custom/test", methods=["POST"])
@auth
def custom_rules_test():
    """Testa uma regra (ainda não salva) contra eventos recentes."""
    if not CUSTOM_RULES_AVAILABLE:
        return jsonify({"results": []}), 200
    data = request.get_json(force=True) or {}
    rule = data.get("rule", {})
    if not rule:
        return jsonify({"error": "Campo 'rule' obrigatório"}), 400
    # Carrega últimos 20 eventos para teste
    try:
        repo   = getattr(app, "_repo", None)
        tid    = _resolve_tenant_id()
        events = repo.query(tenant_id=tid, limit=20) if repo else []
        sample = [e if isinstance(e, dict) else vars(e) for e in events]
    except Exception:
        sample = []
    from custom_rules import evaluate_rule
    results = [
        {
            "event_id":   ev.get("event_id", ""),
            "event_type": ev.get("event_type", ""),
            "severity":   ev.get("severity", ""),
            "host_id":    ev.get("host_id", ""),
            "matched":    evaluate_rule(rule, ev),
        }
        for ev in sample
    ]
    matched = sum(1 for r in results if r["matched"])
    return jsonify({"results": results, "matched": matched, "total": len(results)})


@app.route("/api/rules/operators", methods=["GET"])
def custom_rules_operators():
    """Retorna operadores e campos disponíveis para criação de regras."""
    from custom_rules import OPERATORS, SEVERITY_LEVELS
    return jsonify({
        "operators": sorted(OPERATORS),
        "severity_levels": list(SEVERITY_LEVELS),
        "fields": [
            {"field": "severity",   "type": "string",  "example": "HIGH"},
            {"field": "event_type", "type": "string",  "example": "process_unknown"},
            {"field": "source",     "type": "string",  "example": "SOC"},
            {"field": "host_id",    "type": "string",  "example": "server-01"},
            {"field": "rule_name",  "type": "string",  "example": "Unknown Process"},
            {"field": "raw",        "type": "string",  "example": "powershell"},
            {"field": "hour",       "type": "number",  "example": 3},
            {"field": "weekday",    "type": "number",  "example": 6},
            {"field": "details.process", "type": "string", "example": "cmd.exe"},
            {"field": "details.cpu",     "type": "number", "example": 95},
            {"field": "details.ip",      "type": "string", "example": "1.2.3.4"},
        ],
        "logic_options": ["AND", "OR"],
    })


# ═══════════════════════════════════════════ TRIAL SYSTEM ══════════

try:
    from engine.trial_engine import get_trial_engine
    TRIAL_AVAILABLE = True
    logger.info("Trial Engine carregado")
except Exception as _te:
    TRIAL_AVAILABLE = False
    logger.warning("Trial Engine indisponível: %s", _te)

def _get_trial_engine():
    db = str(pathlib.Path(__file__).parent / "netguard_soc.db")
    return get_trial_engine(db)

def _render_trial_dashboard(trial: dict, remaining_seconds: int) -> str:
    """Serve o dashboard com metadados do trial injetados."""
    p = pathlib.Path(__file__).parent / "dashboard.html"
    html = p.read_text(encoding="utf-8")
    # Injeta variáveis do trial logo após a abertura do <body>.
    inject = f"""<script>
window.__TRIAL__ = {{
  token:     "{trial['token']}",
  name:      "{trial.get('name','').replace('"','')}",
  company:   "{trial.get('company','').replace('"','')}",
  email:     "{trial.get('email','').replace('"','')}",
  expiresAt: "{trial['expires_at']}",
  remainingSeconds: {remaining_seconds},
  durationH: {trial.get('duration_h', 72)}
}};
</script>"""
    html = re.sub(r"(<body\b[^>]*>)", rf"\1{inject}", html, count=1, flags=re.IGNORECASE)
    return html


def _set_no_cache_headers(resp):
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

def _render_trial_expired(trial: dict) -> str:
    company = trial.get("company") or trial.get("name") or trial.get("email","")
    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Trial Expirado — NetGuard IDS</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#e6edf3;
     display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center;padding:2rem}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:16px;padding:3rem 2.5rem;max-width:480px;width:100%}}
.icon{{font-size:3rem;margin-bottom:1rem}}
h1{{font-size:1.6rem;font-weight:700;margin-bottom:.5rem}}
p{{color:#8b949e;line-height:1.7;margin-bottom:1.5rem}}
.highlight{{color:#58a6ff;font-weight:600}}
.btn{{display:inline-block;background:#1f6feb;color:#fff;padding:12px 28px;border-radius:8px;
      text-decoration:none;font-weight:600;font-size:.95rem;transition:background .2s}}
.btn:hover{{background:#388bfd}}
.meta{{font-size:.78rem;color:#8b949e;margin-top:1.5rem;border-top:1px solid #30363d;padding-top:1rem}}
</style>
</head>
<body>
<div class="card">
  <div class="icon">⏱</div>
  <h1>Seu trial expirou</h1>
  <p>O acesso de demonstração para <span class="highlight">{company}</span> chegou ao fim.
     Você teve acesso completo ao NetGuard IDS — detecção em tempo real, ML Anomaly,
     Compliance PDF e muito mais.</p>
  <p>Assine agora e continue protegendo sua infraestrutura sem interrupção.</p>
  <a href="/pricing" class="btn">Ver planos e assinar →</a>
  <div class="meta">
    Dúvidas? Entre em contato: <a href="mailto:vendas@netguard.io" style="color:#58a6ff">vendas@netguard.io</a>
  </div>
</div>
</body>
</html>"""

@app.route("/trial/<token>")
def trial_access(token):
    """Acesso ao dashboard via link de trial com tempo limitado."""
    if not TRIAL_AVAILABLE:
        return redirect("/demo")

    result = _get_trial_engine().validate_trial(token)

    if result["expired"]:
        return _render_trial_expired(result["trial"]), 200, {"Content-Type": "text/html; charset=utf-8"}

    if not result["valid"]:
        return redirect("/pricing")

    # Seed de dados demo para este trial (tenant isolado por token hash)
    trial    = result["trial"]
    trial_tenant = "trial_" + token[-12:]
    try:
        from demo_seed import seed_demo
        from storage.event_repository import EventRepository as _ER
        _repo = _ER()
        cnt = _repo.count(tenant_id=trial_tenant)
        if cnt < 10:
            seed_demo(_repo, n_events=300, verbose=False, tenant_override=trial_tenant)
    except Exception as _se:
        logger.warning("Trial seed parcial: %s", _se)
        try:
            from demo_seed import DEMO_TOKEN
            trial_token_cookie = DEMO_TOKEN
        except Exception:
            trial_token_cookie = token
    else:
        trial_token_cookie = token

    html = _render_trial_dashboard(trial, result["remaining_seconds"])
    resp = make_response(html, 200)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    _set_no_cache_headers(resp)
    _clear_preview_cookies(resp)
    resp.set_cookie("netguard_token", trial_token_cookie,
                    httponly=True, samesite="Lax", max_age=result["remaining_seconds"],
                    secure=_HTTPS_ONLY)
    resp.set_cookie("netguard_trial", token,
                    httponly=False, samesite="Lax", max_age=result["remaining_seconds"])
    return resp


# ── Admin: gestão de trials ───────────────────────────────────────
@app.route("/api/admin/trials", methods=["GET"])
@auth
@require_role("admin")
def admin_trials_list():
    if not TRIAL_AVAILABLE:
        return jsonify({"error": "Trial Engine indisponível"}), 503
    trials = _get_trial_engine().list_trials()
    stats  = _get_trial_engine().stats()
    base   = request.host_url.rstrip("/")
    for t in trials:
        t["trial_url"] = f"{base}/trial/{t['token']}"
    return jsonify({"trials": trials, "stats": stats})

@app.route("/api/admin/trials", methods=["POST"])
@auth
@require_role("admin")
@csrf_protect
def admin_trials_create():
    if not TRIAL_AVAILABLE:
        return jsonify({"error": "Trial Engine indisponível"}), 503
    data = request.get_json(force=True) or {}
    try:
        trial = _get_trial_engine().create_trial(
            email      = data.get("email",""),
            name       = data.get("name",""),
            company    = data.get("company",""),
            duration_h = int(data.get("duration_h", 72)),
            notes      = data.get("notes",""),
        )
        base = request.host_url.rstrip("/")
        trial["trial_url"] = f"{base}/trial/{trial['token']}"
        return jsonify({"ok": True, "trial": trial}), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/admin/trials/<token>/revoke", methods=["POST"])
@auth
@require_role("admin")
@csrf_protect
def admin_trials_revoke(token):
    if not TRIAL_AVAILABLE:
        return jsonify({"error": "Trial Engine indisponível"}), 503
    _get_trial_engine().revoke_trial(token)
    return jsonify({"ok": True})

@app.route("/api/admin/trials/<token>/extend", methods=["POST"])
@auth
@require_role("admin")
@csrf_protect
def admin_trials_extend(token):
    if not TRIAL_AVAILABLE:
        return jsonify({"error": "Trial Engine indisponível"}), 503
    data  = request.get_json(force=True) or {}
    trial = _get_trial_engine().extend_trial(token, int(data.get("hours", 24)))
    return jsonify({"ok": True, "trial": trial})


# ── Admin Dashboard ───────────────────────────────────────────────

@app.route("/admin")
@require_session
@require_role("admin")
def admin_dashboard():
    """
    Painel de administração.
    Acesso: apenas tenants com role=admin E plano pago (pro/business/enterprise).
    Usuários free são redirecionados para /pricing mesmo que tenham role=admin.
    """
    from flask import render_template, redirect as _redir
    # Modo local (sem auth) → acesso total ao admin
    if not AUTH_ENABLED:
        return render_template("admin_dashboard.html")
    # Verificação extra de plano pago (dupla barreira além do require_role)
    token = (
        request.cookies.get("netguard_token", "")
        or request.headers.get("X-API-Token", "")
    )
    result = verify_any_token(token, repo)
    if result.get("type") != "admin":                  # admin token do sistema → acesso total
        tenant = result.get("tenant")
        if tenant:
            t    = dict(tenant) if not isinstance(tenant, dict) else tenant
            plan = t.get("plan", "free")
            if plan not in ("pro", "business", "enterprise"):
                logger.warning("Tentativa de acesso ao admin por tenant free | tid=%s",
                               t.get("tenant_id",""))
                return _redir("/pricing?upgrade=admin_required")
    return render_template("admin_dashboard.html")


@app.route("/api/admin/tenants", methods=["GET"])
@auth
@require_role("admin")
def admin_tenants_list():
    """Lista todos os tenants com stats de uso."""
    try:
        tenants_raw = repo.list_tenants()
        tenants = []
        for t in tenants_raw:
            td = dict(t) if not isinstance(t, dict) else t
            # O repositório já retorna apenas prefixos seguros; reforçamos aqui.
            td.pop("token_hash", None)
            td["token"] = td.get("token_prefix") or td.get("token", "")
            td["host_count"] = len(_ids_engines.get(td.get("tenant_id", ""), {__class__: None}).__dict__) \
                if td.get("tenant_id") in _ids_engines else 0
            tenants.append(td)
        return jsonify({"tenants": tenants, "total": len(tenants)})
    except Exception as exc:
        logger.error("admin_tenants_list error: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/admin/tenants", methods=["POST"])
@auth
@require_role("admin")
@csrf_protect
def admin_tenants_create():
    """Cria um tenant diretamente (sem self-serve)."""
    import uuid
    data     = request.get_json(force=True) or {}
    name     = sanitize(data.get("name","").strip(), 200, "name")
    plan_key = data.get("plan", "pro")
    max_hosts = int(data.get("max_hosts", 10))
    if not name:
        return jsonify({"error": "nome obrigatório"}), 400
    if plan_key not in ("free", "pro", "business", "enterprise"):
        plan_key = "pro"
    token     = generate_api_token()
    tenant_id = str(uuid.uuid4())
    try:
        repo.create_tenant(tenant_id=tenant_id, name=name, token=token,
                           plan=plan_key, max_hosts=max_hosts)
        audit("TENANT_CREATED", actor=tenant_id, ip=request.remote_addr or "-",
              detail=f"plan={plan_key} name={name}")
        _notify("TENANT_CREATED", tenant_id=tenant_id, name=name, plan=plan_key)
        return jsonify({"ok": True, "tenant_id": tenant_id, "token": token}), 201
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/admin/tenants/<tid>", methods=["DELETE"])
@auth
@require_role("admin")
@csrf_protect
def admin_tenants_delete(tid):
    """Remove um tenant do banco (não apaga dados de detecção)."""
    try:
        repo.delete_tenant(tid)
        # Remove engine em memória se existir
        with _ids_lock:
            _ids_engines.pop(tid, None)
        audit("TENANT_DELETED", actor=tid, ip=request.remote_addr or "-")
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/admin/tenants/<tid>/rotate-token", methods=["POST"])
@auth
@require_role("admin")
@csrf_protect
def admin_rotate_tenant_token(tid):
    """Rotaciona o token de um tenant específico (ação admin)."""
    try:
        old_row = repo.get_tenant_by_id(tid) if hasattr(repo, "get_tenant_by_id") else None
        old_prefix = (dict(old_row).get("token_prefix","") if old_row else "")
        new_token, new_hash = rotate_token(old_prefix, generate_api_token)
        repo.update_tenant_token(tid, new_token, new_hash)
        audit("TOKEN_ROTATED", actor=tid, ip=request.remote_addr or "-",
              detail=f"by=admin new_prefix={new_token[:8]}")
        return jsonify({"ok": True, "new_token": new_token})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/admin/audit", methods=["GET"])
@auth
@require_role("admin")
def admin_audit_log():
    """
    Retorna entradas do audit log (netguard_audit.log) como JSON.
    Parâmetros: limit (default 200), action (filtro), since (ISO datetime)
    """
    import json as _json
    limit  = min(int(request.args.get("limit", 200)), 1000)
    action_filter = request.args.get("action", "").strip().upper()

    entries = []
    audit_path = os.environ.get("IDS_AUDIT_LOG", "netguard_audit.log")
    try:
        if os.path.exists(audit_path):
            with open(audit_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = _json.loads(line)
                        if action_filter and obj.get("msg","").upper() != action_filter:
                            continue
                        entries.append({
                            "ts":     obj.get("ts",""),
                            "action": obj.get("msg",""),
                            "actor":  obj.get("actor","—"),
                            "ip":     obj.get("ip","—"),
                            "detail": obj.get("detail",""),
                        })
                    except _json.JSONDecodeError:
                        pass
        # Retorna as mais recentes primeiro
        entries = list(reversed(entries[-limit:]))
    except Exception as exc:
        logger.error("admin_audit_log error: %s", exc)
        return jsonify({"error": str(exc)}), 500

    return jsonify({"entries": entries, "total": len(entries)})


@app.route("/api/admin/security-stats", methods=["GET"])
@auth
@require_role("admin")
def admin_security_stats():
    """
    Stats de segurança: tentativas bloqueadas hoje, MRR estimado.
    """
    import json as _json
    from datetime import datetime, timezone

    today = datetime.now(timezone.utc).date().isoformat()
    blocked_today = 0
    mrr = 0

    # Conta LOGIN_BLOCKED no audit log de hoje
    audit_path = os.environ.get("IDS_AUDIT_LOG", "netguard_audit.log")
    try:
        if os.path.exists(audit_path):
            with open(audit_path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        obj = _json.loads(line)
                        if obj.get("msg","") == "LOGIN_BLOCKED" and obj.get("ts","").startswith(today):
                            blocked_today += 1
                    except Exception:
                        pass
    except Exception:
        pass

    # MRR estimado pelos planos dos tenants
    plan_prices = {"free": 0, "pro": 149, "business": 349, "enterprise": 999}
    try:
        tenants = repo.list_tenants()
        for t in tenants:
            td = dict(t) if not isinstance(t, dict) else t
            plan = td.get("plan", "free")
            mrr += plan_prices.get(plan, 0)
    except Exception:
        pass

    return jsonify({
        "blocked_today": blocked_today,
        "mrr": mrr,
        "mrr_formatted": f"R${mrr:,}".replace(",", "."),
    })


# ═══════════════════════════════════════ MITRE ATT&CK ══════════════

def _get_mitre_engine():
    db  = str(pathlib.Path(__file__).parent / "netguard_soc.db")
    tid = _resolve_tenant_id()
    return get_mitre_engine(db, tid)

@app.route("/api/mitre/stats", methods=["GET"])
@auth
def mitre_stats():
    """Estatísticas de cobertura MITRE ATT&CK."""
    if not MITRE_AVAILABLE:
        return jsonify({"error": "MITRE Engine indisponível"}), 503
    try:
        return jsonify(_get_mitre_engine().stats())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/mitre/heatmap", methods=["GET"])
@auth
def mitre_heatmap():
    """Heat map de técnicas ATT&CK detectadas nos últimos N dias."""
    if not MITRE_AVAILABLE:
        return jsonify({"error": "MITRE Engine indisponível"}), 503
    try:
        days = int(request.args.get("days", 30))
        return jsonify(_get_mitre_engine().heat_map(days))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/mitre/hits", methods=["GET"])
@auth
def mitre_hits():
    """Últimas N detecções mapeadas no ATT&CK."""
    if not MITRE_AVAILABLE:
        return jsonify({"error": "MITRE Engine indisponível"}), 503
    try:
        limit = int(request.args.get("limit", 50))
        days  = int(request.args.get("days", 30))
        hm    = _get_mitre_engine().heat_map(days)
        return jsonify({
            "hits":  hm.get("top10", []),
            "total": hm.get("total_hits", 0),
            "days":  days,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/mitre/navigator", methods=["GET"])
@auth
def mitre_navigator():
    """Exporta layer JSON compatível com ATT&CK Navigator."""
    if not MITRE_AVAILABLE:
        return jsonify({"error": "MITRE Engine indisponível"}), 503
    try:
        days  = int(request.args.get("days", 30))
        layer = _get_mitre_engine().navigator_layer(days)
        resp  = Response(
            json.dumps(layer, indent=2),
            mimetype="application/json",
        )
        resp.headers["Content-Disposition"] = "attachment; filename=netguard_mitre_layer.json"
        return resp
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/mitre/technique/<tid_param>", methods=["GET"])
@auth
def mitre_technique(tid_param: str):
    """Detalhe de uma técnica ATT&CK específica."""
    if not MITRE_AVAILABLE:
        return jsonify({"error": "MITRE Engine indisponível"}), 503
    try:
        detail = _get_mitre_engine().technique_detail(tid_param.upper())
        if not detail:
            return jsonify({"error": "Técnica não encontrada"}), 404
        return jsonify(detail)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════ WEBHOOK ALERTS ════════════

try:
    from engine.webhook_engine import get_webhook_engine
    WEBHOOK_AVAILABLE = True
    logger.info("Webhook Engine carregado")
except Exception as _we:
    WEBHOOK_AVAILABLE = False
    logger.warning("Webhook Engine indisponível: %s", _we)

# Threat Intel Feed
try:
    from engine.threat_intel_feed import get_ti_feed
    TI_AVAILABLE = True
    logger.info("Threat Intel Feed carregado")
except Exception as _ti_err:
    TI_AVAILABLE = False
    get_ti_feed = None
    logger.warning("Threat Intel Feed indisponível: %s", _ti_err)

# Incident Response Playbooks
try:
    from engine.playbook_engine import get_playbook_engine
    PLAYBOOK_AVAILABLE = True
    logger.info("Playbook Engine carregado")
except Exception as _pb_err:
    PLAYBOOK_AVAILABLE = False
    get_playbook_engine = None
    logger.warning("Playbook Engine indisponível: %s", _pb_err)

# Forensics Snapshot
try:
    from engine.forensics_engine import get_forensics_engine
    FORENSICS_AVAILABLE = True
    logger.info("Forensics Engine carregado")
except Exception as _fo_err:
    FORENSICS_AVAILABLE = False
    get_forensics_engine = None
    logger.warning("Forensics Engine indisponível: %s", _fo_err)

def _get_webhook_engine():
    db = str(pathlib.Path(__file__).parent / "netguard_soc.db")
    tid = _resolve_tenant_id()
    return get_webhook_engine(db, tid)

@app.route("/api/webhooks", methods=["GET"])
@auth
@require_role("analyst", "admin")
def webhooks_list():
    if not WEBHOOK_AVAILABLE:
        return jsonify({"error": "Webhook Engine indisponível"}), 503
    return jsonify({"webhooks": _get_webhook_engine().list_webhooks()})

@app.route("/api/webhooks", methods=["POST"])
@auth
@csrf_protect
@require_role("analyst", "admin")
def webhooks_create():
    if not WEBHOOK_AVAILABLE:
        return jsonify({"error": "Webhook Engine indisponível"}), 503
    try:
        wh = _get_webhook_engine().create_webhook(request.get_json(force=True) or {})
        return jsonify({"ok": True, "webhook": wh}), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/webhooks/<int:wid>", methods=["PUT"])
@auth
@csrf_protect
@require_role("analyst", "admin")
def webhooks_update(wid):
    if not WEBHOOK_AVAILABLE:
        return jsonify({"error": "Webhook Engine indisponível"}), 503
    wh = _get_webhook_engine().update_webhook(wid, request.get_json(force=True) or {})
    return jsonify({"ok": True, "webhook": wh})

@app.route("/api/webhooks/<int:wid>", methods=["DELETE"])
@auth
@csrf_protect
@require_role("analyst", "admin")
def webhooks_delete(wid):
    if not WEBHOOK_AVAILABLE:
        return jsonify({"error": "Webhook Engine indisponível"}), 503
    _get_webhook_engine().delete_webhook(wid)
    return jsonify({"ok": True})

@app.route("/api/webhooks/<int:wid>/toggle", methods=["POST"])
@auth
@csrf_protect
@require_role("analyst", "admin")
def webhooks_toggle(wid):
    if not WEBHOOK_AVAILABLE:
        return jsonify({"error": "Webhook Engine indisponível"}), 503
    wh = _get_webhook_engine().toggle_webhook(wid)
    return jsonify({"ok": True, "webhook": wh})

@app.route("/api/webhooks/<int:wid>/test", methods=["POST"])
@auth
@csrf_protect
@require_role("analyst", "admin")
def webhooks_test(wid):
    if not WEBHOOK_AVAILABLE:
        return jsonify({"error": "Webhook Engine indisponível"}), 503
    result = _get_webhook_engine().test_webhook(wid)
    return jsonify(result)

@app.route("/api/webhooks/<int:wid>/logs", methods=["GET"])
@auth
@require_role("analyst", "admin")
def webhooks_logs(wid):
    if not WEBHOOK_AVAILABLE:
        return jsonify({"error": "Webhook Engine indisponível"}), 503
    logs = _get_webhook_engine().recent_logs(wid, limit=30)
    return jsonify({"logs": logs})

@app.route("/api/webhooks/types", methods=["GET"])
@auth
def webhooks_types():
    """Lista os tipos de webhook suportados com instruções de configuração."""
    if not WEBHOOK_AVAILABLE:
        return jsonify({"error": "Webhook Engine indisponível"}), 503
    return jsonify({"types": _get_webhook_engine().supported_types()})


# ── Threat Intel Feed ────────────────────────────────────────────────────────

def _get_ti_feed():
    db = str(pathlib.Path(__file__).parent / "netguard_soc.db")
    feed = get_ti_feed(db)
    # Start scheduler on first call
    feed.start_scheduler(interval_check_s=300)
    return feed

@app.route("/api/ti/stats")
@auth
def ti_stats():
    if not TI_AVAILABLE:
        return jsonify({"available": False}), 503
    tenant_id = _resolve_tenant_id()
    return jsonify({"available": True, **_get_ti_feed().stats(tenant_id=tenant_id)})

@app.route("/api/ti/iocs")
@auth
def ti_iocs():
    if not TI_AVAILABLE:
        return jsonify({"available": False}), 503
    tenant_id = _resolve_tenant_id()
    source    = request.args.get("source")
    ioc_type  = request.args.get("type")
    limit     = min(int(request.args.get("limit", 200)), 1000)
    offset    = int(request.args.get("offset", 0))
    iocs = _get_ti_feed().list_iocs(source=source, ioc_type=ioc_type,
                                     limit=limit, offset=offset, tenant_id=tenant_id)
    return jsonify({"iocs": iocs, "count": len(iocs)})

@app.route("/api/ti/lookup")
@auth
def ti_lookup():
    if not TI_AVAILABLE:
        return jsonify({"available": False}), 503
    value     = request.args.get("value", "").strip()
    tenant_id = _resolve_tenant_id()
    if not value:
        return jsonify({"error": "value required"}), 400
    match = _get_ti_feed().lookup(value, tenant_id=tenant_id)
    return jsonify({"value": value, "match": match, "found": match is not None})

@app.route("/api/ti/feeds/<feed_name>/refresh", methods=["POST"])
@auth
@csrf_protect
@require_role("analyst", "admin")
def ti_refresh_feed(feed_name):
    if not TI_AVAILABLE:
        return jsonify({"available": False}), 503
    def _run():
        try:
            _get_ti_feed().refresh_feed(feed_name)
        except Exception as e:
            logger.error("TI refresh error: %s", e)
    threading.Thread(target=_run, daemon=True, name=f"ti-refresh-{feed_name}").start()
    return jsonify({"ok": True, "feed": feed_name, "status": "refresh_started"})

@app.route("/api/ti/feeds/refresh_all", methods=["POST"])
@auth
@csrf_protect
@require_role("analyst", "admin")
def ti_refresh_all():
    if not TI_AVAILABLE:
        return jsonify({"available": False}), 503
    def _run():
        try:
            _get_ti_feed().refresh_all()
        except Exception as e:
            logger.error("TI refresh_all error: %s", e)
    threading.Thread(target=_run, daemon=True, name="ti-refresh-all").start()
    return jsonify({"ok": True, "status": "refresh_all_started"})

# ── Incident Response Playbooks ───────────────────────────────────────────────

def _get_playbook_engine():
    db = str(pathlib.Path(__file__).parent / "netguard_soc.db")
    return get_playbook_engine(db)

@app.route("/api/playbooks")
@auth
def playbooks_list_route():
    if not PLAYBOOK_AVAILABLE:
        return jsonify({"available": False}), 503
    pbe = _get_playbook_engine()
    return jsonify({
        "available": True,
        "playbooks": pbe.playbooks_list(),
        "stats":     pbe.stats(_resolve_tenant_id()),
    })

@app.route("/api/playbooks/incidents")
@auth
def playbooks_incidents():
    if not PLAYBOOK_AVAILABLE:
        return jsonify({"available": False}), 503
    tenant_id = _resolve_tenant_id()
    status    = request.args.get("status")
    limit     = min(int(request.args.get("limit", 50)), 200)
    incidents = _get_playbook_engine().list_incidents(tenant_id=tenant_id, status=status, limit=limit)
    return jsonify({"incidents": incidents, "count": len(incidents)})

@app.route("/api/playbooks/incidents", methods=["POST"])
@auth
@csrf_protect
@require_role("analyst", "admin")
def playbooks_open_incident():
    if not PLAYBOOK_AVAILABLE:
        return jsonify({"available": False}), 503
    data = request.get_json(force=True) or {}
    pb_key = data.get("playbook")
    if not pb_key:
        return jsonify({"error": "playbook required"}), 400
    try:
        inc = _get_playbook_engine().open_incident(
            pb_key,
            trigger_event=data.get("trigger_event", {}),
            tenant_id=_resolve_tenant_id(),
        )
        return jsonify({"ok": True, "incident": inc}), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/playbooks/incidents/<incident_id>")
@auth
def playbooks_get_incident(incident_id):
    if not PLAYBOOK_AVAILABLE:
        return jsonify({"available": False}), 503
    inc = _get_playbook_engine().get_incident(incident_id)
    if not inc:
        return jsonify({"error": "Incidente não encontrado"}), 404
    return jsonify(inc)

@app.route("/api/playbooks/incidents/<incident_id>/status", methods=["POST"])
@auth
@csrf_protect
@require_role("analyst", "admin")
def playbooks_update_status(incident_id):
    if not PLAYBOOK_AVAILABLE:
        return jsonify({"available": False}), 503
    data   = request.get_json(force=True) or {}
    status = data.get("status", "")
    notes  = data.get("notes", "")
    _get_playbook_engine().update_incident_status(incident_id, status, notes)
    return jsonify({"ok": True})

@app.route("/api/playbooks/incidents/<incident_id>/steps/<int:step_order>", methods=["POST"])
@auth
@csrf_protect
@require_role("analyst", "admin")
def playbooks_update_step(incident_id, step_order):
    if not PLAYBOOK_AVAILABLE:
        return jsonify({"available": False}), 503
    data   = request.get_json(force=True) or {}
    status = data.get("status", "done")
    output = data.get("output", "")
    _get_playbook_engine().update_step(incident_id, step_order, status, output)
    return jsonify({"ok": True})

# ── Forensics Snapshots ───────────────────────────────────────────────────────

def _get_forensics_engine():
    db = str(pathlib.Path(__file__).parent / "netguard_soc.db")
    return get_forensics_engine(db)

@app.route("/api/forensics/snapshots")
@auth
def forensics_list():
    if not FORENSICS_AVAILABLE:
        return jsonify({"available": False}), 503
    tenant_id = _resolve_tenant_id()
    limit     = min(int(request.args.get("limit", 50)), 200)
    snaps = _get_forensics_engine().list_snapshots(tenant_id=tenant_id, limit=limit)
    stats = _get_forensics_engine().stats(tenant_id=tenant_id)
    return jsonify({"snapshots": snaps, "stats": stats, "available": True})

@app.route("/api/forensics/snapshots", methods=["POST"])
@auth
@csrf_protect
@require_role("analyst", "admin")
def forensics_capture():
    if not FORENSICS_AVAILABLE:
        return jsonify({"available": False}), 503
    data      = request.get_json(force=True) or {}
    tenant_id = _resolve_tenant_id()
    def _run():
        try:
            _get_forensics_engine().capture(
                trigger_type="manual",
                trigger_event=data,
                severity=data.get("severity", "high"),
                tenant_id=tenant_id,
            )
        except Exception as e:
            logger.error("Forensics capture error: %s", e)
    threading.Thread(target=_run, daemon=True, name="forensics-manual").start()
    return jsonify({"ok": True, "status": "capture_started"}), 202

@app.route("/api/forensics/snapshots/<snapshot_id>")
@auth
def forensics_get(snapshot_id):
    if not FORENSICS_AVAILABLE:
        return jsonify({"available": False}), 503
    snap = _get_forensics_engine().get_snapshot(snapshot_id)
    if not snap:
        return jsonify({"error": "Snapshot não encontrado"}), 404
    return jsonify(snap)

@app.route("/api/forensics/snapshots/<snapshot_id>", methods=["DELETE"])
@auth
@csrf_protect
@require_role("analyst", "admin")
def forensics_delete(snapshot_id):
    if not FORENSICS_AVAILABLE:
        return jsonify({"available": False}), 503
    _get_forensics_engine().delete_snapshot(snapshot_id)
    return jsonify({"ok": True})

# ═══════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    """Landing page pública — apresentação do produto."""
    from flask import render_template
    contact_email = CONTACT_EMAIL if BILLING_OK else "contato@netguard.io"
    return render_template("landing.html", contact_email=contact_email)


@app.route("/dashboard")
@require_session
def dashboard():
    p = pathlib.Path(__file__).parent/"dashboard.html"
    if not p.exists(): return "dashboard.html nao encontrado",404
    from flask import make_response
    resp = make_response(p.read_text(encoding="utf-8"), 200)
    resp.headers["Content-Type"] = "text/html;charset=utf-8"
    _set_no_cache_headers(resp)
    return resp

# ── Inicialização ─────────────────────────────────────────────────
def iniciar_monitoramento():
    if os.environ.get("IDS_DISABLE_BACKGROUND", "false").lower() == "true" or "pytest" in sys.modules:
        monitor_status["captura"] = "desativada"
        logger.info("Monitoramento em background desativado neste contexto")
        return
    threading.Thread(target=loop_monitor, kwargs={"intervalo":30},
                     daemon=True, name="ids-monitor").start()
    try:
        from packet_capture import PacketCapture, detectar_interface_ativa
        interface = detectar_interface_ativa()
        capture   = PacketCapture(callback=analisar, interface=interface)
        capture.iniciar()
        monitor_status["captura"] = f"ativa | interface={interface}"
        logger.info("Captura de pacotes iniciada | interface=%s", interface)
    except Exception as e:
        monitor_status["captura"] = f"indisponivel: {e}"
        logger.warning("Captura de pacotes indisponivel: %s", e)

iniciar_monitoramento()

if __name__=="__main__":
    host     = os.environ.get("IDS_HOST","127.0.0.1")
    port     = int(os.environ.get("IDS_PORT",5000))
    debug    = os.environ.get("IDS_DEBUG","false").lower()=="true"
    ssl_ctx  = get_ssl_context()
    print_startup_info()
    if ssl_ctx:
        app.run(host=host, port=HTTPS_PORT, debug=debug,
                use_reloader=False, ssl_context=ssl_ctx)
    else:
        app.run(host=host, port=port, debug=debug, use_reloader=False)
