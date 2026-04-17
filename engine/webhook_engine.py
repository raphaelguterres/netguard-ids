"""
NetGuard IDS — Webhook Alert Engine
Envia alertas críticos para Slack, Teams, Discord, Telegram, WhatsApp ou qualquer HTTP endpoint.
"""
from __future__ import annotations  # noqa: F401

from contextlib import contextmanager
import ipaddress
import json
import logging
import socket
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("netguard.webhook")

# ── SSRF Guard ────────────────────────────────────────────────
# Blocos de IP privados / reservados que nunca devem ser destinos de webhook.
_BLOCKED_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / cloud metadata
    ipaddress.ip_network("100.64.0.0/10"),     # shared address space (RFC 6598)
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]
_BLOCKED_HOSTS = {"localhost", "metadata.google.internal"}


def _validate_webhook_url(url: str) -> None:
    """
    Valida uma URL de destino de webhook contra SSRF.
    Levanta ValueError se a URL for interna, privada ou inválida.

    Regras:
    - Apenas https:// e http:// permitidos (não file://, ftp://, etc.)
    - Hostname não pode ser localhost, .local, IPs privados ou link-local
    - Resolve o hostname para verificar o IP resultante
    """
    if not url:
        raise ValueError("URL do webhook é obrigatória")

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        raise ValueError("URL inválida")

    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Scheme inválido '{parsed.scheme}': use https:// ou http://")

    host = parsed.hostname or ""
    if not host:
        raise ValueError("Hostname ausente na URL")

    # Bloquear hostnames internos conhecidos
    if host.lower() in _BLOCKED_HOSTS or host.lower().endswith(".local"):
        raise ValueError(f"Destino não permitido (host interno): {host}")

    # Resolver hostname e verificar IP resultante
    try:
        infos = socket.getaddrinfo(host, None)
        for _family, _type, _proto, _canonname, sockaddr in infos:
            raw_ip = sockaddr[0]
            try:
                addr = ipaddress.ip_address(raw_ip)
                for blocked in _BLOCKED_NETS:
                    if addr in blocked:
                        raise ValueError(
                            f"Destino bloqueado por política SSRF: "
                            f"{host} resolve para {raw_ip} (range privado/reservado)"
                        )
            except ValueError:
                raise
            except Exception:
                pass
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(
            f"Não foi possível validar o destino do webhook: falha ao resolver {host}"
        ) from exc


# ── Constantes ────────────────────────────────────────────────
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
MAX_RETRIES    = 3
RETRY_DELAY    = 2   # segundos (dobra a cada tentativa)
TIMEOUT        = 8   # segundos por request

SCHEMA = """
CREATE TABLE IF NOT EXISTS webhooks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   TEXT    NOT NULL DEFAULT 'default',
    name        TEXT    NOT NULL,
    url         TEXT    NOT NULL,
    type        TEXT    NOT NULL DEFAULT 'generic',
    min_severity TEXT   NOT NULL DEFAULT 'high',
    event_types TEXT    NOT NULL DEFAULT '[]',
    enabled     INTEGER NOT NULL DEFAULT 1,
    secret      TEXT,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    last_hit    TEXT,
    hit_count   INTEGER NOT NULL DEFAULT 0,
    fail_count  INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS webhook_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    webhook_id  INTEGER NOT NULL,
    tenant_id   TEXT    NOT NULL DEFAULT 'default',
    event_type  TEXT,
    severity    TEXT,
    status      TEXT    NOT NULL,
    status_code INTEGER,
    error       TEXT,
    sent_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
"""

# ── Formatadores por tipo ─────────────────────────────────────
def _fmt_slack(event: dict, webhook: dict) -> dict:
    sev = event.get("severity", "info")
    colors = {"critical": "#f85149", "high": "#f0883e",
              "medium":   "#d29922", "low":  "#3fb950", "info": "#58a6ff"}
    icons  = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}
    return {
        "username": "NetGuard IDS",
        "icon_emoji": ":shield:",
        "attachments": [{
            "color":  colors.get(sev, "#8b949e"),
            "title":  f"{icons.get(sev,'⚠')} [{sev.upper()}] {event.get('threat','Alerta de segurança')}",
            "text":   event.get("details", {}).get("description", event.get("msg", "")),
            "fields": [
                {"title": "IP Origem",  "value": event.get("source_ip", "—"),   "short": True},
                {"title": "Host",       "value": event.get("hostname", "—"),    "short": True},
                {"title": "Tipo",       "value": event.get("event_type", "—"),  "short": True},
                {"title": "Horário",    "value": event.get("timestamp", "—"),   "short": True},
            ],
            "footer": "NetGuard IDS",
            "ts":     int(time.time()),
        }]
    }


def _fmt_teams(event: dict, webhook: dict) -> dict:
    sev    = event.get("severity", "info")
    colors = {"critical": "attention", "high": "warning",
              "medium":   "accent",    "low":  "good", "info": "accent"}
    return {
        "@type":      "MessageCard",
        "@context":   "http://schema.org/extensions",
        "themeColor": {"critical": "f85149", "high": "f0883e",
                       "medium":   "d29922", "low":  "3fb950"}.get(sev, "58a6ff"),
        "summary":    event.get("threat", "Alerta NetGuard"),
        "sections":   [{
            "activityTitle":    f"**[{sev.upper()}]** {event.get('threat','Alerta de segurança')}",
            "activitySubtitle": event.get("details", {}).get("description", ""),
            "facts": [
                {"name": "IP Origem",  "value": event.get("source_ip", "—")},
                {"name": "Host",       "value": event.get("hostname", "—")},
                {"name": "Tipo",       "value": event.get("event_type", "—")},
                {"name": "Horário",    "value": event.get("timestamp", "—")},
            ],
        }],
    }


def _fmt_discord(event: dict, webhook: dict) -> dict:
    sev    = event.get("severity", "info")
    int_colors = {"critical": 0xf85149, "high": 0xf0883e,
                  "medium":   0xd29922, "low":  0x3fb950, "info": 0x58a6ff}
    return {
        "username": "NetGuard IDS",
        "embeds": [{
            "title":       f"[{sev.upper()}] {event.get('threat','Alerta de segurança')}",
            "description": event.get("details", {}).get("description", event.get("msg", "")),
            "color":       int_colors.get(sev, 0x8b949e),
            "fields": [
                {"name": "IP Origem",  "value": event.get("source_ip", "—"),  "inline": True},
                {"name": "Host",       "value": event.get("hostname", "—"),   "inline": True},
                {"name": "Tipo",       "value": event.get("event_type", "—"), "inline": True},
            ],
            "footer": {"text": "NetGuard IDS"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }]
    }


def _fmt_generic(event: dict, webhook: dict) -> dict:
    return {
        "source":     "netguard-ids",
        "severity":   event.get("severity"),
        "threat":     event.get("threat"),
        "event_type": event.get("event_type"),
        "source_ip":  event.get("source_ip"),
        "hostname":   event.get("hostname"),
        "timestamp":  event.get("timestamp"),
        "details":    event.get("details", {}),
    }


def _fmt_telegram(event: dict, webhook: dict) -> dict:
    """Formata para a Bot API do Telegram (sendMessage com Markdown).

    A URL do webhook deve ser:
        https://api.telegram.org/bot{TOKEN}/sendMessage?chat_id={CHAT_ID}

    O NetGuard monta o payload como JSON enviado via POST.
    """
    sev   = event.get("severity", "info")
    icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}
    icon  = icons.get(sev, "⚠️")
    desc  = event.get("details", {}).get("description", event.get("msg", "sem descrição"))
    ts    = event.get("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

    text = (
        f"{icon} *\\[{sev.upper()}\\] {event.get('threat', 'Alerta de Segurança')}*\n\n"
        f"📡 *IP Origem:* `{event.get('source_ip', '—')}`\n"
        f"🖥️ *Host:* `{event.get('hostname', '—')}`\n"
        f"🎯 *Tipo:* `{event.get('event_type', '—')}`\n"
        f"🕐 *Horário:* `{ts}`\n\n"
        f"📝 {desc}"
    )
    return {
        "text":       text,
        "parse_mode": "MarkdownV2",
    }


def _fmt_whatsapp(event: dict, webhook: dict) -> dict:
    """Formata para a API do WhatsApp Business (Z-API / Twilio / Evolution API).

    A URL e o campo de destino variam por provedor.
    Formato genérico compatível com Z-API e Evolution:
        POST {url}
        Body: {"phone": "{PHONE}", "message": "{TEXT}"}

    Para Twilio:
        Body: {"To": "whatsapp:+55...", "From": "whatsapp:+1...", "Body": "{TEXT}"}

    Escolha o subtipo via campo `secret` do webhook:
        secret = "twilio"  → usa formato Twilio
        secret = ""        → usa Z-API/Evolution (padrão)
    """
    sev     = event.get("severity", "info")
    icons   = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}
    icon    = icons.get(sev, "⚠️")
    desc    = event.get("details", {}).get("description", event.get("msg", "sem descrição"))
    ts      = event.get("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    subtype = (webhook.get("secret") or "").lower()

    msg = (
        f"{icon} *[{sev.upper()}] {event.get('threat', 'Alerta NetGuard')}*\n"
        f"IP: {event.get('source_ip', '—')} | Host: {event.get('hostname', '—')}\n"
        f"Tipo: {event.get('event_type', '—')} | {ts}\n\n"
        f"{desc}"
    )

    if subtype == "twilio":
        # Twilio WhatsApp — número configurado via URL query param ?To=whatsapp:+55...
        return {"Body": msg}
    else:
        # Z-API / Evolution API — número no campo `phone` da URL
        return {"message": msg}


FORMATTERS = {
    "slack":     _fmt_slack,
    "teams":     _fmt_teams,
    "discord":   _fmt_discord,
    "telegram":  _fmt_telegram,
    "whatsapp":  _fmt_whatsapp,
    "generic":   _fmt_generic,
}


# ── Engine ────────────────────────────────────────────────────
class WebhookEngine:
    def __init__(self, db_path: str, tenant_id: str = "default"):
        self.db_path   = db_path
        self.tenant_id = tenant_id
        self._lock     = threading.Lock()
        self._init_db()

    @contextmanager
    def _db(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self):
        with self._db() as c:
            c.executescript(SCHEMA)

    # ── CRUD ──────────────────────────────────────────────────
    def create_webhook(self, data: dict) -> dict:
        name        = str(data.get("name", "")).strip()
        url         = str(data.get("url", "")).strip()
        wtype       = data.get("type", "generic")
        min_sev     = data.get("min_severity", "high")
        event_types = json.dumps(data.get("event_types", []))
        secret      = data.get("secret", "")

        if not name or not url:
            raise ValueError("name e url são obrigatórios")
        if len(name) > 120:
            raise ValueError("name: máximo 120 caracteres")
        if len(url) > 2048:
            raise ValueError("url: máximo 2048 caracteres")
        if secret and len(str(secret)) > 512:
            raise ValueError("secret: máximo 512 caracteres")
        if wtype not in FORMATTERS:
            raise ValueError(f"type inválido: {wtype}")
        if min_sev not in SEVERITY_ORDER:
            raise ValueError(f"min_severity inválido: {min_sev}")
        # SSRF validation — raises ValueError on private/reserved destinations
        _validate_webhook_url(url)

        with self._db() as c:
            cur = c.execute(
                "INSERT INTO webhooks(tenant_id,name,url,type,min_severity,event_types,secret) "
                "VALUES(?,?,?,?,?,?,?)",
                (self.tenant_id, name, url, wtype, min_sev, event_types, secret)
            )
            return self._row_safe(self._get_raw(cur.lastrowid))

    def _get_raw(self, wid: int) -> Optional[sqlite3.Row]:
        """Retorna a row crua do banco (com secret) — uso interno apenas."""
        with self._db() as c:
            return c.execute(
                "SELECT * FROM webhooks WHERE id=? AND tenant_id=?",
                (wid, self.tenant_id)
            ).fetchone()

    def get_webhook(self, wid: int) -> Optional[dict]:
        """Retorna webhook com secret real — uso interno (_send, dispatch)."""
        return self._row(self._get_raw(wid))

    def get_webhook_safe(self, wid: int) -> Optional[dict]:
        """Retorna webhook com secret mascarado — uso em respostas de API."""
        return self._row_safe(self._get_raw(wid))

    def list_webhooks(self) -> list:
        """Retorna lista com secrets mascarados — seguro para retornar em API."""
        with self._db() as c:
            rows = c.execute(
                "SELECT * FROM webhooks WHERE tenant_id=? ORDER BY id DESC",
                (self.tenant_id,)
            ).fetchall()
        return [self._row_safe(r) for r in rows]

    def _list_webhooks_raw(self) -> list:
        """Retorna lista com secrets reais — uso interno (dispatch)."""
        with self._db() as c:
            rows = c.execute(
                "SELECT * FROM webhooks WHERE tenant_id=? ORDER BY id DESC",
                (self.tenant_id,)
            ).fetchall()
        return [self._row(r) for r in rows]

    def update_webhook(self, wid: int, data: dict) -> dict:
        fields, vals = [], []
        for k, v in data.items():
            if k == "url":
                # SSRF validation on URL updates
                _validate_webhook_url(str(v).strip())
            if k == "event_types":
                v = json.dumps(v)
            if k in ("name","url","type","min_severity","event_types","enabled","secret"):
                fields.append(f"{k}=?")
                vals.append(v)
        if not fields:
            return self.get_webhook_safe(wid)
        vals += [wid, self.tenant_id]
        with self._db() as c:
            c.execute(f"UPDATE webhooks SET {','.join(fields)} WHERE id=? AND tenant_id=?", vals)
        return self.get_webhook_safe(wid)

    def delete_webhook(self, wid: int) -> bool:
        with self._db() as c:
            c.execute("DELETE FROM webhooks WHERE id=? AND tenant_id=?", (wid, self.tenant_id))
        return True

    def toggle_webhook(self, wid: int) -> dict:
        wh = self.get_webhook(wid)
        if not wh:
            raise ValueError("Webhook não encontrado")
        return self.update_webhook(wid, {"enabled": 0 if wh["enabled"] else 1})

    def recent_logs(self, wid: int, limit: int = 20) -> list:
        with self._db() as c:
            rows = c.execute(
                "SELECT * FROM webhook_logs WHERE webhook_id=? AND tenant_id=? "
                "ORDER BY id DESC LIMIT ?",
                (wid, self.tenant_id, limit)
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Disparo ───────────────────────────────────────────────
    def dispatch(self, event: dict):
        """Verifica todos os webhooks ativos e dispara em background se o evento qualificar."""
        try:
            # _list_webhooks_raw retorna secrets reais — necessário para _send()
            webhooks = self._list_webhooks_raw()
        except Exception:
            return
        for wh in webhooks:
            if not wh.get("enabled"):
                continue
            if not self._qualifies(event, wh):
                continue
            threading.Thread(
                target=self._send_with_retry,
                args=(wh, event),
                daemon=True,
                name=f"webhook-{wh['id']}"
            ).start()

    def _qualifies(self, event: dict, wh: dict) -> bool:
        sev        = event.get("severity", "info")
        min_sev    = wh.get("min_severity", "high")
        event_type = event.get("event_type", "")
        allowed    = wh.get("event_types", [])

        if SEVERITY_ORDER.get(sev, 0) < SEVERITY_ORDER.get(min_sev, 3):
            return False
        if allowed and event_type not in allowed:
            return False
        return True

    def _send_with_retry(self, wh: dict, event: dict):
        delay = RETRY_DELAY
        for attempt in range(1, MAX_RETRIES + 1):
            ok, code, err = self._send(wh, event)
            self._log(wh, event, ok, code, err)
            if ok:
                self._bump(wh["id"], hit=True)
                return
            if attempt < MAX_RETRIES:
                time.sleep(delay)
                delay *= 2
        self._bump(wh["id"], hit=False)

    def _send(self, wh: dict, event: dict):
        wtype   = wh.get("type", "generic")
        fmt     = FORMATTERS.get(wtype, _fmt_generic)
        body    = fmt(event, wh)
        url     = wh["url"]
        headers = {"Content-Type": "application/json", "User-Agent": "NetGuard-IDS/3.0"}

        # Telegram: injeta chat_id na URL se ainda não estiver lá
        if wtype == "telegram" and "chat_id=" not in url:
            chat_id = wh.get("secret", "")   # secret = chat_id para Telegram
            if chat_id:
                sep = "&" if "?" in url else "?"
                url = f"{url}{sep}chat_id={chat_id}"

        # WhatsApp (Twilio): auth via Basic no header
        if wtype == "whatsapp" and (wh.get("secret") or "").lower() == "twilio":
            # secret deve ser "twilio:SID:AUTH_TOKEN"
            parts = (wh.get("secret", "") + "::").split(":")
            if len(parts) >= 3:
                import base64 as _b64
                creds = _b64.b64encode(f"{parts[1]}:{parts[2]}".encode()).decode()
                headers["Authorization"] = f"Basic {creds}"

        if wtype not in ("telegram", "whatsapp") and wh.get("secret"):
            headers["X-NetGuard-Secret"] = wh["secret"]

        # Revalida no momento do dispatch para reduzir janela de DNS rebinding / TOCTOU.
        _validate_webhook_url(url)

        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        try:
            req  = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                return True, resp.status, None
        except urllib.error.HTTPError as e:
            return False, e.code, str(e)
        except Exception as e:
            return False, None, str(e)

    def _log(self, wh: dict, event: dict, ok: bool, code, err):
        try:
            with self._db() as c:
                c.execute(
                    "INSERT INTO webhook_logs(webhook_id,tenant_id,event_type,severity,status,status_code,error) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (wh["id"], self.tenant_id, event.get("event_type"),
                     event.get("severity"), "ok" if ok else "error", code, err)
                )
        except Exception:
            pass

    def _bump(self, wid: int, hit: bool):
        try:
            col = "hit_count" if hit else "fail_count"
            with self._db() as c:
                c.execute(
                    f"UPDATE webhooks SET {col}={col}+1, last_hit=strftime('%Y-%m-%dT%H:%M:%SZ','now') "
                    "WHERE id=?", (wid,)
                )
        except Exception:
            pass

    def test_webhook(self, wid: int) -> dict:
        wh = self.get_webhook(wid)
        if not wh:
            return {"ok": False, "error": "Webhook não encontrado"}
        test_event = {
            "severity":   "high",
            "threat":     "Teste de Webhook — NetGuard IDS",
            "event_type": "test",
            "source_ip":  "192.168.1.100",
            "hostname":   "netguard-host",
            "msg":        "Evento de teste",
            "timestamp":  datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "details":    {
                "description": (
                    "✅ Integração funcionando! Este é um evento de teste gerado pelo NetGuard IDS. "
                    f"Canal: {wh.get('type','generic').upper()}"
                )
            },
        }
        ok, code, err = self._send(wh, test_event)
        self._log(wh, test_event, ok, code, err)
        return {"ok": ok, "status_code": code, "error": err}

    def supported_types(self) -> list:
        """Lista os tipos de webhook suportados com instruções de configuração."""
        return [
            {"type": "slack",    "label": "Slack",          "url_example": "https://hooks.slack.com/services/T.../B.../...", "secret_hint": ""},
            {"type": "teams",    "label": "Microsoft Teams", "url_example": "https://outlook.office.com/webhook/...", "secret_hint": ""},
            {"type": "discord",  "label": "Discord",        "url_example": "https://discord.com/api/webhooks/...", "secret_hint": ""},
            {"type": "telegram", "label": "Telegram Bot",   "url_example": "https://api.telegram.org/bot{TOKEN}/sendMessage", "secret_hint": "chat_id (ex: -1001234567890)"},
            {"type": "whatsapp", "label": "WhatsApp (Z-API/Evolution)", "url_example": "https://api.z-api.io/instances/{ID}/token/{TOKEN}/send-text", "secret_hint": "Deixe vazio para Z-API; 'twilio:SID:TOKEN' para Twilio"},
            {"type": "generic",  "label": "HTTP Genérico",  "url_example": "https://seu-sistema.com/webhook", "secret_hint": "Enviado no header X-NetGuard-Secret"},
        ]

    @staticmethod
    def _row(row) -> Optional[dict]:
        """Converte Row em dict com secret real — uso interno apenas."""
        if row is None:
            return None
        d = dict(row)
        try:
            d["event_types"] = json.loads(d.get("event_types", "[]"))
        except Exception:
            d["event_types"] = []
        return d

    @staticmethod
    def _row_safe(row) -> Optional[dict]:
        """Converte Row em dict com secret mascarado — seguro para respostas de API."""
        if row is None:
            return None
        d = dict(row)
        try:
            d["event_types"] = json.loads(d.get("event_types", "[]"))
        except Exception:
            d["event_types"] = []
        # Mascara o secret: mostra apenas que existe (ou não)
        raw_secret = d.get("secret") or ""
        if raw_secret:
            d["secret"] = raw_secret[:4] + "****"  # mostra primeiros 4 chars
        else:
            d["secret"] = ""
        # Remove URL completa do payload de lista (evita vazar tokens embutidos)
        # Mantém apenas o host para display
        raw_url = d.get("url", "")
        if raw_url:
            try:
                import urllib.parse as _up
                parsed = _up.urlparse(raw_url)
                d["url_display"] = f"{parsed.scheme}://{parsed.netloc}/..."
            except Exception:
                d["url_display"] = raw_url[:40] + "..."
            del d["url"]
        return d


# ── Singleton ─────────────────────────────────────────────────
_engines: dict[str, WebhookEngine] = {}
_engines_lock = threading.Lock()

def get_webhook_engine(db_path: str, tenant_id: str) -> WebhookEngine:
    global _engines
    with _engines_lock:
        key = f"{db_path}:{tenant_id}"
        if key not in _engines:
            _engines[key] = WebhookEngine(db_path, tenant_id)
    return _engines[f"{db_path}:{tenant_id}"]
