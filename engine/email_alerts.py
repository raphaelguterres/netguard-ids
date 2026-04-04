"""
NetGuard IDS — Email Alert Engine
Envia notificações por SMTP (Gmail / qualquer provedor) para eventos CRITICAL e HIGH.

Variáveis de ambiente necessárias:
  ALERT_EMAIL_ENABLED=true
  SMTP_HOST=smtp.gmail.com
  SMTP_PORT=587
  SMTP_USER=seu@gmail.com
  SMTP_PASS=xxxx xxxx xxxx xxxx   # senha de app do Gmail
  ALERT_EMAIL_TO=destino@email.com  # opcional; usa SMTP_USER se omitido
  DASHBOARD_URL=https://seudominio.com
"""

import os
import logging
import smtplib
import threading
from collections import OrderedDict
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html import escape
from datetime import datetime

logger = logging.getLogger("ids.email_alerts")

_ENABLED   = os.environ.get("ALERT_EMAIL_ENABLED", "false").lower() == "true"
_SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
_SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
_SMTP_USER = os.environ.get("SMTP_USER", "")
_SMTP_PASS = os.environ.get("SMTP_PASS", "")
_MAIL_TO   = os.environ.get("ALERT_EMAIL_TO", _SMTP_USER)
_DASHBOARD = os.environ.get("DASHBOARD_URL", "http://localhost:5000")

# Evita spam: não reenvia o mesmo (threat+ip) em menos de 5 min
# Cap em 10 000 entradas para evitar memory leak em instâncias longas
_CACHE_MAX = 10_000
_THROTTLE_SECONDS = 300
_cache_lock = threading.Lock()


class _TTLDict(OrderedDict):
    """OrderedDict com limite de tamanho — descarta as entradas mais antigas."""
    def __setitem__(self, key, value):
        with _cache_lock:
            if key in self:
                self.move_to_end(key)
            super().__setitem__(key, value)
            if len(self) > _CACHE_MAX:
                self.popitem(last=False)


_sent_cache: _TTLDict = _TTLDict()


def _throttle_key(threat: str, ip: str) -> str:
    return f"{threat}|{ip}"


def _is_throttled(key: str) -> bool:
    last = _sent_cache.get(key)
    if last is None:
        return False
    return (datetime.now() - last).total_seconds() < _THROTTLE_SECONDS


def _mark_sent(key: str):
    _sent_cache[key] = datetime.now()


def _severity_color(sev: str) -> str:
    return {"critical": "#c0392b", "high": "#e67e22"}.get(sev.lower(), "#7f8c8d")


def _build_html(sev: str, threat: str, ip: str, msg: str,
                tenant_name: str, ts: str) -> str:
    """Constrói o corpo HTML do e-mail com todos os campos escapados."""
    color       = _severity_color(sev)
    label       = escape(sev.upper())
    e_tenant    = escape(tenant_name)
    e_threat    = escape(threat)
    e_ip        = escape(ip)
    e_msg       = escape(msg)
    e_ts        = escape(ts)
    # Dashboard URL: só permite http(s) para evitar javascript: injection
    safe_dash   = _DASHBOARD if _DASHBOARD.startswith(("http://", "https://")) else "#"

    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head><meta charset="UTF-8"></head>
<body style="font-family:Arial,sans-serif;background:#f4f4f4;margin:0;padding:20px">
  <div style="max-width:600px;margin:0 auto;background:#fff;border-radius:8px;
              box-shadow:0 2px 8px rgba(0,0,0,.1);overflow:hidden">
    <div style="background:{color};padding:20px 30px">
      <h1 style="color:#fff;margin:0;font-size:22px">
        &#9888; Alerta de Segurança &mdash; {label}
      </h1>
    </div>
    <div style="padding:30px">
      <table style="width:100%;border-collapse:collapse">
        <tr><td style="padding:8px 0;color:#666;width:130px">Tenant</td>
            <td style="padding:8px 0;font-weight:bold">{e_tenant}</td></tr>
        <tr><td style="padding:8px 0;color:#666">Severidade</td>
            <td style="padding:8px 0">
              <span style="background:{color};color:#fff;padding:3px 10px;
                           border-radius:4px;font-size:13px">{label}</span>
            </td></tr>
        <tr><td style="padding:8px 0;color:#666">Ameaça</td>
            <td style="padding:8px 0;font-weight:bold">{e_threat}</td></tr>
        <tr><td style="padding:8px 0;color:#666">IP</td>
            <td style="padding:8px 0;font-family:monospace">{e_ip}</td></tr>
        <tr><td style="padding:8px 0;color:#666">Detalhes</td>
            <td style="padding:8px 0">{e_msg}</td></tr>
        <tr><td style="padding:8px 0;color:#666">Horário</td>
            <td style="padding:8px 0;font-family:monospace">{e_ts}</td></tr>
      </table>
      <div style="margin-top:25px;text-align:center">
        <a href="{safe_dash}" style="background:#2c3e50;color:#fff;padding:12px 28px;
           border-radius:5px;text-decoration:none;font-size:14px">
          Abrir Dashboard
        </a>
      </div>
    </div>
    <div style="background:#f8f8f8;padding:15px 30px;font-size:12px;color:#999;text-align:center">
      NetGuard IDS &middot; Alerta automático &middot; Não responda este e-mail
    </div>
  </div>
</body>
</html>"""


def _send_sync(to: str, subject: str, html: str):
    """Envia o e-mail via SMTP (chamado em thread separada)."""
    try:
        msg = MIMEMultipart("alternative")
        # Header() sanitiza quebras de linha — previne email header injection
        msg["Subject"] = Header(subject, "utf-8")
        msg["From"]    = _SMTP_USER
        msg["To"]      = Header(to, "utf-8")
        msg.attach(MIMEText(html, "html", "utf-8"))

        with smtplib.SMTP(_SMTP_HOST, _SMTP_PORT, timeout=10) as s:
            s.ehlo()
            s.starttls()
            s.login(_SMTP_USER, _SMTP_PASS)
            s.sendmail(_SMTP_USER, [to], msg.as_string())

        logger.info("E-mail de alerta enviado → %s", to)
    except smtplib.SMTPAuthenticationError as exc:
        logger.error("SMTP autenticação falhou (verifique SMTP_USER/SMTP_PASS): %s", exc)
    except smtplib.SMTPException as exc:
        logger.error("SMTP erro ao enviar alerta: %s", exc, exc_info=True)
    except Exception as exc:
        logger.error("Erro inesperado ao enviar e-mail de alerta: %s", exc, exc_info=True)


def send_alert(sev: str, threat: str, ip: str, msg: str,
               tenant_name: str = "NetGuard", to: str = None):
    """
    Envia alerta por e-mail (async, com throttle).
    Só dispara se ALERT_EMAIL_ENABLED=true e severidade for critical ou high.
    """
    if not _ENABLED:
        return
    if sev.lower() not in ("critical", "high"):
        return
    if not _SMTP_USER or not _SMTP_PASS:
        logger.warning("ALERT_EMAIL_ENABLED=true mas SMTP_USER/SMTP_PASS não configurados")
        return

    key = _throttle_key(threat, ip)
    if _is_throttled(key):
        return
    _mark_sent(key)

    dest = to or _MAIL_TO or _SMTP_USER
    ts   = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    subj = f"[NetGuard] {sev.upper()} — {threat[:80]} | {ip}"
    html = _build_html(sev, threat, ip, msg, tenant_name, ts)

    threading.Thread(
        target=_send_sync, args=(dest, subj, html),
        daemon=True, name="email-alert"
    ).start()
