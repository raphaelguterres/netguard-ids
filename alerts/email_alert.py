"""
NetGuard IDS — Alertas de Ameaça por E-mail
============================================
Envia e-mail HTML quando um evento CRITICAL ou HIGH é detectado.

Configuração via variáveis de ambiente:
    ALERT_EMAIL_ENABLED=true          # Ativa os alertas (default: false)
    SMTP_HOST=smtp.gmail.com          # Servidor SMTP
    SMTP_PORT=587                     # Porta (587 = STARTTLS)
    SMTP_USER=seu@gmail.com           # Usuário SMTP
    SMTP_PASS=xxxx xxxx xxxx xxxx    # Senha de app do Gmail (ou senha normal)
    SMTP_FROM=seu@gmail.com           # Remetente (padrão = SMTP_USER)
    ALERT_RATE_LIMIT_SECONDS=900      # Intervalo mínimo por tenant+severidade (15min)
    ALERT_SEVERITIES=CRITICAL,HIGH    # Quais severidades disparam alerta

Gmail — como gerar senha de app:
    myaccount.google.com → Segurança → Verificação 2 etapas → Senhas de app
"""

from __future__ import annotations

import os
import time
import queue
import smtplib
import logging
import threading
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger("netguard.alerts")

# ── Configuração via env ──────────────────────────────────────────
ALERT_ENABLED   = os.environ.get("ALERT_EMAIL_ENABLED", "false").lower() == "true"
SMTP_HOST       = os.environ.get("SMTP_HOST",  "smtp.gmail.com")
SMTP_PORT       = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER       = os.environ.get("SMTP_USER",  "")
SMTP_PASS       = os.environ.get("SMTP_PASS",  "")
SMTP_FROM       = os.environ.get("SMTP_FROM",  "") or SMTP_USER
RATE_LIMIT_SEC  = int(os.environ.get("ALERT_RATE_LIMIT_SECONDS", "900"))  # 15 min
_SEV_RAW        = os.environ.get("ALERT_SEVERITIES", "CRITICAL,HIGH")
ALERT_SEVERITIES = {s.strip().upper() for s in _SEV_RAW.split(",") if s.strip()}

# ── Rate limiting ─────────────────────────────────────────────────
# chave: (tenant_id, severity) → timestamp do último envio
_rate_cache: dict[tuple, float] = {}
_rate_lock = threading.Lock()


# ══════════════════════════════════════════════════════════════════
#  HTML do e-mail
# ══════════════════════════════════════════════════════════════════

def _build_html(
    tenant_name: str,
    sev:         str,
    sev_color:   str,
    rule_name:   str,
    event_type:  str,
    source_ip:   str,
    host_id:     str,
    ts:          str,
    raw_msg:     str,
    dashboard_url: str = "http://localhost:5000",
) -> str:
    sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(sev, "🔵")
    ts_fmt = ts[:19].replace("T", " ") + " UTC" if "T" in ts else ts

    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head><meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
</head>
<body style="margin:0;padding:0;background:#0d1117;font-family:'Segoe UI',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0d1117;padding:32px 16px">
<tr><td>
<table width="100%" cellpadding="0" cellspacing="0" style="max-width:600px;margin:0 auto;">

  <!-- Header -->
  <tr>
    <td style="background:#161b22;border:1px solid #30363d;border-bottom:none;
               border-radius:12px 12px 0 0;padding:20px 28px;
               display:flex;align-items:center;">
      <span style="display:inline-block;width:10px;height:10px;border-radius:50%;
                   background:#1f6feb;margin-right:10px;"></span>
      <span style="color:#e6edf3;font-weight:700;font-size:15px;">NetGuard IDS</span>
      <span style="color:#8b949e;font-size:13px;margin-left:12px;">Sistema de Detecção de Intrusão</span>
    </td>
  </tr>

  <!-- Severity Banner -->
  <tr>
    <td style="background:{sev_color};padding:14px 28px;text-align:center;">
      <span style="color:#fff;font-size:18px;font-weight:800;letter-spacing:.03em;">
        {sev_emoji} ALERTA {sev} DETECTADO
      </span>
    </td>
  </tr>

  <!-- Body -->
  <tr>
    <td style="background:#161b22;border:1px solid #30363d;border-top:none;border-bottom:none;
               padding:28px;">

      <p style="color:#8b949e;font-size:13px;margin:0 0 4px">Empresa monitorada</p>
      <p style="color:#e6edf3;font-size:20px;font-weight:700;margin:0 0 24px">{tenant_name}</p>

      <!-- Event card -->
      <table width="100%" cellpadding="0" cellspacing="0"
             style="background:#0d1117;border:1px solid #30363d;border-radius:8px;
                    margin-bottom:20px;overflow:hidden;">
        <tr>
          <td style="background:#1f6feb;padding:10px 16px;">
            <span style="color:#fff;font-size:12px;font-weight:700;
                         text-transform:uppercase;letter-spacing:.08em;">
              Detalhes do Evento
            </span>
          </td>
        </tr>
        <tr><td style="padding:16px;">
          <table width="100%" cellpadding="6" cellspacing="0">
            <tr>
              <td style="color:#8b949e;font-size:12px;width:130px;vertical-align:top">Ameaça detectada</td>
              <td style="color:#e6edf3;font-size:13px;font-weight:700">{rule_name}</td>
            </tr>
            <tr style="border-top:1px solid #30363d">
              <td style="color:#8b949e;font-size:12px;vertical-align:top">Tipo de evento</td>
              <td style="color:#e6edf3;font-size:13px">{event_type}</td>
            </tr>
            <tr style="border-top:1px solid #30363d">
              <td style="color:#8b949e;font-size:12px;vertical-align:top">Severidade</td>
              <td style="color:{sev_color};font-size:13px;font-weight:700">{sev}</td>
            </tr>
            <tr style="border-top:1px solid #30363d">
              <td style="color:#8b949e;font-size:12px;vertical-align:top">IP de origem</td>
              <td style="color:#e6edf3;font-size:13px;font-family:monospace">{source_ip}</td>
            </tr>
            <tr style="border-top:1px solid #30363d">
              <td style="color:#8b949e;font-size:12px;vertical-align:top">Host afetado</td>
              <td style="color:#e6edf3;font-size:13px;font-family:monospace">{host_id}</td>
            </tr>
            <tr style="border-top:1px solid #30363d">
              <td style="color:#8b949e;font-size:12px;vertical-align:top">Data/hora</td>
              <td style="color:#e6edf3;font-size:13px">{ts_fmt}</td>
            </tr>
            {f'''<tr style="border-top:1px solid #30363d">
              <td style="color:#8b949e;font-size:12px;vertical-align:top">Descrição</td>
              <td style="color:#8b949e;font-size:12px;line-height:1.5">{raw_msg}</td>
            </tr>''' if raw_msg else ""}
          </table>
        </td></tr>
      </table>

      <!-- Recomendação rápida -->
      <table width="100%" cellpadding="0" cellspacing="0"
             style="background:rgba(248,81,73,.08);border:1px solid rgba(248,81,73,.25);
                    border-radius:8px;margin-bottom:24px;">
        <tr><td style="padding:14px 16px;">
          <p style="color:#f85149;font-size:12px;font-weight:700;
                    text-transform:uppercase;letter-spacing:.07em;margin:0 0 6px">
            ⚡ Ação Recomendada
          </p>
          <p style="color:#e6edf3;font-size:13px;margin:0;line-height:1.5">
            {'Isole o host afetado imediatamente e revise os logs. Verifique se o IP de origem ' +
             source_ip + ' está bloqueado no firewall.' if sev == 'CRITICAL' else
             'Revise os logs do host ' + host_id + ' e verifique se o IP ' +
             source_ip + ' já foi bloqueado nas regras de firewall.'}
          </p>
        </td></tr>
      </table>

      <!-- CTA -->
      <div style="text-align:center;margin-bottom:8px">
        <a href="{dashboard_url}"
           style="background:#1f6feb;color:#fff;padding:12px 28px;
                  border-radius:8px;text-decoration:none;font-weight:700;
                  font-size:14px;display:inline-block;">
          Ver dashboard completo →
        </a>
      </div>

    </td>
  </tr>

  <!-- Footer -->
  <tr>
    <td style="background:#0d1117;border:1px solid #30363d;border-top:none;
               border-radius:0 0 12px 12px;padding:16px 28px;text-align:center;">
      <p style="color:#8b949e;font-size:11px;margin:0 0 4px">
        Este alerta foi gerado automaticamente pelo NetGuard IDS em {ts_fmt}
      </p>
      <p style="color:#8b949e;font-size:11px;margin:0">
        Para desativar alertas por e-mail, acesse as configurações do seu tenant.
      </p>
    </td>
  </tr>

</table>
</td></tr>
</table>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════
#  AlertManager
# ══════════════════════════════════════════════════════════════════

class AlertManager:
    """
    Gerenciador de alertas por e-mail.
    Thread-safe. Processa numa fila em background para não bloquear a API.
    Rate limiting por (tenant_id, severity) para evitar spam.
    """

    def __init__(self):
        self._queue:  queue.Queue = queue.Queue(maxsize=1000)
        self._thread: threading.Thread = threading.Thread(
            target=self._worker, name="netguard-alert-worker", daemon=True
        )
        self._thread.start()
        logger.info(
            "AlertManager iniciado | enabled=%s | severities=%s | rate_limit=%ds",
            ALERT_ENABLED, ALERT_SEVERITIES, RATE_LIMIT_SEC,
        )

    # ── API pública ───────────────────────────────────────────────

    def trigger(self, event: dict, tenant: dict) -> bool:
        """
        Enfileira um alerta para envio assíncrono.
        Retorna True se foi enfileirado, False se ignorado.
        Nunca lança exceção — seguro chamar em qualquer contexto.
        """
        if not ALERT_ENABLED:
            return False

        sev = (event.get("severity") or "").upper()
        if sev not in ALERT_SEVERITIES:
            return False

        email = (tenant or {}).get("email", "").strip()
        if not email:
            logger.debug("Alert ignorado — tenant sem e-mail: %s",
                         (tenant or {}).get("tenant_id"))
            return False

        try:
            self._queue.put_nowait({"event": event, "tenant": tenant})
            return True
        except queue.Full:
            logger.warning("Fila de alertas cheia — alerta descartado")
            return False

    def send_test(self, to_email: str, tenant_name: str = "Empresa Teste") -> bool:
        """Envia e-mail de teste imediatamente (síncrono). Útil para /api/alerts/test."""
        fake_event = {
            "severity":   "HIGH",
            "rule_name":  "Teste de Alerta — NetGuard IDS",
            "event_type": "test_alert",
            "source":     "203.0.113.42",
            "host_id":    "srv-teste-01",
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "raw":        "Este é um e-mail de teste do sistema de alertas NetGuard IDS.",
        }
        fake_tenant = {"email": to_email, "name": tenant_name, "tenant_id": "test"}
        try:
            self._send_email(fake_event, fake_tenant)
            return True
        except Exception as exc:
            logger.error("Teste de alerta falhou: %s", exc)
            raise

    # ── Internos ──────────────────────────────────────────────────

    def _worker(self):
        """Loop de background que processa a fila de alertas."""
        while True:
            try:
                item = self._queue.get(timeout=5)
                try:
                    self._process(item)
                except Exception as exc:
                    logger.error("Erro ao processar alerta: %s", exc)
                finally:
                    self._queue.task_done()
            except queue.Empty:
                continue

    def _process(self, item: dict):
        event  = item["event"]
        tenant = item["tenant"]
        sev    = (event.get("severity") or "").upper()
        tid    = (tenant or {}).get("tenant_id", "unknown")

        # Verifica rate limit
        key = (tid, sev)
        now = time.monotonic()
        with _rate_lock:
            last_sent = _rate_cache.get(key, 0.0)
            if now - last_sent < RATE_LIMIT_SEC:
                remaining = int(RATE_LIMIT_SEC - (now - last_sent))
                logger.debug(
                    "Alerta suprimido por rate limit | tenant=%s sev=%s próximo em %ds",
                    tid, sev, remaining,
                )
                return
            _rate_cache[key] = now

        self._send_email(event, tenant)

    def _send_email(self, event: dict, tenant: dict):
        sev        = (event.get("severity") or "LOW").upper()
        rule_name  = (event.get("rule_name") or event.get("threat_name")
                      or event.get("event_type") or "Ameaça detectada")
        source_ip  = event.get("source") or event.get("source_ip") or "-"
        host_id    = event.get("host_id") or "-"
        ts         = event.get("timestamp") or datetime.now(timezone.utc).isoformat()
        raw_msg    = event.get("raw") or event.get("message") or ""
        event_type = event.get("event_type") or "unknown"

        tenant_name  = (tenant or {}).get("name", "Cliente")
        to_email     = (tenant or {}).get("email", "")
        tenant_id    = (tenant or {}).get("tenant_id", "")

        sev_color = {
            "CRITICAL": "#f85149",
            "HIGH":     "#f0883e",
            "MEDIUM":   "#d29922",
        }.get(sev, "#58a6ff")

        dashboard_url = os.environ.get("DASHBOARD_URL", "http://localhost:5000")
        sev_emoji     = {"CRITICAL": "🔴", "HIGH": "🟠"}.get(sev, "🟡")
        subject       = (
            f"[NetGuard IDS] {sev_emoji} {sev} — {rule_name} | {tenant_name}"
        )

        html = _build_html(
            tenant_name=tenant_name,
            sev=sev, sev_color=sev_color,
            rule_name=rule_name, event_type=event_type,
            source_ip=source_ip, host_id=host_id,
            ts=ts, raw_msg=raw_msg,
            dashboard_url=dashboard_url,
        )

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"NetGuard IDS <{SMTP_FROM}>"
        msg["To"]      = to_email
        msg["X-NetGuard-Tenant"] = tenant_id
        msg.attach(MIMEText(html, "html", "utf-8"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)

        logger.info(
            "✉ Alerta enviado | tenant=%s | sev=%s | ameaça=%s | to=%s",
            tenant_id, sev, rule_name, to_email,
        )


# ── Singleton global ──────────────────────────────────────────────
_manager: AlertManager | None = None
_manager_lock = threading.Lock()


def get_alert_manager() -> AlertManager:
    """Retorna o singleton do AlertManager (lazy init, thread-safe)."""
    global _manager
    if _manager is None:
        with _manager_lock:
            if _manager is None:
                _manager = AlertManager()
    return _manager
