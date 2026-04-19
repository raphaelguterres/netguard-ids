"""
mailer.py — NetGuard IDS · Módulo de envio de e-mail
=====================================================
Envia e-mails transacionais via SMTP genérico (Gmail, SendGrid,
Mailgun, AWS SES, Resend, Brevo…) usando apenas a stdlib Python.

Configuração via variáveis de ambiente:
  SMTP_HOST        Servidor SMTP  (ex: smtp.gmail.com)
  SMTP_PORT        Porta          (padrão: 587)
  SMTP_USER        Usuário/login  (ex: noreply@seudominio.com)
  SMTP_PASS        Senha / App Password / API Key
  SMTP_FROM        Endereço "De" (padrão: SMTP_USER)
  SMTP_STARTTLS    true/false     (padrão: true)
  SMTP_SSL         true/false     (padrão: false — use apenas porta 465)
  APP_URL          URL pública    (ex: https://netguard.io)

Se SMTP_HOST não estiver definido, os e-mails são apenas logados
(modo "dry-run silencioso") — nunca bloqueia a requisição.

Uso:
  from mailer import send_welcome
  send_welcome(name="Ana", email="ana@empresa.com",
               token="ng_abc123", plan="pro")
"""

import logging
import os
import smtplib
import ssl
import threading
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate

logger = logging.getLogger("netguard.mailer")

# ── Configuração ──────────────────────────────────────────────────

def _cfg(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()

def _smtp_configured() -> bool:
    return bool(_cfg("SMTP_HOST"))


def smtp_configured() -> bool:
    """Indica se o SMTP está configurado para envio real."""
    return _smtp_configured()


# ── Envio base ────────────────────────────────────────────────────

def _send(to_email: str, to_name: str, subject: str,
          html: str, plain: str, attachments: list[dict] | None = None) -> None:
    """
    Envia um e-mail via SMTP. Levanta exceção em caso de falha.
    Chamado sempre dentro de uma thread de background.
    """
    host     = _cfg("SMTP_HOST")
    port     = int(_cfg("SMTP_PORT", "587"))
    user     = _cfg("SMTP_USER")
    passwd   = _cfg("SMTP_PASS")
    from_raw = _cfg("SMTP_FROM") or user
    use_ssl  = _cfg("SMTP_SSL",      "false").lower() == "true"
    starttls = _cfg("SMTP_STARTTLS", "true").lower()  != "false"

    msg = MIMEMultipart("mixed")
    msg["Subject"] = subject
    msg["From"]    = formataddr(("NetGuard IDS", from_raw))
    msg["To"]      = formataddr((to_name, to_email))
    msg["Date"]    = formatdate(localtime=False)
    msg["X-Mailer"] = "NetGuard-IDS/3.0"

    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText(plain, "plain", "utf-8"))
    alt.attach(MIMEText(html,  "html",  "utf-8"))
    msg.attach(alt)

    for attachment in attachments or []:
        data = attachment.get("data")
        filename = attachment.get("filename") or "attachment.bin"
        if not data:
            continue
        part = MIMEApplication(data, Name=filename)
        if attachment.get("content_type"):
            part.set_type(attachment["content_type"])
        part["Content-Disposition"] = f'attachment; filename="{filename}"'
        msg.attach(part)

    ctx = ssl.create_default_context()

    if use_ssl:
        with smtplib.SMTP_SSL(host, port, context=ctx) as srv:
            if user and passwd:
                srv.login(user, passwd)
            srv.sendmail(from_raw, [to_email], msg.as_bytes())
    else:
        with smtplib.SMTP(host, port) as srv:
            if starttls:
                srv.starttls(context=ctx)
            if user and passwd:
                srv.login(user, passwd)
            srv.sendmail(from_raw, [to_email], msg.as_bytes())


def _send_async(to_email: str, to_name: str, subject: str,
                html: str, plain: str) -> None:
    """Dispara o envio em background — não bloqueia a requisição."""
    if not _smtp_configured():
        logger.info("[mailer:dry-run] Para: %s | Assunto: %s", to_email, subject)
        return

    def _worker():
        try:
            _send(to_email, to_name, subject, html, plain)
            logger.info("[mailer] E-mail enviado → %s | %s", to_email, subject)
        except Exception as exc:
            logger.error("[mailer] Falha ao enviar para %s: %s", to_email, exc)

    t = threading.Thread(target=_worker, daemon=True, name="mailer")
    t.start()


def _send_async_email(
    *,
    to_email: str,
    to_name: str,
    subject: str,
    html: str,
    plain: str,
    attachments: list[dict] | None = None,
) -> None:
    """Versão assíncrona com suporte a anexos."""
    if not _smtp_configured():
        logger.info("[mailer:dry-run] Para: %s | Assunto: %s", to_email, subject)
        return

    def _worker():
        try:
            _send(to_email, to_name, subject, html, plain, attachments=attachments)
            logger.info("[mailer] E-mail enviado -> %s | %s", to_email, subject)
        except Exception as exc:
            logger.error("[mailer] Falha ao enviar para %s: %s", to_email, exc)

    t = threading.Thread(target=_worker, daemon=True, name="mailer-generic")
    t.start()


def send_email(
    *,
    to_email: str,
    subject: str,
    html: str,
    plain: str = "",
    to_name: str = "",
    attachments: list[dict] | None = None,
    async_send: bool = True,
) -> None:
    """Envia um e-mail genérico, com suporte opcional a anexos."""
    if not to_email:
        logger.warning("[mailer] send_email ignorado â€” email vazio")
        return

    if async_send:
        _send_async_email(
            to_email=to_email,
            to_name=to_name or to_email,
            subject=subject,
            html=html,
            plain=plain or subject,
            attachments=attachments,
        )
        return

    if not _smtp_configured():
        logger.info("[mailer:dry-run] Para: %s | Assunto: %s", to_email, subject)
        return

    _send(
        to_email,
        to_name or to_email,
        subject,
        html,
        plain or subject,
        attachments=attachments,
    )


# ── Templates ─────────────────────────────────────────────────────

_PLAN_LABELS = {
    "free":       "Free",
    "pro":        "Pro (14 dias grátis)",
    "enterprise": "Enterprise",
    "mssp":       "MSSP",
}

_PLAN_COLORS = {
    "free":       "#8b949e",
    "pro":        "#58a6ff",
    "enterprise": "#3fb950",
    "mssp":       "#f0883e",
}


def _welcome_html(name: str, email: str, token: str,
                  plan: str, app_url: str) -> str:
    plan_label = _PLAN_LABELS.get(plan, plan.title())
    plan_color = _PLAN_COLORS.get(plan, "#58a6ff")
    dashboard  = f"{app_url}/dashboard"

    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Bem-vindo ao NetGuard IDS</title>
</head>
<body style="margin:0;padding:0;background:#0d1117;font-family:'Segoe UI',Arial,sans-serif;color:#e6edf3;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0d1117;padding:40px 16px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0"
             style="max-width:600px;background:#161b22;border-radius:12px;border:1px solid #30363d;overflow:hidden;">

        <!-- Header -->
        <tr>
          <td style="background:#0d1117;padding:28px 36px;border-bottom:1px solid #30363d;">
            <table cellpadding="0" cellspacing="0">
              <tr>
                <td style="padding-right:10px;">
                  <svg width="28" height="28" viewBox="0 0 24 24" fill="none"
                       stroke="#58a6ff" stroke-width="2" style="display:block;">
                    <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z"/>
                  </svg>
                </td>
                <td style="font-size:18px;font-weight:800;color:#58a6ff;letter-spacing:-.02em;">
                  NetGuard IDS
                </td>
                <td style="padding-left:16px;">
                  <span style="background:{plan_color}22;color:{plan_color};font-size:11px;
                               font-weight:700;padding:3px 10px;border-radius:999px;
                               border:1px solid {plan_color}44;letter-spacing:.06em;">
                    {plan_label.upper()}
                  </span>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- Body -->
        <tr>
          <td style="padding:36px 36px 0;">
            <p style="font-size:22px;font-weight:800;margin:0 0 8px;color:#e6edf3;">
              Bem-vindo, {name}! 🎉
            </p>
            <p style="color:#8b949e;font-size:15px;margin:0 0 28px;line-height:1.6;">
              Sua conta NetGuard IDS foi criada com sucesso. Abaixo está
              seu token de API — guarde-o em segurança, ele é sua chave de acesso.
            </p>

            <!-- Token box -->
            <table width="100%" cellpadding="0" cellspacing="0"
                   style="background:#0d1117;border:1px solid #30363d;border-radius:8px;margin-bottom:28px;">
              <tr>
                <td style="padding:6px 16px;background:#21262d;border-radius:8px 8px 0 0;
                           border-bottom:1px solid #30363d;">
                  <span style="font-size:11px;color:#8b949e;font-weight:700;
                               text-transform:uppercase;letter-spacing:.08em;">
                    🔑 Seu Token de API
                  </span>
                </td>
              </tr>
              <tr>
                <td style="padding:18px 20px;font-family:Consolas,'Courier New',monospace;
                           font-size:14px;color:#58a6ff;letter-spacing:.04em;word-break:break-all;">
                  {token}
                </td>
              </tr>
            </table>

            <!-- Steps -->
            <p style="font-size:14px;font-weight:700;color:#e6edf3;margin:0 0 16px;">
              Como começar em 3 passos:
            </p>
            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:28px;">
              <tr>
                <td style="padding:0 0 14px;">
                  <table cellpadding="0" cellspacing="0">
                    <tr>
                      <td style="width:32px;height:32px;background:#1f6feb;border-radius:50%;
                                 text-align:center;vertical-align:middle;font-weight:800;
                                 font-size:14px;color:#fff;flex-shrink:0;">1</td>
                      <td style="padding-left:14px;font-size:14px;color:#8b949e;line-height:1.5;">
                        <strong style="color:#e6edf3;">Acesse o dashboard</strong><br>
                        Entre em <a href="{dashboard}" style="color:#58a6ff;">{dashboard}</a>
                        e faça login com seu token.
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>
              <tr>
                <td style="padding:0 0 14px;">
                  <table cellpadding="0" cellspacing="0">
                    <tr>
                      <td style="width:32px;height:32px;background:#1f6feb;border-radius:50%;
                                 text-align:center;vertical-align:middle;font-weight:800;
                                 font-size:14px;color:#fff;">2</td>
                      <td style="padding-left:14px;font-size:14px;color:#8b949e;line-height:1.5;">
                        <strong style="color:#e6edf3;">Configure um alerta</strong><br>
                        Vá em Configurações → Webhooks e adicione seu bot do Telegram
                        ou WhatsApp para receber alertas em tempo real.
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>
              <tr>
                <td>
                  <table cellpadding="0" cellspacing="0">
                    <tr>
                      <td style="width:32px;height:32px;background:#1f6feb;border-radius:50%;
                                 text-align:center;vertical-align:middle;font-weight:800;
                                 font-size:14px;color:#fff;">3</td>
                      <td style="padding-left:14px;font-size:14px;color:#8b949e;line-height:1.5;">
                        <strong style="color:#e6edf3;">Envie o primeiro log</strong><br>
                        Use a API ou instale o agente na sua rede para começar a monitorar.<br>
                        <code style="font-size:12px;color:#58a6ff;background:#0d1117;
                                     padding:2px 6px;border-radius:4px;">
                          curl -X POST {app_url}/api/analyze \\<br>
                          &nbsp;&nbsp;-H "X-API-Key: {token[:12]}..." \\<br>
                          &nbsp;&nbsp;-d '{{"log":"teste de detecção"}}'
                        </code>
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>

            <!-- CTA button -->
            <table cellpadding="0" cellspacing="0" style="margin-bottom:32px;">
              <tr>
                <td style="background:#1f6feb;border-radius:8px;">
                  <a href="{dashboard}"
                     style="display:block;padding:13px 28px;font-size:15px;
                            font-weight:700;color:#fff;text-decoration:none;">
                    Acessar o dashboard →
                  </a>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="padding:20px 36px 28px;border-top:1px solid #30363d;
                     background:#0d1117;margin-top:8px;">
            <p style="color:#8b949e;font-size:12px;margin:0;line-height:1.6;">
              Dúvidas? Responda este e-mail ou acesse nossa
              <a href="{app_url}" style="color:#58a6ff;">documentação</a>.<br>
              Você recebeu este e-mail porque criou uma conta em NetGuard IDS.<br>
              <span style="color:#484f58;">{email}</span>
            </p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


def _welcome_plain(name: str, email: str, token: str,
                   plan: str, app_url: str) -> str:
    plan_label = _PLAN_LABELS.get(plan, plan.title())
    return f"""Bem-vindo ao NetGuard IDS, {name}!

Sua conta ({plan_label}) foi criada com sucesso.

══ SEU TOKEN DE API ══════════════════════════
{token}
══════════════════════════════════════════════

Como começar:

1. Dashboard: {app_url}/dashboard
   Faça login com seu token acima.

2. Configure alertas:
   Vá em Configurações → Webhooks e adicione
   seu bot do Telegram ou WhatsApp.

3. Envie o primeiro log:
   curl -X POST {app_url}/api/analyze \\
        -H "X-API-Key: {token}" \\
        -d '{{"log":"teste de detecção"}}'

Dúvidas? Responda este e-mail.

— Equipe NetGuard IDS
"""


# ── API pública ───────────────────────────────────────────────────

def send_welcome(name: str, email: str, token: str,
                 plan: str = "pro", app_url: str = None) -> None:
    """
    Envia e-mail de boas-vindas após criação de conta/trial.

    Parâmetros
    ----------
    name    : Nome do usuário (ex: "Ana")
    email   : Endereço de destino
    token   : Token de API gerado (ex: "ng_abc123...")
    plan    : Chave do plano (free, pro, enterprise, mssp)
    app_url : URL base da aplicação (padrão: APP_URL env ou http://localhost:5000)
    """
    if not email:
        logger.warning("[mailer] send_welcome ignorado — email vazio")
        return

    url = (app_url or _cfg("APP_URL") or "http://localhost:5000").rstrip("/")

    plan_label = _PLAN_LABELS.get(plan, plan.title())
    subject    = f"🚀 Bem-vindo ao NetGuard IDS — plano {plan_label}"

    html  = _welcome_html(name, email, token, plan, url)
    plain = _welcome_plain(name, email, token, plan, url)

    _send_async(email, name, subject, html, plain)


def send_trial_invite(name: str, email: str, company: str,
                      trial_url: str, duration_h: int = 72,
                      expires_at: str = "") -> None:
    """
    Envia o link de trial personalizado para o cliente em potencial.
    """
    if not email:
        return

    url      = (_cfg("APP_URL") or "http://localhost:5000").rstrip("/")
    duration_label = (f"{duration_h // 24} dias" if duration_h >= 24
                      else f"{duration_h} horas")
    subject  = f"🔑 Seu acesso de {duration_label} ao NetGuard IDS está pronto"

    plain = f"""Olá, {name}!

Preparamos um acesso exclusivo ao NetGuard IDS para {company}.

══ SEU LINK DE ACESSO ({duration_label}) ══════════════
{trial_url}
══════════════════════════════════════════

O acesso expira em {duration_label}. Nenhum cartão de crédito é necessário.

O que você vai encontrar:
✔ Dashboard de segurança em tempo real
✔ Detecção de ameaças com ML (Isolation Forest)
✔ IOC Manager — lista negra de IPs e domínios
✔ Regras de detecção customizadas
✔ Relatórios de Compliance (SOC2 / PCI-DSS / HIPAA)

Qualquer dúvida, responda este e-mail.

— Equipe NetGuard IDS
"""

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Seu acesso ao NetGuard IDS</title>
</head>
<body style="margin:0;padding:0;background:#0d1117;font-family:'Segoe UI',Arial,sans-serif;color:#e6edf3;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0d1117;padding:40px 16px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0"
             style="max-width:600px;background:#161b22;border-radius:12px;border:1px solid #30363d;overflow:hidden;">

        <!-- Header -->
        <tr>
          <td style="background:#0d1117;padding:24px 36px;border-bottom:1px solid #30363d;">
            <table cellpadding="0" cellspacing="0"><tr>
              <td style="padding-right:10px;">
                <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#58a6ff" stroke-width="2">
                  <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z"/>
                </svg>
              </td>
              <td style="font-size:17px;font-weight:800;color:#58a6ff;">NetGuard IDS</td>
              <td style="padding-left:16px;">
                <span style="background:#1f6feb22;color:#58a6ff;font-size:11px;font-weight:700;
                             padding:3px 10px;border-radius:999px;border:1px solid #1f6feb44;">
                  TRIAL {duration_label.upper()}
                </span>
              </td>
            </tr></table>
          </td>
        </tr>

        <!-- Body -->
        <tr><td style="padding:36px 36px 0;">
          <p style="font-size:21px;font-weight:800;margin:0 0 8px;">
            Olá, {name}! Seu acesso está pronto. 🎉
          </p>
          <p style="color:#8b949e;font-size:14px;line-height:1.6;margin:0 0 24px;">
            Preparamos um acesso exclusivo de <strong style="color:#e6edf3;">{duration_label}</strong>
            ao NetGuard IDS para <strong style="color:#e6edf3;">{company}</strong>.
            Clique no botão abaixo para entrar direto no dashboard — sem cadastro, sem cartão.
          </p>

          <!-- CTA -->
          <table cellpadding="0" cellspacing="0" style="margin-bottom:28px;">
            <tr><td style="background:#1f6feb;border-radius:8px;">
              <a href="{trial_url}"
                 style="display:block;padding:14px 32px;font-size:15px;font-weight:700;
                        color:#fff;text-decoration:none;">
                Acessar o NetGuard IDS →
              </a>
            </td></tr>
          </table>

          <!-- URL fallback -->
          <p style="font-size:12px;color:#8b949e;margin:0 0 24px;">
            Ou copie o link: <a href="{trial_url}" style="color:#58a6ff;word-break:break-all;">{trial_url}</a>
          </p>

          <!-- Features -->
          <table width="100%" cellpadding="0" cellspacing="0"
                 style="background:#0d1117;border:1px solid #30363d;border-radius:8px;
                        margin-bottom:28px;padding:18px 20px;">
            <tr><td>
              <p style="font-size:13px;font-weight:700;color:#e6edf3;margin:0 0 12px;">
                O que você vai encontrar no trial:
              </p>
              {''.join(f'<p style="font-size:13px;color:#8b949e;margin:0 0 8px;"><span style="color:#3fb950;margin-right:8px;">✔</span>{feat}</p>' for feat in [
                'Dashboard de segurança em tempo real',
                'Detecção de ameaças com ML (Isolation Forest)',
                'IOC Manager — lista negra de IPs, domínios e hashes',
                'Regras de detecção customizadas (14 operadores)',
                'Relatórios de Compliance: SOC2 / PCI-DSS / HIPAA',
              ])}
            </td></tr>
          </table>
        </td></tr>

        <!-- Footer -->
        <tr><td style="padding:20px 36px 28px;border-top:1px solid #30363d;background:#0d1117;">
          <p style="color:#8b949e;font-size:12px;margin:0;line-height:1.6;">
            Dúvidas? Responda este e-mail ou acesse
            <a href="{url}" style="color:#58a6ff;">netguard.io</a>.<br>
            Você recebeu este e-mail porque foi convidado para um trial do NetGuard IDS.
          </p>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""

    _send_async(email, name, subject, html, plain)


def send_contact_confirmation(name: str, email: str,
                              plan: str = "enterprise") -> None:
    """
    Confirma recebimento do formulário de contato Enterprise/MSSP.
    """
    if not email:
        return

    url        = (_cfg("APP_URL") or "http://localhost:5000").rstrip("/")
    plan_label = _PLAN_LABELS.get(plan, plan.title())
    subject    = f"✉️ Recebemos seu contato — NetGuard IDS {plan_label}"

    plain = f"""Olá, {name}!

Recebemos sua mensagem sobre o plano {plan_label}.
Nossa equipe retornará em até 1 dia útil.

Enquanto isso, você pode conhecer melhor o produto:
{url}

— Equipe NetGuard IDS
"""

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head><meta charset="UTF-8"/></head>
<body style="background:#0d1117;font-family:'Segoe UI',Arial,sans-serif;color:#e6edf3;padding:40px 16px;">
  <table width="600" cellpadding="0" cellspacing="0"
         style="max-width:600px;background:#161b22;border-radius:12px;
                border:1px solid #30363d;margin:0 auto;overflow:hidden;">
    <tr><td style="padding:32px 36px;">
      <p style="font-size:20px;font-weight:800;margin:0 0 12px;">Recebemos seu contato! ✅</p>
      <p style="color:#8b949e;font-size:14px;line-height:1.6;margin:0 0 20px;">
        Olá <strong style="color:#e6edf3;">{name}</strong>,<br><br>
        Obrigado pelo interesse no plano
        <strong style="color:#58a6ff;">{plan_label}</strong>.
        Nossa equipe comercial retornará em até <strong>1 dia útil</strong>
        no e-mail <strong style="color:#e6edf3;">{email}</strong>.
      </p>
      <p style="color:#8b949e;font-size:14px;margin:0;">
        Enquanto isso, explore nossa
        <a href="{url}" style="color:#58a6ff;">demonstração ao vivo</a>.
      </p>
    </td></tr>
    <tr><td style="padding:16px 36px;background:#0d1117;border-top:1px solid #30363d;">
      <p style="color:#484f58;font-size:12px;margin:0;">
        NetGuard IDS · {url}
      </p>
    </td></tr>
  </table>
</body>
</html>"""

    _send_async(email, name, subject, html, plain)


# ── Trial — lembrete de expiração ────────────────────────────────────────────

def send_trial_expiry_reminder(name: str, email: str, company: str,
                                trial_url: str, remaining_h: float,
                                upgrade_url: str = "") -> None:
    """
    Envia lembrete quando faltam ~24h para o trial expirar.
    Chamado automaticamente pelo scheduler do app.py.
    """
    if not email:
        return

    url          = (_cfg("APP_URL") or "http://localhost:5000").rstrip("/")
    upgrade_url  = upgrade_url or f"{url}/pricing"
    hours_left   = int(remaining_h)
    urgency_label = f"{hours_left}h restantes" if hours_left > 1 else "menos de 1h restante"

    subject = f"⚠️ Seu trial do NetGuard IDS expira em {urgency_label}"

    plain = f"""Olá, {name}!

Seu período de avaliação do NetGuard IDS para {company} está chegando ao fim.

Tempo restante: {urgency_label}

── Continue protegendo sua rede ──────────────────────────────────
Não perca o acesso ao seu dashboard e aos dados de detecção coletados.

Assine agora em: {upgrade_url}

Seu trial: {trial_url}

Planos a partir de R$990/mês:
✔ Dashboard em tempo real
✔ Detecção ML + IOC Manager
✔ Regras customizadas
✔ Compliance SOC2 / PCI-DSS / HIPAA
✔ Alertas via Webhook (Slack, Teams, Discord)

Ficou com dúvidas? Responda este e-mail.

— Equipe NetGuard IDS
"""

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
</head>
<body style="margin:0;padding:0;background:#0d1117;font-family:'Segoe UI',Arial,sans-serif;color:#e6edf3;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0d1117;padding:40px 16px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0"
             style="max-width:600px;background:#161b22;border-radius:12px;border:1px solid #30363d;overflow:hidden;">

        <!-- Header urgência -->
        <tr>
          <td style="background:#b91c1c;padding:14px 36px;text-align:center;">
            <span style="font-size:14px;font-weight:700;color:#fef2f2;letter-spacing:.5px;">
              ⏱ {urgency_label.upper()} — SEU TRIAL ESTÁ EXPIRANDO
            </span>
          </td>
        </tr>

        <!-- Logo -->
        <tr>
          <td style="background:#0d1117;padding:20px 36px;border-bottom:1px solid #30363d;">
            <table cellpadding="0" cellspacing="0"><tr>
              <td style="padding-right:10px;">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#58a6ff" stroke-width="2">
                  <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z"/>
                </svg>
              </td>
              <td style="font-size:16px;font-weight:800;color:#58a6ff;">NetGuard IDS</td>
            </tr></table>
          </td>
        </tr>

        <!-- Body -->
        <tr><td style="padding:36px 36px 0;">
          <p style="font-size:20px;font-weight:800;margin:0 0 8px;color:#f87171;">
            Não perca seu acesso, {name}!
          </p>
          <p style="color:#8b949e;font-size:14px;line-height:1.6;margin:0 0 24px;">
            Seu trial de <strong style="color:#e6edf3;">{company}</strong> expira em
            <strong style="color:#f87171;">{urgency_label}</strong>.
            Assine agora para manter o dashboard e todos os dados de detecção.
          </p>

          <!-- CTA principal -->
          <table cellpadding="0" cellspacing="0" style="margin-bottom:16px;">
            <tr><td style="background:#1f6feb;border-radius:8px;">
              <a href="{upgrade_url}"
                 style="display:block;padding:14px 32px;font-size:15px;font-weight:700;
                        color:#fff;text-decoration:none;">
                🔒 Assinar NetGuard IDS →
              </a>
            </td></tr>
          </table>

          <!-- CTA secundário — continuar no trial -->
          <p style="font-size:13px;color:#8b949e;margin:0 0 24px;">
            Ainda no trial?
            <a href="{trial_url}" style="color:#58a6ff;">Voltar ao dashboard →</a>
          </p>

          <!-- Planos -->
          <table width="100%" cellpadding="0" cellspacing="0"
                 style="background:#0d1117;border:1px solid #30363d;border-radius:8px;
                        margin-bottom:28px;padding:18px 20px;">
            <tr><td>
              <p style="font-size:13px;font-weight:700;color:#e6edf3;margin:0 0 14px;">
                O que você mantém ao assinar:
              </p>
              {''.join(f'<p style="font-size:13px;color:#8b949e;margin:0 0 8px;"><span style="color:#3fb950;margin-right:8px;">✔</span>{feat}</p>' for feat in [
                'Dashboard de segurança em tempo real',
                'Detecção ML (Isolation Forest) + IOC Manager',
                'Regras de detecção customizadas (14 operadores)',
                'Compliance: SOC2, PCI-DSS, HIPAA',
                'Alertas Webhook — Slack, Teams, Discord, HTTP',
              ])}
              <p style="font-size:12px;color:#6e7681;margin:12px 0 0;">
                Planos a partir de <strong style="color:#e6edf3;">R$990/mês</strong> · 14 dias grátis na assinatura
              </p>
            </td></tr>
          </table>
        </td></tr>

        <!-- Footer -->
        <tr><td style="padding:20px 36px 28px;border-top:1px solid #30363d;background:#0d1117;">
          <p style="color:#8b949e;font-size:12px;margin:0;line-height:1.6;">
            Dúvidas? Responda este e-mail.<br>
            <a href="{url}" style="color:#58a6ff;">{url}</a>
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""

    _send_async(email, name, subject, html, plain)
