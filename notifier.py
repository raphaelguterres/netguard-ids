"""
notifier.py — NetGuard IDS · Notificações de eventos de negócio
================================================================
Dispara alertas via Telegram e/ou Slack para eventos críticos:
  • Novo trial criado
  • Trial expirado (72h / 7 dias)
  • Tenant upgradou de plano
  • Tentativa de brute-force (20+ falhas)
  • Token rotacionado

Configuração (variáveis de ambiente)
-------------------------------------
  TELEGRAM_BOT_TOKEN   — token do bot (@BotFather)
  TELEGRAM_CHAT_ID     — ID do canal/grupo de alertas
  SLACK_WEBHOOK_URL    — Incoming Webhook URL do Slack
  NOTIFY_EVENTS        — lista separada por vírgula dos eventos desejados
                         padrão: TRIAL_CREATED,TRIAL_EXPIRED,PLAN_UPGRADED,
                                 BRUTE_FORCE_ALERT,TOKEN_ROTATED

Design:
  - Todas as chamadas de rede rodam em threads daemon (nunca bloqueiam HTTP)
  - Falha silenciosa — nunca propagas exceções para o app
  - Dry-run automático quando nenhum destino configurado (apenas loga)
  - Mensagens formatadas com Markdown (Telegram) e Block Kit (Slack)
"""

from __future__ import annotations

import json
import logging
import os
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("netguard.notifier")

# ── Configuração ──────────────────────────────────────────────────
_TELEGRAM_TOKEN  = os.environ.get("TELEGRAM_BOT_TOKEN", "")
_TELEGRAM_CHAT   = os.environ.get("TELEGRAM_CHAT_ID", "")
_SLACK_WEBHOOK   = os.environ.get("SLACK_WEBHOOK_URL", "")

_NOTIFY_EVENTS_RAW = os.environ.get(
    "NOTIFY_EVENTS",
    "TRIAL_CREATED,TRIAL_EXPIRED,PLAN_UPGRADED,BRUTE_FORCE_ALERT,TOKEN_ROTATED,TENANT_CREATED"
)
_NOTIFY_EVENTS = {e.strip().upper() for e in _NOTIFY_EVENTS_RAW.split(",") if e.strip()}

_DRY_RUN = not _TELEGRAM_TOKEN and not _SLACK_WEBHOOK


# ══════════════════════════════════════════════════════════════════
# PONTO DE ENTRADA PÚBLICO
# ══════════════════════════════════════════════════════════════════

def notify(event: str, **kwargs) -> None:
    """
    Dispara notificação assíncrona para o evento dado.

    Parâmetros
    ----------
    event : str
        Um dos eventos configurados em NOTIFY_EVENTS, ex: "TRIAL_CREATED"
    **kwargs : dados do evento (name, email, plan, ip, tenant_id, etc.)

    Uso:
        from notifier import notify
        notify("TRIAL_CREATED", name="João", email="j@j.com", plan="pro")
        notify("BRUTE_FORCE_ALERT", ip="1.2.3.4", count=20)
        notify("PLAN_UPGRADED", tenant_id="abc", old_plan="pro", new_plan="business")
        notify("TRIAL_EXPIRED", name="João", email="j@j.com", tenant_id="abc")
    """
    event = event.upper()
    if event not in _NOTIFY_EVENTS:
        return  # evento não configurado para notificação

    t = threading.Thread(
        target=_dispatch,
        args=(event,),
        kwargs=kwargs,
        daemon=True,
        name=f"notifier-{event}",
    )
    t.start()


# ══════════════════════════════════════════════════════════════════
# INTERNOS
# ══════════════════════════════════════════════════════════════════

def _dispatch(event: str, **kwargs) -> None:
    """Thread worker — monta mensagem e envia para todos os destinos."""
    try:
        msg_md   = _format_telegram(event, **kwargs)
        msg_slack = _format_slack(event, **kwargs)

        if _DRY_RUN:
            logger.info("[notifier dry-run] %s | %s", event, kwargs)
            return

        if _TELEGRAM_TOKEN and _TELEGRAM_CHAT:
            _send_telegram(msg_md)

        if _SLACK_WEBHOOK:
            _send_slack(msg_slack)

    except Exception as exc:
        logger.warning("[notifier] Erro ao despachar %s: %s", event, exc)


# ── Formatação Telegram (Markdown v2) ────────────────────────────

_ICONS = {
    "TRIAL_CREATED":      "🟢",
    "TRIAL_EXPIRED":      "🔴",
    "PLAN_UPGRADED":      "⭐",
    "BRUTE_FORCE_ALERT":  "🚨",
    "TOKEN_ROTATED":      "🔄",
    "TENANT_CREATED":     "🏢",
    "LOGIN_BLOCKED":      "🛑",
}

def _esc(s: str) -> str:
    """Escapa caracteres especiais do MarkdownV2 do Telegram."""
    for c in r'_*[]()~`>#+-=|{}.!':
        s = s.replace(c, f'\\{c}')
    return s


def _format_telegram(event: str, **kw) -> str:
    icon = _ICONS.get(event, "ℹ️")
    ts   = datetime.now(timezone.utc).strftime("%d/%m %H:%M UTC")

    if event == "TRIAL_CREATED":
        return (
            f"{icon} *Novo Trial* — {_esc(kw.get('plan','pro').upper())}\n"
            f"👤 {_esc(kw.get('name',''))}\n"
            f"📧 {_esc(kw.get('email',''))}\n"
            f"🏢 {_esc(kw.get('company','') or '—')}\n"
            f"🕐 {_esc(ts)}"
        )
    if event == "TRIAL_EXPIRED":
        return (
            f"{icon} *Trial Expirado*\n"
            f"👤 {_esc(kw.get('name',''))}\n"
            f"📧 {_esc(kw.get('email',''))}\n"
            f"🆔 {_esc(kw.get('tenant_id','')[:12])}…\n"
            f"🕐 {_esc(ts)}"
        )
    if event == "PLAN_UPGRADED":
        old = kw.get('old_plan','?')
        new = kw.get('new_plan','?')
        return (
            f"{icon} *Upgrade de Plano\\!* 💰\n"
            f"🆔 {_esc(kw.get('tenant_id','')[:12])}…\n"
            f"📈 {_esc(old)} → {_esc(new)}\n"
            f"🕐 {_esc(ts)}"
        )
    if event == "BRUTE_FORCE_ALERT":
        return (
            f"{icon} *Alerta Brute Force*\n"
            f"🌐 IP: `{_esc(kw.get('ip',''))}`\n"
            f"🔢 Tentativas: {_esc(str(kw.get('count',0)))}\n"
            f"⏱ Bloqueado por: {_esc(str(kw.get('duration_s',0)))}s\n"
            f"🕐 {_esc(ts)}"
        )
    if event == "TOKEN_ROTATED":
        return (
            f"{icon} *Token Rotacionado*\n"
            f"🆔 {_esc(kw.get('tenant_id','')[:12])}…\n"
            f"🔑 Novo prefixo: `{_esc(kw.get('new_prefix','')[:8])}`\n"
            f"🌐 IP: `{_esc(kw.get('ip',''))}`\n"
            f"🕐 {_esc(ts)}"
        )
    if event == "TENANT_CREATED":
        return (
            f"{icon} *Novo Tenant Criado*\n"
            f"🏢 {_esc(kw.get('name',''))}\n"
            f"📦 Plano: {_esc(kw.get('plan',''))}\n"
            f"🆔 {_esc(kw.get('tenant_id','')[:12])}…\n"
            f"🕐 {_esc(ts)}"
        )
    # Fallback genérico
    detail = " | ".join(f"{k}={v}" for k, v in kw.items() if v)
    return f"{icon} *{_esc(event)}*\n{_esc(detail)}\n🕐 {_esc(ts)}"


# ── Formatação Slack (Block Kit) ─────────────────────────────────

_PLAN_EMOJI = {"free": "🆓", "pro": "⚡", "business": "💼", "enterprise": "🏆"}

def _format_slack(event: str, **kw) -> dict:
    icon = _ICONS.get(event, "ℹ️")
    ts   = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")

    fields = []

    if event == "TRIAL_CREATED":
        title = f"{icon} Novo Trial — {kw.get('plan','pro').upper()}"
        fields = [
            {"type":"mrkdwn","text":f"*Nome:*\n{kw.get('name','')}"},
            {"type":"mrkdwn","text":f"*E-mail:*\n{kw.get('email','')}"},
            {"type":"mrkdwn","text":f"*Empresa:*\n{kw.get('company','—')}"},
            {"type":"mrkdwn","text":f"*Data:*\n{ts}"},
        ]
        color = "#3fb950"

    elif event == "TRIAL_EXPIRED":
        title = f"{icon} Trial Expirado"
        fields = [
            {"type":"mrkdwn","text":f"*Nome:*\n{kw.get('name','')}"},
            {"type":"mrkdwn","text":f"*E-mail:*\n{kw.get('email','')}"},
            {"type":"mrkdwn","text":f"*Tenant:*\n{str(kw.get('tenant_id',''))[:12]}…"},
            {"type":"mrkdwn","text":f"*Data:*\n{ts}"},
        ]
        color = "#f85149"

    elif event == "PLAN_UPGRADED":
        old, new = kw.get('old_plan','?'), kw.get('new_plan','?')
        title = f"{icon} Upgrade de Plano!"
        fields = [
            {"type":"mrkdwn","text":f"*Tenant:*\n{str(kw.get('tenant_id',''))[:12]}…"},
            {"type":"mrkdwn","text":f"*Mudança:*\n{old} → {new}"},
            {"type":"mrkdwn","text":f"*Data:*\n{ts}"},
        ]
        color = "#e3b341"

    elif event == "BRUTE_FORCE_ALERT":
        title = f"{icon} Alerta Brute Force"
        fields = [
            {"type":"mrkdwn","text":f"*IP:*\n`{kw.get('ip','')}`"},
            {"type":"mrkdwn","text":f"*Tentativas:*\n{kw.get('count',0)}"},
            {"type":"mrkdwn","text":f"*Bloqueio:*\n{kw.get('duration_s',0)}s"},
            {"type":"mrkdwn","text":f"*Data:*\n{ts}"},
        ]
        color = "#f85149"

    elif event == "TOKEN_ROTATED":
        title = f"{icon} Token Rotacionado"
        fields = [
            {"type":"mrkdwn","text":f"*Tenant:*\n{str(kw.get('tenant_id',''))[:12]}…"},
            {"type":"mrkdwn","text":f"*Novo prefixo:*\n`{str(kw.get('new_prefix',''))[:8]}`"},
            {"type":"mrkdwn","text":f"*IP:*\n{kw.get('ip','—')}"},
            {"type":"mrkdwn","text":f"*Data:*\n{ts}"},
        ]
        color = "#58a6ff"

    else:
        title = f"{icon} {event}"
        detail = " | ".join(f"{k}={v}" for k, v in kw.items() if v)
        fields = [{"type":"mrkdwn","text":f"*Detalhes:*\n{detail}"}]
        color = "#8b949e"

    return {
        "attachments": [{
            "color": color,
            "blocks": [
                {"type":"section","text":{"type":"mrkdwn","text":f"*{title}*"}},
                {"type":"section","fields": fields},
            ]
        }]
    }


# ── HTTP send ─────────────────────────────────────────────────────

def _send_telegram(text: str) -> None:
    url  = f"https://api.telegram.org/bot{_TELEGRAM_TOKEN}/sendMessage"
    body = json.dumps({
        "chat_id":    _TELEGRAM_CHAT,
        "text":       text,
        "parse_mode": "MarkdownV2",
    }).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status != 200:
                logger.warning("[notifier] Telegram status=%d", resp.status)
    except urllib.error.HTTPError as exc:
        logger.warning("[notifier] Telegram HTTP %d: %s", exc.code, exc.read()[:200])
    except Exception as exc:
        logger.warning("[notifier] Telegram error: %s", exc)


def _send_slack(payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(
        _SLACK_WEBHOOK, data=body, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status != 200:
                logger.warning("[notifier] Slack status=%d", resp.status)
    except urllib.error.HTTPError as exc:
        logger.warning("[notifier] Slack HTTP %d: %s", exc.code, exc.read()[:200])
    except Exception as exc:
        logger.warning("[notifier] Slack error: %s", exc)


# ── Export conveniente ────────────────────────────────────────────
__all__ = ["notify"]
