"""
NetGuard — Stripe Billing Integration
Gerencia planos, checkout e webhooks para o modo SaaS.

Variáveis de ambiente necessárias:
  STRIPE_SECRET_KEY       sk_live_... ou sk_test_...
  STRIPE_PUBLISHABLE_KEY  pk_live_... ou pk_test_...
  STRIPE_WEBHOOK_SECRET   whsec_...
  STRIPE_PRICE_FREE       price_...  (R$ 0 — plano gratuito, pode ser omitido)
  STRIPE_PRICE_PRO        price_...  (R$ 990/mês)
  STRIPE_PRICE_ENTERPRISE price_...  (R$ 3.900/mês)
  STRIPE_PRICE_MSSP       price_...  (R$ 300/cliente/mês)
  APP_URL                 https://seudominio.com (sem barra final)
  TRIAL_DAYS              14 (dias de trial gratuito sem cartão, default 14)
  CONTACT_EMAIL           contato@suaempresa.com (exibido na página de preços)
"""

import os
import secrets
import logging
from typing import Optional, Dict

logger = logging.getLogger("netguard.billing")

# ── Configuração via env ───────────────────────────────────────────
STRIPE_SECRET_KEY      = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET  = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY", "")
APP_URL                = os.environ.get("APP_URL", "http://localhost:5000")
TRIAL_DAYS             = int(os.environ.get("TRIAL_DAYS", "14"))
CONTACT_EMAIL          = os.environ.get("CONTACT_EMAIL", "contato@netguard.io")

# ── Catálogo de planos (BRL) ───────────────────────────────────────
PLANS: Dict[str, Dict] = {
    "free": {
        "name":           "Free",
        "label":          "Gratuito",
        "price_brl":      0,
        "price_id":       os.environ.get("STRIPE_PRICE_FREE", ""),
        "max_hosts":      1,
        "retention_days": 3,
        "trial_days":     0,
        "badge":          None,
        "cta":            "Começar grátis",
        "cta_action":     "trial",   # vai para /trial sem cartão
        "features": [
            "1 host monitorado",
            "500 eventos/dia",
            "Dashboard básico",
            "Alertas por e-mail",
            "Suporte via GitHub Issues",
        ],
        "limits": {
            "webhooks": 1,
            "api_calls_day": 500,
            "pdf_reports": False,
        },
    },
    "pro": {
        "name":           "Pro",
        "label":          "Pro",
        "price_brl":      990,
        "price_id":       os.environ.get("STRIPE_PRICE_PRO", ""),
        "max_hosts":      20,
        "retention_days": 30,
        "trial_days":     TRIAL_DAYS,
        "badge":          "MAIS POPULAR",
        "cta":            f"Testar {TRIAL_DAYS} dias grátis",
        "cta_action":     "trial",
        "features": [
            "Até 20 hosts monitorados",
            "Eventos ilimitados",
            "Todas as fases MITRE ATT&CK",
            "Alertas Telegram / WhatsApp / Slack",
            "Relatórios PDF/CSV",
            "API REST completa + Webhooks",
            "Correlação de eventos",
            "Suporte por chat em 24h",
        ],
        "limits": {
            "webhooks": 10,
            "api_calls_day": 50_000,
            "pdf_reports": True,
        },
    },
    "enterprise": {
        "name":           "Enterprise",
        "label":          "Enterprise",
        "price_brl":      3_900,
        "price_id":       os.environ.get("STRIPE_PRICE_ENTERPRISE", ""),
        "max_hosts":      9_999,
        "retention_days": 365,
        "trial_days":     TRIAL_DAYS,
        "badge":          None,
        "cta":            "Falar com especialista",
        "cta_action":     "contact",
        "features": [
            "Hosts ilimitados",
            "1 ano de retenção",
            "SSO / LDAP / Azure AD",
            "SLA 99,9% — suporte 4h",
            "White-label disponível",
            "Relatórios de compliance (ISO 27001, NIST)",
            "Onboarding dedicado",
            "API GraphQL completa",
        ],
        "limits": {
            "webhooks": 999,
            "api_calls_day": -1,   # ilimitado
            "pdf_reports": True,
        },
    },
    "mssp": {
        "name":           "MSSP Partner",
        "label":          "MSSP",
        "price_brl":      300,       # por cliente/mês
        "price_id":       os.environ.get("STRIPE_PRICE_MSSP", ""),
        "max_hosts":      9_999,
        "retention_days": 90,
        "trial_days":     30,
        "badge":          "REVENDEDORES",
        "cta":            "Tornar-se parceiro",
        "cta_action":     "contact",
        "features": [
            "Multi-tenant nativo",
            "Painel de gerenciamento unificado",
            "White-label total (logo, domínio, temas)",
            "Comissão de 20% em novos clientes indicados",
            "Suporte técnico prioritário",
            "Treinamento e certificação",
        ],
        "limits": {
            "webhooks": 999,
            "api_calls_day": -1,
            "pdf_reports": True,
        },
    },
}

# ── Inicialização do SDK Stripe ────────────────────────────────────
STRIPE_OK = False
stripe = None  # type: ignore

if STRIPE_SECRET_KEY:
    try:
        import stripe as _stripe
        _stripe.api_key = STRIPE_SECRET_KEY
        stripe = _stripe
        STRIPE_OK = True
        logger.info("Stripe billing: ativo (key=...%s)", STRIPE_SECRET_KEY[-6:])
    except ImportError:
        logger.warning(
            "Pacote 'stripe' não instalado — billing desativado. "
            "Execute: pip install stripe"
        )
else:
    logger.info("STRIPE_SECRET_KEY não definido — billing em modo demo")


# ══════════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════════

def get_plan(plan_key: str) -> Dict:
    """Retorna configuração do plano; cai no starter se desconhecido."""
    return PLANS.get(plan_key, PLANS["starter"])


def generate_api_token() -> str:
    """Gera token de API seguro para o tenant (prefixo ng_)."""
    return "ng_" + secrets.token_urlsafe(32)


def billing_active() -> bool:
    """True se Stripe está configurado e pronto."""
    return STRIPE_OK


# ══════════════════════════════════════════════════════════════════
#  Checkout
# ══════════════════════════════════════════════════════════════════

def create_checkout_session(
    plan_key: str,
    email: str,
    name: str,
    company: str,
) -> Optional[str]:
    """
    Cria sessão de checkout no Stripe e retorna URL de pagamento.

    Em modo demo (sem STRIPE_SECRET_KEY), retorna URL de welcome direta
    com token fake para testes locais sem cartão.
    """
    if not STRIPE_OK:
        # Modo demo: cria tenant simulado sem passar pelo Stripe
        fake_token = generate_api_token()
        return (
            f"{APP_URL}/welcome"
            f"?demo=1&plan={plan_key}&token={fake_token}"
            f"&name={name}&email={email}"
        )

    plan = get_plan(plan_key)
    if not plan["price_id"]:
        logger.error(
            "STRIPE_PRICE_%s não configurado — defina a variável de ambiente",
            plan_key.upper(),
        )
        return None

    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            mode="subscription",
            customer_email=email,
            line_items=[{"price": plan["price_id"], "quantity": 1}],
            success_url=f"{APP_URL}/welcome?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{APP_URL}/pricing?cancelled=1",
            metadata={
                "plan":    plan_key,
                "name":    name,
                "company": company,
                "email":   email,
            },
        )
        logger.info("Checkout session criada: %s | plano=%s | email=%s",
                    session.id, plan_key, email)
        return session.url
    except Exception as exc:
        logger.error("Stripe checkout error: %s", exc)
        return None


# ══════════════════════════════════════════════════════════════════
#  Portal de billing (auto-atendimento do cliente)
# ══════════════════════════════════════════════════════════════════

def create_portal_session(stripe_customer_id: str) -> Optional[str]:
    """
    Retorna URL do portal Stripe onde o cliente pode:
    - Ver/trocar plano
    - Cancelar assinatura
    - Atualizar cartão
    - Baixar faturas
    """
    if not STRIPE_OK:
        return None
    try:
        session = stripe.billing_portal.Session.create(
            customer=stripe_customer_id,
            return_url=f"{APP_URL}/",
        )
        return session.url
    except Exception as exc:
        logger.error("Stripe portal error: %s", exc)
        return None


# ══════════════════════════════════════════════════════════════════
#  Retrieve checkout (pós-pagamento)
# ══════════════════════════════════════════════════════════════════

def retrieve_checkout_session(session_id: str) -> Optional[Dict]:
    """
    Recupera dados completos de uma sessão após pagamento bem-sucedido.
    Expandido com customer e subscription para extrair IDs.
    """
    if not STRIPE_OK:
        return None
    try:
        return stripe.checkout.Session.retrieve(
            session_id,
            expand=["customer", "subscription"],
        )
    except Exception as exc:
        logger.error("Stripe retrieve session error: %s", exc)
        return None


# ══════════════════════════════════════════════════════════════════
#  Webhook handler
# ══════════════════════════════════════════════════════════════════

def handle_webhook(payload: bytes, sig_header: str) -> Optional[object]:
    """
    Valida assinatura e desserializa evento do Stripe.

    Retorna o objeto Event do Stripe ou None se inválido.
    O chamador é responsável por reagir ao event['type'].

    Eventos importantes:
      checkout.session.completed     → criar tenant, gerar token
      invoice.paid                   → renovação OK, manter ativo
      customer.subscription.deleted  → cancelamento, desativar tenant
      customer.subscription.updated  → troca de plano
    """
    if not STRIPE_OK:
        logger.warning("Webhook recebido mas Stripe não está configurado")
        return None

    if not STRIPE_WEBHOOK_SECRET:
        logger.warning("STRIPE_WEBHOOK_SECRET não definido — validação ignorada (inseguro!)")
        try:
            import json
            event = stripe.Event.construct_from(
                json.loads(payload), stripe.api_key
            )
            return event
        except Exception as exc:
            logger.error("Webhook parse error: %s", exc)
            return None

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
        logger.info("Webhook recebido: type=%s | id=%s", event["type"], event["id"])
        return event
    except stripe.error.SignatureVerificationError:
        logger.error("Assinatura do webhook inválida — possível ataque ou misconfiguration")
        return None
    except Exception as exc:
        logger.error("Webhook error: %s", exc)
        return None
