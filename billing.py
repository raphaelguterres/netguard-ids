"""
NetGuard — Stripe Billing Integration
Gerencia planos, checkout e webhooks para o modo SaaS.

Variáveis de ambiente necessárias:
  STRIPE_SECRET_KEY       sk_live_... ou sk_test_...
  STRIPE_PUBLISHABLE_KEY  pk_live_... ou pk_test_...
  STRIPE_WEBHOOK_SECRET   whsec_...
  STRIPE_PRICE_STARTER    price_...
  STRIPE_PRICE_PRO        price_...
  STRIPE_PRICE_ENTERPRISE price_...
  APP_URL                 https://seudominio.com (sem barra final)
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

# ── Catálogo de planos ─────────────────────────────────────────────
PLANS: Dict[str, Dict] = {
    "starter": {
        "name": "Starter",
        "price_usd": 29,
        "price_id": os.environ.get("STRIPE_PRICE_STARTER", ""),
        "max_hosts": 3,
        "retention_days": 7,
        "features": [
            "3 hosts monitorados",
            "7 dias de retenção",
            "Alertas por email",
            "Dashboard web",
            "API REST básica",
        ],
    },
    "pro": {
        "name": "Pro",
        "price_usd": 99,
        "price_id": os.environ.get("STRIPE_PRICE_PRO", ""),
        "max_hosts": 20,
        "retention_days": 30,
        "features": [
            "20 hosts monitorados",
            "30 dias de retenção",
            "Alertas Slack / Teams / PagerDuty",
            "API completa + Webhooks",
            "Prometheus + Grafana",
            "Correlação de eventos",
        ],
    },
    "enterprise": {
        "name": "Enterprise",
        "price_usd": 299,
        "price_id": os.environ.get("STRIPE_PRICE_ENTERPRISE", ""),
        "max_hosts": 9_999,
        "retention_days": 365,
        "features": [
            "Hosts ilimitados",
            "1 ano de retenção",
            "SLA 99,9 %",
            "Suporte dedicado 24/7",
            "Deploy on-premise assistido",
            "SSO / SAML",
        ],
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
