#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
#  NetGuard IDS — Emissão inicial do certificado Let's Encrypt
#
#  Uso: ./scripts/certbot-init.sh seu.dominio.com
#
#  Pré-requisitos:
#    - docker compose -f docker-compose.prod.yml up -d nginx
#    - Domínio apontando para este servidor (A record)
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

DOMAIN="${1:-}"
EMAIL="${CERTBOT_EMAIL:-admin@${DOMAIN}}"

if [[ -z "$DOMAIN" ]]; then
  echo "Uso: $0 <dominio>"
  echo "Exemplo: $0 netguard.suaempresa.com"
  exit 1
fi

echo "→ Emitindo certificado para: $DOMAIN"
echo "→ Email de contato:           $EMAIL"
echo ""

# Atualiza o arquivo de configuração Nginx com o domínio real
sed -i "s/YOUR_DOMAIN/$DOMAIN/g" nginx/netguard.conf

echo "→ Iniciando Nginx (porta 80 para desafio ACME)..."
docker compose -f docker-compose.prod.yml up -d nginx

echo "→ Aguardando Nginx ficar pronto..."
sleep 3

echo "→ Solicitando certificado via Certbot (webroot)..."
docker compose -f docker-compose.prod.yml run --rm certbot certonly \
  --webroot \
  --webroot-path=/var/www/certbot \
  --email "$EMAIL" \
  --agree-tos \
  --no-eff-email \
  --force-renewal \
  -d "$DOMAIN" \
  -d "www.$DOMAIN"

echo ""
echo "→ Recarregando Nginx com o novo certificado..."
docker compose -f docker-compose.prod.yml exec nginx nginx -s reload

echo ""
echo "✓ Certificado emitido com sucesso!"
echo "  Acesse: https://$DOMAIN"
echo ""
echo "  Renovação automática está configurada no serviço 'certbot'."
echo "  Verificação: docker compose -f docker-compose.prod.yml logs certbot"
