# NetGuard IDS — Guia de Deploy em Produção

> **Antes de começar:** certifique-se de que o `.env` está preenchido com base no `.env.example`.
> Nunca commite o arquivo `.env` — ele já está no `.gitignore`.

---

## Índice

1. [Opção A — Docker Compose (recomendado)](#opção-a--docker-compose-recomendado)
2. [Opção B — Railway / Render (PaaS — 1 clique)](#opção-b--railway--render-paas)
3. [Opção C — VPS manual (Ubuntu 22.04)](#opção-c--vps-manual-ubuntu-2204)
4. [Nginx + HTTPS com Let's Encrypt](#nginx--https-com-lets-encrypt)
5. [Variáveis de ambiente — checklist completo](#variáveis-de-ambiente--checklist-completo)
6. [PostgreSQL em produção](#postgresql-em-produção)
7. [E-mail transacional (SMTP)](#e-mail-transacional-smtp)
8. [Health check & monitoramento](#health-check--monitoramento)
9. [Backup do banco de dados](#backup-do-banco-de-dados)
10. [Checklist de segurança pré-lançamento](#checklist-de-segurança-pré-lançamento)

---

## Opção A — Docker Compose (recomendado)

A forma mais rápida de subir o stack completo com PostgreSQL, Prometheus e Grafana.

### Pré-requisitos

- Docker ≥ 24 e Docker Compose ≥ 2.20
- Porta 80 e 443 liberadas no firewall

### 1. Clone e configure

```bash
git clone https://github.com/raphaelguterres/netguard-ids.git
cd netguard-ids
cp .env.example .env
nano .env   # preencha os valores obrigatórios
```

### 2. Suba o stack

```bash
docker compose up -d
```

Serviços iniciados:

| Serviço      | Porta interna | Descrição                  |
|--------------|---------------|----------------------------|
| `app`        | 5000          | NetGuard IDS (Flask)       |
| `postgres`   | 5432          | Banco de dados             |
| `prometheus` | 9090          | Métricas                   |
| `grafana`    | 3000          | Dashboards de observabilidade |
| `nginx`      | 80 / 443      | Proxy reverso + TLS        |

### 3. Verifique

```bash
docker compose ps
curl http://localhost/api/health
```

### 4. Logs em tempo real

```bash
docker compose logs -f app        # NetGuard IDS
docker compose logs -f postgres   # banco
```

### 5. Atualizar para nova versão

```bash
git pull origin main
docker compose build app
docker compose up -d --no-deps app
```

---

## Opção B — Railway / Render (PaaS)

Deploy em 1 clique, sem gerenciar servidor. Ideal para começar.

### Railway

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template/netguard-ids)

1. Clique em "Deploy on Railway"
2. Conecte sua conta GitHub e selecione o repositório `netguard-ids`
3. Railway detecta o `Dockerfile` automaticamente
4. Adicione as variáveis de ambiente em **Settings → Variables**:
   ```
   DATABASE_URL=postgresql://...   ← gerado automaticamente pelo plugin PostgreSQL do Railway
   IDS_DASHBOARD_AUTH=true
   HTTPS_ONLY=true
   TOKEN_SIGNING_SECRET=<string aleatória de 64 chars>
   SECRET_KEY=<string aleatória de 64 chars>
   APP_URL=https://seu-app.railway.app
   ```
5. Clique em **Deploy**

### Render

1. New → Web Service → conecte o repositório
2. Runtime: **Docker**
3. Adicione as env vars (mesmas acima)
4. Adicione um **PostgreSQL** database em New → PostgreSQL
5. Copie a `DATABASE_URL` para as env vars do web service

> **Dica:** ambos oferecem plano gratuito, mas recomenda-se o plano pago ($5-7/mês) para evitar sleep em inatividade.

---

## Opção C — VPS manual (Ubuntu 22.04)

Para quem prefere controle total sobre a infra.

### 1. Prepare o servidor

```bash
# Atualize o sistema
sudo apt update && sudo apt upgrade -y

# Instale dependências
sudo apt install -y python3.11 python3.11-venv python3-pip \
                    nginx certbot python3-certbot-nginx git ufw

# Configure o firewall
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable
```

### 2. Clone e configure o projeto

```bash
sudo useradd -m -s /bin/bash netguard
sudo su - netguard

git clone https://github.com/raphaelguterres/netguard-ids.git
cd netguard-ids
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
nano .env   # configure as variáveis obrigatórias
```

### 3. Configure o serviço systemd

```bash
sudo tee /etc/systemd/system/netguard.service <<'EOF'
[Unit]
Description=NetGuard IDS
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=netguard
WorkingDirectory=/home/netguard/netguard-ids
EnvironmentFile=/home/netguard/netguard-ids/.env
ExecStart=/home/netguard/netguard-ids/.venv/bin/gunicorn \
    --workers 4 \
    --bind 127.0.0.1:5000 \
    --timeout 120 \
    --access-logfile /var/log/netguard/access.log \
    --error-logfile /var/log/netguard/error.log \
    app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo mkdir -p /var/log/netguard
sudo chown netguard: /var/log/netguard

sudo systemctl daemon-reload
sudo systemctl enable netguard
sudo systemctl start netguard
sudo systemctl status netguard
```

---

## Nginx + HTTPS com Let's Encrypt

```bash
# Crie o arquivo de configuração do Nginx
sudo tee /etc/nginx/sites-available/netguard <<'EOF'
server {
    listen 80;
    server_name seu-dominio.com www.seu-dominio.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name seu-dominio.com www.seu-dominio.com;

    ssl_certificate     /etc/letsencrypt/live/seu-dominio.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/seu-dominio.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # Segurança
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options            DENY                                  always;
    add_header X-Content-Type-Options     nosniff                               always;
    add_header Referrer-Policy            strict-origin-when-cross-origin       always;

    # SSE — desabilita buffering para stream funcionar
    location /api/events/stream {
        proxy_pass         http://127.0.0.1:5000;
        proxy_buffering    off;
        proxy_cache        off;
        proxy_read_timeout 3600s;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_set_header   Host              $host;
    }

    location / {
        proxy_pass         http://127.0.0.1:5000;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        client_max_body_size 10M;
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/netguard /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# Gere o certificado TLS
sudo certbot --nginx -d seu-dominio.com -d www.seu-dominio.com \
     --non-interactive --agree-tos -m seu@email.com

# Renovação automática (já vem configurada pelo certbot)
sudo systemctl status certbot.timer
```

---

## Variáveis de ambiente — checklist completo

Marque cada item antes de colocar em produção:

### Obrigatórias

| Variável | Valor recomendado | Status |
|----------|-------------------|--------|
| `TOKEN_SIGNING_SECRET` | String aleatória de 64 chars: `python3 -c "import secrets; print(secrets.token_hex(32))"` | ☐ |
| `SECRET_KEY` | String aleatória de 64 chars: `python3 -c "import secrets; print(secrets.token_hex(32))"` | ☐ |
| `HTTPS_ONLY` | `true` | ☐ |
| `IDS_DASHBOARD_AUTH` | `true` | ☐ |
| `APP_URL` | `https://seu-dominio.com` | ☐ |
| `DATABASE_URL` | `postgresql://user:pass@host:5432/netguard` | ☐ |
| `CONTACT_EMAIL` | `contato@seu-dominio.com` | ☐ |

### Recomendadas

| Variável | Valor | Status |
|----------|-------|--------|
| `SMTP_HOST` | `smtp.resend.com` | ☐ |
| `SMTP_USER` | `resend` | ☐ |
| `SMTP_PASS` | Sua API Key do Resend | ☐ |
| `SMTP_FROM` | `noreply@seu-dominio.com` | ☐ |
| `IDS_CORS_ORIGINS` | `https://seu-dominio.com` | ☐ |
| `IDS_AUDIT_LOG` | `/var/log/netguard/audit.log` | ☐ |
| `TRIAL_DAYS` | `14` | ☐ |

### Opcionais

| Variável | Descrição |
|----------|-----------|
| `IDS_ABUSEIPDB_KEY` | Enriquecimento de IPs via AbuseIPDB |
| `IDS_VIRUSTOTAL_KEY` | Análise de hashes via VirusTotal |
| `IDS_AUTO_BLOCK` | `true` para bloqueio automático via iptables (Linux) |
| `IDS_WHITELIST_IPS` | IPs confiáveis separados por vírgula |
| `STRIPE_SECRET_KEY` | Para billing via Stripe |
| `STRIPE_WEBHOOK_SECRET` | Para receber eventos do Stripe |

---

## PostgreSQL em produção

### Provedor recomendado: Supabase (gratuito até 500MB)

1. Crie um projeto em [supabase.com](https://supabase.com)
2. Vá em **Settings → Database**
3. Copie a **Connection string (URI)**:
   ```
   postgresql://postgres:[PASSWORD]@db.[PROJECT].supabase.co:5432/postgres
   ```
4. Defina no `.env`:
   ```
   DATABASE_URL=postgresql://postgres:SENHA@db.xxxx.supabase.co:5432/postgres
   ```

O NetGuard IDS cria o schema automaticamente na primeira inicialização.

### Alternativas

| Provedor | Gratuito | Notas |
|----------|----------|-------|
| [Supabase](https://supabase.com) | 500MB | Recomendado |
| [Railway](https://railway.app) | $5/mês | Integrado ao deploy |
| [Render](https://render.com) | 90 dias | Plano free expira |
| [Neon](https://neon.tech) | 3GB | Serverless PostgreSQL |

---

## E-mail transacional (SMTP)

### Resend (recomendado — gratuito até 3.000/mês)

1. Crie conta em [resend.com](https://resend.com)
2. Adicione e verifique seu domínio (SPF + DKIM automático)
3. Gere uma API Key em **API Keys**
4. Configure no `.env`:
   ```
   SMTP_HOST=smtp.resend.com
   SMTP_PORT=587
   SMTP_USER=resend
   SMTP_PASS=re_SUA_API_KEY
   SMTP_FROM=noreply@seu-dominio.com
   ```

### Teste antes de ir ao ar

```bash
python3 - <<'EOF'
from mailer import send_welcome
send_welcome(
    name    = "Teste Deploy",
    email   = "seu@email.com",
    token   = "ng_test123",
    plan    = "pro",
    app_url = "https://seu-dominio.com",
)
print("Se não levantou exceção, o e-mail foi enviado (ou logado em dry-run).")
EOF
```

---

## Health check & monitoramento

### Endpoint de saúde

```bash
curl https://seu-dominio.com/api/health
# Esperado: {"status": "healthy", ...}
```

Configure um monitor externo (UptimeRobot, Better Uptime, Freshping — todos gratuitos):

- **URL:** `https://seu-dominio.com/api/health`
- **Intervalo:** 1 minuto
- **Alerta:** e-mail / Telegram quando status ≠ 200

### Métricas Prometheus

```
https://seu-dominio.com/metrics
```

Recomenda-se proteger esse endpoint com IP allowlist no Nginx em produção:

```nginx
location /metrics {
    allow 10.0.0.0/8;   # sua rede interna / Prometheus server
    deny  all;
    proxy_pass http://127.0.0.1:5000;
}
```

---

## Backup do banco de dados

### SQLite (modo padrão)

```bash
# Backup diário — adicione ao cron
0 3 * * * sqlite3 /home/netguard/netguard-ids/netguard_events.db \
    ".backup /backups/netguard_$(date +\%Y\%m\%d).db"
```

### PostgreSQL

```bash
# Dump comprimido
pg_dump $DATABASE_URL | gzip > backup_$(date +%Y%m%d).sql.gz

# Restore
gunzip -c backup_20250101.sql.gz | psql $DATABASE_URL
```

### Automatizar com rclone (enviar para S3/GCS/R2)

```bash
rclone copy /backups/ s3:seu-bucket/netguard-backups/ --max-age 30d
```

---

## Checklist de segurança pré-lançamento

Execute cada item antes de divulgar o produto:

**Configuração**
- [ ] `TOKEN_SIGNING_SECRET` gerada aleatoriamente e distinta de `SECRET_KEY`
- [ ] `SECRET_KEY` gerada aleatoriamente (nunca o valor padrão)
- [ ] `HTTPS_ONLY=true` ativo
- [ ] `IDS_DASHBOARD_AUTH=true` ativo
- [ ] `DEBUG=false` (Flask não expõe traceback)
- [ ] CORS restrito ao domínio (`IDS_CORS_ORIGINS=https://seu-dominio.com`)

**Infraestrutura**
- [ ] Certificado TLS válido (`certbot` ou Let's Encrypt via provedor)
- [ ] Firewall ativo — somente portas 80, 443 e 22 abertas
- [ ] SSH com autenticação por chave (senha desabilitada)
- [ ] `/metrics` protegido por IP allowlist no Nginx

**Dados**
- [ ] PostgreSQL com senha forte (não use `postgres`/`postgres`)
- [ ] Backup automático configurado e testado
- [ ] Audit log ativo e gravando (`IDS_AUDIT_LOG`)

**Monitoramento**
- [ ] Health check externo configurado (UptimeRobot ou similar)
- [ ] Alerta de downtime configurado (e-mail / Telegram)
- [ ] Logs em `/var/log/netguard/` com rotação (`logrotate`)

**E-mail**
- [ ] SMTP configurado e testado com `python3 -c "from mailer import send_welcome; ..."`
- [ ] SPF e DKIM do domínio configurados (evita spam)
- [ ] `SMTP_FROM` usando domínio próprio (não Gmail pessoal)

---

## Comandos úteis pós-deploy

```bash
# Reiniciar o serviço
sudo systemctl restart netguard

# Ver logs ao vivo
sudo journalctl -u netguard -f

# Testar a API
curl -s https://seu-dominio.com/api/health | python3 -m json.tool

# Ver tenants cadastrados (requer acesso ao banco)
sqlite3 netguard_events.db "SELECT tenant_id, name, plan, created_at FROM tenants ORDER BY created_at DESC LIMIT 10;"

# Criar tenant manualmente (sem passar pela UI)
curl -X POST https://seu-dominio.com/trial \
     -H "Content-Type: application/json" \
     -d '{"name":"Cliente Teste","email":"cliente@empresa.com","plan":"pro"}'
```
## Atualizações recentes de operação segura

### Segredos obrigatórios

- `TOKEN_SIGNING_SECRET` é obrigatório fora de dev/test.
- O boot falha fechado se ele não estiver configurado.
- Use valor distinto de `SECRET_KEY`.

### Audit log

- Há rotação embutida do audit log.
- Variáveis novas/relevantes:
  `IDS_AUDIT_LOG_ROTATE_WHEN`,
  `IDS_AUDIT_LOG_ROTATE_INTERVAL`,
  `IDS_AUDIT_LOG_RETENTION`

### Rate limit admin

- O rate limit admin agora usa SQLite compartilhado por host.
- Variável relevante: `IDS_ADMIN_RL_DB`

### Background jobs

- `app.py` não inicia monitoramento/schedulers ao ser importado.
- Em `python app.py`, os jobs podem autostartar conforme as flags.
- Em WSGI/Gunicorn multi-worker, mantenha opt-in explícito para evitar side effects.
