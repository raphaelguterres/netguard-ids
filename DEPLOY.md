# NetGuard IDS - Production Deploy Guide

Use this guide when you want NetGuard running as a serious demo, portfolio environment, small SOC lab, or early SaaS deployment.

## Production baseline

Treat these items as mandatory before exposing the app outside localhost:

- `IDS_AUTH=true`
- `IDS_DASHBOARD_AUTH=true`
- strong `TOKEN_SIGNING_SECRET`
- reverse proxy with TLS
- PostgreSQL recommended for production
- persistent admin rate-limit DB (`IDS_ADMIN_RL_DB`)
- audit log rotation and retention configured

Additional current-state notes:

- the server already supports Agent + Server workflows
- agents can enroll with an admin or tenant bootstrap token
- agents can operate with an issued host key (`nga_...`)
- the agent does not persist the issued host key automatically yet, so unattended execution must provide `--token` or `--agent-key`

## Supported deployment shapes

### 1. Local lab or serious demo

- Flask app on one host
- SQLite acceptable
- reverse proxy optional
- suitable for portfolio demos and internal testing

### 2. Single-node production

- Flask app behind Nginx
- Gunicorn or equivalent WSGI server
- PostgreSQL strongly recommended
- persistent filesystem for logs and local buffers

### 3. Early SaaS / MSSP-style node

- same as single-node production
- PostgreSQL required
- explicit backup, metrics, and audit retention
- shared-cache improvements are still future work, so stay single-node unless you are ready to extend the platform

## Environment checklist

Start from `.env.example`:

```bash
cp .env.example .env
```

Minimum production values:

```dotenv
IDS_ENV=production
IDS_HOST=127.0.0.1
IDS_PORT=5000
IDS_AUTH=true
IDS_DASHBOARD_AUTH=true
HTTPS_ONLY=true
TOKEN_SIGNING_SECRET=<64+ char random secret>
SECRET_KEY=<separate random secret if used>
APP_URL=https://your-domain.example
DATABASE_URL=postgresql://user:pass@host:5432/netguard
IDS_AUDIT_LOG=/var/log/netguard/audit.log
IDS_AUDIT_LOG_ROTATE_WHEN=midnight
IDS_AUDIT_LOG_ROTATE_INTERVAL=1
IDS_AUDIT_LOG_RETENTION=14
IDS_ADMIN_RL_DB=/var/lib/netguard/netguard_security.db
IDS_CORS_ORIGINS=https://your-domain.example
```

Generate a signing secret:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

## Docker-based deploy

Typical flow:

```bash
git clone https://github.com/raphaelguterres/netguard-ids.git
cd netguard-ids
cp .env.example .env
docker compose up -d
```

After startup, verify:

```bash
docker compose ps
curl http://127.0.0.1/api/health
```

Recommended for Docker production:

- map persistent volumes for database, logs, and agent buffers
- terminate TLS at Nginx or another reverse proxy
- do not expose Flask directly on the internet

## VPS / manual deploy

### 1. System packages

```bash
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3-pip nginx certbot python3-certbot-nginx git
```

### 2. Application setup

```bash
git clone https://github.com/raphaelguterres/netguard-ids.git
cd netguard-ids
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

### 3. Gunicorn example

```bash
.venv/bin/gunicorn \
  --workers 4 \
  --bind 127.0.0.1:5000 \
  --timeout 120 \
  app:app
```

Important:

- keep `IDS_HOST=127.0.0.1`
- let Nginx expose the service publicly
- do not run with `IDS_AUTH=false` on a public bind

## Nginx and TLS

Recommended reverse proxy layout:

```nginx
server {
    listen 80;
    server_name your-domain.example;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.example;

    ssl_certificate     /etc/letsencrypt/live/your-domain.example/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.example/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Then issue certificates:

```bash
sudo certbot --nginx -d your-domain.example
```

## PostgreSQL guidance

SQLite is still excellent for:

- local desktop use
- single-operator demos
- tests

Use PostgreSQL when you need:

- production durability
- cleaner operational backups
- larger event volumes
- stronger separation between app process and data

The repositories already support PostgreSQL-ready behavior through:

- `EventRepository`
- `HostRepository`
- `IncidentRepository`

## Agent execution against the central server

Bootstrap with admin or tenant token:

```bash
python -m netguard_agent \
  --hub https://your-domain.example \
  --token YOUR_BOOTSTRAP_TOKEN \
  --host-id endpoint-finance-01 \
  --mode xdr
```

Execution with a host key:

```bash
python -m netguard_agent \
  --hub https://your-domain.example \
  --agent-key nga_HOST_KEY \
  --host-id endpoint-finance-01 \
  --mode xdr
```

Operational recommendation:

- use bootstrap token for enrollment and controlled demos
- use host key for already-approved hosts
- keep the local event buffer on persistent disk

## Background jobs and startup behavior

NetGuard now avoids dangerous side effects on import.

By default:

- direct `python app.py` can autostart the intended background components
- WSGI/Gunicorn imports do not autostart background jobs implicitly

Review these flags when packaging:

- `IDS_AUTOSTART_BACKGROUND`
- `IDS_AUTOSTART_SOC_ENGINE`
- `IDS_AUTOSTART_MONITOR`
- `IDS_AUTOSTART_TRIAL_SCHEDULER`
- `IDS_AUTOSTART_TI_FEED_SCHEDULER`

## Logs, monitoring, and metrics

Recommended production signals:

- application logs from Gunicorn/Nginx
- audit log from `IDS_AUDIT_LOG`
- `/api/health`
- `/metrics`

Audit log controls:

- `IDS_AUDIT_LOG_ROTATE_WHEN`
- `IDS_AUDIT_LOG_ROTATE_INTERVAL`
- `IDS_AUDIT_LOG_RETENTION`

## Backup

Minimum backup strategy:

- PostgreSQL logical dump or managed snapshots
- audit log retention and shipping if needed
- `.env` stored in a secrets manager or encrypted backup

Example PostgreSQL dump:

```bash
pg_dump "$DATABASE_URL" > netguard_backup.sql
```

## Pre-launch checklist

- auth enabled
- dashboard auth enabled
- strong signing secret configured
- TLS active
- PostgreSQL in use
- audit log path writable
- admin rate-limit DB persistent
- reverse proxy health checks working
- `/api/health` and `/metrics` reachable internally
- at least one end-to-end enrollment test completed with `netguard_agent`
