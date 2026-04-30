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
- shared modular API rate-limit DB (`NETGUARD_RATE_LIMIT_BACKEND=sqlite`)
- audit log rotation and retention configured

Additional current-state notes:

- the server already supports Agent + Server workflows
- agents can enroll with an admin or tenant bootstrap token
- agents can operate with an issued host key (`nga_...`)
- the production-oriented `agent/` runtime persists the issued host key in its local credential store after enrollment
- the legacy-compatible `netguard_agent/` runtime still accepts `--token` or `--agent-key` for scripted/demo execution

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
- SQLite shared rate limiting is available for single-host multi-worker deploys; Redis/shared-cache remains future work for true multi-node topologies

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
NETGUARD_RATE_LIMIT_BACKEND=sqlite
NETGUARD_RATE_LIMIT_DB=/var/lib/netguard/netguard_rate_limit.db
NETGUARD_RATE_LIMIT_RATE_PER_SEC=20
NETGUARD_RATE_LIMIT_BURST=40
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
- modular EDR `Repository` schema version and migration status metadata

For the modular EDR repository, `init_schema()` records applied migrations
with deterministic checksums. Before and after upgrades, check
`repo.migration_status()` in a maintenance script or Python shell; it reports
the current version, latest expected version, pending migrations, unknown
migrations, and checksum mismatches.

## Agent execution against the central server

For production-style endpoint tests, prefer the `agent/` runtime documented in
`agent/README_AGENT.md`. It supports local host identity, credential storage,
offline buffering, response-action polling, Windows service installation, and
`agent.exe` packaging.

Minimal `agent/` execution:

```bash
cd agent
python -m agent
```

Build Windows `agent.exe`:

```powershell
cd agent
powershell -ExecutionPolicy Bypass -File .\build_agent.ps1 -Clean -WithService
```

The compatibility collector remains useful for demos and older automation.
Bootstrap it with an admin or tenant token:

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
- use narrowly scoped tenant tokens for automation (`events:write` for ingest-only, not host management)
- use host key for already-approved hosts
- rotate host keys after suspected exposure and during planned credential refresh windows
- verify the `agent/` credential store on the endpoint after first enrollment
- keep `NETGUARD_AGENT_ALLOW_DESTRUCTIVE_RESPONSE_ACTIONS=false` unless endpoint-side policy secrets and handlers are explicitly approved
- keep the local event buffer on persistent disk

## SOC and detection verification

After deploy, validate the detection/SOC path before adding real endpoints:

```bash
curl http://127.0.0.1:5000/api/health
curl -H "X-API-Token: $ADMIN_TOKEN" http://127.0.0.1:5000/api/detection/rules
curl http://127.0.0.1:5000/soc/grid/api/rules
```

Expected checks:

- `/api/detection/rules` shows built-in and YAML/Sigma-like rule coverage
- `/soc/grid/api/rules` returns `ok=true` and YAML health data
- invalid YAML rules are skipped and reported, not silently loaded
- creating an incident twice for the same active `event_id` returns the
  existing incident with `deduplicated=true`

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
- modular `/api/events` rate-limit DB persistent when running multiple workers
- reverse proxy health checks working
- `/api/health` and `/metrics` reachable internally
- `/api/detection/rules` and `/soc/grid/api/rules` reviewed for YAML health
- incident idempotency tested with a repeated `event_id`
- at least one end-to-end enrollment test completed with `agent/` or `netguard_agent/`
