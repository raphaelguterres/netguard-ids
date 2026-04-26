# NetGuard IDS

Host-centric detection and response platform built in Python, with a local-first SOC dashboard, XDR-style endpoint ingest, incident workflow, risk scoring, and a path from desktop demo to lightweight SaaS.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Aligned-red)](https://attack.mitre.org)
[![CI](https://github.com/raphaelguterres/netguard-ids/actions/workflows/tests.yml/badge.svg)](https://github.com/raphaelguterres/netguard-ids/actions/workflows/tests.yml)
[![License](https://img.shields.io/badge/License-MIT-lightgrey)]()
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker)](DOCKER.md)

## What NetGuard is now

NetGuard is no longer only a local IDS dashboard. The project now has the foundation of a lightweight EDR/SIEM:

- Flask server with REST API and SOC dashboard
- Modular endpoint agent (`netguard_agent/`) with legacy and XDR transport modes
- Host enrollment and inventory registry
- Structured endpoint event ingest (`/api/agent/events` and `/api/xdr/events`)
- RBAC-aware auth model (`admin`, `analyst`, `viewer`)
- Incident lifecycle API with status, severity, assignment, and comments
- SQLite-first storage for local/demo, with repositories written to be PostgreSQL-ready
- Sigma-like YAML rules loaded from `rules/yaml/`

The project still runs locally with the current app entrypoint, but it is now organized to support a more professional Agent + Server model.

## Quick Start

### 1. Local server

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python app.py
```

Open:

- Dashboard: `http://127.0.0.1:5000`
- Demo flow: `http://127.0.0.1:5000/demo`
- Health check: `http://127.0.0.1:5000/api/health`

### 2. Run the modular endpoint agent

Use an admin token from `.netguard_token` or a tenant token (`ng_...`) as the bootstrap credential:

```bash
python -m netguard_agent \
  --hub http://127.0.0.1:5000 \
  --token YOUR_BOOTSTRAP_TOKEN \
  --host-id lab-win-01 \
  --mode xdr
```

You can also reuse an issued host key:

```bash
python -m netguard_agent \
  --hub http://127.0.0.1:5000 \
  --agent-key nga_ISSUED_HOST_KEY \
  --host-id lab-win-01 \
  --mode xdr
```

## Operating Modes

| Mode | Storage | Auth posture | Typical use |
|------|---------|--------------|-------------|
| Local dev | SQLite | `IDS_AUTH=false` on loopback only | Fast desktop iteration |
| Demo / preview | SQLite | Token or preview flow | Portfolio demos and customer preview |
| Production | PostgreSQL recommended | `IDS_AUTH=true`, dashboard auth, reverse proxy/TLS | VPS, cloud, small SaaS deployment |

Important hardening already enforced:

- `TOKEN_SIGNING_SECRET` is mandatory outside `dev/test`
- Startup fails closed if `IDS_AUTH=false` is exposed outside loopback unless explicitly bypassed
- Admin rate limiting uses shared SQLite storage per host
- Audit logs rotate and retain automatically
- Background jobs do not autostart on import in WSGI/Gunicorn mode

## Architecture

See the full architecture note in [NETGUARD_AGENT_SERVER_ARCHITECTURE.md](NETGUARD_AGENT_SERVER_ARCHITECTURE.md).

High-level flow:

```text
netguard_agent / external producers
        |
        +--> POST /api/agent/register
        +--> POST /api/agent/heartbeat
        +--> POST /api/agent/events
        +--> POST /api/xdr/events
                    |
                    v
             XDR pipeline
     normalize -> detect -> correlate
        -> score host -> persist events
        -> create response actions
        -> feed incidents / SOC views
                    |
                    v
     repositories (SQLite local, PostgreSQL-ready)
        - EventRepository
        - HostRepository
        - IncidentRepository
                    |
                    v
      SOC dashboard + incidents + reporting APIs
```

Core building blocks:

- `netguard_agent/`: modular endpoint collector and transport runtime
- `server/agent_service.py`: host enrollment and agent auth rules
- `storage/event_repository.py`: event/tenant storage abstraction
- `storage/host_repository.py`: enrolled host registry and API key validation
- `storage/incident_repository.py`: incident lifecycle persistence
- `engine/incident_engine.py`: incident business logic
- `rules/yaml_loader.py`: Sigma-like YAML rule loading and validation
- `xdr/`: endpoint schema, detections, pipeline, and agent-side transport helpers

## Authentication and Authorization

NetGuard now supports multiple access models:

- Admin token from `.netguard_token`
- Tenant tokens (`ng_...`) stored in the repository
- Host API keys (`nga_...`) for enrolled agents

RBAC is enforced across sensitive flows:

- `admin`: full platform access
- `analyst`: operational access to incidents, hosts, and agent enrollment
- `viewer`: read-oriented access, no host enrollment or incident mutation

Sensitive actions emit audit entries, and incident changes are timeline-backed.

## Detection and Rule Model

The project now supports two complementary rule layers:

- Built-in behavioral/XDR detections in `xdr/detections/`
- Folder-backed YAML rules in `rules/yaml/`

Included YAML examples:

- `rules/yaml/suspicious_powershell.yml`
- `rules/yaml/bruteforce.yml`
- `rules/yaml/port_scan.yml`

These rules support:

- field matching (`equals`, `contains`, `regex`, numeric comparisons)
- `all` / `any` matching blocks
- simple aggregation windows (`count`, `within_seconds`, `group_by`, `distinct_field`)

## Main Endpoints

### Agent and ingest

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/agent/register` | `POST` | Enroll a host and issue a host API key |
| `/api/agent/heartbeat` | `POST` | Update host liveness, version, and metadata |
| `/api/agent/events` | `POST` | Ingest agent events using host key or token |
| `/api/xdr/events` | `POST` | Generic structured endpoint event ingest |
| `/api/agent/status` | `GET` | Agent inventory status view |

### Incidents and SOC

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/incidents` | `GET` | List incidents and summary stats |
| `/api/incidents` | `POST` | Create incident manually or from `event_id` |
| `/api/incidents/<id>` | `GET` | Incident details and timeline |
| `/api/incidents/<id>/status` | `PATCH` | Update status (`open`, `investigating`, `resolved`, etc.) |
| `/api/incidents/<id>/severity` | `PATCH` | Update severity |
| `/api/incidents/<id>/comments` | `POST` | Add analyst comment |
| `/api/incidents/<id>/assign` | `POST` | Assign an owner |
| `/soc-preview` | `GET` | Public preview of the SOC experience |
| `/soc/incidents` | `GET` | Authenticated incidents queue |

### Platform

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/health` | `GET` | Health and subsystem status |
| `/api/hosts` | `GET` | Host-centric inventory, risk, and telemetry summary |
| `/metrics` | `GET` | Prometheus metrics |
| `/demo` | `GET` | Demo bootstrap flow |
| `/trial/<token>` | `GET` | Trial access flow |

## Storage Strategy

NetGuard keeps SQLite as the default local/demo backend, but the storage layer is now structured so production can move to PostgreSQL without rewriting business logic.

Current repository abstractions:

- `EventRepository`: events, tenants, onboarding artifacts
- `HostRepository`: managed hosts, API key hashes, heartbeat metadata
- `IncidentRepository`: incidents and incident timeline records

This makes it easier to:

- keep desktop demos frictionless
- move SaaS or VPS installs to PostgreSQL
- write tests against business logic without coupling every feature to `app.py`

## Testing

Run the focused regression suite for the new architecture:

```bash
python -m pytest \
  tests/test_agent.py \
  tests/test_agent_xdr.py \
  tests/test_xdr_pipeline.py \
  tests/test_agent_server.py \
  tests/test_incident_engine.py \
  tests/test_incidents_api.py \
  tests/test_yaml_rules.py \
  tests/test_api_endpoints.py \
  tests/test_integration.py \
  tests/test_security.py -q
```

The new coverage adds checks for:

- agent registration, heartbeat, and event ingest
- agent RBAC enforcement
- incident engine lifecycle and grouped EDR alerts
- incident API create/update/comment flows
- YAML rule loading and aggregation behavior

## Production and Ops Docs

- [DEPLOY.md](DEPLOY.md): deployment patterns and production checklist
- [SECURITY.md](SECURITY.md): hardening notes and security posture
- [NETGUARD_AGENT_SERVER_ARCHITECTURE.md](NETGUARD_AGENT_SERVER_ARCHITECTURE.md): Agent + Server architecture
- [DOCKER.md](DOCKER.md): containerized execution

## Realistic Roadmap

- [x] Agent + Server foundation with host enrollment and structured endpoint ingest
- [x] Incident API with severity, status, assignment, and comments
- [x] YAML rule loader with bundled examples
- [x] Repository abstraction for hosts and incidents
- [ ] Database migrations for production upgrades
- [ ] Persistent host-key storage/rotation workflow for unattended agents
- [ ] Agent packaging as service/daemon for Windows and Linux
- [ ] Response actions executed by the endpoint agent, not only suggested by the server
- [ ] Redis/shared cache options for multi-node production topologies
- [ ] Tenant-scoped API tokens with narrower operational scopes

## License

MIT © Raphael Guterres
