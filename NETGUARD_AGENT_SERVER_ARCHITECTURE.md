# NetGuard Agent + Server Architecture

## Goal

This document describes the current NetGuard runtime shape after the move from a local IDS dashboard toward a lightweight EDR/SIEM architecture.

The design goal is pragmatic:

- keep local execution simple
- preserve compatibility with the current Flask app
- allow a real endpoint agent to report into a central server
- keep the codebase evolvable toward production SaaS

## High-Level Topology

```text
+-------------------+        HTTPS / HTTP        +---------------------------+
| agent / agent.exe | -------------------------> | Flask server / API        |
| Windows endpoint  |                            | app.py + server/api.py    |
+-------------------+                            +---------------------------+
         |                                                   |
         | collect snapshot                                   |
         v                                                   v
+-------------------+                            +---------------------------+
| process list      |                            | AgentService              |
| network sessions  |                            | HostRepository            |
| ports             |                            | EventRepository           |
| system load       |                            | IncidentRepository        |
+-------------------+                            +---------------------------+
                                                             |
                                                             v
                                                  +---------------------------+
                                                  | XDR pipeline              |
                                                  | detections                |
                                                  | correlations              |
                                                  | risk scoring              |
                                                  +---------------------------+
                                                             |
                                                             v
                                                  +---------------------------+
                                                  | SOC dashboard             |
                                                  | incidents API             |
                                                  | metrics / reporting       |
                                                  +---------------------------+
```

## Main Components

### Agent runtime

Relevant files:

- `agent/agent.py`
- `agent/collector.py`
- `agent/sender.py`
- `agent/service.py`
- `agent/build_agent.ps1`
- `agent/README_AGENT.md`
- `netguard_agent/` (legacy/compatibility runtime kept for older flows)

Current capabilities:

- collect local process, port, connection, and system snapshot data
- send canonical EDR batches to `/api/events`
- keep compatibility with legacy structured ingest via `/api/agent/events`
- bootstrap with an admin or tenant token
- bootstrap with a short-lived enrollment token (`nge_...`)
- authenticate steady-state with a host API key (`nga_...`)
- persist the issued host key in a local credential store for unattended restarts
- buffer outbound events locally when the server is temporarily unavailable
- poll `/api/agent/actions` and ACK response actions after local execution/refusal
- run as `python -m agent` or as `agent.exe` / Windows service

### Server/API

Relevant files:

- `app.py`
- `server/api.py`
- `server/agent_service.py`
- `auth.py`
- `security.py`

Current capabilities:

- canonical ingest via `/api/events`
- host enrollment via `/api/agent/register`
- liveness updates via `/api/agent/heartbeat`
- structured ingest via `/api/agent/events`
- response action queue via `/api/agent/hosts/<host_id>/actions`
- action lease/ACK via `/api/agent/actions` and `/api/agent/actions/<id>/ack`
- generic endpoint event ingest via `/api/xdr/events`
- RBAC-aware authorization for admin, analyst, viewer
- audit logging of sensitive actions
- safe startup rules for local vs exposed environments
- integrated read-only SOC grid at `/soc/grid`

### Storage layer

Relevant files:

- `storage/event_repository.py`
- `storage/host_repository.py`
- `storage/incident_repository.py`

Design intent:

- SQLite remains the default local and demo backend
- repository APIs are written so PostgreSQL can be used in production
- business logic does not need to know whether the backend is SQLite or PostgreSQL

### Detection and response

Relevant files:

- `xdr/pipeline.py`
- `xdr/detections/`
- `rules/yaml_loader.py`
- `rules/yaml/`
- `engine/incident_engine.py`

Current capabilities:

- built-in behavior detections
- correlation logic
- per-host risk scoring
- Sigma-like YAML rule loading
- incident creation, severity/status changes, assignment, comments

## Enrollment and Auth Flow

### Bootstrap

The agent starts with one of:

- admin token from `.netguard_token`
- tenant token (`ng_...`)
- short-lived enrollment token (`nge_...`)
- previously issued host key (`nga_...`)

### Enrollment sequence

```text
1. Admin/analyst creates POST /api/agent/enrollment-token
2. Server stores only the enrollment token hash, tenant scope, expiry, and max uses
3. Agent sends POST /api/agent/register with the `nge_...` token
4. Server consumes the token, stores host metadata and host API key hash
5. Server returns one issued `nga_...` host key
6. Agent stores the host key locally and uses it for heartbeat and event ingest
```

### Steady-state ingest

```text
1. Agent sends heartbeat and/or event batch
2. Server validates `X-API-Key` (and also accepts `X-NetGuard-Agent-Key` for compatibility)
3. HostRepository updates last_seen / last_event_at
4. XDR pipeline processes events
5. EventRepository persists security events
6. IncidentEngine and dashboard views consume persisted data
```

## Data Model Overview

### Managed hosts

Stored in `managed_hosts`:

- `tenant_id`
- `host_id`
- `display_name`
- `api_key_hash`
- `agent_version`
- `platform`
- `status`
- `last_seen`
- `last_event_at`
- `metadata`
- `tags`

### Events

Stored through `EventRepository`:

- normalized security events
- tenant metadata
- tags, MITRE details, raw payload reference

### Incidents

Stored in `incidents` and `incident_timeline`:

- severity
- status
- source and host
- linked `event_ids`
- comments and timeline entries
- owner / assignee

## Running Modes

### Local desktop

- SQLite
- loopback bind
- fast iteration
- suitable for demos and single-operator lab use
- `agent/` can run with `config.yaml` pointing to `http://127.0.0.1:5000/api/events`

### Central lab server

- SQLite or PostgreSQL
- one central Flask app
- multiple enrolled hosts sending events
- useful for portfolio demos and proof-of-concept deployments

### Production

- PostgreSQL recommended
- reverse proxy / TLS
- `IDS_AUTH=true`
- background jobs explicitly controlled
- audit log rotation and retention enabled

## Current Strengths

- backward-compatible with the existing Flask-first application
- supports both local-first and central-server workflows
- separates host registry, incidents, and event persistence
- adds realistic SaaS/security concepts without overcomplicating the repo

## Current Gaps

These are intentional next-step items, not hidden assumptions:

- destructive response actions are refused by default until signed policy controls exist
- database migrations are not formalized
- multi-node shared cache patterns are still future work

## Recommended Next Iteration

1. Add migration tooling for repositories and schema changes.
2. Add signed policy controls for destructive actions such as isolation, process kill, and IP block.
3. Add service wrappers for Linux agent deployment.
4. Add central policy distribution for collection interval, tags, and collector toggles.
5. Add Redis/shared cache support for rate limits and multi-node API deployments.
