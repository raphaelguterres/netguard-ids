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
| netguard_agent    | -------------------------> | Flask server / API        |
| legacy or xdr     |                            | app.py                    |
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

- `netguard_agent/service.py`
- `netguard_agent/collector.py`
- `xdr/agent/client.py`
- `xdr/agent/service.py`
- `xdr/agent/buffer.py`
- `agent.py` (compatibility wrapper)

Current capabilities:

- collect local process, port, connection, and system snapshot data
- send legacy snapshot payloads to `/api/agent/push`
- send structured XDR events to `/api/agent/events`
- bootstrap with an admin or tenant token
- authenticate steady-state with a host API key (`nga_...`)
- buffer outbound events locally when the server is temporarily unavailable

### Server/API

Relevant files:

- `app.py`
- `server/agent_service.py`
- `auth.py`
- `security.py`

Current capabilities:

- host enrollment via `/api/agent/register`
- liveness updates via `/api/agent/heartbeat`
- structured ingest via `/api/agent/events`
- generic endpoint event ingest via `/api/xdr/events`
- RBAC-aware authorization for admin, analyst, viewer
- audit logging of sensitive actions
- safe startup rules for local vs exposed environments

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
- previously issued host key (`nga_...`)

### Enrollment sequence

```text
1. Agent sends POST /api/agent/register with bootstrap token
2. Server validates RBAC through AgentService
3. HostRepository stores host metadata and API key hash
4. Server returns one issued host key
5. Agent can use that host key for heartbeat and event ingest
```

### Steady-state ingest

```text
1. Agent sends heartbeat and/or event batch
2. Server validates X-NetGuard-Agent-Key
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

- the agent does not yet persist issued host keys on disk by itself
- response actions are generated by the server but not yet executed by the agent
- database migrations are not formalized
- multi-node shared cache patterns are still future work

## Recommended Next Iteration

1. Add migration tooling for repositories and schema changes.
2. Persist issued host keys locally in the agent runtime or config store.
3. Add optional signed enrollment tokens scoped per tenant and expiration.
4. Move from suggested response actions to server-to-agent action delivery and acknowledgement.
5. Add service wrappers for Windows and Linux agent deployment.
