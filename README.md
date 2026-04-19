<div align="center">

```
███╗   ██╗███████╗████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
████╗  ██║██╔════╝╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██╔██╗ ██║█████╗     ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██║╚██╗██║██╔══╝     ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
██║ ╚████║███████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
```

**NetGuard IDS** — Host-centric detection and response platform built in Python,  
with local-first telemetry, correlation engine, risk scoring and incident workflow.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![Architecture](https://img.shields.io/badge/Architecture-Host--Centric%20EDR-green)]()
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Aligned-red)](https://attack.mitre.org)
[![CI](https://github.com/raphaelguterres/netguard-ids/actions/workflows/tests.yml/badge.svg)](https://github.com/raphaelguterres/netguard-ids/actions/workflows/tests.yml)
[![License](https://img.shields.io/badge/License-MIT-lightgrey)]()
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker)](DOCKER.md)

</div>

---

## Quick Start

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/raphaelguterres/netguard-ids/main/install.ps1 | iex
```

**Linux / macOS:**
```bash
curl -fsSL https://raw.githubusercontent.com/raphaelguterres/netguard-ids/main/install.sh | bash
```

**Docker:**
```bash
docker run -d --name netguard --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v netguard_data:/data -p 5000:5000 \
  ghcr.io/raphaelguterres/netguard-ids:latest
```

Dashboard: **http://localhost:5000** · [Full Docker Guide](DOCKER.md)

---

## What is NetGuard?

NetGuard is a **host-centric detection and response** platform that runs locally and monitors your endpoints in real time. It ships a lightweight endpoint agent (`agent.py`, in progress), captures live process trees and network connections, correlates multi-event attack patterns, fires webhook alerts to Slack / Teams / Telegram, and displays everything in a professional dark-mode SOC dashboard — no cloud required, no vendor lock-in.

Architecturally it implements the same primitives used by **CrowdStrike Falcon**, **Elastic EDR** and **Wazuh** — behavioral scoring per host, MITRE ATT&CK kill-chain correlation, ML-based anomaly detection — at a fraction of the cost.

**Core philosophy:** every alert, risk score and incident is anchored to a specific host. The dashboard is host-first, not alert-first.

---

## Architecture

```
Endpoint Telemetry
├── Process tree (psutil / agent.py)
├── Network connections (netstat / psutil)
├── Open ports (platform_utils)
├── Windows Event Log (win32evtlog)
└── Web request payloads (OWASP CRS)
        │
        ▼
  Detection Pipeline
  ┌──────────────────────────────────────────────────────────┐
  │  normalize → enrich → run_rules → classify_severity      │
  │  → persist → correlate → score_host → dispatch_webhooks  │
  └──────────────────────────────────────────────────────────┘
        │
        ├─▶  SOC Engine          (12 behavioral rules, MITRE-aligned)
        ├─▶  Correlation Engine  (5 multi-event patterns)
        ├─▶  Risk Engine         (0–100 host score, updated in real time)
        ├─▶  Kill Chain          (MITRE ATT&CK tactic/technique tracker)
        ├─▶  EDR Sentinel        (process behavioral scoring, auto-response)
        ├─▶  Incident Engine     (auto-groups related alerts into incidents)
        ├─▶  IOC Manager         (IP / domain / hash blacklists + hit tracking)
        ├─▶  ML Anomaly          (Isolation Forest, 10-feature hourly windows)
        ├─▶  Webhook Engine      (Slack / Teams / Discord / Telegram / WhatsApp)
        ├─▶  Fail2Ban            (auto-block on threshold breach)
        └─▶  SQLite Storage      (WAL mode, multi-tenant, local-first)

Lightweight endpoint agent (in progress — agent.py):
        ├─▶  Reports heartbeat, process list and open connections to server
        └─▶  Enables multi-host visibility from a single dashboard
```

---

## Feature Matrix

| Feature | Free | Pro | Enterprise |
|---------|:----:|:---:|:----------:|
| Real-time SOC dashboard | ✓ | ✓ | ✓ |
| Host-centric view (risk, timeline, MITRE) | ✓ | ✓ | ✓ |
| IDS detection (22 rules) | ✓ | ✓ | ✓ |
| Correlation engine (5 patterns) | ✓ | ✓ | ✓ |
| Kill Chain / MITRE ATT&CK | ✓ | ✓ | ✓ |
| EDR Sentinel (process scoring) | ✓ | ✓ | ✓ |
| Incident auto-grouping | ✓ | ✓ | ✓ |
| GeoIP world map | ✓ | ✓ | ✓ |
| Fail2Ban auto-block | ✓ | ✓ | ✓ |
| Webhook alerts (Slack/Teams/Telegram…) | ✓ | ✓ | ✓ |
| IOC Manager | — | ✓ | ✓ |
| Custom detection rules | — | ✓ | ✓ |
| ML Anomaly Detection | — | ✓ | ✓ |
| Risk Score (per-host 0–100) | — | ✓ | ✓ |
| Compliance PDF (SOC2/PCI/HIPAA) | — | — | ✓ |
| Multi-tenant / MSSP mode | — | — | ✓ |
| Time-limited trial tokens | — | — | ✓ |
| Lightweight endpoint agent (in progress) | — | ✓ | ✓ |

---

## Detection Rules

### SOC Engine (12 Rules)

| Rule | Type | Severity | Trigger |
|------|------|----------|---------|
| R1 | process_unknown | MEDIUM | Process not in baseline |
| R2 | process_high_cpu | HIGH | CPU > 80% for 30s |
| R3 | port_opened | HIGH | Well-known port opened by suspicious process |
| R4 | network_spike | HIGH | 50+ connections in 10s |
| R5 | network_scan | HIGH | 20+ unique IPs in 30s |
| R6 | process_external_conn | MEDIUM | Unknown process with external connection |
| R7 | port_new_listen | MEDIUM | New port in LISTEN state |
| R8 | ip_new_external | LOW | External IP never seen before |
| R9 | behavior_deviation | MEDIUM | z-score > 2.5 deviation from baseline |
| R10 | web_sqli | HIGH | SQL Injection pattern match |
| R11 | web_xss | HIGH | XSS pattern match |
| R12 | web_suspicious_ua | MEDIUM | Scanner/tool User-Agent detected |

### Correlation Engine (5 Patterns)

| Rule | Pattern | MITRE |
|------|---------|-------|
| COR-1 | Unknown process + high CPU + external connection | T1059 — Execution |
| COR-2 | Multiple new IPs + port scan + suspicious DNS | T1595 — Reconnaissance |
| COR-3 | Periodic connections to same external IP (low CV) | T1071.001 — C2 |
| COR-4 | Process accessing 3+ internal IPs in 5 minutes | T1021 — Lateral Movement |
| COR-5 | 5+ auth attempts from same IP in 2 minutes | T1110 — Brute Force |

---

## Webhook Alerts

Configure real-time alerts with no restart required.

| Channel | Type |
|---------|------|
| 🟩 Slack | `slack` |
| 🔵 Microsoft Teams | `teams` |
| 🎮 Discord | `discord` |
| 📱 Telegram | `telegram` |
| 💬 WhatsApp (Z-API / Twilio) | `whatsapp` |
| 🌐 Generic HTTP POST | `generic` |

```bash
# Register a Slack webhook (min severity: high)
curl -X POST http://localhost:5000/api/webhooks \
  -H "Content-Type: application/json" \
  -d '{"name":"Slack SOC","type":"slack","url":"https://hooks.slack.com/...","min_severity":"high"}'

# Fire a test alert immediately
curl -X POST http://localhost:5000/api/webhooks/1/test
```

---

## Trial Token System

Share a time-limited, branded demo with potential clients — unique URL, live countdown, isolated demo data.

```bash
# Create a 72-hour trial for a prospect
curl -X POST http://localhost:5000/api/admin/trials \
  -H "Content-Type: application/json" \
  -d '{"email":"cto@acme.com","name":"Alice","company":"Acme Corp","duration_h":72}'

# Returns trial URL → send to client via email or WhatsApp
# { "trial_url": "http://your-server/trial/ng_trial_..." }
```

When the trial expires, the client sees an upgrade CTA page automatically.

---

## API Reference

50+ REST endpoints at `http://localhost:5000`.

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Server health + subsystem status |
| `GET /api/hosts` | All hosts — risk, MITRE, last heartbeat |
| `GET /api/hosts/<host>/timeline` | Per-host event timeline |
| `GET /api/detections` | IDS detections |
| `GET /api/soc/events` | SOC Engine events |
| `GET /api/risk/hosts` | Host risk scores (0–100) |
| `GET /api/killchain/incidents` | Kill chain incidents |
| `GET /api/ioc` | IOC blacklist |
| `POST /api/ioc/check` | Check IP/domain/hash against IOC list |
| `GET /api/ml/anomaly/status` | ML anomaly engine status |
| `GET /api/webhooks` | Configured webhooks |
| `POST /api/webhooks/<id>/test` | Fire test alert |
| `POST /api/admin/trials` | Create client trial token |
| `GET /api/admin/trials` | List all trials + access stats |
| `GET /metrics` | Prometheus metrics |
| `GET /demo` | Instant demo (no login) |
| `GET /trial/<token>` | Time-limited client trial |

---

## Roadmap

- [ ] Multi-host agent (`agent.py`) — heartbeat, process list, network telemetry
- [ ] Host detail page — per-host process tree, connection timeline, MITRE heatmap
- [ ] YARA rule scanning on running processes
- [ ] Sigma rule hot-reload from directory
- [ ] Postgres backend option (alongside SQLite)
- [ ] REST API token scoping per tenant

---

## License

MIT © 2024 Raphael Guterres
