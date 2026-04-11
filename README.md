<div align="center">

```
███╗   ██╗███████╗████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
████╗  ██║██╔════╝╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██╔██╗ ██║█████╗     ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██║╚██╗██║██╔══╝     ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
██║ ╚████║███████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
```

**NetGuard IDS v3.0** — Real-time SOC/SIEM platform built in Python

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![Architecture](https://img.shields.io/badge/Architecture-Event--Driven-green)]()
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Aligned-red)](https://attack.mitre.org)
[![CI](https://github.com/raphaelguterres/netguard-ids/actions/workflows/tests.yml/badge.svg)](https://github.com/raphaelguterres/netguard-ids/actions/workflows/tests.yml)
[![License](https://img.shields.io/badge/License-MIT-lightgrey)]()
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker)](DOCKER.md)

</div>

---

## Quick Start

### One-liner installers

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/raphaelguterres/netguard-ids/main/install.ps1 | iex
```

**Linux / macOS:**
```bash
curl -fsSL https://raw.githubusercontent.com/raphaelguterres/netguard-ids/main/install.sh | bash
```

### Docker
```bash
git clone https://github.com/raphaelguterres/netguard-ids.git
cd netguard-ids
docker build -t netguard-ids .
docker run -d --name netguard --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v netguard_data:/data -p 5000:5000 netguard-ids
```

Dashboard: **http://localhost:5000** · [Full Docker Guide](DOCKER.md)

### Manual (Windows / Linux / macOS)
```bash
git clone https://github.com/raphaelguterres/netguard-ids.git
cd netguard-ids
python -m venv venv
source venv/bin/activate         # Windows: .\venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

---

## What is NetGuard?

NetGuard is a fully functional **Security Operations Center (SOC)** platform that runs locally and monitors your system in real time. It captures live network connections, detects process anomalies, correlates multi-event attack patterns, fires webhook alerts to Slack / Teams / Telegram / WhatsApp, and displays everything in a professional dark-mode dashboard — no cloud, no agents, no subscriptions.

Architecturally it implements the same concepts used by enterprise tools like **Elastic SIEM**, **Splunk**, **Wazuh**, and **CrowdStrike Falcon** — at a fraction of the cost and zero vendor lock-in.

---

## Architecture

```
Raw Data Sources
├── Network connections (netstat / psutil)
├── Processes (psutil)
├── Ports / Connections (platform_utils)
└── Web Payloads (OWASP CRS)
        │
        ▼
  Event Pipeline
  ┌──────────────────────────────────────────────────────────┐
  │  normalize → validate → enrich → run_rules               │
  │  → classify_severity → generate_alerts                   │
  │  → persist → dispatch_webhooks → return                  │
  └──────────────────────────────────────────────────────────┘
        │
        ├─▶  SOC Engine          (12 behavioral rules, MITRE aligned)
        ├─▶  Correlation Engine  (5 multi-event patterns)
        ├─▶  Risk Engine         (0–100 host score, CrowdStrike-style)
        ├─▶  Kill Chain          (MITRE ATT&CK progression)
        ├─▶  Webhook Engine      (Slack / Teams / Discord / Telegram / WhatsApp)
        ├─▶  IOC Manager         (custom + ThreatFox feed)
        ├─▶  ML Anomaly          (Isolation Forest)
        ├─▶  Fail2Ban            (auto-block on threshold)
        └─▶  SQLite Storage      (netguard_soc.db)
```

---

## Feature Matrix

| Feature | Free | Pro | Enterprise |
|---------|:----:|:---:|:----------:|
| Real-time SOC dashboard | ✓ | ✓ | ✓ |
| IDS detection (22 rules) | ✓ | ✓ | ✓ |
| Correlation engine (5 patterns) | ✓ | ✓ | ✓ |
| Kill Chain / MITRE ATT&CK | ✓ | ✓ | ✓ |
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
| COR-3 | Periodic connections to same external IP (low jitter CV) | T1071.001 — C2 |
| COR-4 | Process accessing 3+ internal IPs in 5 minutes | T1021 — Lateral Movement |
| COR-5 | 5+ auth attempts from same IP in 2 minutes | T1110 — Brute Force |

---

## Webhook Alerts

NetGuard fires real-time alerts to any of these channels. Configure via API — no restart required.

| Channel | Type token |
|---------|-----------|
| 🟩 Slack | `slack` |
| 🔵 Microsoft Teams | `teams` |
| 🎮 Discord | `discord` |
| 📱 Telegram | `telegram` |
| 💬 WhatsApp (Z-API) | `whatsapp` |
| 💬 WhatsApp (Twilio) | `whatsapp` |
| 🌐 Generic HTTP POST | `generic` |

```bash
# Register a Telegram webhook
curl -X POST http://localhost:5000/api/webhooks \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Telegram SOC",
    "type": "telegram",
    "url": "https://api.telegram.org/botTOKEN/sendMessage",
    "secret": "CHAT_ID",
    "min_severity": "high"
  }'

# Test it immediately
curl -X POST http://localhost:5000/api/webhooks/1/test \
  -H "X-API-Key: YOUR_KEY"
```

See [ALERTAS_NOTIFICACOES.md](ALERTAS_NOTIFICACOES.md) for full per-channel setup guides.

---

## Trial Token System

Share a time-limited, branded demo with potential clients — each gets a unique URL with a live countdown and isolated demo data.

```bash
# Create a 72-hour trial for a client
curl -X POST http://localhost:5000/api/admin/trials \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "cto@acme.com",
    "name": "Alice",
    "company": "Acme Corp",
    "duration_h": 72
  }'

# Returns:
# { "token": "ng_trial_...", "url": "http://your-server/trial/ng_trial_..." }
```

The trial dashboard shows a live countdown banner. When time expires, an upgrade CTA page appears automatically.

---

## API Reference

The server exposes 50+ REST endpoints at `http://localhost:5000`.

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Server health (opaque errors with `request_id`) |
| `GET /api/detections` | IDS detections (tenant-scoped) |
| `GET /api/soc/events` | SOC Engine events |
| `GET /api/soc/stats` | SOC Engine statistics |
| `GET /api/correlation/alerts` | Correlation Engine alerts |
| `GET /api/risk/hosts` | All hosts risk scores (0–100) |
| `GET /api/risk/report/<host>` | Full risk report for a host |
| `GET /api/killchain/incidents` | Kill chain incidents |
| `GET /api/fail2ban/status` | Fail2Ban jail status |
| `GET /api/connections` | Active network connections |
| `GET /api/processes` | Running processes |
| `GET /api/devices` | Local network devices |
| `GET /api/geo` | GeoIP map (async, stale-while-revalidate) |
| `GET /api/graph` | Connection graph (async, stale-while-revalidate) |
| `GET /api/system` | CPU / RAM / disk stats |
| `GET /api/ioc` | IOC list (tenant-scoped) |
| `POST /api/ioc` | Add IOC |
| `GET /api/webhooks` | List configured webhooks |
| `POST /api/webhooks` | Add webhook |
| `POST /api/webhooks/<id>/test` | Fire test alert |
| `POST /api/admin/trials` | Create trial token |
| `GET /api/admin/trials` | List all trials |
| `POST /api/admin/trials/<token>/revoke` | Revoke trial |
| `POST /api/admin/trials/<token>/extend` | Extend trial |
| `GET /metrics` | Prometheus exposition format |
| `GET /api/stream` | Server-Sent Events (live feed) |
| `GET /demo` | Demo mode (no login required) |
| `GET /trial/<token>` | Time-limited trial dashboard |

---

## Performance

Both `/api/graph` and `/api/geo` use a **stale-while-revalidate** cache pattern:

- Fresh window (30s graph / 60s geo): served from memory, zero I/O
- Stale window (2min graph / 5min geo): served from memory immediately, background thread silently refreshes
- First request (cold): computed synchronously, result cached for all future requests

DNS reverse lookups (`socket.gethostbyaddr`) run in a dedicated 6-worker thread pool and never block the request thread. Hostnames appear on the second request cycle.

---

## Running Tests

```bash
pip install pytest pytest-cov
pytest tests/ -v --tb=short

# With coverage
pytest tests/ --cov=engine --cov=rules --cov-report=term-missing --cov-fail-under=40
```

| Test file | Module covered |
|-----------|---------------|
| `test_severity_classifier.py` | `engine/severity_classifier.py` |
| `test_baseline_engine.py` | `engine/baseline_engine.py` |
| `test_rule_executor.py` | `engine/rule_executor.py` |
| `test_correlation_engine.py` | `engine/correlation_engine.py` |
| `test_web_rules.py` | `rules/web_rules.py` |
| `test_risk_engine.py` | `engine/risk_engine.py` |
| `test_trial_engine.py` | `engine/trial_engine.py` |
| `test_api_endpoints.py` | `/api/health`, `/api/graph`, `/api/geo`, compliance |

---

## Project Structure

```
PROJETO SOC/
├── app.py                    # Flask server — 50+ API endpoints
├── dashboard.html            # 14-tab SOC dashboard (single file)
├── landing.html              # Product landing page
├── netguard.py               # pywebview launcher (native window)
├── platform_utils.py         # Cross-platform OS abstraction layer
├── soc_engine.py             # SOC Engine — 12 behavioral rules
├── ids_engine.py             # IDS Engine — 22 signature rules
├── packet_capture.py         # Scapy real-time packet capture
├── killchain.py              # MITRE ATT&CK Kill Chain correlator
├── fail2ban_engine.py        # Auto-block engine (6 jails)
├── sigma_rules.py            # 40 Sigma detection rules
├── owasp_engine.py           # OWASP CRS + ASVS rules
├── geo_ip.py                 # Embedded GeoIP database
├── threat_feeds.py           # ThreatFox + AbuseIPDB integration
├── demo_seed.py              # Demo/trial data seeder
├── install.ps1               # Windows one-click installer
├── install.sh                # Linux/macOS one-click installer
│
├── engine/
│   ├── event_engine.py       # Main pipeline orchestrator
│   ├── rule_executor.py      # Safe rule execution pipeline
│   ├── severity_classifier.py # Severity classification logic
│   ├── baseline_engine.py    # In-memory baseline tracking
│   ├── correlation_engine.py # Multi-event pattern detection
│   ├── risk_engine.py        # Per-host risk score (0-100)
│   ├── webhook_engine.py     # Multi-channel alert dispatcher
│   ├── trial_engine.py       # Time-limited trial token system
│   ├── threat_hunter.py      # Advanced threat hunting
│   ├── lateral_movement.py   # Lateral movement detector
│   ├── honeypot.py           # Honeypot trap
│   ├── dns_monitor.py        # DNS anomaly monitoring
│   ├── enrichment.py         # IP enrichment (Shodan + WHOIS)
│   └── yara_engine.py        # YARA rule matching
│
├── rules/
│   ├── process_rules.py      # 7 process detection rules
│   ├── network_rules.py      # 6 network detection rules
│   └── web_rules.py          # 6 web detection rules (SQLi, XSS…)
│
├── models/
│   └── event_model.py        # Event and Alert data models
│
├── storage/
│   └── event_repository.py   # SQLite storage layer
│
├── tests/
│   ├── test_severity_classifier.py
│   ├── test_baseline_engine.py
│   ├── test_rule_executor.py
│   ├── test_correlation_engine.py
│   ├── test_web_rules.py
│   ├── test_risk_engine.py
│   ├── test_trial_engine.py
│   └── test_api_endpoints.py
│
└── .github/workflows/
    └── tests.yml             # CI: tests + lint + pip-audit + mypy
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `IDS_AUTH` | `true` | Enable API key authentication |
| `IDS_DASHBOARD_AUTH` | `true` | Protect dashboard with auth |
| `IDS_API_KEY` | auto-generated | Master API key (shown at startup) |
| `IDS_HTTPS` | `false` | Enable HTTPS (self-signed cert) |
| `HTTPS_ONLY` | `false` | Redirect HTTP → HTTPS |
| `IDS_ABUSEIPDB_KEY` | — | AbuseIPDB API key (free tier: 1000/day) |
| `IDS_RATE_LIMIT` | `true` | Enable Flask-Limiter rate limiting |
| `SMTP_HOST` | — | SMTP server (e.g. `smtp.resend.com`) |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USER` / `SMTP_PASS` | — | SMTP credentials |
| `SMTP_FROM` | same as USER | Sender address |
| `APP_URL` | `http://localhost:5000` | Public URL (used in emails/trials) |

---

## Technical Highlights

- **Event pipeline** inspired by Elastic ECS and MITRE CAR — normalize → enrich → correlate → dispatch
- **Correlation engine** uses sliding time windows and statistical methods (coefficient of variation for beaconing)
- **Risk Score** implements temporal decay (half-life 6h) and MITRE tactic weighting — same concept as CrowdStrike Falcon
- **Stale-while-revalidate cache** on heavy endpoints — zero-latency responses after warm-up
- **Non-blocking DNS** — `socket.gethostbyaddr` runs in a thread pool, never stalls request threads
- **Thread-safe throughout** — multiple monitoring threads share state via RLock + threading.Lock
- **Opaque error responses** — no tracebacks in HTTP bodies, all errors carry `request_id` for log correlation
- **Zero external dependencies** for core detection — runs fully offline

---

## Roadmap

- [x] Docker support + one-click installers (Windows & Linux)
- [x] GitHub Actions CI (tests + lint + pip-audit + type check)
- [x] Token authentication (`IDS_AUTH=true`)
- [x] Rate limiting (Flask-Limiter) + security headers (CSP, HSTS)
- [x] Webhook alerts (Slack, Teams, Discord, Telegram, WhatsApp)
- [x] IOC Manager with ThreatFox feed
- [x] ML Anomaly Detection (Isolation Forest)
- [x] Compliance PDF reports (SOC2 / PCI / HIPAA)
- [x] Time-limited trial token system
- [x] Async stale-while-revalidate cache for graph & geo
- [ ] Distributed agents (multi-machine monitoring)
- [ ] Automatic IP blocking by risk score threshold
- [ ] SAML / SSO authentication

---

## License

MIT License — free to use, modify, and distribute.

---

<div align="center">
Built with Python · Real network data · No cloud required
</div>
