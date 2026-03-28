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
[![Tests](https://img.shields.io/badge/Tests-102%20passing-brightgreen)]()
[![License](https://img.shields.io/badge/License-MIT-lightgrey)]()
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker)](DOCKER.md)

</div>

---

## Quick Start (Docker)

```bash
git clone https://github.com/raphaelguterres/netguard-ids.git
cd netguard-ids
docker build -t netguard-ids .
docker run -d --name netguard --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v netguard_data:/data -p 5000:5000 netguard-ids
```

Dashboard: **http://localhost:5000** · [Full Docker Guide](DOCKER.md)

---

## What is NetGuard?

NetGuard is a fully functional **Security Operations Center (SOC)** platform that runs locally on Windows and monitors your system in real-time. It captures real network packets, detects process anomalies, correlates multi-event attack patterns, and displays everything in a professional dark-mode dashboard — no cloud, no agents, no subscriptions.

Built as a personal cybersecurity project, it implements the same architectural concepts used by enterprise tools like **Elastic SIEM**, **Splunk**, **Wazuh**, and **CrowdStrike Falcon**.

---

## Architecture

```
Raw Data Sources
├── Network (Scapy packet capture)
├── Processes (psutil)
├── Ports / Connections
└── Web Payloads (OWASP CRS)
        │
        ▼
  Event Pipeline
  ┌─────────────────────────────────────────────────┐
  │  normalize → validate → enrich → run_rules      │
  │  → classify_severity → generate_alerts          │
  │  → persist → return                             │
  └─────────────────────────────────────────────────┘
        │
        ├─▶  SOC Engine      (12 behavioral rules)
        ├─▶  Correlation Engine  (5 multi-event patterns)
        ├─▶  Risk Engine     (0–100 host score, CrowdStrike-style)
        ├─▶  Kill Chain      (MITRE ATT&CK progression)
        ├─▶  Fail2Ban        (auto-block on threshold)
        └─▶  SQLite Storage  (netguard_soc.db)
```

---

## Features

| Module | Description |
|--------|-------------|
| **Event Engine** | 7-step pipeline: normalize → validate → enrich → run_rules → classify → generate → persist |
| **SOC Engine** | 12 behavioral rules (R1–R12), aligned to MITRE ATT&CK |
| **Correlation Engine** | 5 multi-event patterns: Suspicious Execution, Recon, C2 Beaconing, Lateral Movement, Brute Force |
| **Risk Score** | Per-host score 0–100 with temporal decay, tactic bonuses, and CrowdStrike-style risk levels |
| **Kill Chain** | Automatic MITRE ATT&CK kill chain progression tracking per IP |
| **Process Rules** | 7 rules: unknown process, high CPU, off-hours execution, PowerShell suspicious, suspicious path, shell from Office, external connection |
| **Network Rules** | 6 rules: connection spike, multi-IP scan, new LISTEN port, new external IP, beaconing (CV < 15%), suspicious DNS |
| **Web Rules** | 6 rules: SQLi (11 patterns), XSS (13 patterns), path traversal, suspicious UA, RCE/SSRF/XXE/SSTI payload, behavior deviation |
| **Packet Capture** | Real-time Scapy capture: SYN flood, port scan, ARP spoofing, DNS tunneling |
| **OWASP Engine** | OWASP CRS + ASVS + Testing Guide rules |
| **Sigma Rules** | 40 detection rules |
| **Fail2Ban** | 6 jails with Windows Firewall integration |
| **GeoIP** | Embedded IP geolocation, world map visualization |
| **Threat Intel** | ThreatFox IOC lookup, AbuseIPDB reputation score |
| **Baseline Engine** | In-memory baseline for processes, IPs, ports with storage hook |

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

## Getting Started

### Requirements

- Windows 10/11
- Python 3.10+
- Npcap (for packet capture) — [download](https://npcap.com)
- Admin privileges recommended (for Fail2Ban firewall rules)

### Installation

```powershell
# Clone or extract the project
cd "C:\Users\YourUser\PROJETO SOC"

# Create virtual environment
python -m venv venv
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run
python netguard.py
```

The dashboard opens automatically at `http://127.0.0.1:5000`.

### Optional: Threat Intelligence APIs

```powershell
# AbuseIPDB (free tier — 1000 checks/day)
$env:IDS_ABUSEIPDB_KEY = "your_key_here"

# Get key at: https://www.abuseipdb.com/register
```

---

## Running Tests

```powershell
# Install pytest
pip install pytest

# Run all tests
pytest tests/ -v

# Run specific module
pytest tests/test_correlation_engine.py -v

# Run with coverage
pip install pytest-cov
pytest tests/ --cov=engine --cov=rules --cov-report=term-missing
```

**Test coverage: 102 tests across 6 modules**

| File | Tests | Coverage |
|------|-------|----------|
| `test_severity_classifier.py` | 20 | `engine/severity_classifier.py` |
| `test_baseline_engine.py` | 17 | `engine/baseline_engine.py` |
| `test_rule_executor.py` | 20 | `engine/rule_executor.py` |
| `test_correlation_engine.py` | 14 | `engine/correlation_engine.py` |
| `test_web_rules.py` | 16 | `rules/web_rules.py` |
| `test_risk_engine.py` | 15 | `engine/risk_engine.py` |

---

## Project Structure

```
PROJETO SOC/
├── app.py                    # Flask server + 40 API endpoints
├── dashboard.html            # 12-tab SOC dashboard (single file)
├── netguard.py               # pywebview launcher (native window)
├── soc_engine.py             # SOC Engine — 12 behavioral rules
├── ids_engine.py             # IDS Engine — 22 signature rules
├── packet_capture.py         # Scapy real-time packet capture
├── killchain.py              # MITRE ATT&CK Kill Chain correlator
├── fail2ban_engine.py        # Auto-block engine (6 jails)
├── sigma_rules.py            # 40 Sigma detection rules
├── owasp_engine.py           # OWASP CRS + ASVS rules
├── geo_ip.py                 # Embedded GeoIP database
├── threat_feeds.py           # ThreatFox + AbuseIPDB integration
│
├── engine/
│   ├── event_engine.py       # Main pipeline orchestrator
│   ├── rule_executor.py      # Safe rule execution pipeline
│   ├── severity_classifier.py # Severity classification logic
│   ├── baseline_engine.py    # In-memory baseline tracking
│   ├── correlation_engine.py # Multi-event pattern detection
│   ├── risk_engine.py        # Per-host risk score (0-100)
│   └── examples.py           # Usage examples + 11 sample rules
│
├── rules/
│   ├── process_rules.py      # 7 process detection rules
│   ├── network_rules.py      # 6 network detection rules
│   └── web_rules.py          # 6 web detection rules (SQLi, XSS...)
│
├── models/
│   └── event_model.py        # Event and Alert data models
│
├── storage/
│   └── event_repository.py   # SQLite storage layer
│
└── tests/
    ├── test_severity_classifier.py
    ├── test_baseline_engine.py
    ├── test_rule_executor.py
    ├── test_correlation_engine.py
    ├── test_web_rules.py
    └── test_risk_engine.py
```

---

## API Reference

The server exposes 40+ REST endpoints at `http://127.0.0.1:5000`.

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Server health check |
| `GET /api/detections` | IDS detections |
| `GET /api/soc/events` | SOC Engine events |
| `GET /api/soc/stats` | SOC Engine statistics |
| `GET /api/correlation/alerts` | Correlation Engine alerts |
| `POST /api/correlation/demo` | Inject demo events |
| `GET /api/risk/hosts` | All hosts risk scores |
| `GET /api/risk/report/<host>` | Full risk report for host |
| `GET /api/killchain/incidents` | Kill chain incidents |
| `GET /api/fail2ban/status` | Fail2Ban status |
| `GET /api/connections` | Active network connections |
| `GET /api/processes` | Running processes |
| `GET /api/devices` | Local network devices |
| `GET /api/geo` | GeoIP data for external IPs |
| `GET /api/system` | CPU/RAM/disk stats |

---

## Adding a New Detection Rule

```python
# rules/my_rules.py
from models.event_model import make_event, Severity

def rule_detect_mimikatz(event: dict):
    """Detects Mimikatz execution patterns."""
    proc = event.get("details", {}).get("process", "").lower()
    cmdline = event.get("details", {}).get("cmdline", "").lower()

    if "mimikatz" in proc or "sekurlsa" in cmdline:
        return make_event(
            event_type      = "credential_dump",
            severity        = Severity.CRITICAL,
            source          = "agent.process",
            details         = event.get("details", {}),
            rule_id         = "CUSTOM-1",
            rule_name       = "Mimikatz Detectado",
            mitre_tactic    = "credential_access",
            mitre_technique = "T1003.001",
            tags            = ["mimikatz", "credential", "lsass"],
        )
    return None
```

Register in your engine:
```python
engine.registry.register(rule_detect_mimikatz, tags=["process", "credential"])
```

---

## Dashboard

12 monitoring tabs:

1. **Visão Geral** — Network map, IDS feed, live graph, terminal
2. **Conexões** — Active connections grouped by process
3. **⬡ Ao Vivo** — Real-time SVG network graph
4. **🌐 Geo Map** — World map of external IP connections
5. **Sistema** — CPU/RAM/disk, top processes, open ports
6. **⚔ OWASP** — OWASP CRS analysis
7. **Analisar** — Manual analysis: IDS + Sigma + OWASP
8. **Estatísticas** — Threat distribution, 24h activity
9. **⛓ Kill Chain** — MITRE ATT&CK kill chain, heatmap, timeline
10. **🚫 Fail2Ban** — Active bans, jail status, whitelist
11. **🔎 SOC Events** — SOC Engine events table with filters
12. **🔗 Correlation** — Multi-event pattern alerts with confidence rings
13. **🎯 Risk Score** — Per-host risk score, CrowdStrike-style

---

## Technical Highlights

**For interviews and portfolio:**

- **Event pipeline** inspired by Elastic ECS and MITRE CAR — normalize → enrich → correlate
- **Correlation engine** uses sliding time windows and statistical methods (coefficient of variation for beaconing detection)
- **Risk Score** implements temporal decay (half-life 6h) and MITRE tactic weighting — same concept as CrowdStrike Falcon's host score
- **Baseline engine** follows the same pattern as Wazuh's FIM — track what's normal, alert on deviations
- **Thread-safe** throughout — multiple monitoring threads share state via RLock
- **Zero external dependencies** for core detection — runs fully offline

---

## Roadmap

- [ ] Telegram alerts for HIGH/CRITICAL events
- [ ] Daily PDF report (automated at midnight)
- [ ] Docker support (`docker-compose up`)
- [ ] Distributed agents (multi-machine monitoring)
- [ ] Automatic IP blocking by risk score threshold
- [ ] VirusTotal API integration

---

## License

MIT License — free to use, modify, and distribute.

---

<div align="center">
Built with Python · Real network data · No cloud required
</div>
