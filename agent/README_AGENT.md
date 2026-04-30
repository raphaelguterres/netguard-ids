# NetGuard Endpoint Agent

Lightweight Windows / Linux endpoint agent that ships host telemetry —
processes, network connections, security indicators — to a central
NetGuard server over HTTPS.

The agent is a single Python package that runs natively (`python -m
agent`) **and** ships as a standalone Windows binary (`agent.exe`)
built with PyInstaller.

---

## Features

- **Stable host identity** — UUIDv4 persisted under `C:\ProgramData\NetGuard\host_id`
  (Windows) or `/var/lib/netguard/host_id` (Linux). Survives reboot and reinstall.
- **Delta telemetry** — only emits *new* processes / connections per cycle,
  not the full snapshot every time. Drastically reduces bandwidth.
- **Built-in security indicators** — detects `powershell -enc`, `certutil
  -urlcache`, `mshta http://`, `rundll32 javascript:`, `regsvr32` Squiblydoo,
  scheduled tasks, registry Run keys, anomalous parent/child pairs (Office →
  cmd, cmd → powershell from Office).
- **Offline buffer** — events are persisted to a SQLite buffer when the
  server is unreachable; a background drain thread retries with backoff.
- **API-key auth** — `X-API-Key` on every request (`X-NetGuard-Agent-Key`
  also enviado por compatibilidade com o ingest legado), masked in logs.
- **Windows service mode** — installs as `NetGuardAgent` SCM service via
  pywin32. Survives logoff, starts at boot.
- **Linux systemd mode** - installs as `netguard-agent.service` with
  persistent state/log paths and conservative systemd hardening.
- **Single binary** — `agent.exe` from `build_agent.ps1`.

---

## Quick start (development, Python)

```powershell
# 1. clone / cd into the repo
cd netguard-ids\agent

# 2. install deps (pin major versions, allow patches)
python -m pip install -r requirements.txt

# 3. point the agent at the server and set the API key
copy config.yaml config.local.yaml
notepad config.local.yaml
#   server_url: https://soc.example.com/api/events
#   api_key:    nga_<your-key>

# 4. run in foreground (Ctrl+C to stop)
$env:NETGUARD_AGENT_API_KEY = "nga_xxx..."
python -m agent
```

The agent logs to stdout and to `C:\ProgramData\NetGuard\agent.log`
(rotating 5 MB × 5).

---

## Secure enrollment

For production-style installs, avoid placing an admin token on the
endpoint. Create a short-lived enrollment token from the server, register
the host once, then let the agent reuse the issued host key from its local
credential store.

```powershell
# Server side, with an admin/analyst token.
curl.exe -X POST http://127.0.0.1:5000/api/agent/enrollment-token `
  -H "X-API-Token: <admin-or-analyst-token>" `
  -H "Content-Type: application/json" `
  -d "{\"tenant_id\":\"default\",\"expires_in_seconds\":3600,\"max_uses\":1}"

# Endpoint side: register once with the returned nge_... token.
curl.exe -X POST http://127.0.0.1:5000/api/agent/register `
  -H "Content-Type: application/json" `
  -d "{\"host_id\":\"lab-win-01\",\"platform\":\"windows\",\"enrollment_token\":\"nge_...\"}"
```

Copy the returned `nga_...` value into `NETGUARD_AGENT_API_KEY` or
`config.yaml` for the first service start. The agent then writes it to
`credentials.json` and can restart with `api_key: "CHANGE_ME"` as long as
the credential store remains intact.

To rotate a host key without deleting endpoint history, call the management
endpoint, update the returned `nga_...` in the endpoint credential store, and
restart the service:

```powershell
curl.exe -X POST http://127.0.0.1:5000/api/agent/hosts/lab-win-01/rotate-key `
  -H "X-API-Token: <admin-or-analyst-token>"
```

To revoke a compromised endpoint key without deleting host history:

```powershell
curl.exe -X POST http://127.0.0.1:5000/api/agent/hosts/lab-win-01/revoke `
  -H "X-API-Token: <admin-or-analyst-token>"
```

---

## Response actions

The agent polls `/api/agent/actions` with its host key and ACKs each leased
action to `/api/agent/actions/<action_id>/ack`.

Safe actions enabled by default:

- `ping`
- `collect_diagnostics`
- `flush_buffer`

Guarded actions are intentionally refused by default:

- `isolate_host`
- `kill_process`
- `block_ip`
- `delete_file`

This keeps the response channel from becoming arbitrary remote execution.
The server also fails closed before queueing guarded actions unless an admin
request includes a short-lived HMAC policy approval signed with
`NETGUARD_RESPONSE_POLICY_SECRET`. If an endpoint operator explicitly enables
guarded response, the agent independently verifies the queued policy with
`NETGUARD_AGENT_RESPONSE_POLICY_SECRET` before reaching any guarded handler.
Keep destructive response disabled until destructive handlers are implemented,
tested, and approved for the environment.

---

## Building `agent.exe`

```powershell
cd agent
powershell -ExecutionPolicy Bypass -File .\build_agent.ps1 -Clean -WithService
# → dist\agent.exe   (~12-18 MB, standalone, no Python required on target)
```

`build_agent.bat` is a one-liner wrapper for environments where PowerShell
execution policies are locked down.

Recommended PyInstaller flags are baked in:

| Flag | Why |
|------|-----|
| `--onefile` | Single, distributable binary. |
| `--clean` | Wipe stale PyInstaller cache; avoids stale module imports. |
| `--collect-submodules agent` | Forces every `agent.*` submodule into the bundle. |
| `--hidden-import yaml,psutil,requests,urllib3` | These are imported lazily; PyInstaller doesn't always trace them. |
| `--hidden-import win32serviceutil,...` | Only with `-WithService`; pulls in pywin32 service framework. |

After build, ship two files to the endpoint:

```
agent.exe
config.yaml   # edited with server_url + api_key
```

The runtime finds config in this order:

- explicit `--config`
- `NETGUARD_AGENT_CONFIG`
- current working directory
- Python package directory
- directory that contains `agent.exe` when frozen with PyInstaller

---

## Installing as a Windows Service

```powershell
# from an elevated prompt on the endpoint
powershell -ExecutionPolicy Bypass -File .\install_agent.ps1 -Start

# verify
sc.exe query NetGuardAgent

# uninstall
powershell -ExecutionPolicy Bypass -File .\uninstall_agent.ps1
```

`install_agent.ps1` copies `agent.exe` and `config.yaml` into
`C:\Program Files\NetGuard\Agent`, creates a state directory, locks the ACL to
`SYSTEM` and local `Administrators`, sets machine-level
`NETGUARD_AGENT_CONFIG` / `NETGUARD_AGENT_HOME`, installs the Windows service,
and optionally starts it.

The service runs as `LocalSystem` by default (required to enumerate all
processes / network connections). To run under a service account:

```powershell
sc.exe config NetGuardAgent obj= "DOMAIN\soc-agent" password= "..."
```

---

## Installing as a Linux systemd Service

```bash
# from the repository's agent/ directory on the endpoint
sudo sh ./install_agent.sh --start

# verify
systemctl status netguard-agent
journalctl -u netguard-agent -n 100 --no-pager

# uninstall, preserving identity/credential/buffer state
sudo sh ./uninstall_agent.sh --keep-state --keep-config
```

`install_agent.sh` copies the `agent` Python package to `/opt/netguard`,
copies `config.yaml`, creates `/var/lib/netguard` and `/var/log/netguard`,
writes `/etc/netguard/agent.env`, and installs
`/etc/systemd/system/netguard-agent.service`.

The generated unit runs `python3 -m agent --config /opt/netguard/config.yaml`,
restarts on failure, waits for `network-online.target`, and uses conservative
hardening controls such as `NoNewPrivileges=true`, `ProtectSystem=full`,
`ProtectHome=read-only`, `PrivateTmp=true`, and explicit state/log
`ReadWritePaths`.

Root is the default service user because full process/network visibility often
requires elevated privileges. If your Linux telemetry requirements are narrower,
install with `--user netguard` after creating that user and validating collector
coverage on the target distro.

---

## Configuration

`config.yaml` lives next to `agent.exe`. Every field can be overridden
via env var (`NETGUARD_AGENT_<UPPER_FIELD>`), which is the recommended
approach for production deploys. After first enrollment, the agent can also
load the issued key from `credential_path` instead of keeping it in config.

| Field | Default | Notes |
|-------|---------|-------|
| `server_url` | `https://127.0.0.1:5000/api/events` | HTTPS required in prod. |
| `api_key` | `CHANGE_ME` | Agent refuses to start with the literal string `CHANGE_ME`. |
| `interval_seconds` | `30` | Min `5`. Lighter hosts can run at 60-120s. |
| `verify_tls` | `true` | Set `false` only in lab w/ self-signed cert. |
| `request_timeout` | `15` | POST timeout. |
| `batch_max_events` | `200` | Server caps at 500 (`batch_too_large`). |
| `offline_buffer_max` | `5000` | Events kept on disk while server unreachable. |
| `log_path` | `""` | Empty = OS default. |
| `credential_path` | `""` | Empty = OS default credential store. DPAPI is used on Windows when available. |
| `enable_response_actions` | `true` | Poll server-side response action queue. |
| `action_poll_interval_seconds` | `30` | Min `10`; server lease is longer than poll interval. |
| `allow_destructive_response_actions` | `false` | Keep false until guarded handlers are approved. |
| `response_policy_secret` | `""` | Required only when destructive response is explicitly enabled; prefer env `NETGUARD_AGENT_RESPONSE_POLICY_SECRET`. |
| `tags` | `[]` | Free-form labels echoed back in dashboard. |
| `collect_processes` | `true` | Toggle off to silence on noisy hosts. |
| `collect_connections` | `true` | |
| `collect_security_indicators` | `true` | |

### Transport hardening

The agent fails closed for unsafe production transport:

- `http://` is allowed for loopback demo targets such as `127.0.0.1` and `localhost`.
- Remote `http://` targets are rejected outside `NETGUARD_AGENT_ENV=dev|test|local|demo|ci`.
- `verify_tls=false` with HTTPS is rejected in production.
- Lab/self-signed testing can opt in with `NETGUARD_AGENT_ALLOW_INSECURE_TRANSPORT=true`.

Production installs should use `https://.../api/events` with `verify_tls: true`.

---

## Event schema

Every event posted to the server matches this shape (canonical per the
NetGuard EDR/XDR spec):

```json
{
  "timestamp":      "2026-04-27T12:34:56Z",
  "host_id":        "f0a1...e9",
  "hostname":       "WIN-DEV-01",
  "agent_version":  "1.0.0",
  "event_type":     "process_execution | network_connection | script_execution | persistence_indicator | behavioral_anomaly | authentication",
  "source":         "netguard-agent",
  "severity":       "low | medium | high | critical",
  "confidence":     0-100,

  "process_name":   "powershell.exe",
  "pid":            1234,
  "ppid":           789,
  "command_line":   "...",
  "user":           "DOMAIN\\jdoe",

  "src_ip":         "10.0.0.5",
  "dst_ip":         "203.0.113.7",
  "dst_port":       443,

  "mitre_tactic":   "Defense Evasion",
  "mitre_technique":"T1027",
  "evidence":       "PowerShell -EncodedCommand detected",
  "raw":            { ... }
}
```

The agent batches up to `batch_max_events` per POST to `/api/events`;
the envelope adds `host_id`, `hostname`, `agent_version`, plus
compatibility fields such as `display_name`, `platform`, `metadata`.

---

## Troubleshooting

**"`api_key não configurada`" on startup**
The literal string `CHANGE_ME` is treated as unset. Set
`NETGUARD_AGENT_API_KEY`, edit `config.yaml`, or enroll once so the
issued `nga_...` host key can be loaded from the local credential store
on the next service start.

**"`POST falhou (network error: ConnectionError)`"**
Server unreachable. Events are buffered in
`C:\ProgramData\NetGuard\agent_buffer.db`; the drain thread will
flush them once connectivity returns. Check buffer growth:
`Get-Item "C:\ProgramData\NetGuard\agent_buffer.db" | Select Length`.

**"`net_connections sem permissão`" in agent.log**
Agent is running unprivileged. On Windows, install as service
(LocalSystem). On Linux, run as root or grant `cap_net_raw`.

**`agent.exe` flagged by Windows Defender**
PyInstaller binaries occasionally trigger heuristic AV. Solutions
(in order of preference): code-sign the binary, submit to Microsoft as
clean, or build with `--noupx`. The repo's CI build is reproducible —
hash check against `dist/agent.exe.sha256`.

**"`pywin32 não instalado`" when running `--service`**
Build with `-WithService`, or `pip install pywin32` on the target.

**Agent uses too much CPU**
Bump `interval_seconds` to 60+, disable `collect_connections` on
network-heavy hosts. Each cycle is O(processes + connections); a busy
build server with 5000 procs will see ~3% CPU at 30s interval.

**Logs not appearing in `C:\ProgramData\NetGuard\agent.log`**
Service running as a non-admin user can't write there. Either run as
`LocalSystem` or set `NETGUARD_AGENT_LOG_PATH=C:\Users\Public\netguard.log`.

---

## Layout

```
agent/
├── agent.py            # main loop, lifecycle, signals
├── collector.py        # processes, connections, security pattern scan
├── sender.py           # HTTPS + retry + SQLite offline buffer
├── host_identity.py    # UUID host_id, persisted
├── config.py           # YAML + env, dataclass-validated
├── service.py          # Windows SCM wrapper (pywin32)
├── config.yaml         # template
├── requirements.txt
├── build_agent.ps1     # PyInstaller build (Windows)
├── build_agent.bat     # one-liner wrapper
└── README_AGENT.md     # this file
```

---

## Security notes

- API key is never logged in full — only the first 8 chars + a length
  marker (`nga_xxxx... (44)`).
- `host_id` file is `chmod 600` on POSIX; Windows ACL inherits from
  `ProgramData\NetGuard`.
- Buffer DB (`agent_buffer.db`) holds *unencrypted* events on disk while
  offline. If the host has Bitlocker / LUKS / FileVault this is fine; on
  a stolen unencrypted disk an attacker can read pending telemetry.
  Plan: per-host AES-GCM with a key sealed by the TPM. Tracked in
  `SECURITY.md`.
- TLS verification is **on** by default. Disable only in a closed lab.

---

## Versioning

Agent advertises its version in every event (`agent_version`) and in
the `User-Agent` header. The current version lives in
`agent/__init__.py:__version__`. Bump with the SemVer rules in
`CONTRIBUTING.md`.
