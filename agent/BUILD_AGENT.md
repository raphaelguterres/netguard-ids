# NetGuard Endpoint Agent — Build Guide (`agent.exe`)

This guide is for the engineer or release manager who needs to produce a
clean, distributable `agent.exe` for Windows endpoints. For runtime
behavior, configuration reference, and deployment topology, see
[`README_AGENT.md`](README_AGENT.md).

---

## TL;DR

**Always build in a clean virtualenv.** Globally-installed packages like
`pyOpenSSL`, `cryptography`, `cffi`, or stale pywin32 versions get
silently bundled and cause `STATUS_ACCESS_VIOLATION` (0xC0000005) on
`import requests` at runtime. A venv has zero chance of leaking them.

```powershell
cd netguard-ids\agent
python -m venv .venv-build
.\.venv-build\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install pyinstaller==6.6.0
.\build_agent.ps1 -Clean
```

You'll end up with `agent\dist\` containing:

```
agent.exe                ← the binary
agent.exe.sha256         ← integrity manifest
config.yaml              ← edit this on the endpoint
install_agent.ps1        ← optional; registers agent.exe as a Windows service
README_AGENT.md          ← operator runtime reference
BUILD_AGENT.md           ← this file
```

The build script also runs `agent.exe --selftest` at the end. If selftest
fails, the build exits non-zero and you should *not* ship the artifact.

---

## Prerequisites

| Component        | Version         | Notes                                           |
| ---------------- | --------------- | ----------------------------------------------- |
| Windows          | 10/11 or Server 2019+ | 64-bit. Build machine and target should match arch. |
| Python           | 3.10 – 3.12     | Use the official python.org installer; check **Add to PATH**. |
| PyInstaller      | 6.x             | Pinned in `pip install pyinstaller`. Don't use 5.x — broken `version_info` parser. |
| Visual C++ runtime | 2015–2022     | Pre-installed on most Windows hosts. PyInstaller emits a binary linked against it. |
| pywin32          | ≥ 306           | Only needed if you'll build with `--service` mode. Comes from `requirements.txt` on Windows. |

Verify you have a clean toolchain:

```powershell
python --version           # 3.10.x – 3.12.x
python -m pip --version
python -c "import PyInstaller; print(PyInstaller.__version__)"
```

---

## Standard build

From the repo root:

```powershell
cd agent
python -m pip install -r requirements.txt
python -m pip install pyinstaller
.\build_agent.ps1 -Clean
```

Or via the `cmd` wrapper:

```cmd
cd agent
build_agent.bat clean
```

### What the script does, step by step

1. **Sanity checks.** Confirms `agent.py` exists in the working directory and that `python` is on `PATH`.
2. **(`-Clean`) wipes** `build/`, `dist/`, and stale `*.spec` from prior runs.
3. **Verifies PyInstaller** is importable; installs it via pip if not.
4. **Builds via `agent.spec`** if present (the recommended path). Falls back to inline flags only if `-NoSpec` is passed or the spec was deleted.
5. **Copies `config.yaml`** + helpers (`install_agent.ps1`, `README_AGENT.md`, `BUILD_AGENT.md`) next to `dist/agent.exe` so the operator gets a self-contained drop folder.
6. **Emits `dist/agent.exe.sha256`** — single-line manifest you can verify on the target host with `Get-FileHash`.
7. **Runs `agent.exe --selftest`** as a post-build smoke check. Any non-zero exit fails the build.

---

## Build flags

```
.\build_agent.ps1 [-Clean] [-NoSpec] [-NoSelftest] [-NoUpx] [-WithService]
                  [-EntryPoint agent.py] [-AppName agent]
                  [-SpecFile agent.spec]
```

| Flag             | Purpose                                                                 |
| ---------------- | ----------------------------------------------------------------------- |
| `-Clean`         | Wipe `build/`, `dist/`, and stray `*.spec` before building.             |
| `-NoSpec`        | Skip `agent.spec` and use the inline PyInstaller flags. Use for debugging the spec itself. |
| `-NoSelftest`    | Skip the post-build `--selftest` invocation. **Don't use for release builds.** |
| `-NoUpx`         | Already the default when building from `agent.spec` (UPX trips Defender SmartScreen). |
| `-WithService`   | Legacy. Adds pywin32 hidden imports for the inline build. The spec already includes them. |

The `cmd` wrapper accepts positional words in any order:

```cmd
build_agent.bat clean noselftest
build_agent.bat nospec service
```

---

## What's inside `agent.spec`

Before you ship a custom build, read [`agent.spec`](agent.spec). The
important knobs are at the top:

```python
APP_NAME = "agent"
ENTRY_POINT = "agent.py"
ENABLE_WINDOWS_SERVICE = True   # include pywin32 service hooks
ENABLE_CONSOLE = True           # False = windowed, no console window
ENABLE_UPX = False              # leave off — see comment in spec
```

The spec also pins:

- `version="version_info.txt"` — embeds Windows file metadata (CompanyName, ProductName, FileVersion). Without this, antivirus heuristics flag the binary as a generic unsigned packed exe.
- `excludes=[tkinter, test, curses, ...]` — drops ~6 MB of unused stdlib.
- `collect_submodules("agent")` — guarantees every submodule of the `agent` package ends up in the bundle.

If you bump `agent/__init__.py::__version__`, also bump `filevers` /
`prodvers` / the `FileVersion` and `ProductVersion` strings in
`agent/version_info.txt`. (Or wire up a small `bump_version_info.py`
script — left as a follow-up.)

---

## Verifying the build

The build script does this for you. To verify a build you received from
someone else:

```powershell
# 1. Hash matches the published manifest
$expected = (Get-Content .\agent.exe.sha256 -Raw).Trim().Split(" ")[0].ToLower()
$actual   = (Get-FileHash -Algorithm SHA256 -Path .\agent.exe).Hash.ToLower()
$expected -eq $actual

# 2. Windows file metadata is set
(Get-Item .\agent.exe).VersionInfo

# 3. Binary boots and self-validates
.\agent.exe --version
.\agent.exe --selftest
```

Or run the full bundled suite:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\smoke_test_agent.ps1 `
  -ExePath .\agent\dist\agent.exe
```

That checks: presence, size sanity, Windows VersionInfo, SHA256
manifest, `--version` output, `--selftest` against an unreachable dummy
server (config OK + network WARN is the expected good path).

---

## Distribution

Hand the operator the entire `dist/` directory contents (or zip it).
At minimum:

```
agent.exe
agent.exe.sha256
config.yaml
install_agent.ps1   (optional, for service install)
```

On the endpoint:

```powershell
# 1. Verify integrity
Get-FileHash -Algorithm SHA256 .\agent.exe
#    compare against agent.exe.sha256

# 2. Edit config
notepad .\config.yaml
#    set server_url to https://<your-soc>/api/events
#    set api_key to the nga_... issued by /api/agent/register

# 3. Smoke test before installing as a service
.\agent.exe --selftest

# 4a. Run interactively (Ctrl+C to stop)
.\agent.exe

# 4b. OR install as a Windows service
.\agent.exe --service install
.\agent.exe --service start
```

---

## Troubleshooting

### `ImportError: No module named '_yaml'` at runtime

PyYAML's optional C extension didn't get bundled. Force it:

```powershell
.\build_agent.ps1 -Clean
# in agent.spec, add to hidden_imports:  "_yaml"
```

Or install PyYAML before building so PyInstaller picks up the extension
on disk. (Issue typically appears when building inside a venv that has
PyYAML installed without wheels.)

### `ImportError: DLL load failed while importing win32api`

You included `-WithService` (or have `ENABLE_WINDOWS_SERVICE = True` in
the spec) but pywin32 isn't installed in the build environment. Fix:

```powershell
python -m pip install --upgrade pywin32
python -m pywin32_postinstall -install   # registers the COM helpers
.\build_agent.ps1 -Clean
```

### `agent.exe --selftest` crashes with exit code -1073741819 (0xC0000005)

That's a Windows access violation. Almost always caused by
globally-installed Python packages leaking into the bundle and creating
a DLL conflict with Python's bundled OpenSSL. **Build in a clean venv**
(see TL;DR at the top of this guide). If you still hit it inside a
clean venv, the next suspect is enterprise EDR/AV intercepting DLL
loads -- temporarily allowlist `dist\agent.exe` and rebuild.

### Defender quarantines the .exe immediately

Two common causes:

1. **UPX compression.** Confirm `ENABLE_UPX = False` in `agent.spec` and that you're not passing `--upx-dir` to PyInstaller anywhere.
2. **No file metadata.** Confirm `version="version_info.txt"` is present in `agent.spec` (without it the .exe looks generic-packed). Re-build, then re-check `(Get-Item .\agent.exe).VersionInfo` — `CompanyName` should read `NetGuard`.

For corporate environments, the long-term fix is **code signing**. Get
an Authenticode cert and sign with `signtool sign /tr <ts> /td sha256
/fd sha256 /a agent.exe`. Hook it after step 7 of `build_agent.ps1`.

### `--selftest` exits with code 2 (`[FAIL] config`)

The bundled `config.yaml` still has `api_key: "CHANGE_ME"`. Edit it on
the endpoint, or pass `--config <path-to-real-config.yaml>`.

### `--selftest` exits with code 4 (`[FAIL] sender init`)

The `server_url` in your config isn't a valid URL, or `verify_tls=true`
is set against an HTTPS endpoint with a self-signed cert and you're not
in a `NETGUARD_AGENT_ENV=local|test|dev` environment. Either fix the
URL/cert or set `NETGUARD_AGENT_ALLOW_INSECURE_TRANSPORT=true` for lab
hosts.

### Antivirus blocks the build itself

PyInstaller's bootloader is a frequent false-positive target. Allowlist
`%LocalAppData%\Programs\Python\Python311\Lib\site-packages\PyInstaller\bootloader\Windows-64bit\`
or run the build inside a CI VM where the AV agent is configured to
skip build artifacts.

### Build succeeds but the .exe is huge (> 60 MB)

Something pulled in `numpy`, `pandas`, or `scipy` transitively. Check
`build/agent/warn-agent.txt` and the `Analysis(...)` output. Usually
this means a dev dependency leaked into `requirements.txt`. Pin
`requirements.txt` to runtime-only deps and rebuild.

---

## Reproducible builds

To get byte-identical artifacts across machines:

1. Pin Python: same minor version (e.g. 3.11.8 everywhere).
2. Pin PyInstaller: `pip install pyinstaller==6.6.0` (or whatever you've blessed).
3. Pin runtime deps via `requirements.txt` (already pinned with `>=X,<Y`).
4. Build inside a clean virtualenv:

```powershell
python -m venv .venv-build
.\.venv-build\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install pyinstaller==6.6.0
.\build_agent.ps1 -Clean
```

5. Compare SHA256 of `dist/agent.exe` against the previous release. PyInstaller's bootloader timestamp prevents *bit-perfect* identity, but the bulk of the binary is stable.

For true reproducibility you'll need a containerized build environment
(Windows Server Core image with a frozen Python + PyInstaller). Out of
scope for this guide.

---

## CI integration sketch

Minimum GitHub Actions workflow (Windows runner):

```yaml
# .github/workflows/build-agent.yml
name: build-agent
on: [push, pull_request]
jobs:
  build:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: python -m pip install -r agent/requirements.txt
      - run: python -m pip install pyinstaller==6.6.0
      - run: powershell -NoProfile -ExecutionPolicy Bypass -File agent/build_agent.ps1 -Clean
      - run: powershell -NoProfile -ExecutionPolicy Bypass -File scripts/smoke_test_agent.ps1
      - uses: actions/upload-artifact@v4
        with:
          name: agent-windows
          path: |
            agent/dist/agent.exe
            agent/dist/agent.exe.sha256
            agent/dist/config.yaml
```

The smoke test is the merge gate. If `--selftest` fails, the workflow
fails and the build is discarded.
