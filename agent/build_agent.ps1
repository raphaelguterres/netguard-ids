# NetGuard Agent — build script (PowerShell, Windows)
#
# Gera dist\agent.exe via PyInstaller. Roda do diretorio /agent.
#
# Requisitos no host:
#   - Python 3.10+ (64-bit recomendado)
#   - pip install -r requirements.txt
#   - pip install pyinstaller
#
# Uso:
#   cd agent
#   powershell -ExecutionPolicy Bypass -File .\build_agent.ps1
#
# Saida:
#   .\dist\agent.exe
#
# O .exe gerado eh standalone (--onefile). Distribuicao tipica:
#   1. Copiar agent.exe + config.yaml pro endpoint
#   2. Editar config.yaml (server_url, api_key)
#   3. Rodar manualmente OU instalar como servico:
#        agent.exe --service install
#        agent.exe --service start

[CmdletBinding()]
param(
    [switch]$Clean,                    # Apaga build/dist antes
    [switch]$NoUpx,                    # Pula compressao UPX
    [switch]$WithService,              # Inclui modulo de servico Windows
    [string]$EntryPoint = "agent.py",
    [string]$AppName = "agent"
)

$ErrorActionPreference = "Stop"
Set-Location -Path (Split-Path -Parent $MyInvocation.MyCommand.Path)

Write-Host "=== NetGuard Agent build ===" -ForegroundColor Cyan
Write-Host "CWD: $(Get-Location)"

# ── 1. Sanity checks ──────────────────────────────────────────────
if (-not (Test-Path $EntryPoint)) {
    Write-Error "Entry point '$EntryPoint' nao encontrado em $(Get-Location)"
    exit 1
}

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Error "Python nao encontrado no PATH. Instale Python 3.10+."
    exit 1
}

Write-Host "Python: $($python.Source)"

# ── 2. Limpa artefatos antigos ────────────────────────────────────
if ($Clean) {
    foreach ($d in @("build", "dist", "__pycache__")) {
        if (Test-Path $d) {
            Write-Host "Removendo $d/" -ForegroundColor Yellow
            Remove-Item -Recurse -Force $d
        }
    }
    Get-ChildItem -Filter "*.spec" | Remove-Item -Force -ErrorAction SilentlyContinue
}

# ── 3. Verifica PyInstaller ───────────────────────────────────────
$piCheck = & python -c "import PyInstaller; print(PyInstaller.__version__)" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "PyInstaller nao instalado. Instalando..." -ForegroundColor Yellow
    & python -m pip install --upgrade pyinstaller
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Falha ao instalar PyInstaller"
        exit 1
    }
} else {
    Write-Host "PyInstaller: $piCheck"
}

# ── 4. Build ──────────────────────────────────────────────────────
$args = @(
    "-m", "PyInstaller",
    "--onefile",
    "--name", $AppName,
    "--clean",
    "--noconfirm",
    # Hidden imports — pacotes que PyInstaller as vezes nao detecta
    # automaticamente (importados dinamicamente).
    "--hidden-import", "yaml",
    "--hidden-import", "psutil",
    "--hidden-import", "requests",
    "--hidden-import", "urllib3",
    # Pacote do agente: garante que todos os submodulos entrem.
    "--collect-submodules", "agent"
)

if ($WithService) {
    $args += @(
        "--hidden-import", "win32serviceutil",
        "--hidden-import", "win32service",
        "--hidden-import", "win32event",
        "--hidden-import", "servicemanager"
    )
}

if ($NoUpx) {
    $args += "--noupx"
}

$args += $EntryPoint

Write-Host ""
Write-Host "Comando: python $($args -join ' ')" -ForegroundColor DarkGray
Write-Host ""

& python @args
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build falhou (exit=$LASTEXITCODE)"
    exit $LASTEXITCODE
}

# ── 5. Verifica saida ─────────────────────────────────────────────
$exePath = Join-Path (Get-Location) "dist\$AppName.exe"
if (-not (Test-Path $exePath)) {
    Write-Error "Build aparentemente OK mas $exePath nao existe"
    exit 1
}

$size = (Get-Item $exePath).Length
$sizeMB = [math]::Round($size / 1MB, 2)
Write-Host ""
Write-Host "OK. agent.exe gerado em:" -ForegroundColor Green
Write-Host "  $exePath"
Write-Host "  Tamanho: $sizeMB MB"
Write-Host ""
Write-Host "Proximos passos:"
Write-Host "  1. Copiar agent.exe + config.yaml + install_agent.ps1 pro endpoint alvo"
Write-Host "  2. Editar config.yaml (server_url, api_key)"
Write-Host "  3. Rodar:    .\dist\agent.exe"
Write-Host "     Servico:  powershell -ExecutionPolicy Bypass -File .\install_agent.ps1 -Start"
