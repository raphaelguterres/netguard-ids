# NetGuard Agent -- build script (PowerShell, Windows)
#
# Gera dist\agent.exe via PyInstaller. Roda do diretorio /agent.
#
# IMPORTANTE: este arquivo eh estritamente ASCII (sem em-dash, sem
# box-drawing, sem aspas curvas) porque PowerShell 5.1 (Windows
# default) le scripts como Windows-1252 quando nao ha BOM, e
# caracteres UTF-8 multi-byte dentro de STRINGS quebram o parser
# de forma mascarada (erro reportado em linha errada).
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
    [switch]$NoUpx,                    # (mantido por compat; spec ja desliga UPX)
    [switch]$WithService,              # (legacy; spec ja inclui hooks de servico)
    [switch]$NoSpec,                   # Forca o build inline antigo (ignora agent.spec)
    [switch]$NoSelftest,               # Pula a chamada agent.exe --selftest pos-build
    [string]$EntryPoint = "agent.py",
    [string]$AppName = "agent",
    [string]$SpecFile = "agent.spec"
)

$ErrorActionPreference = "Stop"
Set-Location -Path (Split-Path -Parent $MyInvocation.MyCommand.Path)

Write-Host "=== NetGuard Agent build ===" -ForegroundColor Cyan
Write-Host "CWD: $(Get-Location)"

# ===== 1. Sanity checks =============================================
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

# ===== 2. Limpa artefatos antigos ===================================
if ($Clean) {
    foreach ($d in @("build", "dist", "__pycache__")) {
        if (Test-Path $d) {
            Write-Host "Removendo $d/" -ForegroundColor Yellow
            Remove-Item -Recurse -Force $d
        }
    }
    # Nao apaga *.spec quando estamos usando agent.spec versionado.
    if ($NoSpec) {
        Get-ChildItem -Filter "*.spec" | Remove-Item -Force -ErrorAction SilentlyContinue
    }
}

# ===== 3. Verifica PyInstaller ======================================
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

# ===== 4. Build =====================================================
# Caminho preferido: agent.spec (reproducivel, carrega version_info.txt,
# define hidden imports e exclude lists em um lugar so).
# Fallback: build inline antigo (mantido com -NoSpec ou se o spec sumir).
$useSpec = (-not $NoSpec) -and (Test-Path $SpecFile)

if ($useSpec) {
    Write-Host "Build via spec: $SpecFile" -ForegroundColor Cyan
    $piArgs = @(
        "-m", "PyInstaller",
        "--clean",
        "--noconfirm",
        "--distpath", "dist",
        "--workpath", "build",
        $SpecFile
    )
} else {
    Write-Host "Build inline (sem agent.spec)" -ForegroundColor Yellow
    $piArgs = @(
        "-m", "PyInstaller",
        "--onefile",
        "--name", $AppName,
        "--clean",
        "--noconfirm",
        "--hidden-import", "yaml",
        "--hidden-import", "psutil",
        "--hidden-import", "requests",
        "--hidden-import", "urllib3",
        "--collect-submodules", "agent"
    )
    if ($WithService) {
        $piArgs += @(
            "--hidden-import", "win32serviceutil",
            "--hidden-import", "win32service",
            "--hidden-import", "win32event",
            "--hidden-import", "servicemanager"
        )
    }
    if ($NoUpx) { $piArgs += "--noupx" }
    $piArgs += $EntryPoint
}

Write-Host ""
Write-Host "Comando: python $($piArgs -join ' ')" -ForegroundColor DarkGray
Write-Host ""

& python @piArgs
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build falhou (exit=$LASTEXITCODE)"
    exit $LASTEXITCODE
}

# ===== 5. Verifica saida ============================================
$exePath = Join-Path (Get-Location) "dist\$AppName.exe"
if (-not (Test-Path $exePath)) {
    Write-Error "Build aparentemente OK mas $exePath nao existe"
    exit 1
}

$size = (Get-Item $exePath).Length
$sizeMB = [math]::Round($size / 1MB, 2)

# ===== 6. Bundle config.yaml + manifest junto do .exe ==============
# Copia o template pro lado do binario pra que o operador receba um
# pacote auto-suficiente (agent.exe + config.yaml). Re-edita sem
# rebuild -- o .exe le config.yaml do diretorio em runtime.
$distDir = Split-Path -Parent $exePath
$configSrc = Join-Path (Get-Location) "config.yaml"
if (Test-Path $configSrc) {
    Copy-Item -Force $configSrc (Join-Path $distDir "config.yaml")
    Write-Host "Config copiado: $configSrc -> $distDir\config.yaml" -ForegroundColor DarkGray
} else {
    Write-Warning "config.yaml nao encontrado em $configSrc -- operador tera que prover manualmente"
}

# Copia helpers de instalacao se existirem (uso opcional pelo operador).
foreach ($helper in @("install_agent.ps1", "uninstall_agent.ps1", "README_AGENT.md", "BUILD_AGENT.md")) {
    $src = Join-Path (Get-Location) $helper
    if (Test-Path $src) {
        Copy-Item -Force $src (Join-Path $distDir $helper)
    }
}

# ===== 7. SHA256 do .exe (manifest de integridade) =================
$hash = Get-FileHash -Algorithm SHA256 -Path $exePath
$manifestPath = Join-Path $distDir "agent.exe.sha256"
"$($hash.Hash.ToLower())  agent.exe" | Out-File -FilePath $manifestPath -Encoding ascii -NoNewline
Write-Host "SHA256: $($hash.Hash.ToLower())" -ForegroundColor DarkGray
Write-Host "  manifest: $manifestPath"

# ===== 8. Smoke test pos-build (--selftest) ========================
# Garante que o binario sobe, carrega config, resolve host_id e
# inicializa o sender. Falha aqui = build quebrado, pare a CI.
if (-not $NoSelftest) {
    Write-Host ""
    Write-Host "Selftest: executando '$AppName.exe --selftest'..." -ForegroundColor Cyan
    Push-Location $distDir
    try {
        & ".\$AppName.exe" --selftest
        $selftestExit = $LASTEXITCODE
    } finally {
        Pop-Location
    }
    if ($selftestExit -ne 0) {
        Write-Error "Selftest falhou (exit=$selftestExit). Binario nao esta saudavel."
        exit $selftestExit
    }
    Write-Host "Selftest: OK" -ForegroundColor Green
}

Write-Host ""
Write-Host "OK. agent.exe gerado em:" -ForegroundColor Green
Write-Host "  $exePath"
Write-Host "  Tamanho: $sizeMB MB"
Write-Host "  SHA256:  $($hash.Hash.ToLower())"
Write-Host ""
Write-Host "Pacote distribuivel: $distDir\"
Write-Host "  - agent.exe"
Write-Host "  - agent.exe.sha256"
Write-Host "  - config.yaml"
if (Test-Path (Join-Path $distDir "install_agent.ps1")) {
    Write-Host "  - install_agent.ps1"
}
Write-Host ""
Write-Host "Proximos passos:"
Write-Host "  1. Copiar o conteudo de dist\ pro endpoint alvo"
Write-Host "  2. Editar config.yaml (server_url, api_key)"
Write-Host "  3. Rodar:    .\agent.exe                 (foreground)"
Write-Host "     Servico:  nssm install NetGuardAgent .\agent.exe"
Write-Host "               nssm start   NetGuardAgent"
Write-Host "     (NSSM: https://nssm.cc -- robusto, suporta restart e log redirect)"
