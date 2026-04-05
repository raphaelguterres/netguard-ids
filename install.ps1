#Requires -Version 5.1
<#
.SYNOPSIS
    NetGuard IDS — Instalador para Windows (PowerShell)
.DESCRIPTION
    Instala dependências, cria venv, registra serviço Windows e abre o dashboard.
    Tempo estimado: 2-5 minutos.
.EXAMPLE
    iex (irm https://seudominio.com/install.ps1)
    # ou localmente:
    .\install.ps1
#>
[CmdletBinding()]
param(
    [string]$Port      = "5000",
    [string]$Interface = "127.0.0.1",
    [switch]$AsService,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Cores e helpers ───────────────────────────────────────────────
function Write-Step  { param($msg) Write-Host "`n  ▶ $msg" -ForegroundColor Cyan }
function Write-OK    { param($msg) Write-Host "  ✔ $msg"  -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "  ⚠ $msg"  -ForegroundColor Yellow }
function Write-Fail  { param($msg) Write-Host "  ✗ $msg"  -ForegroundColor Red; exit 1 }

function Test-Admin {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

Clear-Host
Write-Host ""
Write-Host "  ╔══════════════════════════════════════╗" -ForegroundColor Blue
Write-Host "  ║   NetGuard IDS — Instalação Rápida   ║" -ForegroundColor Blue
Write-Host "  ╚══════════════════════════════════════╝" -ForegroundColor Blue
Write-Host ""

# ── Verificações de sistema ───────────────────────────────────────
Write-Step "Verificando requisitos do sistema"

# Python
$python = $null
foreach ($cmd in @("python","python3","py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "Python (\d+)\.(\d+)") {
            $major = [int]$Matches[1]; $minor = [int]$Matches[2]
            if ($major -ge 3 -and $minor -ge 9) { $python = $cmd; break }
        }
    } catch {}
}
if (-not $python) {
    Write-Warn "Python 3.9+ não encontrado."
    Write-Host "  → Baixe em: https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "  → Marque 'Add Python to PATH' durante a instalação." -ForegroundColor Yellow
    Write-Fail "Instale o Python e execute este script novamente."
}
$pyVer = (& $python --version 2>&1)
Write-OK "Python encontrado: $pyVer"

# pip
try { & $python -m pip --version | Out-Null }
catch { Write-Fail "pip não encontrado. Execute: $python -m ensurepip" }
Write-OK "pip disponível"

# Pasta do projeto
$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not (Test-Path "$projectDir\app.py")) {
    Write-Fail "app.py não encontrado em '$projectDir'. Execute o script dentro da pasta do NetGuard."
}
Write-OK "Pasta do projeto: $projectDir"

# ── Ambiente virtual ──────────────────────────────────────────────
Write-Step "Criando ambiente virtual Python"

$venvPath = "$projectDir\venv"
if ((Test-Path $venvPath) -and -not $Force) {
    Write-OK "Venv já existe (use -Force para recriar)"
} else {
    if (Test-Path $venvPath) { Remove-Item $venvPath -Recurse -Force }
    & $python -m venv $venvPath
    Write-OK "Venv criado em: $venvPath"
}

$pip    = "$venvPath\Scripts\pip.exe"
$pyExe  = "$venvPath\Scripts\python.exe"

# ── Dependências ──────────────────────────────────────────────────
Write-Step "Instalando dependências (pode levar 2-3 minutos)"

$reqFile = "$projectDir\requirements.txt"
if (-not (Test-Path $reqFile)) { Write-Fail "requirements.txt não encontrado" }

& $pip install --upgrade pip --quiet
& $pip install -r $reqFile --quiet

# Opcionais — não falha se ausentes
Write-Host "  → Instalando extras opcionais..." -ForegroundColor DarkGray
& $pip install scikit-learn numpy flask-talisman flask-limiter --quiet 2>$null

Write-OK "Dependências instaladas"

# ── Arquivo de configuração ───────────────────────────────────────
Write-Step "Configurando ambiente"

$envFile = "$projectDir\.env"
if (-not (Test-Path $envFile)) {
    @"
IDS_HOST=$Interface
IDS_PORT=$Port
IDS_AUTH=false
IDS_DEBUG=false
"@ | Set-Content $envFile -Encoding UTF8
    Write-OK ".env criado"
} else {
    Write-OK ".env já existe"
}

# ── Serviço Windows (opcional) ────────────────────────────────────
if ($AsService) {
    if (-not (Test-Admin)) {
        Write-Warn "-AsService requer privilégios de administrador. Pulando."
    } else {
        Write-Step "Registrando serviço Windows"
        $svcName = "NetGuardIDS"
        $existing = Get-Service -Name $svcName -ErrorAction SilentlyContinue

        # Usa NSSM se disponível, senão cria via sc.exe
        $nssm = (Get-Command nssm -ErrorAction SilentlyContinue)?.Source
        if ($nssm) {
            if ($existing) { & $nssm stop $svcName; & $nssm remove $svcName confirm }
            & $nssm install $svcName $pyExe "$projectDir\app.py"
            & $nssm set $svcName AppDirectory $projectDir
            & $nssm set $svcName DisplayName "NetGuard IDS"
            & $nssm set $svcName Start SERVICE_AUTO_START
            & $nssm start $svcName
            Write-OK "Serviço '$svcName' registrado e iniciado via NSSM"
        } else {
            Write-Warn "NSSM não encontrado — serviço não registrado."
            Write-Warn "Para instalar NSSM: winget install nssm / https://nssm.cc"
        }
    }
}

# ── Resumo ────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔══════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║        Instalação concluída!         ║" -ForegroundColor Green
Write-Host "  ╚══════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Para iniciar o NetGuard:" -ForegroundColor White
Write-Host "    cd `"$projectDir`"" -ForegroundColor Cyan
Write-Host "    venv\Scripts\activate" -ForegroundColor Cyan
Write-Host "    python app.py" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Dashboard: http://${Interface}:${Port}" -ForegroundColor Blue
Write-Host ""

$open = Read-Host "  Iniciar o NetGuard agora? [S/n]"
if ($open -ne "n" -and $open -ne "N") {
    Write-Host "  Iniciando..." -ForegroundColor Green
    Start-Process $pyExe -ArgumentList "$projectDir\app.py" -WorkingDirectory $projectDir -NoNewWindow
    Start-Sleep 3
    Start-Process "http://${Interface}:${Port}"
}
