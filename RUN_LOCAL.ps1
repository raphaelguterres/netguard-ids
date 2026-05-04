# ============================================================
# NetGuard IDS - start local
# Uso: powershell -ExecutionPolicy Bypass -File .\RUN_LOCAL.ps1
# ============================================================

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot
Set-Location $ProjectRoot

Write-Host ""
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host "  NetGuard IDS - boot local" -ForegroundColor Yellow
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host ""

# 1. Confere Python
$pyOk = $false
try {
    $pyVersion = & python --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host ">> Python detectado: $pyVersion" -ForegroundColor Green
        $pyOk = $true
    }
} catch { }

if (-not $pyOk) {
    Write-Host "!! Python nao encontrado." -ForegroundColor Red
    Write-Host "   Instala em: https://www.python.org/downloads/" -ForegroundColor Red
    Write-Host "   (versao 3.11 ou mais nova)" -ForegroundColor Red
    exit 1
}

# 2. Cria venv se nao existir
if (-not (Test-Path ".venv")) {
    Write-Host ">> Criando virtualenv em .venv ..." -ForegroundColor Cyan
    & python -m venv .venv
    Write-Host ">> venv criada" -ForegroundColor Green
} else {
    Write-Host ">> venv ja existe" -ForegroundColor Green
}

# 3. Ativa venv
$activate = ".\.venv\Scripts\Activate.ps1"
if (Test-Path $activate) {
    & $activate
    Write-Host ">> venv ativada" -ForegroundColor Green
} else {
    Write-Host "!! Falha ao ativar venv" -ForegroundColor Red
    exit 1
}

# 4. Instala dependencias (so se nao existir flag de install)
$installFlag = ".venv\.installed"
if (-not (Test-Path $installFlag)) {
    Write-Host ">> Instalando dependencias 1-2 min na primeira vez ..." -ForegroundColor Cyan
    & python -m pip install --upgrade pip --quiet
    & python -m pip install -r requirements.txt --quiet
    New-Item -ItemType File -Path $installFlag -Force | Out-Null
    Write-Host ">> dependencias instaladas" -ForegroundColor Green
} else {
    Write-Host ">> dependencias ja instaladas" -ForegroundColor Green
    Write-Host "   apaga .venv\.installed pra reinstalar" -ForegroundColor DarkGray
}

# 5. Copia .env se nao existir
if (-not (Test-Path ".env")) {
    Copy-Item .env.example .env
    Write-Host ">> .env criado a partir do .env.example" -ForegroundColor Green
} else {
    Write-Host ">> .env ja existe" -ForegroundColor Green
}

# 6. Variaveis de ambiente locais
# (o projeto nao usa python-dotenv, entao .env nao carrega sozinho)
$env:IDS_HOST              = "127.0.0.1"
$env:IDS_PORT              = "5000"
$env:IDS_DEBUG             = "false"
$env:IDS_ENV               = "development"
$env:NETGUARD_ENV          = "development"
$env:FLASK_ENV             = "development"
$env:HTTPS_ONLY            = "false"
$env:IDS_HTTPS             = "false"
$env:IDS_AUTH              = "false"
$env:IDS_DASHBOARD_AUTH    = "false"
# Forca SQLite em local (limpa qualquer DATABASE_URL ambiente que possa apontar pra Postgres)
if (Test-Path Env:DATABASE_URL) {
    Remove-Item Env:DATABASE_URL -ErrorAction SilentlyContinue
    Write-Host ">> DATABASE_URL removida do ambiente (forcando SQLite)" -ForegroundColor DarkGray
}
$env:NETGUARD_DB_BACKEND   = "sqlite"
# Secret apenas para dev local. Em producao, troque por valor forte gerado.
$env:TOKEN_SIGNING_SECRET  = "local-dev-only-not-for-production-use-32chars-minimum-xxxx"
$env:SECRET_KEY            = "local-dev-flask-secret-key-not-for-production-use-xxxx"

Write-Host ""
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host "  Subindo servidor em http://127.0.0.1:5000" -ForegroundColor Yellow
Write-Host "  Pressione Ctrl+C pra parar." -ForegroundColor Yellow
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host ""

# 7. Abre browser depois de 8s em background (Flask demora pra warm up)
Start-Job -ScriptBlock {
    Start-Sleep -Seconds 8
    Start-Process "http://127.0.0.1:5000"
} | Out-Null

# 8. Sobe o servidor
& python app.py
