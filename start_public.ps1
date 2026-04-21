# NetGuard IDS - Iniciar com tunel publico (ngrok)
# Uso: .\start_public.ps1
# Requer ngrok instalado: winget install ngrok.ngrok
#   ou baixe em https://ngrok.com/download

param(
    [string]$Port = "5000",
    [string]$Token = "",      # ngrok authtoken (opcional se ja configurado)
    [switch]$AllowInsecure    # bypass explicito: expor sem auth so em lab isolado
)

$ErrorActionPreference = "Stop"

function Write-Step { param($m) Write-Host "`n  > $m" -ForegroundColor Cyan }
function Write-OK { param($m) Write-Host "  [OK] $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Write-Err { param($m) Write-Host "  [ERR] $m" -ForegroundColor Red }

# -- Verifica ngrok -------------------------------------------------
Write-Step "Verificando ngrok"
$ngrokCmd = Get-Command ngrok -ErrorAction SilentlyContinue
$ngrok = if ($ngrokCmd) { $ngrokCmd.Source } else { $null }
if (-not $ngrok) {
    Write-Host ""
    Write-Host "  ngrok nao encontrado. Instale com:" -ForegroundColor Red
    Write-Host "    winget install ngrok.ngrok" -ForegroundColor Cyan
    Write-Host "  ou baixe em: https://ngrok.com/download" -ForegroundColor Cyan
    Write-Host ""
    exit 1
}
Write-OK "ngrok encontrado: $ngrok"

# -- Authtoken (se passado como parametro) --------------------------
if ($Token) {
    Write-Step "Configurando authtoken"
    & ngrok config add-authtoken $Token
    Write-OK "Token configurado"
}

# -- Pasta do projeto -----------------------------------------------
$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = "$projectDir\venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    Write-Warn "venv nao encontrado - usando python do sistema"
    $python = "python"
}

# -- Guard rail: tunel publico exige autenticacao -------------------
$authEnabled = [string]$env:IDS_AUTH
$authEnabled = $authEnabled.Trim().ToLower()
if (-not $authEnabled) {
    $authEnabled = "true"
    $env:IDS_AUTH = "true"
    Write-OK "IDS_AUTH nao estava definido - habilitando autenticacao para exposicao publica"
} elseif ($authEnabled -ne "true" -and -not $AllowInsecure.IsPresent) {
    Write-Err "Exposicao publica bloqueada: IDS_AUTH=$authEnabled."
    Write-Host "  Para publicar com seguranca, rode novamente com IDS_AUTH=true." -ForegroundColor Yellow
    Write-Host "  So use -AllowInsecure em laboratorio totalmente isolado." -ForegroundColor Yellow
    exit 1
} elseif ($authEnabled -ne "true" -and $AllowInsecure.IsPresent) {
    Write-Warn "Bypass explicito aceito - exposicao publica SEM auth. Use apenas em ambiente isolado."
}

# -- Inicia Flask em background -------------------------------------
Write-Step "Iniciando NetGuard IDS na porta $Port"
$env:IDS_PORT = $Port
$env:IDS_HOST = "127.0.0.1"
$flaskJob = Start-Process $python -ArgumentList "$projectDir\app.py" `
    -WorkingDirectory $projectDir -PassThru -WindowStyle Hidden
Write-OK "Flask iniciado (PID $($flaskJob.Id))"
Start-Sleep 3

# -- Inicia ngrok em background -------------------------------------
Write-Step "Abrindo tunel ngrok para a porta $Port"
$ngrokJob = Start-Process ngrok -ArgumentList "http $Port" -PassThru -WindowStyle Hidden
Start-Sleep 4

# -- Obtem URL publica via API local do ngrok -----------------------
Write-Step "Obtendo URL publica"
$publicUrl = $null
for ($i = 0; $i -lt 10; $i++) {
    try {
        $resp = Invoke-RestMethod "http://127.0.0.1:4040/api/tunnels" -ErrorAction SilentlyContinue
        $publicUrl = ($resp.tunnels | Where-Object { $_.proto -eq "https" } | Select-Object -First 1).public_url
        if ($publicUrl) { break }
    } catch {}
    Start-Sleep 1
}

if (-not $publicUrl) {
    Write-Warn "Nao foi possivel obter a URL automaticamente. Abra http://127.0.0.1:4040 para ver."
} else {
    Write-OK "URL publica obtida"
    Write-Host ""
    Write-Host "  NetGuard IDS esta acessivel publicamente." -ForegroundColor Green
    Write-Host ""
    Write-Host "  URL publica:   $publicUrl" -ForegroundColor Blue
    Write-Host "  Link de trial: $publicUrl/trial/<token>" -ForegroundColor Cyan
    Write-Host "  Dashboard:     $publicUrl" -ForegroundColor Cyan
    Write-Host "  Painel ngrok:  http://127.0.0.1:4040" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Para gerar um trial, acesse o dashboard e abra a aba Trials." -ForegroundColor White
    Write-Host "  O link gerado ja vai usar essa URL publica." -ForegroundColor DarkGray
    Write-Host ""

    $publicUrl | Set-Clipboard
    Write-Host "  (URL copiada para o clipboard)" -ForegroundColor DarkGray

    Start-Process $publicUrl
}

Write-Host "  Pressione CTRL+C para encerrar tudo." -ForegroundColor Yellow
Write-Host ""

# -- Aguarda e limpa ao sair ----------------------------------------
try {
    Wait-Process -Id $flaskJob.Id
} finally {
    Write-Host "`n  Encerrando..." -ForegroundColor Yellow
    Stop-Process -Id $flaskJob.Id -ErrorAction SilentlyContinue
    Stop-Process -Id $ngrokJob.Id -ErrorAction SilentlyContinue
    Write-Host "  Encerrado." -ForegroundColor Green
}
