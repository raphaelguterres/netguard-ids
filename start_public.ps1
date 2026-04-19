# NetGuard IDS — Iniciar com túnel público (ngrok)
# Uso: .\start_public.ps1
# Requer ngrok instalado: winget install ngrok.ngrok
#   ou baixe em https://ngrok.com/download

param(
    [string]$Port  = "5000",
    [string]$Token = ""        # ngrok authtoken (opcional se já configurado)
)

$ErrorActionPreference = "Stop"

function Write-Step  { param($m) Write-Host "`n  ▶ $m" -ForegroundColor Cyan }
function Write-OK    { param($m) Write-Host "  ✔ $m"  -ForegroundColor Green }
function Write-Warn  { param($m) Write-Host "  ⚠ $m"  -ForegroundColor Yellow }

# ── Verifica ngrok ────────────────────────────────────────────────
Write-Step "Verificando ngrok"
$ngrok = (Get-Command ngrok -ErrorAction SilentlyContinue)?.Source
if (-not $ngrok) {
    Write-Host ""
    Write-Host "  ngrok não encontrado. Instale com:" -ForegroundColor Red
    Write-Host "    winget install ngrok.ngrok" -ForegroundColor Cyan
    Write-Host "  ou baixe em: https://ngrok.com/download" -ForegroundColor Cyan
    Write-Host ""
    exit 1
}
Write-OK "ngrok encontrado: $ngrok"

# ── Authtoken (se passado como parâmetro) ─────────────────────────
if ($Token) {
    Write-Step "Configurando authtoken"
    & ngrok config add-authtoken $Token
    Write-OK "Token configurado"
}

# ── Pasta do projeto ──────────────────────────────────────────────
$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$python     = "$projectDir\venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    Write-Warn "venv não encontrado — usando python do sistema"
    $python = "python"
}

# ── Inicia Flask em background ────────────────────────────────────
Write-Step "Iniciando NetGuard IDS na porta $Port"
$env:IDS_PORT = $Port
$env:IDS_HOST = "127.0.0.1"
$flaskJob = Start-Process $python -ArgumentList "$projectDir\app.py" `
    -WorkingDirectory $projectDir -PassThru -WindowStyle Hidden
Write-OK "Flask iniciado (PID $($flaskJob.Id))"
Start-Sleep 3

# ── Inicia ngrok em background ────────────────────────────────────
Write-Step "Abrindo túnel ngrok → porta $Port"
$ngrokJob = Start-Process ngrok -ArgumentList "http $Port" -PassThru -WindowStyle Hidden
Start-Sleep 4

# ── Obtém URL pública via API local do ngrok ──────────────────────
Write-Step "Obtendo URL pública"
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
    Write-Warn "Não conseguiu obter URL automaticamente. Abra http://127.0.0.1:4040 para ver."
} else {
    Write-OK "URL pública obtida!"
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "  ║  NetGuard IDS está acessível publicamente!           ║" -ForegroundColor Green
    Write-Host "  ╚══════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "  🌐 URL pública:   $publicUrl" -ForegroundColor Blue
    Write-Host "  🔗 Link de trial: $publicUrl/trial/<token>" -ForegroundColor Cyan
    Write-Host "  📊 Dashboard:     $publicUrl" -ForegroundColor Cyan
    Write-Host "  🔍 ngrok painel:  http://127.0.0.1:4040" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Para gerar um trial, acesse o dashboard e vá na aba 🔗 Trials." -ForegroundColor White
    Write-Host "  O link gerado já vai usar essa URL pública." -ForegroundColor DarkGray
    Write-Host ""

    # Copia URL para o clipboard
    $publicUrl | Set-Clipboard
    Write-Host "  (URL copiada para o clipboard)" -ForegroundColor DarkGray

    # Abre o dashboard no browser
    Start-Process $publicUrl
}

Write-Host "  Pressione CTRL+C para encerrar tudo." -ForegroundColor Yellow
Write-Host ""

# ── Aguarda e limpa ao sair ───────────────────────────────────────
try {
    Wait-Process -Id $flaskJob.Id
} finally {
    Write-Host "`n  Encerrando..." -ForegroundColor Yellow
    Stop-Process -Id $flaskJob.Id  -ErrorAction SilentlyContinue
    Stop-Process -Id $ngrokJob.Id  -ErrorAction SilentlyContinue
    Write-Host "  Encerrado." -ForegroundColor Green
}
