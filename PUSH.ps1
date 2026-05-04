# ============================================================
# NetGuard IDS - commit + push das mudancas de design
# Uso: powershell -ExecutionPolicy Bypass -File .\PUSH.ps1
# ============================================================

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host ""
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host "  NetGuard - git commit + push" -ForegroundColor Yellow
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host ""

# 1. Remove lock se existir
if (Test-Path ".git/index.lock") {
    Remove-Item ".git/index.lock" -Force
    Write-Host ">> lock removido" -ForegroundColor DarkGray
}

# 2. Confirma branch
$branch = git rev-parse --abbrev-ref HEAD
Write-Host ">> branch: $branch" -ForegroundColor Cyan

# 3. Mostra resumo do que vai entrar
Write-Host ">> arquivos modificados:" -ForegroundColor Cyan
git status --short | Select-Object -First 30

# 4. Stage tudo (gitignore ja filtra noise)
git add -A

# 5. Verifica se tem o que commitar
$staged = git diff --cached --shortstat
if (-not $staged) {
    Write-Host ">> nada a commitar." -ForegroundColor Yellow
    exit 0
}
Write-Host ">> staged: $staged" -ForegroundColor Green

# 6. Commit message
$msg = @"
ui: Apple Pro design + day/night theme toggle

Visual redesign across landing, login, pricing, welcome, dashboard,
SOC views, admin and host triage. New token system: midnight navy +
champagne accent. All buttons, cards, hairlines, typography aligned.

- enterprise.css: dark + light token blocks (Apple Pro day/night)
- dashboard-enterprise.css, soc-dashboard.css, admin-enterprise.css:
  matching token rewrite
- netguard.css: replaced Apple-blue accent with champagne
- new theme-toggle.js: persistent <html data-theme> + body.theme-light,
  prefers-color-scheme aware, mounts a sun/moon button in headers
- inline-styled templates (host_triage, admin_dashboard, operator_inbox)
  ganharam font Inter + light theme block
- engine/playbook_engine.py: singleton invalida db_path orfao entre
  testes (state-leak fix)
- RUN_LOCAL.ps1: secret de dev + DATABASE_URL cleanup
- RUN_TESTS.ps1: runner pytest com escopo (kill / fast / verbose / file)
"@

# 7. Commit
git commit -m $msg
if ($LASTEXITCODE -ne 0) {
    Write-Host ">> commit falhou" -ForegroundColor Red
    exit 1
}
Write-Host ">> commit ok" -ForegroundColor Green

# 8. Push
Write-Host ">> push origin $branch ..." -ForegroundColor Cyan
git push origin $branch
if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "==============================================" -ForegroundColor Green
    Write-Host "  PUSHED com sucesso." -ForegroundColor Green
    Write-Host "==============================================" -ForegroundColor Green
} else {
    Write-Host ">> push falhou. Verifique credenciais GitHub." -ForegroundColor Red
    Write-Host "   Se for 1a vez nesta maquina, rode:" -ForegroundColor DarkGray
    Write-Host "   gh auth login   (com GitHub CLI)" -ForegroundColor DarkGray
    Write-Host "   ou configure um Personal Access Token." -ForegroundColor DarkGray
    exit 1
}
