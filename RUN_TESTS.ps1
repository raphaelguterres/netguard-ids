# ============================================================
# NetGuard IDS - rodar suite de testes pytest local
# Uso: powershell -ExecutionPolicy Bypass -File .\RUN_TESTS.ps1
# ============================================================

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot
Set-Location $ProjectRoot

Write-Host ""
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host "  NetGuard IDS - pytest" -ForegroundColor Yellow
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host ""

# Ativa venv (assume que ja existe via RUN_LOCAL.ps1)
$activate = ".\.venv\Scripts\Activate.ps1"
if (-not (Test-Path $activate)) {
    Write-Host "!! venv nao encontrada. Rode RUN_LOCAL.ps1 primeiro." -ForegroundColor Red
    exit 1
}
& $activate

# Garante pytest e timeout instalados
& python -m pip install pytest pytest-timeout --quiet 2>&1 | Out-Null

# Variaveis de ambiente para testes (sem Postgres, sem auth, dev mode)
if (Test-Path Env:DATABASE_URL) { Remove-Item Env:DATABASE_URL }
$env:TOKEN_SIGNING_SECRET   = "pytest-local-secret-not-for-production-32chars-xxx"
$env:SECRET_KEY             = "pytest-local-flask-secret"
$env:IDS_ENV                = "testing"
$env:NETGUARD_ENV           = "testing"
$env:FLASK_ENV              = "testing"
$env:IDS_AUTH               = "false"
$env:IDS_DASHBOARD_AUTH     = "false"
$env:HTTPS_ONLY             = "false"
$env:IDS_HTTPS              = "false"
$env:NETGUARD_DB_BACKEND    = "sqlite"

Write-Host ">> Ambiente configurado para teste" -ForegroundColor Green
Write-Host ""

# Determina escopo via argumento
$scope = $args[0]
if (-not $scope) { $scope = "all" }

switch ($scope) {
    "kill" {
        Write-Host ">> Rodando apenas testes de Kill Operation / agent actions / auto-block" -ForegroundColor Cyan
        & python -m pytest tests/test_auto_block.py tests/test_agent.py tests/test_agent_server.py tests/test_endpoint_agent.py tests/test_custom_rules.py tests/test_agent_xdr.py tests/test_xdr_pipeline.py -v --tb=short --timeout=30
    }
    "fast" {
        Write-Host ">> Rodando suite rapida (sem testes lentos)" -ForegroundColor Cyan
        & python -m pytest tests/ --tb=line -q --timeout=15 -p no:cacheprovider --continue-on-collection-errors -m "not slow"
    }
    "all" {
        Write-Host ">> Rodando suite completa (855 testes, ~15s)" -ForegroundColor Cyan
        & python -m pytest tests/ --tb=line -q --timeout=30 -p no:cacheprovider --continue-on-collection-errors
    }
    "verbose" {
        Write-Host ">> Rodando suite completa com output detalhado" -ForegroundColor Cyan
        & python -m pytest tests/ -v --tb=short --timeout=30 -p no:cacheprovider --continue-on-collection-errors
    }
    default {
        Write-Host ">> Rodando arquivo/pasta especifico: $scope" -ForegroundColor Cyan
        & python -m pytest $scope -v --tb=short --timeout=30 -p no:cacheprovider
    }
}

Write-Host ""
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host "  pytest finalizado" -ForegroundColor Yellow
Write-Host "==============================================" -ForegroundColor Yellow
