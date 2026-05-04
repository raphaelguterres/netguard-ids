# NetGuard Agent -- post-build smoke test (PowerShell, Windows).
#
# IMPORTANTE: arquivo estritamente ASCII. Veja a nota equivalente em
# agent/build_agent.ps1 -- PowerShell 5.1 sem BOM le como Windows-1252
# e UTF-8 multi-byte em strings quebra o parser.
#
# Independente do build_agent.ps1: assume que dist/agent.exe ja existe
# e roda uma bateria deterministica de checks contra ele. Util pra:
#   - CI: gate de merge ("nao mergeie se o exe nao roda")
#   - Operador: validar um build recebido via download/sftp
#   - Engenharia: regressao rapida apos mexer no agent.spec
#
# Uso:
#   pwsh -NoProfile -ExecutionPolicy Bypass `
#     -File .\scripts\smoke_test_agent.ps1 `
#     [-ExePath .\agent\dist\agent.exe] `
#     [-DummyServer http://127.0.0.1:65500/api/events]
#
# Exit codes:
#   0  todos os checks PASS
#   1  arquivo nao encontrado / nao executavel
#   2  --version falhou ou retornou output inesperado
#   3  --selftest falhou
#   4  selftest contra dummy server retornou WARN errado (config bug)

[CmdletBinding()]
param(
    [string]$ExePath = "agent\dist\agent.exe",
    [string]$DummyServer = "http://127.0.0.1:65500/api/events",
    [string]$DummyApiKey = "smoke-test-not-real",
    [int]$VersionTimeoutSec = 10,
    [int]$SelftestTimeoutSec = 30
)

$ErrorActionPreference = "Stop"
$startedAt = Get-Date
$failures = @()
$passes   = @()

function Section($title) {
    Write-Host ""
    Write-Host "=== $title ===" -ForegroundColor Cyan
}

function Pass($msg) {
    $script:passes += $msg
    Write-Host "  [PASS] $msg" -ForegroundColor Green
}

function Fail($msg) {
    $script:failures += $msg
    Write-Host "  [FAIL] $msg" -ForegroundColor Red
}

# ===== 1. arquivo existe ============================================
Section "1. Binario presente"
$exe = Resolve-Path -ErrorAction SilentlyContinue $ExePath
if (-not $exe) {
    Fail "Nao encontrei $ExePath. Rode build_agent.ps1 primeiro."
    exit 1
}
$exeFile = Get-Item $exe
$sizeMB = [math]::Round($exeFile.Length / 1MB, 2)
Pass "agent.exe encontrado | $($exe.Path) | $sizeMB MB"

if ($exeFile.Length -lt 4MB) {
    Fail "Binario suspeito de incompleto: $sizeMB MB (esperado >= 4 MB)"
}

# ===== 2. metadados Windows (version_info) =========================
Section "2. Metadados Windows"
try {
    $ver = $exeFile.VersionInfo
    if ($ver.CompanyName -eq "NetGuard" -and $ver.ProductName -like "NetGuard*") {
        Pass "VersionInfo: Company=$($ver.CompanyName) Product='$($ver.ProductName)' v=$($ver.FileVersion)"
    } else {
        Fail "VersionInfo ausente ou errado (Company='$($ver.CompanyName)' Product='$($ver.ProductName)'). Confirme version_info.txt no agent.spec."
    }
} catch {
    Fail "Nao consegui ler VersionInfo: $_"
}

# ===== 3. SHA256 manifest (se presente) ============================
Section "3. SHA256 manifest"
$manifestPath = Join-Path (Split-Path $exe.Path) "agent.exe.sha256"
if (Test-Path $manifestPath) {
    $expected = (Get-Content $manifestPath -Raw).Trim().Split(" ")[0].ToLower()
    $actual = (Get-FileHash -Algorithm SHA256 -Path $exe.Path).Hash.ToLower()
    if ($expected -eq $actual) {
        Pass "SHA256 confere com agent.exe.sha256 ($actual)"
    } else {
        Fail "SHA256 NAO confere | esperado=$expected | atual=$actual"
    }
} else {
    Write-Host "  [skip] sem agent.exe.sha256 ao lado do binario" -ForegroundColor DarkGray
}

# ===== 4. --version ================================================
Section "4. agent.exe --version"
try {
    $job = Start-Job -ScriptBlock {
        param($p) & $p --version 2>&1
    } -ArgumentList $exe.Path
    if (Wait-Job $job -Timeout $VersionTimeoutSec) {
        $out = Receive-Job $job
        Remove-Job $job -Force
        $line = ($out | Out-String).Trim()
        if ($line -match "NetGuard Endpoint Agent\s+\d+\.\d+\.\d+") {
            Pass "stdout: $line"
        } else {
            Fail "Output inesperado: '$line'"
        }
    } else {
        Stop-Job $job; Remove-Job $job -Force
        Fail "Timeout em --version (>$VersionTimeoutSec s). Loader provavelmente travado."
    }
} catch {
    Fail "Erro executando --version: $_"
}

# ===== 5. --selftest contra dummy server (nao deve crashar) ========
Section "5. agent.exe --selftest"
# Geramos um config.yaml temporario apontando pra um endpoint que nao
# existe; o exit esperado eh 0 (config OK + WARN de network), nunca
# 2/3/4 (config/identity/sender errado).
$tmp = New-TemporaryFile
$tmpYaml = [System.IO.Path]::ChangeExtension($tmp.FullName, ".yaml")
Move-Item $tmp.FullName $tmpYaml
@"
server_url: "$DummyServer"
api_key: "$DummyApiKey"
interval_seconds: 30
verify_tls: false
request_timeout: 3
batch_max_events: 50
offline_buffer_max: 100
log_path: ""
credential_path: ""
enable_response_actions: false
collect_processes: false
collect_connections: false
collect_security_indicators: false
tags: []
"@ | Out-File -FilePath $tmpYaml -Encoding utf8 -NoNewline

try {
    # Forca env de dev pra que verify_tls=false + http nao seja recusado.
    $env:NETGUARD_AGENT_ENV = "test"
    $env:NETGUARD_AGENT_HOME = (Join-Path $env:TEMP "netguard-smoke")
    New-Item -ItemType Directory -Force -Path $env:NETGUARD_AGENT_HOME | Out-Null

    $job = Start-Job -ScriptBlock {
        param($p, $cfg) & $p --selftest --config $cfg 2>&1
    } -ArgumentList $exe.Path, $tmpYaml

    if (Wait-Job $job -Timeout $SelftestTimeoutSec) {
        $out = Receive-Job $job
        Remove-Job $job -Force
        $text = ($out | Out-String)
        Write-Host $text -ForegroundColor DarkGray
        if ($text -match "selftest:\s+OK") {
            Pass "selftest concluiu com 'selftest: OK'"
        } elseif ($text -match "\[FAIL\]\s+(config|identity/facts|sender init)") {
            Fail "selftest reportou falha hard: $($Matches[0])"
        } else {
            Fail "selftest nao terminou com 'selftest: OK'. Veja stdout acima."
        }
    } else {
        Stop-Job $job; Remove-Job $job -Force
        Fail "Timeout em --selftest (>$SelftestTimeoutSec s)"
    }
} finally {
    Remove-Item $tmpYaml -ErrorAction SilentlyContinue
    if (Test-Path $env:NETGUARD_AGENT_HOME) {
        Remove-Item -Recurse -Force $env:NETGUARD_AGENT_HOME -ErrorAction SilentlyContinue
    }
    Remove-Item Env:\NETGUARD_AGENT_HOME -ErrorAction SilentlyContinue
    Remove-Item Env:\NETGUARD_AGENT_ENV  -ErrorAction SilentlyContinue
}

# ===== Resumo ======================================================
Section "Resumo"
$dur = [math]::Round((New-TimeSpan -Start $startedAt -End (Get-Date)).TotalSeconds, 1)
Write-Host "PASS:    $($passes.Count)" -ForegroundColor Green
Write-Host "FAIL:    $($failures.Count)" -ForegroundColor $(if ($failures.Count -eq 0) {"Green"} else {"Red"})
Write-Host "Duracao: ${dur}s"

if ($failures.Count -gt 0) {
    Write-Host ""
    Write-Host "Falhas:" -ForegroundColor Red
    foreach ($f in $failures) { Write-Host "  - $f" -ForegroundColor Red }
    exit 3
}
exit 0
