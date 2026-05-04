# SETUP_GEOLITE2.ps1
# Baixa e instala GeoLite2-City + GeoLite2-ASN (MaxMind) no diretorio
# ./geolite2/, substituindo os placeholders. Restart do Flask depois
# pra que o lazy-load do geo_ip.py pegue os arquivos novos.
#
# Pre-requisito:
#   1. Conta gratuita em https://www.maxmind.com/en/geolite2/signup
#   2. License key gerada em "My Account > Manage License Keys"
#
# Uso:
#   .\SETUP_GEOLITE2.ps1 -LicenseKey "SUA_KEY_AQUI"
#
# Opcional:
#   -SkipAsn       pula o GeoLite2-ASN (so City)
#   -KeepArchives  mantem os .tar.gz baixados (default: apaga)

param(
    [Parameter(Mandatory=$true)]
    [string]$LicenseKey,

    [switch]$SkipAsn = $false,
    [switch]$KeepArchives = $false
)

$ErrorActionPreference = "Stop"

$ProjectRoot = $PSScriptRoot
$GeoDir = Join-Path $ProjectRoot "geolite2"

if (-not (Test-Path $GeoDir)) {
    New-Item -ItemType Directory -Path $GeoDir | Out-Null
}

function Download-MaxMind {
    param([string]$Edition, [string]$OutFile)

    $url = "https://download.maxmind.com/app/geoip_download" +
           "?edition_id=$Edition" +
           "&license_key=$LicenseKey" +
           "&suffix=tar.gz"

    Write-Host "  baixando $Edition..." -ForegroundColor DarkGray
    try {
        Invoke-WebRequest -Uri $url -OutFile $OutFile -UseBasicParsing
    } catch {
        throw "Download de $Edition falhou: $_. Verifique LicenseKey e conexao."
    }

    $size = (Get-Item $OutFile).Length
    if ($size -lt 100KB) {
        Remove-Item $OutFile -Force
        throw "$Edition retornou apenas $size bytes - LicenseKey invalida?"
    }
    Write-Host ("  $Edition OK ({0:N1} MB)" -f ($size/1MB)) -ForegroundColor Green
}

function Extract-Mmdb {
    param([string]$Archive, [string]$Edition)

    $tempDir = Join-Path $env:TEMP ("geolite2_" + [guid]::NewGuid().ToString("N").Substring(0,8))
    New-Item -ItemType Directory -Path $tempDir | Out-Null

    try {
        Write-Host "  extraindo..." -ForegroundColor DarkGray
        tar -xzf $Archive -C $tempDir
        if ($LASTEXITCODE -ne 0) { throw "tar -xzf falhou" }

        $mmdb = Get-ChildItem -Path $tempDir -Filter "*.mmdb" -Recurse | Select-Object -First 1
        if (-not $mmdb) { throw "Nenhum .mmdb encontrado em $Archive" }

        $dest = Join-Path $GeoDir "$Edition.mmdb"
        Move-Item -Path $mmdb.FullName -Destination $dest -Force

        $size = (Get-Item $dest).Length
        Write-Host ("  $Edition.mmdb instalado ({0:N1} MB)" -f ($size/1MB)) -ForegroundColor Green
    } finally {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ""
Write-Host "=== Setup GeoLite2 ===" -ForegroundColor Cyan
Write-Host "Destino: $GeoDir" -ForegroundColor DarkGray
Write-Host ""

# ── City ────────────────────────────────────────────────────────────
Write-Host "[1] GeoLite2-City" -ForegroundColor Cyan
$cityArchive = Join-Path $GeoDir "GeoLite2-City.tar.gz"
Download-MaxMind -Edition "GeoLite2-City" -OutFile $cityArchive
Extract-Mmdb -Archive $cityArchive -Edition "GeoLite2-City"
if (-not $KeepArchives) { Remove-Item $cityArchive -Force }

# ── ASN ─────────────────────────────────────────────────────────────
if (-not $SkipAsn) {
    Write-Host ""
    Write-Host "[2] GeoLite2-ASN" -ForegroundColor Cyan
    $asnArchive = Join-Path $GeoDir "GeoLite2-ASN.tar.gz"
    Download-MaxMind -Edition "GeoLite2-ASN" -OutFile $asnArchive
    Extract-Mmdb -Archive $asnArchive -Edition "GeoLite2-ASN"
    if (-not $KeepArchives) { Remove-Item $asnArchive -Force }
}

# ── Validacao ───────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== Validacao ===" -ForegroundColor Cyan
Get-ChildItem $GeoDir -Filter "*.mmdb" | Format-Table Name, @{N='Size(MB)';E={'{0:N1}' -f ($_.Length/1MB)}}, LastWriteTime -AutoSize

Write-Host "Done." -ForegroundColor Green
Write-Host ""
Write-Host "Proximos passos:" -ForegroundColor Yellow
Write-Host "  1. Reinicie o Flask (Ctrl+C, depois 'python app.py')"
Write-Host "  2. Confira /api/admin/geolite2/status -> city_loaded:true"
Write-Host "  3. Abra God View -> drill-down de qualquer tenant"
