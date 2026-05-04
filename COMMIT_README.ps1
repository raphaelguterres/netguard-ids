# COMMIT_README.ps1 -- Stage README + LICENSE + screenshots, commit, push.
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$src = "C:\Users\rapha\Downloads"
$dst = Join-Path $PSScriptRoot "docs\screenshots"

if (-not (Test-Path $dst)) {
    New-Item -ItemType Directory -Path $dst -Force | Out-Null
}

$shots = @(
    "netguard-01-godview.png",
    "netguard-02-tenant-drilldown.png",
    "netguard-03-operator-inbox.png",
    "netguard-04-host-triage.png"
)

foreach ($f in $shots) {
    $srcPath = Join-Path $src $f
    $dstPath = Join-Path $dst $f
    if (Test-Path $srcPath) {
        Move-Item -LiteralPath $srcPath -Destination $dstPath -Force
        Write-Host "  moved: $f" -ForegroundColor Gray
    } elseif (Test-Path $dstPath) {
        Write-Host "  already in place: $f" -ForegroundColor DarkGray
    } else {
        Write-Host "  MISSING: $f" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Screenshots in docs/screenshots/:" -ForegroundColor Cyan
Get-ChildItem -LiteralPath $dst -Filter "netguard-*.png" |
    ForEach-Object { Write-Host ("  {0}  {1,7} bytes" -f $_.Name, $_.Length) -ForegroundColor Gray }
Write-Host ""

git add README.md LICENSE "docs/screenshots/netguard-01-godview.png" "docs/screenshots/netguard-02-tenant-drilldown.png" "docs/screenshots/netguard-03-operator-inbox.png" "docs/screenshots/netguard-04-host-triage.png"

Write-Host "Staged for commit:" -ForegroundColor Cyan
git diff --cached --name-status
Write-Host ""

$msg = @"
docs: rewrite README as public capa, add MIT LICENSE, add screenshots

- README: new pitch (host-centric IDS/EDR/SIEM hybrid), capability table,
  quick start, endpoint agent block; preserved foundation/architecture.
- Screenshots from running app: God View, tenant drilldown, Operator Inbox,
  Host Triage View (T14 + T15 in action).
- LICENSE: MIT, 2026 Raphael Guterres.
"@

git commit -m $msg

Write-Host ""
Write-Host "Pushing to origin/main..." -ForegroundColor Cyan
git push origin main

Write-Host ""
Write-Host "Done. View at: https://github.com/raphaelguterres/netguard-ids" -ForegroundColor Green

Remove-Item -LiteralPath $PSCommandPath -ErrorAction SilentlyContinue
