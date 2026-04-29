# NetGuard Agent Windows service installer.
#
# Run from an elevated PowerShell prompt on the endpoint:
#   powershell -ExecutionPolicy Bypass -File .\install_agent.ps1 -Start

[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\NetGuard\Agent",
    [string]$ExePath = "",
    [string]$ConfigPath = ".\config.yaml",
    [string]$ServiceName = "NetGuardAgent",
    [switch]$Start,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
    if (-not $principal.IsInRole($adminRole)) {
        throw "Run this installer from an elevated PowerShell prompt."
    }
}

function Resolve-AgentExe {
    param([string]$Candidate)
    $scriptDir = $PSScriptRoot
    $candidates = @()
    if ($Candidate) { $candidates += $Candidate }
    $candidates += (Join-Path $scriptDir "dist\agent.exe")
    $candidates += (Join-Path $scriptDir "agent.exe")
    foreach ($item in $candidates) {
        if ($item -and (Test-Path -LiteralPath $item)) {
            return (Resolve-Path -LiteralPath $item).Path
        }
    }
    throw "agent.exe not found. Build first with build_agent.ps1 -WithService."
}

function Stop-ServiceIfPresent {
    param([string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne "Stopped") {
        Stop-Service -Name $Name -Force -ErrorAction Stop
        $svc.WaitForStatus("Stopped", "00:00:30")
    }
}

Assert-Admin

$sourceExe = Resolve-AgentExe -Candidate $ExePath
$installDirFull = [IO.Path]::GetFullPath($InstallDir)
$targetExe = Join-Path $installDirFull "agent.exe"
$targetConfig = Join-Path $installDirFull "config.yaml"
$stateDir = Join-Path $installDirFull "state"

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing -and -not $Force) {
    throw "Service $ServiceName already exists. Re-run with -Force to upgrade in place."
}

if ($existing) {
    Stop-ServiceIfPresent -Name $ServiceName
}

New-Item -ItemType Directory -Path $installDirFull -Force | Out-Null
New-Item -ItemType Directory -Path $stateDir -Force | Out-Null

Copy-Item -LiteralPath $sourceExe -Destination $targetExe -Force
if (Test-Path -LiteralPath $ConfigPath) {
    Copy-Item -LiteralPath $ConfigPath -Destination $targetConfig -Force
} elseif (-not (Test-Path -LiteralPath $targetConfig)) {
    throw "config.yaml not found. Pass -ConfigPath or create $targetConfig."
}

# Lock down install/state files. LocalSystem and Administrators retain access.
& icacls $installDirFull /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
& icacls $installDirFull /remove:g "Users" "Authenticated Users" "Everyone" 2>$null | Out-Null

[Environment]::SetEnvironmentVariable("NETGUARD_AGENT_CONFIG", $targetConfig, "Machine")
[Environment]::SetEnvironmentVariable("NETGUARD_AGENT_HOME", $stateDir, "Machine")

if (-not $existing) {
    & $targetExe --service install
    if ($LASTEXITCODE -ne 0) {
        throw "Service install failed with exit code $LASTEXITCODE."
    }
}

& sc.exe config $ServiceName start= delayed-auto | Out-Null
& sc.exe description $ServiceName "NetGuard Endpoint Agent telemetry and response sensor" | Out-Null

if ($Start) {
    Start-Service -Name $ServiceName
}

Write-Host "NetGuard Agent installed." -ForegroundColor Green
Write-Host "Service: $ServiceName"
Write-Host "Binary:  $targetExe"
Write-Host "Config:  $targetConfig"
Write-Host "State:   $stateDir"
