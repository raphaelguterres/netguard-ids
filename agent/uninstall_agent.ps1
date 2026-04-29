# NetGuard Agent Windows service uninstaller.
#
# Run from an elevated PowerShell prompt on the endpoint:
#   powershell -ExecutionPolicy Bypass -File .\uninstall_agent.ps1

[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\NetGuard\Agent",
    [string]$ServiceName = "NetGuardAgent",
    [switch]$KeepState,
    [switch]$KeepConfig
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
    if (-not $principal.IsInRole($adminRole)) {
        throw "Run this uninstaller from an elevated PowerShell prompt."
    }
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

$installDirFull = [IO.Path]::GetFullPath($InstallDir)
$targetExe = Join-Path $installDirFull "agent.exe"
$targetConfig = Join-Path $installDirFull "config.yaml"
$stateDir = Join-Path $installDirFull "state"

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Stop-ServiceIfPresent -Name $ServiceName
    if (Test-Path -LiteralPath $targetExe) {
        & $targetExe --service remove
        if ($LASTEXITCODE -ne 0) {
            throw "Service removal failed with exit code $LASTEXITCODE."
        }
    } else {
        & sc.exe delete $ServiceName | Out-Null
    }
}

[Environment]::SetEnvironmentVariable("NETGUARD_AGENT_CONFIG", $null, "Machine")
[Environment]::SetEnvironmentVariable("NETGUARD_AGENT_HOME", $null, "Machine")

if (-not $KeepState -and (Test-Path -LiteralPath $stateDir)) {
    Remove-Item -LiteralPath $stateDir -Recurse -Force
}
if (-not $KeepConfig -and (Test-Path -LiteralPath $targetConfig)) {
    Remove-Item -LiteralPath $targetConfig -Force
}
if (Test-Path -LiteralPath $targetExe) {
    Remove-Item -LiteralPath $targetExe -Force
}

$remaining = @()
if (Test-Path -LiteralPath $installDirFull) {
    $remaining = @(Get-ChildItem -LiteralPath $installDirFull -Force -ErrorAction SilentlyContinue)
}
if ((Test-Path -LiteralPath $installDirFull) -and $remaining.Count -eq 0) {
    Remove-Item -LiteralPath $installDirFull -Force
}

Write-Host "NetGuard Agent removed." -ForegroundColor Green
if ($KeepState) { Write-Host "State kept:  $stateDir" }
if ($KeepConfig) { Write-Host "Config kept: $targetConfig" }
