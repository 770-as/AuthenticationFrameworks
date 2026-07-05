# runbook.ps1 — .env file handoff (Pattern B)
param(
    [switch]$Sim,
    [switch]$DockerUp,
    [int]$WaitMin = 15
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repo

Write-Host "=== Pattern B: .env File Handoff ===" -ForegroundColor Cyan
Write-Host "Repo root: $repo"
Write-Host "Capture -> capture-out -> .env -> docker compose"
Write-Host ""

$capArgs = @("-File", "tools\agent\netns-capture\capture-netns.ps1", "-NoDeploy", "-WaitMin", $WaitMin)
if (-not $Sim) { $capArgs += "-InstantReplay" }
& powershell @capArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$depArgs = @("-File", "tools\agent\vm-capture\pull-capture-and-deploy.ps1", "-NoDocker")
if ($Sim) { $depArgs += "-Sim" }
& powershell @depArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($DockerUp) {
    Write-Host "[env-file] starting docker..."
    docker compose -f OAuthIdp_SessionJagex/env-file/docker-compose.yml up --build -d
}
