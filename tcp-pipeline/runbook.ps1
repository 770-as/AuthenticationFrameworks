# runbook.ps1 — TCP pipeline capture + handoff (Pattern A)
param(
    [switch]$SkipDocker,
    [int]$WaitMin = 15
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repo

Write-Host "=== Pattern A: TCP Pipeline ===" -ForegroundColor Cyan
Write-Host "Repo root: $repo"
Write-Host "1. Run instant-replay first (optional but recommended)"
Write-Host "2. Ensure docker compose is listening (HANDOFF_LISTEN=:17494)"
Write-Host "3. Rebuild JVM agent + capture with -InstantReplay"
Write-Host ""

if (-not $SkipDocker) {
    Write-Host "[tcp] Starting bot listener..."
    Start-Process powershell -ArgumentList @(
        "-NoExit", "-Command",
        "cd '$repo'; `$env:HANDOFF_LISTEN=':17494'; `$env:REQUIRE_CAPTURED_MACHINE_INFO='1'; docker compose -f OAuthIdp_SessionJagex/tcp-pipeline/docker-compose.yml up --build"
    )
    Start-Sleep -Seconds 8
}

& powershell -File (Join-Path $repo "tools\agent\build.ps1")
& powershell -File (Join-Path $repo "tools\agent\netns-capture\capture-netns.ps1") -InstantReplay -NoDeploy -WaitMin $WaitMin
