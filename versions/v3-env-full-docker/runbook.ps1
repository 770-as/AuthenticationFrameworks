# runbook.ps1 — full env injection handoff (Pattern C)
param(
    [switch]$Sim,
    [switch]$DockerUp,
    [int]$WaitMin = 15
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repo

Write-Host "=== Pattern C: .env + Full Docker Environment ===" -ForegroundColor Cyan
Write-Host "Repo root: $repo"
Write-Host "All login vars explicit in compose environment block"
Write-Host ""

# Capture (wire-block recommended; use -InstantReplay for host validation only)
& powershell -File tools\agent\netns-capture\capture-netns.ps1 -NoDeploy -WaitMin $WaitMin
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Deploy all blobs into .env (includes framedump/logindiff — slower)
$depArgs = @("-File", "tools\agent\vm-capture\pull-capture-and-deploy.ps1", "-NoDocker")
if ($Sim) { $depArgs += "-Sim" }
& powershell @depArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "[env-full-docker] .env updated. Verify session-hot vars:"
Write-Host "  GAME_SESSION_TOKEN, MACHINE_INFO_HEX, PLATFORM_INFO_HEX, RSA_PLAINTEXT_HEX"
Get-Content .env | Select-String "GAME_SESSION|MACHINE_INFO|PLATFORM_INFO"

if ($DockerUp) {
    Write-Host "[env-full-docker] starting docker with full env injection..."
    docker compose -f OAuthIdp_SessionJagex/env-full-docker/docker-compose.yml up --build -d
    docker compose -f OAuthIdp_SessionJagex/env-full-docker/docker-compose.yml logs -f bot
}
