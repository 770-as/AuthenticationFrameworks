# runbook.ps1 — host instant replay validation (Pattern 0)
param(
    [int]$WaitMin = 15
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repo

Write-Host "=== Pattern 0: Host Instant Replay ===" -ForegroundColor Cyan
Write-Host "Wire-block capture + loginsim -login-only (no Docker)"
Write-Host "Repo root: $repo"
Write-Host ""

$loginsimBin = Join-Path $repo "tools\agent\build\loginsim.exe"
if (-not (Test-Path $loginsimBin)) {
    Write-Host "[instant-replay] building loginsim.exe..."
    go build -o $loginsimBin ./cmd/loginsim
    if ($LASTEXITCODE -ne 0) { throw "loginsim build failed" }
}

& powershell -File (Join-Path $repo "tools\agent\netns-capture\capture-netns.ps1") -InstantReplay -NoDeploy -WaitMin $WaitMin
exit $LASTEXITCODE
