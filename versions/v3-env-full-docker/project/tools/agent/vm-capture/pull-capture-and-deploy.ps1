# pull-capture-and-deploy.ps1 — import VM capture-out into .env, test login, start Docker bot.
#
# Usage:
#   powershell -File tools\agent\vm-capture\pull-capture-and-deploy.ps1
#   powershell -File tools\agent\vm-capture\pull-capture-and-deploy.ps1 -Sim
#   powershell -File tools\agent\vm-capture\pull-capture-and-deploy.ps1 -WaitMin 15 -Sim

param(
    [int]$WaitMin = 0,
    [switch]$Sim,
    [switch]$DockerUp,
    [switch]$NoDocker
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
Set-Location $repo

$capDir = Join-Path $repo "tools\agent\vm-bundle\capture-out"
$cc = Join-Path $capDir "cc_strings.txt"
$frame = Join-Path $capDir "login_frame.txt"
$rsa = Join-Path $capDir "rsa_plaintext.txt"

function Test-CaptureReady {
    if (-not (Test-Path $cc)) { return $false }
    $c = Get-Content $cc -Raw
    return ($c -match '#1\s+\S+')
}

if ($WaitMin -gt 0) {
    Write-Host "[pull] waiting up to ${WaitMin}m for $capDir ..."
    $deadline = (Get-Date).AddMinutes($WaitMin)
    while ((Get-Date) -lt $deadline) {
        if (Test-CaptureReady) { break }
        if (Test-Path $frame) { break }
        Start-Sleep -Seconds 2
    }
}

if (-not (Test-CaptureReady) -and -not (Test-Path $frame)) {
    Write-Host "[pull] no capture in $capDir" -ForegroundColor Red
    Write-Host "VM:  bash ~/local-capture/linux/run-capture.sh"
    Write-Host "Host (if VM Jagex Launcher fails):"
    Write-Host "     powershell -File tools\agent\vm-capture\capture-on-host.ps1 -Sim -DockerUp"
    exit 1
}

# Mirror into profile for refresh-credentials / framedump tools
$homeDir = $env:USERPROFILE
Copy-Item $cc (Join-Path $homeDir "cc_strings.txt") -Force -ErrorAction SilentlyContinue
if (Test-Path $frame) { Copy-Item $frame (Join-Path $homeDir "login_frame.txt") -Force }
if (Test-Path $rsa) { Copy-Item $rsa (Join-Path $homeDir "rsa_plaintext.txt") -Force }

Write-Host "[pull] capture files:"
if (Test-Path $cc) { Get-Content $cc | Select-Object -First 15 }
Write-Host ""

$refreshArgs = @("-File", (Join-Path $repo "tools\agent\refresh-credentials.ps1"), "-NoMint")
if (Test-Path $frame) { $refreshArgs += "-FromCapture", $frame }
if ($Sim) { $refreshArgs += "-Sim" }
& powershell @refreshArgs
$exit = $LASTEXITCODE

if ($NoDocker) { exit $exit }

if ($DockerUp -or ($Sim -and $exit -eq 0)) {
    Write-Host "[pull] docker compose up (--env-file .env)..."
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Host "[pull] docker not in PATH - skip container start" -ForegroundColor Yellow
        exit $exit
    }
    docker compose --env-file .env up -d --build
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Write-Host "[pull] container started: revbot-$($env:BOT_ID)"
}

exit $exit
