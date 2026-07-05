# capture-netns.ps1 - one-shot: windows-netgate (proxy egress) -> native capture -> stop -> deploy.
#
# Native Jagex Launcher + RuneLite on real Windows, all traffic forced through PROXY_URL
# via Wintun/tun2socks (no Proxifier, no Wine). Tokens land in capture-out/, then
# pull-capture-and-deploy updates .env and optionally starts Docker.
#
# Re-launches itself elevated (routing changes need admin). UAC prompt once.
#
# Usage:
#   powershell -File tools\agent\netns-capture\capture-netns.ps1 -Sim -DockerUp
#   powershell -File tools\agent\netns-capture\capture-netns.ps1 -WaitMin 15 -Sim
#   powershell -File tools\agent\netns-capture\capture-netns.ps1 -InstantReplay -NoDeploy
#     (wire-block capture + immediate loginsim -replay-capture — correct bot path)
#   powershell -File tools\agent\netns-capture\capture-netns.ps1 -AllowWireLogin
#     (diagnostic only: RuneLite enters game but pk is BURNED — do NOT deploy for bot)

param(
    [switch]$Sim,
    [switch]$DockerUp,
    [int]$WaitMin = 10,
    [switch]$NoPrompt,
    [switch]$NoDeploy,
    [switch]$NoElevate,
    [switch]$AllowWireLogin,
    [switch]$InstantReplay
)

$ErrorActionPreference = "Stop"
$log = "[capture-netns]"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$netgate = Join-Path $PSScriptRoot "windows-netgate.ps1"
$capture = Join-Path $repo "tools\agent\vm-capture\capture-on-host.ps1"
$deploy = Join-Path $repo "tools\agent\vm-capture\pull-capture-and-deploy.ps1"

function Write-Log([string]$m) { Write-Host "$log $m" }

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Elevated {
    if ($NoElevate -or (Test-IsAdmin)) { return }
    Write-Log "re-launching elevated (UAC)..."
    $a = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $PSCommandPath, "-NoElevate")
    if ($Sim) { $a += "-Sim" }
    if ($DockerUp) { $a += "-DockerUp" }
    if ($NoPrompt) { $a += "-NoPrompt" }
    if ($NoDeploy) { $a += "-NoDeploy" }
    if ($AllowWireLogin) { $a += "-AllowWireLogin" }
    if ($InstantReplay) { $a += "-InstantReplay" }
    $a += "-WaitMin", $WaitMin
    $proc = Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $a -Wait -PassThru
    exit $proc.ExitCode
}

function Read-EnvProp([string]$path, [string]$key) {
    if (-not (Test-Path $path)) { return "" }
    foreach ($line in Get-Content $path) {
        if ($line -match "^\s*$([regex]::Escape($key))=(.*)$") { return $Matches[1].Trim() }
    }
    return ""
}

function Show-Preflight {
    $envPath = Join-Path $repo ".env"
    $proxyUrl = Read-EnvProp $envPath "PROXY_URL"
    if (-not $proxyUrl) { throw "PROXY_URL missing in $envPath" }
    Write-Log "PROXY_URL set (redacted): $($proxyUrl -replace '://[^@]+@', '://***@')"
    try {
        $hostIp = (Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 10).Trim()
        Write-Log "host direct IP (before netgate): $hostIp"
    } catch {
        Write-Log "could not read host IP (offline?): $($_.Exception.Message)"
    }
    if (Get-Process Proxifier -ErrorAction SilentlyContinue) {
        Write-Host "$log WARNING: Proxifier is running - exit it (File -> Exit) or it may fight the tunnel." -ForegroundColor Yellow
    }
}

function Invoke-Netgate([string]$action) {
    & powershell -NoProfile -ExecutionPolicy Bypass -File $netgate "-$action"
    if ($LASTEXITCODE -ne 0) { throw "windows-netgate -$action failed (exit $LASTEXITCODE)" }
}

Ensure-Elevated
Set-Location $repo

if ($AllowWireLogin -and $InstantReplay) {
    throw "Use -InstantReplay (bot path) OR -AllowWireLogin (diagnostic), not both."
}
if ($InstantReplay -and -not $Sim) { $Sim = $true }

Show-Preflight

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CAPTURE via windows-netgate (proxy IP)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$captureOk = $false
try {
    Invoke-Netgate "Start"
    Write-Log "netgate active - starting native capture (click steps in the other prompts)..."
    $capArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $capture,
        "-WaitMin", $WaitMin, "-ViaProxy")
    if ($NoPrompt) { $capArgs += "-NoPrompt" }
    if ($AllowWireLogin) { $capArgs += "-AllowWireLogin" }
    if ($InstantReplay) { $capArgs += "-InstantReplay" }
    & powershell @capArgs
    if ($LASTEXITCODE -ne 0) { throw "capture-on-host failed (exit $LASTEXITCODE)" }
    $captureOk = $true
} finally {
    Write-Log "stopping windows-netgate (restore normal routing)..."
    try { Invoke-Netgate "Stop" } catch {
        Write-Host "$log WARN: netgate -Stop failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "$log If network is broken, run: powershell -File tools\agent\netns-capture\windows-netgate.ps1 -Stop" -ForegroundColor Yellow
    }
}

if (-not $captureOk) { exit 1 }

if ($NoDeploy) {
    if ($InstantReplay) {
        Write-Log "capture + instant replay done (-NoDeploy, -InstantReplay)."
    } else {
        Write-Log "capture done (-NoDeploy). Deploy manually:"
        Write-Host "  powershell -File tools\agent\vm-capture\pull-capture-and-deploy.ps1 -Replay -Sim -NoMint"
    }
    exit 0
}

Write-Log "deploying capture-out -> .env ..."
$depArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $deploy)
if ($Sim) { $depArgs += "-Sim" }
if ($DockerUp) { $depArgs += "-DockerUp" }
& powershell @depArgs
exit $LASTEXITCODE
