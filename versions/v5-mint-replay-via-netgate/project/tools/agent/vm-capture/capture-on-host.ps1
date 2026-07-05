# capture-on-host.ps1 — automated JVM agent capture on Windows (Option A).
#
# Usage:
#   powershell -File tools\agent\vm-capture\capture-on-host.ps1 -Sim -DockerUp
#
# YOU CLICK ONLY WHEN THE SCRIPT SHOWS "CLICK STEP 1/2/3/4" (see capture-no-mitm.ps1).

param(
    [switch]$Sim,
    [switch]$DockerUp,
    [int]$WaitMin = 10,
    [switch]$NoPrompt,
    [switch]$ViaProxy,
    [switch]$AllowWireLogin,
    [switch]$InstantReplay
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$capDir = Join-Path $repo "tools\agent\vm-bundle\capture-out"
New-Item -ItemType Directory -Force -Path $capDir | Out-Null

$args = @("-File", (Join-Path $repo "tools\agent\capture-no-mitm.ps1"), "-WaitMin", $WaitMin)
if ($Sim) { $args += "-Sim" }
if ($NoPrompt) { $args += "-NoPrompt" }
if ($ViaProxy) { $args += "-ViaProxy" }
if ($AllowWireLogin) { $args += "-AllowWireLogin" }
if ($InstantReplay) { $args += "-InstantReplay" }
& powershell @args
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$cc = Join-Path $env:USERPROFILE "cc_strings.txt"
$frame = Join-Path $env:USERPROFILE "login_frame.txt"
$rsa = Join-Path $env:USERPROFILE "rsa_plaintext.txt"

foreach ($pair in @(
        @($cc, "cc_strings.txt"),
        @($frame, "login_frame.txt"),
        @($rsa, "rsa_plaintext.txt")
    )) {
    if (Test-Path $pair[0]) {
        Copy-Item $pair[0] (Join-Path $capDir $pair[1]) -Force
        Write-Host "[capture-on-host] -> capture-out/$($pair[1])"
    }
}

if ($DockerUp) {
    & powershell -File (Join-Path $PSScriptRoot "pull-capture-and-deploy.ps1") -DockerUp
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "[capture-on-host] done. Deploy/test:"
Write-Host "  powershell -File tools\agent\vm-capture\pull-capture-and-deploy.ps1 -Sim -DockerUp"
