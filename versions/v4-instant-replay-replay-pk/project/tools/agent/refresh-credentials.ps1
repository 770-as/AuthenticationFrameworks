# refresh-credentials.ps1 - mint GAME_SESSION_TOKEN and apply a captured login frame to .env
#
# Usage:
#   tools\agent\refresh-credentials.ps1 -FromCapture $env:USERPROFILE\login_frame.txt
#   tools\agent\refresh-credentials.ps1 -WaitCapture
#   tools\agent\refresh-credentials.ps1 -WaitTitleScreen -Sim
#   tools\agent\refresh-credentials.ps1 -LaunchCapture -Sim

param(
    [string]$FromCapture = "",
    [switch]$WaitCapture,
    [switch]$WaitTitleScreen,
    [switch]$LaunchCapture,
    [switch]$Sim,
    [switch]$Replay,
    [switch]$NoMint,
    [switch]$QuickReplay,
    [switch]$ViaNetgate
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repo
$envPath = Join-Path $repo ".env"
$credsPath = Join-Path $env:USERPROFILE ".runelite\credentials.properties"
$frameDefault = Join-Path $env:USERPROFILE "login_frame.txt"
$rsaFile = Join-Path $env:USERPROFILE "rsa_plaintext.txt"
$ccPath = Join-Path $env:USERPROFILE "cc_strings.txt"

function Read-Prop([string]$path, [string]$key) {
    if (-not (Test-Path $path)) { return "" }
    foreach ($line in Get-Content $path) {
        if ($line -match "^\s*$([regex]::Escape($key))=(.*)$") {
            return $Matches[1].Trim()
        }
    }
    return ""
}

function Upsert-Env([string]$path, [string]$key, [string]$value) {
    # Force array: Get-Content on a 1-line file returns a string; += would concatenate.
    $lines = @()
    if (Test-Path -LiteralPath $path) {
        $lines = @(Get-Content -LiteralPath $path)
    }
    $found = $false
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match "^\s*$([regex]::Escape($key))=") {
            $lines[$i] = "$key=$value"
            $found = $true
            break
        }
    }
    if (-not $found) { $lines += "$key=$value" }
    [System.IO.File]::WriteAllLines($path, $lines)
}

function Get-CcString([int]$num) {
    if (-not (Test-Path $ccPath)) { return "" }
    $val = ""
    foreach ($line in Get-Content $ccPath) {
        if ($line -match "^#$num\s+(.+)$") {
            $val = $Matches[1].Trim()
        }
    }
    return $val
}

function Test-TitleScreenTokens {
    $pk = Get-CcString 1
    if ($pk.Length -ge 20) { return $true }
    if (Test-Path $rsaFile) {
        $raw = Get-Content $rsaFile -Raw -ErrorAction SilentlyContinue
        if ($raw -match '\[RSA-PLAINTEXT\]\s*([0-9a-fA-F]{40,})') { return $true }
    }
    return $false
}

if ($WaitTitleScreen) {
    Write-Host "[refresh] title-screen watch armed (10 min timeout)"
    Write-Host "[refresh] 1) Jagex Launcher -> Play (do NOT click Play Now)"
    Write-Host "[refresh] 2) Wait for welcome/title screen, then close RuneLite"
    Write-Host "[refresh] watching $ccPath and $rsaFile ..."
    $deadline = (Get-Date).AddMinutes(10)
    while ((Get-Date) -lt $deadline) {
        if (Test-TitleScreenTokens) {
            Write-Host "[refresh] title-screen token influx detected"
            break
        }
        Start-Sleep -Seconds 1
    }
    if (-not (Test-TitleScreenTokens)) {
        throw "timed out waiting for title-screen tokens in cc_strings / rsa_plaintext"
    }
}

Write-Host "[refresh] resolving GAME_SESSION_TOKEN (client.pk)..."
$pk = ""
$gf = Get-CcString 3

if (Test-Path $rsaFile) {
    $rsaLine = Get-Content $rsaFile -Raw
    $rsaHex = ([regex]'\[RSA-PLAINTEXT\]\s*([0-9a-fA-F]+)').Match($rsaLine).Groups[1].Value
    if ($rsaHex) {
        Upsert-Env $envPath "RSA_PLAINTEXT_HEX" $rsaHex
        Write-Host "[refresh] RSA_PLAINTEXT_HEX updated ($($rsaHex.Length / 2) bytes)"
        $bytes = @()
        for ($i = 0; $i -lt $rsaHex.Length; $i += 2) {
            $bytes += [Convert]::ToByte($rsaHex.Substring($i, 2), 16)
        }
        if ($bytes.Count -gt 31) {
            $sb = New-Object System.Text.StringBuilder
            for ($j = 31; $j -lt $bytes.Count -and $bytes[$j] -ne 0; $j++) {
                [void]$sb.Append([char]$bytes[$j])
            }
            if ($sb.Length -ge 20) {
                $pk = $sb.ToString()
                Write-Host "[refresh] using paired pk from rsa_plaintext.txt (len=$($pk.Length))"
            }
        }
    }
}

if (-not $pk -and (Test-Path $ccPath)) {
    $pk = Get-CcString 1
    if ($pk.Length -ge 20) {
        Write-Host "[refresh] using latest paired pk from cc_strings #1 (len=$($pk.Length))"
    } else {
        $pk = ""
    }
}
if (-not $pk -and -not $NoMint) {
    Write-Host "[refresh] no cc_strings pk; minting via auth API..."
    $session = Read-Prop $credsPath "JX_SESSION_ID"
    $char = Read-Prop $credsPath "JX_CHARACTER_ID"
    if (-not $session -or -not $char) {
        throw "Missing JX_SESSION_ID or JX_CHARACTER_ID in $credsPath. Log into RuneLite once."
    }
    $resp = Invoke-RestMethod -Uri "https://auth.runescape.com/game-session/v1/tokens" -Method POST `
        -Headers @{ Authorization = "Bearer $session"; "Content-Type" = "application/json" } `
        -Body (@{ accountId = $char } | ConvertTo-Json)
    $pk = $resp.token
    if (-not $pk) { throw "token endpoint returned empty token" }
    Write-Host "[refresh] GAME_SESSION_TOKEN minted (len=$($pk.Length))"
}
if (-not $pk) {
    throw "no GAME_SESSION_TOKEN - capture title-screen cc_strings or pass -NoMint after manual capture"
}
Upsert-Env $envPath "GAME_SESSION_TOKEN" $pk
if ($gf.Length -ge 20) {
    Upsert-Env $envPath "CLIENT_TOKEN" $gf
    Write-Host "[refresh] CLIENT_TOKEN from cc_strings #3 (len=$($gf.Length))"
}
if ($LaunchCapture) {
    Write-Host "[refresh] launching capture-login.ps1..."
    & (Join-Path $PSScriptRoot "capture-login.ps1")
}

$framePath = if ($FromCapture) { $FromCapture } else { $frameDefault }
if ($WaitCapture -and -not (Test-Path $framePath)) {
    Write-Host "[refresh] waiting for $framePath (launch RuneLite and click Play Now)..."
    $deadline = (Get-Date).AddMinutes(10)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path $framePath) { break }
        Start-Sleep -Seconds 2
    }
}

if (-not (Test-Path $framePath)) {
    Write-Host "[refresh] no login frame at $framePath"
    if ($WaitTitleScreen -or $NoMint) {
        Write-Host "[refresh] title-screen mode: using paired pk/gf + existing MACHINE_INFO_HEX from .env"
    } else {
        Write-Host "[refresh] updated GAME_SESSION_TOKEN only. Capture CLIENT_TOKEN via RuneLite login agent."
        exit 2
    }
} else {
Write-Host "[refresh] parsing $framePath..."
if ($QuickReplay) {
    Write-Host "[refresh] QuickReplay: skipping framedump/logindiff (pk expires in seconds)"
} else {
Push-Location $repo
try {
    $dump = & go run ./cmd/framedump -file $framePath 2>&1 | Out-String
    Write-Host ($dump.Trim())
    & go run ./cmd/logindiff -file $framePath 2>&1 | Write-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[refresh] logindiff reported differences (continuing anyway)"
    }
} finally {
    Pop-Location
}

$token = ([regex]"clientToken\s*=\s*`"([^`"]*)`"").Match($dump).Groups[1].Value
$machineInfoHex = ([regex]"(?s)MACHINE_INFO_HEX=([0-9a-f]+)").Match($dump).Groups[1].Value
$platformInfoHex = ([regex]"(?s)PLATFORM_INFO_HEX=([0-9a-f]+)").Match($dump).Groups[1].Value
if (-not $token) { throw "could not parse CLIENT_TOKEN from frame" }
if (-not $machineInfoHex) { throw "could not parse MACHINE_INFO_HEX from frame" }
if (-not $platformInfoHex) { throw "could not parse PLATFORM_INFO_HEX from frame" }

Upsert-Env $envPath "CLIENT_TOKEN" $token
Upsert-Env $envPath "MACHINE_INFO_HEX" $machineInfoHex
Upsert-Env $envPath "PLATFORM_INFO_HEX" $platformInfoHex
Write-Host "[refresh] .env updated from login_frame.txt"
}
}

Write-Host "[refresh] .env tokens: GAME_SESSION_TOKEN len=$($pk.Length), CLIENT_TOKEN updated"

if ($Sim) {
    Push-Location $repo
    try {
        $framePath = if ($FromCapture) { $FromCapture } else { $frameDefault }
        $useReplay = $Replay -and (Test-Path $framePath) -and (
            (Test-Path $rsaFile) -or ((Get-Content $envPath -Raw) -match 'RSA_PLAINTEXT_HEX=')
        )
        $proxyFlag = @()
        if ($ViaNetgate) {
            $proxyFlag = @("-no-proxy")
            Write-Host "[refresh] loginsim via netgate OS routing (-no-proxy; same path as RuneLite capture)"
        } else {
            $envProxy = $env:PROXY_URL
            if (-not $envProxy) {
                $dotEnv = Join-Path $repo ".env"
                if (Test-Path $dotEnv) {
                    foreach ($line in Get-Content $dotEnv) {
                        if ($line -match '^\s*PROXY_URL=(.+)$') { $envProxy = $Matches[1].Trim(); break }
                    }
                }
            }
            if ($envProxy) {
                $env:PROXY_URL = $envProxy
                Write-Host "[refresh] loginsim via PROXY_URL ($($envProxy -replace '://[^@]+@', '://***@'))"
            } else {
                $proxyFlag = @("-no-proxy")
                Write-Host "[refresh] loginsim direct (no PROXY_URL)"
            }
        }
        if ($useReplay) {
            Write-Host "[refresh] running loginsim with capture replay..."
            $loginsimBin = Join-Path $repo "tools\agent\build\loginsim.exe"
                        if ($QuickReplay) {
                $loginArgs = @("-login-only", "-replay-capture", "-capture-file", $framePath)
                Write-Host "[refresh] QuickReplay: replay captured pk (v4 - pk reuse, FAILED code 10)"
            } else {
                $loginArgs = @("-replay-capture", "-capture-file", $framePath)
            }
            if ($QuickReplay -and (Test-Path $loginsimBin)) {
                & $loginsimBin @proxyFlag @loginArgs
            } else {
                & go run ./cmd/loginsim @proxyFlag @loginArgs
            }
            exit $LASTEXITCODE
        } else {
            Write-Host "[refresh] running loginsim (built frame)..."
            $loginsimBin = Join-Path $repo "tools\agent\build\loginsim.exe"
            if ($QuickReplay -and (Test-Path $loginsimBin)) {
                & $loginsimBin @proxyFlag
            } else {
                & go run ./cmd/loginsim @proxyFlag
            }
            exit $LASTEXITCODE
        }
    } finally { Pop-Location }
}
