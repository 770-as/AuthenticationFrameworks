# capture-no-mitm.ps1
# Capture paired login tokens WITHOUT mitmproxy or Proxifier.
#
# Usage:
#   powershell -File tools\agent\capture-no-mitm.ps1
#   powershell -File tools\agent\capture-no-mitm.ps1 -Sim
#   powershell -File tools\agent\capture-no-mitm.ps1 -Sim -NoPrompt   # no Read-Host pauses

param(
    [switch]$Sim,
    [int]$WaitMin = 10,
    [switch]$NoPrompt,
    [switch]$ViaProxy,
    [switch]$AllowWireLogin,
    [switch]$InstantReplay
)

$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$repo = (Resolve-Path (Join-Path $here "..\..")).Path
$tag = '[capture-no-mitm]'

if ($AllowWireLogin -and $InstantReplay) {
    throw "Use -InstantReplay (bot path) OR -AllowWireLogin (diagnostic), not both."
}

function Wait-User([string]$Message) {
    Write-Host ""
    Write-Host ">>> $Message" -ForegroundColor Cyan
    if (-not $NoPrompt) {
        Read-Host "Press Enter when done (or Ctrl+C to abort)"
    }
}

function Write-Click([int]$Step, [string]$Text) {
    Write-Host ""
    Write-Host "========== CLICK STEP $Step ==========" -ForegroundColor Yellow
    Write-Host $Text -ForegroundColor White
    Write-Host "=====================================" -ForegroundColor Yellow
}

function Write-Tag {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ConsoleColor]$ForegroundColor
    )
    if ($PSBoundParameters.ContainsKey('ForegroundColor')) {
        Write-Host ($tag + ' ' + $Message) -ForegroundColor $ForegroundColor
    } else {
        Write-Host ($tag + ' ' + $Message)
    }
}

function Stop-ClientHard {
    Write-Tag 'stopping RuneLite/java (before replay)...'
    foreach ($name in @('RuneLite', 'java', 'javaw')) {
        try { & taskkill.exe /F /T /IM "$name.exe" 2>&1 | Out-Null } catch { }
    }
    Get-Process java, RuneLite, javaw -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
}

function Test-InstantReplayReady {
    param([string]$Blocked, [string]$Frame, [string]$Rsa)
    return (Test-Path $Blocked) -and (Test-Path $Frame) -and (Test-Path $Rsa)
}

Write-Tag 'resetting network (no mitm, no proxy)...'
& (Join-Path $here "reset-capture-network.ps1")
if ($ViaProxy) {
    Write-Tag 'windows-netgate is active - RuneLite uses OS routing, not app SOCKS'
}

Write-Tag 'building login agent...'
if ($AllowWireLogin) {
    Write-Tag 'AllowWireLogin: diagnostic mode - pk will be BURNED on wire (NOT for bot deploy)'
}
& (Join-Path $here "build.ps1")

if ($InstantReplay) {
    $env:HANDOFF_HOST = if ($env:HANDOFF_HOST) { $env:HANDOFF_HOST } else { '127.0.0.1' }
    $env:HANDOFF_PORT = if ($env:HANDOFF_PORT) { $env:HANDOFF_PORT } else { '17494' }
    Write-Tag "JVM handoff enabled -> $($env:HANDOFF_HOST):$($env:HANDOFF_PORT) (start Docker with HANDOFF_LISTEN=:17494)"
    $loginsimBin = Join-Path $repo "tools\agent\build\loginsim.exe"
    if (-not (Test-Path $loginsimBin)) {
        Write-Tag 'pre-building loginsim.exe (faster instant replay)...'
        Push-Location $repo
        go build -o $loginsimBin ./cmd/loginsim
        if ($LASTEXITCODE -ne 0) { throw 'loginsim build failed' }
        Pop-Location
    }
}

$ccPath = Join-Path $env:USERPROFILE "cc_strings.txt"
$framePath = Join-Path $env:USERPROFILE "login_frame.txt"
$agentLog = Join-Path $env:USERPROFILE "login_dump_agent.log"
$settings = Join-Path $env:USERPROFILE "Jagex\RuneLite\settings.json"
$agentJar = Join-Path $repo "tools\agent\build\login-agent.jar"
$hookJar = Join-Path $repo "tools\agent\build\login-hook-bootstrap.jar"
$launcher = "${env:ProgramFiles(x86)}\Jagex Launcher\JagexLauncher.exe"

if (-not (Test-Path $settings)) {
    throw "RuneLite settings not found: $settings (log into Jagex Launcher once first)"
}

$json = Get-Content $settings -Raw | ConvertFrom-Json
$wantAgent = "-javaagent:$agentJar=$hookJar"
$jvmArgs = @($wantAgent)
if ($InstantReplay) {
    $handoffHost = if ($env:HANDOFF_HOST) { $env:HANDOFF_HOST } else { '127.0.0.1' }
    $handoffPort = if ($env:HANDOFF_PORT) { $env:HANDOFF_PORT } else { '17494' }
    $jvmArgs = @("-Dhandoff.host=$handoffHost", "-Dhandoff.port=$handoffPort") + $jvmArgs
}
if ($AllowWireLogin) {
    # JVM system property - NOT an env var. Jagex Launcher does not inherit
    # PowerShell $env:LOGIN_NO_BLOCK; the agent reads -Dlogin.noblock=true.
    $jvmArgs = @("-Dlogin.noblock=true") + $jvmArgs
} else {
    Write-Tag 'wire-block ON (agent drops login socket write; pk stays unburned for replay)'
}
$json.jvmArguments = $jvmArgs
if (-not $json.clientArguments) { $json.clientArguments = @() }
if (($json.clientArguments -join '') -notlike "*insecure-write-credentials*") {
    $json.clientArguments = @("--insecure-write-credentials") + @($json.clientArguments)
}
$json.launchMode = "JVM"
$json | ConvertTo-Json -Depth 5 | Set-Content $settings -Encoding UTF8
Write-Tag "agent installed -> $settings (launchMode=JVM)"
if ($AllowWireLogin) {
    Write-Tag 'jvmArguments include -Dlogin.noblock=true (login goes on wire)'
} else {
    Write-Tag 'jvmArguments WITHOUT login.noblock (wire-block for instant replay)'
}

Remove-Item $ccPath, $framePath, $agentLog -ErrorAction SilentlyContinue
Remove-Item (Join-Path $env:USERPROFILE "login_wire_blocked.txt") -ErrorAction SilentlyContinue

Write-Click 0 "AUTOMATED SETUP DONE (agent built + settings.json updated). You only click in steps 1-3 below."

if ($ViaProxy) {
    Write-Click 1 (@(
        "windows-netgate is ON - all traffic exits via PROXY_URL (Marseille).",
        "  - Proxifier must be OFF (File -> Exit) or it fights the tunnel",
        "  - Disconnect WireGuard / McAfee VPN if active",
        "OAuth + game login will share the same proxy egress IP."
    ) -join "`n")
} else {
    Write-Click 1 (@(
        "Quit anything that intercepts HTTPS:",
        "  - Proxifier (autostarts at Windows login - tray -> File -> Exit)",
        "  - WireGuard / McAfee VPN if connected",
        "No proxy needed for capture (bot uses PROXY_URL in Docker later)."
    ) -join "`n")
}
Wait-User "Proxifier/VPN interceptors are off"

$launcherProc = Get-Process JagexLauncher -ErrorAction SilentlyContinue
if (-not $launcherProc -and (Test-Path $launcher)) {
    Write-Tag 'starting Jagex Launcher...'
    Start-Process $launcher
    Start-Sleep -Seconds 5
}

Write-Click 2 $(if ($AllowWireLogin) {
    @(
        "IMPORTANT: quit any open RuneLite/Jagex Launcher first (JVM args apply at startup only).",
        "In JAGEX LAUNCHER window:",
        "  - Select Old School RuneScape",
        "  - Client: RuneLite",
        "  - Click PLAY (big button)",
        "Wait until RuneLite window opens (title screen / welcome)."
    ) -join "`n"
} else {
    @(
        "In JAGEX LAUNCHER window:",
        "  - Select Old School RuneScape",
        "  - Client: RuneLite",
        "  - Click PLAY (big button)",
        "Wait until RuneLite window opens (title screen / welcome)."
    ) -join "`n"
})
Wait-User "You clicked Play and RuneLite is open"

Write-Click 3 $(if ($AllowWireLogin) {
    @(
        "In RUNELITE - complete ONE full login (LOGIN_NO_BLOCK is ON):",
        "  - Click 'Play Now' / log into a world ONCE",
        "  - RuneLite will actually enter the game (session activates on Jagex side)",
        "  - Script captures login_frame.txt + credentials while you play",
        "After title screen loads, you are done - close RuneLite when script says so."
    ) -join "`n"
} elseif ($InstantReplay) {
    @(
        "In RUNELITE - click 'Play Now' ONCE (required):",
        "  - Agent captures login_frame.txt and BLOCKS the socket write",
        '  - You will NOT enter the game - that is correct',
        "  - Script replays login within seconds (pk expires fast)",
        "Complete Leo browser login first if it appears."
    ) -join "`n"
} else {
    @(
        "In RUNELITE - STOP at title screen.",
        "  - Do NOT click 'Play Now' yet (script detects tokens first)",
        "  - If login browser pops up, complete Leo login first",
        'Script is watching for cc_strings.txt (#1 pk + #3 gf)...'
    ) -join "`n"
})
$blockedPath = Join-Path $env:USERPROFILE "login_wire_blocked.txt"
$rsaPath = Join-Path $env:USERPROFILE "rsa_plaintext.txt"
if ($InstantReplay) {
    Write-Tag 'waiting for Play Now -> login_frame + wire-block (pk expires in ~30s after block)...'
} else {
    Write-Tag "waiting up to $WaitMin minutes for title-screen tokens..."
}
Write-Tag "log: $agentLog"

$deadline = (Get-Date).AddMinutes($WaitMin)
$replayDeadline = $null
$dots = 0
while ((Get-Date) -lt $deadline) {
    if ($InstantReplay) {
        if (Test-InstantReplayReady $blockedPath $framePath $rsaPath) {
            Write-Tag 'capture complete: frame + rsa + wire-block marker' -ForegroundColor Green
            $replayDeadline = Get-Date
            break
        }
    } else {
        if (Test-Path $ccPath) {
            $c = Get-Content $ccPath -Raw
            if ($c -match '#1\s+\S+' -and $c -match '#3\s+\S+') {
                Write-Tag 'paired pk+gf detected in cc_strings.txt' -ForegroundColor Green
                break
            }
            if ($c -match '#1\s+\S+') {
                Write-Tag 'pk (#1) seen, still waiting for gf (#3)...'
            }
        }
        if (Test-Path $framePath) {
            Write-Tag 'login_frame.txt captured' -ForegroundColor Green
            break
        }
    }
    $dots = ($dots + 1) % 4
    Write-Host ("  waiting" + ("." * $dots).PadRight(3)) -NoNewline
    Write-Host "`r" -NoNewline
    Start-Sleep -Seconds 2
}

$captureOk = $false
if ($InstantReplay) {
    $captureOk = Test-InstantReplayReady $blockedPath $framePath $rsaPath
} else {
    $captureOk = (Test-Path $ccPath) -or (Test-Path $framePath)
}
if (-not $captureOk) {
    Write-Host ""
    if ($InstantReplay) {
        Write-Tag 'TIMEOUT - need login_frame.txt + rsa_plaintext.txt + login_wire_blocked.txt' -ForegroundColor Red
        Write-Host '  Click Play Now once in RuneLite so the agent can capture and block the login packet.'
    } else {
        Write-Tag 'TIMEOUT - no capture files.' -ForegroundColor Red
    }
    if (Test-Path $agentLog) {
        Write-Host "--- login_dump_agent.log (last 15 lines) ---"
        Get-Content $agentLog -Tail 15
    } else {
        Write-Host "No agent log - check launchMode=JVM in $settings"
    }
    exit 1
}

Write-Host ""
if (Test-Path $ccPath) {
    Write-Host "--- cc_strings.txt ---"
    Get-Content $ccPath -ErrorAction SilentlyContinue
}

if ($AllowWireLogin) {
    if (Test-Path $blockedPath) {
        Write-Host ""
        Write-Tag 'ERROR: login was STILL wire-blocked despite -AllowWireLogin.' -ForegroundColor Red
        Write-Host "  RuneLite did not get -Dlogin.noblock=true (was it already running before Play?)." -ForegroundColor Red
        Write-Host "  Quit RuneLite fully, re-run capture, and launch fresh from Jagex Launcher." -ForegroundColor Red
        exit 1
    }
    if (Test-Path $framePath) {
        $frameHex = (Get-Content $framePath -Raw) -replace '(?s).*?\[LOGIN-FRAME\]\s*','' -replace '[^0-9a-fA-F]',''
        if ($frameHex.Length -ge 2) {
            $loginType = $frameHex.Substring(0, 2).ToLower()
            if ($loginType -eq '12') {
                Write-Host ""
                Write-Tag 'WARN: login_frame is type 0x12 RECONNECT, not 0x10 NEW login.' -ForegroundColor Yellow
                Write-Host "  RuneLite had leftover session state from prior blocked attempts." -ForegroundColor Yellow
                Write-Host "  Kill ALL java.exe, delete cc_strings/login_frame, relaunch fresh, click Play Now ONCE." -ForegroundColor Yellow
                Write-Host "  Bot login (-mint) needs a completed 0x10 NEW login on the wire." -ForegroundColor Yellow
            } elseif ($loginType -eq '10') {
                Write-Tag 'login_frame type 0x10 NEW login (correct for bot -mint)' -ForegroundColor Green
            }
        }
    }
    if (Test-Path $agentLog) {
        $noblock = Select-String -Path $agentLog -Pattern 'LOGIN-BLOCK\] disabled' -Quiet
        if ($noblock) {
            Write-Tag 'wire login confirmed (agent log: LOGIN-BLOCK disabled)' -ForegroundColor Green
        } else {
            Write-Tag "WARN: no 'LOGIN-BLOCK disabled' in agent log - verify RuneLite entered the game" -ForegroundColor Yellow
        }
    }
} else {
    if (-not (Test-Path $blockedPath)) {
        Write-Host ""
        Write-Tag 'ERROR: login was NOT wire-blocked - pk was burned on the wire.' -ForegroundColor Red
        Write-Host "  settings.json still has -Dlogin.noblock=true from a prior -AllowWireLogin run." -ForegroundColor Red
        Write-Host "  Re-run capture WITHOUT -AllowWireLogin (use -InstantReplay for bot login)." -ForegroundColor Red
        exit 1
    }
    Write-Tag 'wire-block confirmed (pk unburned; ready for instant replay)' -ForegroundColor Green
}

if ($InstantReplay -and (Test-Path $blockedPath) -and (Test-Path $framePath)) {
    $elapsed = if ($replayDeadline) { ((Get-Date) - $replayDeadline).TotalSeconds } else { 0 }
    Write-Tag ('INSTANT REPLAY NOW ({0:N1}s since wire-block - pk is short-lived)' -f $elapsed) -ForegroundColor Cyan
    Stop-ClientHard
    Set-Location $repo
    $refreshArgs = @(
        "-File", (Join-Path $here "refresh-credentials.ps1"),
        "-FromCapture", $framePath,
        "-Replay", "-Sim", "-NoMint", "-QuickReplay"
    )
    if ($ViaProxy) { $refreshArgs += "-ViaNetgate" }
    & powershell @refreshArgs
    $simExit = $LASTEXITCODE
    if ($simExit -eq 0) {
        Write-Tag 'login accepted - run full deploy to refresh MACHINE_INFO_HEX in .env:' -ForegroundColor Green
        Write-Host '  powershell -File tools\agent\vm-capture\pull-capture-and-deploy.ps1 -NoDocker'
    } else {
        Write-Tag "login rejected (exit $simExit) - check JX credentials and netgate egress" -ForegroundColor Red
        if ($ViaProxy) {
            Write-Host '  mint-replay uses netgate OS routing; ensure Leo login completed (credentials.properties).'
        }
    }
    exit $simExit
}

if (-not (Test-Path $framePath)) {
    Write-Click 4 $(if ($AllowWireLogin) {
        @(
            "In RuneLite click 'Play Now' ONCE (first login only - not reconnect).",
            "Wait for login_frame.txt, then close RuneLite."
        ) -join "`n"
    } else {
        @(
            "OPTIONAL (recommended): In RuneLite click 'Play Now' ONCE.",
            "Then close RuneLite. Script will pick up login_frame.txt (full packet).",
            "Or wait up to 90s - pk+gf alone may be enough."
        ) -join "`n"
    })
    if (-not $NoPrompt) {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while ($sw.Elapsed.TotalSeconds -lt 90) {
            if (Test-Path $framePath) {
                Write-Tag 'login_frame.txt captured' -ForegroundColor Green
                break
            }
            Start-Sleep -Seconds 2
        }
    }
}

Write-Click 5 "Close RuneLite and Jagex Launcher (if still open). Script continues automatically."
if (-not $NoPrompt) {
    Read-Host "Press Enter after closing RuneLite"
}

Set-Location $repo
$refreshArgs = @("-File", (Join-Path $here "refresh-credentials.ps1"))
if (Test-Path $framePath) { $refreshArgs += "-FromCapture", $framePath }
elseif (Test-Path $ccPath) { $refreshArgs += "-WaitTitleScreen", "-NoMint" }
if ($InstantReplay) {
    Write-Tag 'instant replay: loginsim -replay-capture with captured pk (NOT -mint)'
    $refreshArgs += "-Replay", "-Sim", "-NoMint", "-QuickReplay"
} elseif ($Sim) {
    $refreshArgs += "-Sim"
}
Write-Tag 'updating .env...'
& powershell @refreshArgs
