# windows-netgate.ps1 - the Windows twin of the Linux `netgate` container.
#
# Routes ALL host traffic through the SOCKS proxy in .env using a Wintun virtual
# adapter driven by tun2socks (same engine as the Linux netgate). This lets the
# NATIVE Jagex Launcher + RuneLite + JVM agent run on real Windows (no Wine, real
# ntdll/hardware fingerprint) while every packet - OAuth (Layer 1) AND game login
# (Layer 2) - exits via the proxy. No Proxifier / WinSock hooking (that is the
# detectable part); this works at the IP/routing layer, so apps just see a normal
# network adapter.
#
# It is transparent like a VPN: while -Start is active, the whole box egresses via
# the proxy. Run capture, then -Stop to restore normal routing.
#
# Usage (elevated PowerShell - routing changes need admin):
#   powershell -File tools\agent\netns-capture\windows-netgate.ps1 -Start
#   powershell -File tools\agent\netns-capture\windows-netgate.ps1 -Status
#   powershell -File tools\agent\netns-capture\windows-netgate.ps1 -Stop
#   
# Then (native, separate window):
#   powershell -File tools\agent\vm-capture\capture-on-host.ps1 -Sim
#   powershell -File tools\agent\netns-capture\windows-netgate.ps1 -Stop
#   powershell -File tools\agent\vm-capture\pull-capture-and-deploy.ps1 -Sim -DockerUp

[CmdletBinding(DefaultParameterSetName = 'Start')]
param(
    [Parameter(ParameterSetName = 'Start')][switch]$Start,
    [Parameter(ParameterSetName = 'Stop')][switch]$Stop,
    [Parameter(ParameterSetName = 'Status')][switch]$Status,
    [string]$EnvPath,
    [string]$TunName = "netgate0",
    [int]$TunMetric = 1,
    [string]$Tun2socksVersion = "v2.5.2"
)

$ErrorActionPreference = "Stop"
$log = "[win-netgate]"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
if (-not $EnvPath) { $EnvPath = Join-Path $repo ".env" }
$toolDir = Join-Path $env:LOCALAPPDATA "netgate"
$statePath = Join-Path $toolDir "state.json"
$tunExe = Join-Path $toolDir "tun2socks.exe"
$wintunDll = Join-Path $toolDir "wintun.dll"

# Wintun uses 10.x for the tun subnet; the tun's own gateway is .1, adapter is .2.
$TunAddr = "10.7.0.2"
$TunGw = "10.7.0.1"
$TunPrefix = 24

function Write-Log([string]$m) { Write-Host "$log $m" }

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Must run in an ELEVATED PowerShell (routing changes need admin)."
    }
}

function Read-EnvProp([string]$path, [string]$key) {
    if (-not (Test-Path $path)) { return "" }
    foreach ($line in Get-Content $path) {
        if ($line -match "^\s*$([regex]::Escape($key))=(.*)$") { return $Matches[1].Trim() }
    }
    return ""
}

function Get-Proxy {
    $proxyURL = Read-EnvProp $EnvPath "PROXY_URL"
    if (-not $proxyURL) { throw "PROXY_URL not set in $EnvPath" }
    if ($proxyURL -notmatch '^(?<scheme>socks5h?)://(?:(?<user>[^:@/]+):(?<pass>[^@/]+)@)?(?<host>[^:/]+):(?<port>\d+)$') {
        throw "PROXY_URL must look like socks5h://user:pass@host:port (got: $proxyURL)"
    }
    # tun2socks understands socks5:// (it tunnels IP packets, so DNS resolves remotely anyway).
    return [pscustomobject]@{
        Url    = "socks5://" + ($proxyURL -replace '^socks5h?://', '')
        Host   = $Matches.host
        Port   = [int]$Matches.port
        User   = $Matches.user
        Scheme = $Matches.scheme
    }
}

function Resolve-ProxyIPv4([string]$hostName) {
    if ($hostName -match '^\d{1,3}(\.\d{1,3}){3}$') { return $hostName }
    $r = Resolve-DnsName -Name $hostName -Type A -ErrorAction Stop |
        Where-Object { $_.IPAddress } | Select-Object -First 1
    if (-not $r) { throw "DNS lookup failed for $hostName" }
    return $r.IPAddress
}

function Get-DefaultRoute {
    # Lowest-metric IPv4 default route that is NOT our tun (so we find the real NIC).
    Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -ne $TunName } |
        Sort-Object -Property RouteMetric, ifMetric |
        Select-Object -First 1
}

function Ensure-Tools {
    New-Item -ItemType Directory -Force -Path $toolDir | Out-Null
    $arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }

    if (-not (Test-Path $tunExe)) {
        $zip = Join-Path $toolDir "tun2socks.zip"
        $url = "https://github.com/xjasonlyu/tun2socks/releases/download/$Tun2socksVersion/tun2socks-windows-$arch.zip"
        Write-Log "downloading tun2socks $Tun2socksVersion ($arch)..."
        Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
        $tmp = Join-Path $toolDir "t2s_extract"
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
        Expand-Archive -Path $zip -DestinationPath $tmp -Force
        $bin = Get-ChildItem -Path $tmp -Recurse -Filter "tun2socks-windows-$arch.exe" | Select-Object -First 1
        if (-not $bin) { $bin = Get-ChildItem -Path $tmp -Recurse -Filter "tun2socks*.exe" | Select-Object -First 1 }
        if (-not $bin) { throw "tun2socks exe not found in $url" }
        Copy-Item $bin.FullName $tunExe -Force
        Remove-Item -Recurse -Force $tmp, $zip -ErrorAction SilentlyContinue
    }

    if (-not (Test-Path $wintunDll)) {
        # tun2socks needs wintun.dll next to it. Ship from wintun.net (bundled arch dir).
        $wz = Join-Path $toolDir "wintun.zip"
        Write-Log "downloading wintun.dll..."
        Invoke-WebRequest -Uri "https://www.wintun.net/builds/wintun-0.14.1.zip" -OutFile $wz -UseBasicParsing
        $wtmp = Join-Path $toolDir "wintun_extract"
        Remove-Item -Recurse -Force $wtmp -ErrorAction SilentlyContinue
        Expand-Archive -Path $wz -DestinationPath $wtmp -Force
        $wa = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "x86" }
        $dll = Get-ChildItem -Path $wtmp -Recurse -Filter "wintun.dll" |
            Where-Object { $_.FullName -match "\\$wa\\" } | Select-Object -First 1
        if (-not $dll) { $dll = Get-ChildItem -Path $wtmp -Recurse -Filter "wintun.dll" | Select-Object -First 1 }
        if (-not $dll) { throw "wintun.dll not found in download" }
        Copy-Item $dll.FullName $wintunDll -Force
        Remove-Item -Recurse -Force $wtmp, $wz -ErrorAction SilentlyContinue
    }
    Write-Log "tools ready in $toolDir"
}

function Start-Netgate {
    Assert-Admin
    if (Test-Path $statePath) {
        Write-Log "already running (state.json present). Run -Stop first, or -Status."
        return
    }
    try {
        Start-NetgateCore
    } catch {
        $failLog = Join-Path $toolDir "last-error.log"
        "$(Get-Date -Format o) $($_.Exception.Message)`n$($_.ScriptStackTrace)" | Set-Content $failLog -Encoding UTF8
        Write-Log "FAILED: $($_.Exception.Message) (see $failLog)"
        throw
    }
}

function Start-NetgateCore {
    Ensure-Tools
    $proxy = Get-Proxy
    $proxyIp = Resolve-ProxyIPv4 $proxy.Host
    $def = Get-DefaultRoute
    if (-not $def) { throw "no existing default route found (are you online?)" }
    $realGw = $def.NextHop
    $realIfIndex = $def.ifIndex
    Write-Log "proxy $($proxy.Host):$($proxy.Port) -> $proxyIp ; real gw=$realGw if=$realIfIndex"

    # 1) Pin the proxy endpoint to the REAL gateway so tun2socks' own connection to the
    #    proxy does not loop back through the tun (split-route the /32).
    Write-Log "adding proxy bypass route $proxyIp/32 via $realGw"
    Get-NetRoute -DestinationPrefix "$proxyIp/32" -ErrorAction SilentlyContinue |
        Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    New-NetRoute -DestinationPrefix "$proxyIp/32" -NextHop $realGw -InterfaceIndex $realIfIndex `
        -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null

    # 2) Start tun2socks; it creates the Wintun adapter named $TunName.
    #    Windows uses the tun:// scheme (wintun.dll must sit next to the exe); the
    #    wintun:// scheme is NOT valid and fails with "unsupported driver: wintun".
    #    -interface is Linux/macOS only, so it is omitted here.
    Write-Log "starting tun2socks (adapter '$TunName')..."
    $env:Path = "$toolDir;$env:Path"  # so it finds wintun.dll
    $t2sOut = Join-Path $toolDir "tun2socks.out.log"
    $t2sErr = Join-Path $toolDir "tun2socks.err.log"
    # MTU 1400: Wintun defaults to 65535, which makes the netstack advertise a huge MSS;
    # oversized segments then get dropped on the real 1500-byte path -> TLS handshakes hang
    # (small requests may squeak through, large ones fail). 1400 leaves headroom for SOCKS/TCP.
    $t2sArgs = @(
        "-device", "tun://$TunName",
        "-proxy", $proxy.Url,
        "-mtu", "1400",
        "-loglevel", "warning"
    )
    $proc = Start-Process -FilePath $tunExe -ArgumentList $t2sArgs -WorkingDirectory $toolDir `
        -WindowStyle Hidden -PassThru -RedirectStandardOutput $t2sOut -RedirectStandardError $t2sErr
    Start-Sleep -Seconds 3

    # 3) Configure the tun adapter IP + make it the default route.
    $tunIf = Get-NetAdapter -Name $TunName -ErrorAction SilentlyContinue
    $waited = 0
    while (-not $tunIf -and $waited -lt 10) {
        Start-Sleep -Seconds 1; $waited++
        $tunIf = Get-NetAdapter -Name $TunName -ErrorAction SilentlyContinue
    }
    $t2sMsg = ""
    if (Test-Path $t2sErr) { $t2sMsg = (Get-Content $t2sErr -Raw).Trim() }
    if (-not $t2sMsg -and (Test-Path $t2sOut)) { $t2sMsg = (Get-Content $t2sOut -Raw).Trim() }
    if (-not $tunIf) {
        if ($proc.HasExited) {
            throw "tun2socks exited immediately (code $($proc.ExitCode)): $t2sMsg"
        }
        throw "Wintun adapter '$TunName' did not appear (tun2socks failed to start): $t2sMsg"
    }
    if ($proc.HasExited) { throw "tun2socks died before adapter was ready (exit $($proc.ExitCode)): $t2sMsg" }

    New-NetIPAddress -InterfaceIndex $tunIf.ifIndex -IPAddress $TunAddr -PrefixLength $TunPrefix `
        -ErrorAction SilentlyContinue | Out-Null
    Set-NetIPInterface -InterfaceIndex $tunIf.ifIndex -InterfaceMetric $TunMetric -ErrorAction SilentlyContinue
    # Clamp the adapter MTU too (Wintun defaults to 65535) so Windows segments outbound
    # packets small enough to survive the proxy path.
    Set-NetIPInterface -InterfaceIndex $tunIf.ifIndex -AddressFamily IPv4 -NlMtuBytes 1400 -ErrorAction SilentlyContinue
    Set-NetIPInterface -InterfaceIndex $tunIf.ifIndex -AddressFamily IPv6 -NlMtuBytes 1400 -ErrorAction SilentlyContinue
    # Point the default route at the tun with a lower metric than the real NIC.
    Get-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceIndex $tunIf.ifIndex -ErrorAction SilentlyContinue |
        Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    New-NetRoute -DestinationPrefix "0.0.0.0/0" -NextHop $TunGw -InterfaceIndex $tunIf.ifIndex `
        -RouteMetric 0 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null

    # 4) DNS via a public resolver (carried through the tunnel).
    Set-DnsClientServerAddress -InterfaceIndex $tunIf.ifIndex -ServerAddresses "1.1.1.1", "8.8.8.8" `
        -ErrorAction SilentlyContinue

    $state = [pscustomobject]@{
        Pid         = $proc.Id
        TunName     = $TunName
        TunIfIndex  = $tunIf.ifIndex
        ProxyIp     = $proxyIp
        RealGw      = $realGw
        RealIfIndex = $realIfIndex
        StartedUtc  = (Get-Date).ToUniversalTime().ToString("o")
    }
    $state | ConvertTo-Json | Set-Content $statePath -Encoding UTF8
    Write-Log "started (pid $($proc.Id)). Verifying egress (auto-rollback if it fails)..."

    # SAFETY: the whole host now default-routes through the tun. If tun2socks is not
    # actually forwarding, ALL internet is dead. Verify with retries; if it never comes
    # up, tear everything down so the machine is not left offline.
    Start-Sleep -Seconds 2
    $ip = Test-Egress $proxyIp -Retries 6
    $bigOk = $false
    if ($ip) {
        # The launcher needs LARGE TLS transfers, not just tiny requests. The MTU bug
        # lets small requests through but drops big packets, so validate a real download
        # before handing off - otherwise -Start would look OK but the launcher would fail.
        $bigOk = Test-LargeTransfer
    }
    if (-not $ip -or -not $bigOk) {
        $why = if (-not $ip) { "no egress" } else { "small requests OK but large transfer failed (MTU still too high)" }
        Write-Log "TUNNEL UNHEALTHY ($why) - rolling back so your internet is restored..."
        Remove-NetgateRouting $state
        Remove-Item $statePath -Force -ErrorAction SilentlyContinue
        throw "tunnel not healthy: $why. Routing rolled back (your internet is fine). Tell me this message and I'll adjust MTU / check tun2socks logs."
    }
    Write-Log "TUNNEL HEALTHY (small + large transfers pass). The Jagex Launcher will work now."
    Write-Log "ACTIVE. Run native capture now, then '-Stop' to restore routing."
}

# Exercises full-size packets through the tunnel to catch MTU problems that tiny
# requests (ipify) miss. Returns $true only if a multi-KB download completes.
function Test-LargeTransfer {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $targets = @(
        "https://speed.cloudflare.com/__down?bytes=300000",
        "https://static.runelite.net/bootstrap.json"
    )
    foreach ($u in $targets) {
        try {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $r = Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 25
            $len = 0
            try { $len = $r.RawContentLength } catch {}
            if ($len -le 0 -and $r.Content) { $len = $r.Content.Length }
            if ($len -ge 50000) {
                Write-Log "large-transfer OK ($([math]::Round($len/1024))KB in $($sw.ElapsedMilliseconds)ms via $([Uri]::new($u).Host))"
                return $true
            }
            Write-Log "large-transfer too small ($len bytes) from $u, trying next..."
        } catch {
            Write-Log "large-transfer failed via $([Uri]::new($u).Host): $($_.Exception.Message)"
        }
    }
    return $false
}

function Test-Egress([string]$expectIp, [int]$Retries = 1) {
    for ($n = 1; $n -le $Retries; $n++) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $ip = (Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 12).Trim()
            if ($ip -eq $expectIp) {
                Write-Log "EGRESS OK - exit IP = $ip (matches proxy). OAuth + game login now exit here."
            } else {
                Write-Log "WARNING: exit IP = $ip but proxy IP = $expectIp (check sticky session / NAT)."
            }
            return $ip
        } catch {
            if ($n -lt $Retries) {
                Write-Log "egress attempt $n/$Retries failed, retrying..."
                Start-Sleep -Seconds 3
            } else {
                Write-Log "could not confirm egress after $Retries tries: $($_.Exception.Message)"
            }
        }
    }
    return $null
}

# Shared teardown so both -Stop and the auto-rollback restore routing identically.
function Remove-NetgateRouting($s) {
    if ($s.TunIfIndex) {
        Get-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceIndex $s.TunIfIndex -ErrorAction SilentlyContinue |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    }
    if ($s.ProxyIp) {
        Get-NetRoute -DestinationPrefix "$($s.ProxyIp)/32" -ErrorAction SilentlyContinue |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    }
    if ($s.Pid) {
        Stop-Process -Id $s.Pid -Force -ErrorAction SilentlyContinue
    }
    # Kill any stray tun2socks too.
    Get-Process -Name "tun2socks*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

function Stop-Netgate {
    Assert-Admin
    if (-not (Test-Path $statePath)) {
        # Even with no state file, clear any leftover tun2socks / stale default route.
        Get-Process -Name "tun2socks*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        $stray = Get-NetAdapter -Name $TunName -ErrorAction SilentlyContinue
        if ($stray) {
            Get-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceIndex $stray.ifIndex -ErrorAction SilentlyContinue |
                Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        }
        Write-Log "not running (no state.json). Cleared any strays."
        return
    }
    $s = Get-Content $statePath -Raw | ConvertFrom-Json
    Remove-NetgateRouting $s
    Remove-Item $statePath -Force -ErrorAction SilentlyContinue
    Write-Log "stopped. routing restored to the real NIC."
}

function Show-Status {
    if (-not (Test-Path $statePath)) {
        Write-Log "INACTIVE (no state.json)."
    } else {
        $s = Get-Content $statePath -Raw | ConvertFrom-Json
        $alive = $null -ne (Get-Process -Id $s.Pid -ErrorAction SilentlyContinue)
        Write-Log "ACTIVE - tun '$($s.TunName)' pid=$($s.Pid) alive=$alive proxyIp=$($s.ProxyIp) since $($s.StartedUtc)"
        Test-Egress $s.ProxyIp | Out-Null
    }
}

switch ($PSCmdlet.ParameterSetName) {
    'Stop' { Stop-Netgate }
    'Status' { Show-Status }
    default {
        if ($Stop) { Stop-Netgate }
        elseif ($Status) { Show-Status }
        else { Start-Netgate }
    }
}
