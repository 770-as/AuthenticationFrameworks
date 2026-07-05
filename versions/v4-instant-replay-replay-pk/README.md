# v4 — Instant Replay (Reuse Captured pk)

## Strategy

Wire-block on Windows → immediately replay with `loginsim` using the **same pk** from `rsa_plaintext.txt`.

Fixes applied in this generation:
- `-login-only` — skip JS5/CRC probes (timing fix)
- `-ViaNetgate` / `-no-proxy` — replay via netgate OS routing, not app SOCKS

## Commands

```powershell
cd frm_headless
powershell -File tools\agent\netns-capture\capture-netns.ps1 -InstantReplay -NoDeploy -WaitMin 15
```

Equivalent loginsim:

```powershell
tools\agent\build\loginsim.exe -no-proxy -login-only -replay-capture -capture-file $env:USERPROFILE\login_frame.txt
```

## Key difference in `project/tools/agent/refresh-credentials.ps1`

This snapshot uses **`-replay-capture`** (not `-mint-replay`):

```powershell
$loginArgs = @("-login-only", "-replay-capture", "-capture-file", $framePath)
```

## Project files in `project/`

| File | Role |
|------|------|
| `tools/agent/capture-no-mitm.ps1` | `-InstantReplay`, `-ViaNetgate` on refresh |
| `tools/agent/netns-capture/capture-netns.ps1` | netgate wrapper |
| `tools/agent/netns-capture/windows-netgate.ps1` | TUN → Marseille |
| `tools/agent/refresh-credentials.ps1` | **v4: replay captured pk** |
| `cmd/loginsim/main.go` | `-login-only`, `-replay-capture` |
| `internal/network/login.go` | `LoginFromCapture()` |
| `tools/agent/loginhook/LoginDumpHook.java` | wire-block + frame dump |

## Outcome

**FAILED — code 10** even at 0.1s with correct netgate egress.

**Lesson:** captured `pk` is single-use; wire-block does not make it reusable.

See [FAILURE-LOG.md](FAILURE-LOG.md).
