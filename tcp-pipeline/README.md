# Pattern A: TCP Pipeline (Live Session Handoff)

Zero-file hot path: JVM agent pushes session JSON to a bot listening inside Docker **immediately after wire-block**.

## Flow

```
1. docker compose up          (bot listens HANDOFF_LISTEN=:17494)
2. capture-netns -InstantReplay (Windows, netgate ON)
3. User: Play → Play Now once
4. JVM: wire-block → TCP push JSON → localhost:17494
5. Docker port map → bot receives → LoginFromCapture()
6. Bot enters world (seconds after block)
```

## Latency budget

| Step | Time |
|------|------|
| Wire-block → TCP write | < 10 ms |
| Host → container port map | 1–5 ms |
| Bot parse + dial + login | 2–5 s |
| **Total** | **~2–5 s** (pk still valid) |

## Components (parent repo)

| File | Role |
|------|------|
| `internal/network/handoff.go` | TCP listener, JSON parse, `ApplyToLoginConfig()` |
| `tools/agent/loginhook/LoginDumpHook.java` | `pushHandoffIfConfigured()` after wire-block |
| `cmd/bot/main.go` | `HANDOFF_LISTEN` wait before login |
| `tools/agent/capture-no-mitm.ps1` | `-Dhandoff.host` / `-Dhandoff.port` JVM args |

## JSON payload (one line, UTF-8)

```json
{
  "v": 1,
  "gameSessionToken": "<pk from rsa_plaintext>",
  "clientToken": "<gf from cc_strings #3>",
  "loginFrameHex": "<full [LOGIN-FRAME] hex>",
  "rsaPlaintextHex": "<[RSA-PLAINTEXT] hex>",
  "wireBlocked": true
}
```

## Quick start

```powershell
# From parent repo root (frm_headless) — NOT from C:\Users\shmou
cd C:\Users\shmou\bot-farm-headless\frm_headless

# Optional: validate capture on host first (Pattern 0)
powershell -File OAuthIdp_SessionJagex\instant-replay\runbook.ps1 -WaitMin 15

# Terminal 1 — bot listener
$env:HANDOFF_LISTEN = ":17494"
$env:REQUIRE_CAPTURED_MACHINE_INFO = "1"
docker compose -f OAuthIdp_SessionJagex/tcp-pipeline/docker-compose.yml up --build

# Terminal 2 — rebuild agent + capture
powershell -File tools\agent\build.ps1
powershell -File tools\agent\netns-capture\capture-netns.ps1 -InstantReplay -NoDeploy -WaitMin 15
```

Host capture uses `loginsim -login-only` (v2) when `-InstantReplay` validates before Docker handoff.

## Guard rails

- `REQUIRE_CAPTURED_MACHINE_INFO=1` — refuses golden machine-info fallback
- `wireBlocked: true` required — rejects burned pk captures
- Login uses `LoginFromCapture()` — byte-identical XTEA zone from capture

## When NOT to use

- Bot container not running before capture (handoff goes nowhere)
- `-AllowWireLogin` (pk burned on wire)
- Different `PROXY_URL` between capture and bot (possible IP binding rejection)
