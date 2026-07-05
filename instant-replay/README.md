# Host Instant Replay (Pattern 0 — validation before Docker)

Fastest path to prove wire-block + pk replay works **on the Windows host** before any Docker handoff.

Use this first. If instant replay fails here, tcp-pipeline and `.env` deploy will also fail.

## Flow

```
1. windows-netgate ON (PROXY_URL egress)
2. RuneLite + JVM agent (wire-block, no login.noblock)
3. User: Play → Play Now once (you will NOT enter the game)
4. Agent writes login_frame.txt + rsa_plaintext.txt + login_wire_blocked.txt
5. loginsim -login-only -replay-capture (skips JS5/CRC — pk expires in seconds)
6. Success → proceed to tcp-pipeline or env-file deploy
```

## Why `-login-only` matters

| Mode | Steps before game login | pk risk |
|------|-------------------------|---------|
| Full `loginsim` | JS5 rev + CRC fetch + frame build (~3–10 s) | **code 10** |
| `-login-only -replay-capture` | Dial + handshake + replay (~1–2 s) | pk still valid |

## Quick start

```powershell
cd C:\Users\shmou\bot-farm-headless\frm_headless
powershell -File OAuthIdp_SessionJagex\instant-replay\runbook.ps1 -WaitMin 15
```

Or directly:

```powershell
cd C:\Users\shmou\bot-farm-headless\frm_headless
powershell -File tools\agent\netns-capture\capture-netns.ps1 -InstantReplay -NoDeploy -WaitMin 15
```

## Prerequisites

- Run from **repo root** (`frm_headless`) — relative paths fail from `C:\Users\shmou`
- `PROXY_URL` set (same proxy for capture and replay)
- Proxifier / VPN off (netgate owns egress)
- RuneLite **not** already running before capture (JVM args apply at startup)
- No `-Dlogin.noblock=true` in settings (leftover from `-AllowWireLogin` burns pk)

## Success criteria

```
[capture-no-mitm] wire-block confirmed (pk unburned; ready for instant replay)
[capture-no-mitm] INSTANT REPLAY NOW (0.0s since wire-block - pk is short-lived)
[login-only] skipping JS5/CRC/frame diagnostics (pk is short-lived)
      LOGIN RESULT: success, player index N
```

## After success

| Next step | Pattern |
|-----------|---------|
| Sub-second handoff to Docker bot | [tcp-pipeline](../tcp-pipeline/) |
| Batch deploy to `.env` | [env-file](../env-file/) |
| Full compose env audit | [env-full-docker](../env-full-docker/) |

## Manual replay (if capture files already exist)

```powershell
cd C:\Users\shmou\bot-farm-headless\frm_headless
tools\agent\build\loginsim.exe -login-only -replay-capture -capture-file $env:USERPROFILE\login_frame.txt
```

Requires fresh capture (pk expires in ~30 s after wire-block).
