# OAuthIdp Session Jagex — Host-to-Container Login Handoff

Reference patterns for moving Jagex login state from a **Windows RuneLite capture** (JVM agent + wire-block) to a **headless Go bot in Docker**.

Parent implementation lives in `frm_headless` (OSRS protocol client). This repo documents handoff patterns only.

**Latest:** [CHANGELOG.md](CHANGELOG.md) — v2 adds `-login-only` instant replay (fixes code 10 from JS5/CRC delay).

## Run from repo root

All commands assume:

```powershell
cd C:\Users\shmou\bot-farm-headless\frm_headless
```

Running from `C:\Users\shmou` will fail with "File does not exist".

## The problem

Jagex account login uses short-lived tokens:

| Token | Name | Lifetime |
|-------|------|----------|
| `pk` | `GAME_SESSION_TOKEN` / client.pk | Seconds — must reach game server quickly |
| `gf` | `CLIENT_TOKEN` / fr.gf | Static per client build |
| Machine-info blob | XTEA zone telemetry | Must match capture environment |

Capture runs on **Windows** (RuneLite + JVM agent). The bot runs in **Linux Docker**. Something must bridge that gap.

## Four patterns (this repo)

| Folder | Handoff mechanism | Latency | Best for |
|--------|-------------------|---------|----------|
| [`instant-replay/`](instant-replay/) | Host-only: wire-block + `loginsim -login-only` | ~1–2 s | **Validate capture first** (no Docker) |
| [`tcp-pipeline/`](tcp-pipeline/) | Live TCP JSON push (port 17494) | ~2–5 s | Production farm, pk expiry critical |
| [`env-file/`](env-file/) | Host `.env` updated from capture files | 30–90 s | Dev / batch re-capture |
| [`env-full-docker/`](env-full-docker/) | Full env injection via compose + `env_file` | Same as env-file | Ops / CI / explicit config |

## Recommended order

1. **instant-replay** — prove wire-block + pk replay on host
2. **tcp-pipeline** — production hot path to Docker
3. **env-file** or **env-full-docker** — batch deploy after validated capture

## Shared capture prerequisites (all patterns)

1. **Wire-block capture** (not `-AllowWireLogin`) — pk must not be sent by RuneLite
2. **Same proxy egress** — capture via netgate + bot via `PROXY_URL`
3. **JVM agent** — `-javaagent:login-agent.jar` in RuneLite settings
4. Files produced on wire-block:
   - `login_frame.txt` — plaintext login frame
   - `rsa_plaintext.txt` — RSA block + pk + XTEA seeds
   - `login_wire_blocked.txt` — proof pk was not burned

## v2 instant replay fix

Full `loginsim` runs JS5 + CRC probes before login (~3–10 s) and burns `pk`. Instant replay now uses:

```
loginsim -login-only -replay-capture -capture-file login_frame.txt
```

Triggered automatically by `-InstantReplay -QuickReplay` in capture scripts.

## Architecture overview

```
┌─────────────────────────────────────────────────────────────┐
│  WINDOWS HOST                                               │
│  Jagex Launcher → RuneLite → JVM Agent (wire-block)         │
│  windows-netgate → PROXY_URL                                │
│  instant-replay: loginsim -login-only (host validation)     │
└──────────────────────────┬──────────────────────────────────┘
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
    TCP JSON          .env file       compose env_file
    (tcp-pipeline)    (env-file)      (env-full-docker)
         │                 │                 │
         ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────┐
│  DOCKER (Linux)                                             │
│  Go bot → PROXY_URL → oldschool.runescape.com:43594         │
└─────────────────────────────────────────────────────────────┘
```

## Quick start (full path)

```powershell
cd C:\Users\shmou\bot-farm-headless\frm_headless

# Step 1: validate on host
powershell -File OAuthIdp_SessionJagex\instant-replay\runbook.ps1 -WaitMin 15

# Step 2a: TCP handoff to Docker (production)
powershell -File OAuthIdp_SessionJagex\tcp-pipeline\runbook.ps1 -WaitMin 15

# Step 2b: OR .env deploy (batch)
powershell -File OAuthIdp_SessionJagex\env-file\runbook.ps1 -DockerUp -WaitMin 15
```

## Related

- [AuthenticationFrameworks on GitHub](https://github.com/770-as/AuthenticationFrameworks)
- Parent repo: `frm_headless` — `tools/agent/`, `internal/network/`, `cmd/loginsim`
