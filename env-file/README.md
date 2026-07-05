# Pattern B: `.env` File Handoff (Capture → Deploy)

Classic path: JVM agent writes capture files on Windows host; a script parses them into **`.env`**; Docker bot reads `.env` at startup via `env_file`.

## Flow

```
1. capture-netns (wire-block) → %USERPROFILE%\login_frame.txt, rsa_plaintext.txt, ...
2. capture-on-host copies → tools/agent/vm-bundle/capture-out/
3. pull-capture-and-deploy.ps1 → refresh-credentials.ps1 → updates .env
4. docker compose up --env-file .env
5. Bot reads GAME_SESSION_TOKEN, MACHINE_INFO_HEX, etc. from environment
6. Bot builds login frame (Login()) or replays if configured
```

## Latency budget

| Step | Time (typical) |
|------|----------------|
| User closes RuneLite + Enter | 10–60 s |
| framedump + logindiff | 20–40 s |
| docker compose up | 5–30 s |
| **Total** | **30–90+ s** → pk often **expired (code 10)** |

## Mitigation (parent repo, v2)

`-InstantReplay -QuickReplay` runs `loginsim -login-only -replay-capture` (skips JS5/CRC that burn pk).

Validate on host first:

```powershell
cd C:\Users\shmou\bot-farm-headless\frm_headless
powershell -File OAuthIdp_SessionJagex\instant-replay\runbook.ps1 -WaitMin 15
```

Then deploy to `.env`:

```powershell
powershell -File tools\agent\vm-capture\pull-capture-and-deploy.ps1 -NoDocker
docker compose -f OAuthIdp_SessionJagex/env-file/docker-compose.yml up --build
```

## Components (parent repo)

| File | Role |
|------|------|
| `tools/agent/vm-capture/pull-capture-and-deploy.ps1` | Import capture-out → .env |
| `tools/agent/refresh-credentials.ps1` | Parse frame, upsert tokens + blobs |
| `tools/agent/vm-capture/capture-on-host.ps1` | Copy host capture → capture-out |

## When to use

- Batch capture sessions (many accounts, deploy later)
- Debugging token/frame parsing with `framedump` / `logindiff`
- When Docker bot is not running during capture

## When NOT to use

- Hot login immediately after wire-block (use tcp-pipeline)
- Stale `MACHINE_INFO_HEX` in `.env` from a previous capture mixed with new pk

## Guard rail

Set `REQUIRE_CAPTURED_MACHINE_INFO=1` so bot refuses golden fallback if blobs missing from `.env`.
