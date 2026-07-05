# v1 — TCP Pipeline (Live Handoff)

## Strategy

JVM agent pushes JSON to `localhost:17494` on wire-block. Docker bot listens, receives capture, calls `LoginFromCapture()`.

## Commands

```powershell
cd frm_headless
$env:HANDOFF_LISTEN = ":17494"
docker compose -f OAuthIdp_SessionJagex/versions/v1-tcp-pipeline/docker-compose.yml up --build

powershell -File tools\agent\build.ps1
powershell -File tools\agent\netns-capture\capture-netns.ps1 -InstantReplay -NoDeploy
```

## Project files in `project/`

| File | Role |
|------|------|
| `internal/network/handoff.go` | TCP listener, JSON parse |
| `internal/network/handoff_env.go` | `REQUIRE_CAPTURED_MACHINE_INFO` |
| `cmd/bot/main.go` | `HANDOFF_LISTEN` wait |
| `tools/agent/loginhook/LoginDumpHook.java` | `pushHandoffIfConfigured()` |
| `tools/agent/capture-no-mitm.ps1` | `-Dhandoff.host/port` JVM args |
| `tools/agent/netns-capture/capture-netns.ps1` | netgate wrapper |

## Status

See [STATUS.md](STATUS.md).
