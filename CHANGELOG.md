# Changelog

## v2 — Instant replay + login-only (2026-07-05)

### Problem fixed

Wire-block succeeded at 0.0s but `loginsim` still ran JS5 revision check + CRC fetch (steps 1–5) before the game login handshake. That added 3–10+ seconds and burned the short-lived `pk` → **code 10**.

### Changes (parent repo `frm_headless`)

| Component | Change |
|-----------|--------|
| `cmd/loginsim` | New `-login-only` flag: skip JS5/CRC diagnostics, dial + `LoginFromCapture` immediately |
| `tools/agent/refresh-credentials.ps1` | `-QuickReplay` passes `-login-only -replay-capture`; propagates loginsim exit code |
| `tools/agent/capture-no-mitm.ps1` | Fixed false "login accepted" on failure; ASCII strings (no Unicode em-dash parse errors) |

### Capture command (run from repo root)

```powershell
cd C:\Users\shmou\bot-farm-headless\frm_headless
powershell -File tools\agent\netns-capture\capture-netns.ps1 -InstantReplay -NoDeploy -WaitMin 15
```

### Expected output after wire-block

```
[refresh] QuickReplay: skipping framedump/logindiff ...
[login-only] skipping JS5/CRC/frame diagnostics (pk is short-lived)
      LOGIN RESULT: success, player index ...
```

## v1 — Initial three patterns (2026-07-04)

- `tcp-pipeline/` — live TCP JSON handoff (port 17494)
- `env-file/` — `.env` deploy between Windows host and Docker
- `env-full-docker/` — `.env` + explicit compose `environment` block
