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

## v3 — ViaNetgate + mint-replay (2026-07-05)

| Component | Change |
|-----------|--------|
| `refresh-credentials.ps1` | `-ViaNetgate` → `loginsim -no-proxy` (same OS path as RuneLite via netgate) |
| `internal/network/login.go` | `PatchRSAPlaintextGameSessionToken()` |
| `cmd/loginsim` | `-mint-replay` — mint fresh pk + captured XTEA zone |

### Outcomes documented in [versions/](versions/)

| Version | Strategy | Result |
|---------|----------|--------|
| v4 | Replay captured pk | FAILED code 10 @ 0.1s |
| v5 | Mint fresh pk + captured frame | Mint OK, login FAILED code 10 |

See `versions/v5-mint-replay-via-netgate/OPEN-ISSUES.md` for next steps.

## v1 — Initial three patterns (2026-07-04)

- `tcp-pipeline/` — live TCP JSON handoff (port 17494)
- `env-file/` — `.env` deploy between Windows host and Docker
- `env-full-docker/` — `.env` + explicit compose `environment` block
