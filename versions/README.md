# Five Version Snapshots — Compare Later

Frozen reference copies from `frm_headless` at each stage of the Jagex host-to-Docker handoff work.

| Version | Folder | Handoff / replay strategy | Capture | Replay login | Status |
|---------|--------|---------------------------|---------|--------------|--------|
| **v1** | [v1-tcp-pipeline/](v1-tcp-pipeline/) | Live TCP JSON → Docker `:17494` | Wire-block + JVM push | Bot `LoginFromCapture` after handoff | Not end-to-end tested in farm |
| **v2** | [v2-env-file/](v2-env-file/) | Host `.env` → Docker `env_file` | Wire-block → capture-out | Bot `Login()` from `.env` | pk stale if deploy slow → code 10 |
| **v3** | [v3-env-full-docker/](v3-env-full-docker/) | Same as v2 + explicit compose `environment:` | Same as v2 | Same as v2 | Same pk TTL issue as v2 |
| **v4** | [v4-instant-replay-replay-pk/](v4-instant-replay-replay-pk/) | Host instant replay | Wire-block | `-login-only -replay-capture` reuses captured pk | **FAILED code 10** (pk single-use) |
| **v5** | [v5-mint-replay-via-netgate/](v5-mint-replay-via-netgate/) | Host instant replay | Wire-block | `-login-only -mint-replay` fresh pk + captured XTEA | **FAILED code 10** (see FAILURE-LOG) |

## What each folder contains

```
vN-*/
  README.md          — design, commands, outcome
  STATUS.md            — working / failed / partial
  FAILURE-LOG.md       — user log excerpts (v4, v5)
  docker-compose.yml   — (v1–v3 only)
  runbook.ps1
  .env.example         — (v1–v3)
  project/             — copy of frm_headless files used by this version
    tools/agent/...
    cmd/loginsim/...
    internal/network/...
```

## Evolution timeline

1. **v1–v3** — Three Docker handoff patterns (TCP vs `.env` vs full compose).
2. **v4** — Fixed JS5/CRC timing (`-login-only`) + egress (`-ViaNetgate` / `-no-proxy`). Still replayed **same pk** → code 10 at 0.1s.
3. **v5** — Mint fresh pk, patch RSA, keep captured frame. Mint succeeds; game login still code 10 (open issue).

## Run from repo root

```powershell
cd C:\Users\shmou\bot-farm-headless\frm_headless
```

## Parent repo

Live code continues in `frm_headless/`. These folders are **snapshots for comparison**, not the runtime path.
