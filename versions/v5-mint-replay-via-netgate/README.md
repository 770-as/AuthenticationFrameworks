# v5 — Instant Replay (Mint Fresh pk + Captured Frame)

## Strategy

Wire-block captures `login_frame.txt` + `rsa_plaintext.txt` (for XTEA seeds only).

At replay:
1. Mint **new** `pk` from `~/.runelite/credentials.properties` (HTTPS via netgate)
2. `PatchRSAPlaintextGameSessionToken()` — inject fresh pk into RSA block
3. `LoginFromCapture()` — keep captured XTEA zone byte-for-byte

## Commands

```powershell
cd frm_headless
powershell -File tools\agent\netns-capture\capture-netns.ps1 -InstantReplay -NoDeploy -WaitMin 15
```

Equivalent loginsim:

```powershell
tools\agent\build\loginsim.exe -no-proxy -login-only -mint-replay -capture-file $env:USERPROFILE\login_frame.txt
```

## Key code (v5 additions)

| File | Addition |
|------|----------|
| `internal/network/login.go` | `PatchRSAPlaintextGameSessionToken()` |
| `cmd/loginsim/main.go` | `-mint-replay`, `runMintReplayLogin()` |
| `tools/agent/refresh-credentials.ps1` | QuickReplay → `-mint-replay` |

## Project files in `project/`

Full instant-replay stack — see v4 list plus:
- `internal/network/gamesession.go` — mint API
- `internal/network/login.go` — RSA pk patch

## Outcome

**FAILED — code 10** after successful mint.

See [FAILURE-LOG.md](FAILURE-LOG.md) and [OPEN-ISSUES.md](OPEN-ISSUES.md).
