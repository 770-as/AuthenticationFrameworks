# v5 Failure Log — mint-replay (2026-07-05)

## User run (full excerpt)

```
[capture-no-mitm] wire-block confirmed (pk unburned; ready for instant replay)
[capture-no-mitm] INSTANT REPLAY NOW (0.1s since wire-block - pk is short-lived)
[refresh] loginsim via netgate OS routing (-no-proxy; same path as RuneLite capture)
[refresh] QuickReplay: mint fresh pk + captured XTEA zone (wire-block path)
[login-only] skipping JS5/CRC/frame diagnostics (pk is short-lived)
      minted fresh pk len=53 prefix=Y12ZJO...
      LOGIN RESULT: login rejected: bad session id — CLIENT_TOKEN/GAME_SESSION_TOKEN expired or invalid (code 10)
```

## Capture tokens (same run)

```
#1 3Bqs0OOxi2J3fOEeCOilq5zF5nv5Ads1pecxHCiSroSMmzND6oDg   ← captured pk (not used in v5 replay)
#3 ElZAIrq5NpKN6D3mDdihco3oPeYN2KFy2DCquj7JMmECPmLrDP3Bnw  ← gf (static)
```

## What worked

- netgate egress 81.181.238.60 before/during capture
- wire-block marker + frame + rsa files
- mint API returned 53-char pk

## What failed

- Game login with minted pk + captured frame → code 10

## Compared to v4

| | v4 replay pk | v5 mint pk |
|--|--------------|------------|
| pk source | rsa_plaintext.txt | auth.runescape.com mint |
| Mint step | none | succeeded |
| code 10 | yes @ 0.1s | yes after mint |

v5 proves code 10 is **not only** captured-pk reuse — fresh mint also rejected in this configuration.
