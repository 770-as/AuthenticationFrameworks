# v4 Failure Log — replay captured pk

## Symptom

```
[capture-no-mitm] INSTANT REPLAY NOW (0.1s since wire-block - pk is short-lived)
[refresh] loginsim via netgate OS routing (-no-proxy; same path as RuneLite capture)
[login-only] skipping JS5/CRC/frame diagnostics (pk is short-lived)
      LOGIN RESULT: login rejected: bad session id (code 10)
```

## Agent log (typical)

```
[LOGIN-BLOCK] dropped login socket write type=0x10 wireLen=490 bodyLen=487
```

## What was ruled out

- Slow replay (JS5/CRC) — fixed with `-login-only`
- Wrong egress IP (SOCKS vs netgate) — fixed with `-ViaNetgate`
- pk expired from waiting — replay at 0.1s after wire-block

## Root cause (v4)

`pk` in `rsa_plaintext.txt` cannot be sent again. Wire-block prevents RuneLite from entering the game but does not produce a reusable token.

## Next step → v5

Mint fresh `pk` at replay time; keep captured XTEA zone from `login_frame.txt`.
