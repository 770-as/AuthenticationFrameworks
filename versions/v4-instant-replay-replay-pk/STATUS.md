# v4 Status — replay captured pk

| Item | Status |
|------|--------|
| Wire-block | OK |
| Capture files | OK |
| `-login-only` timing | OK (0.0–0.1s to replay) |
| `-ViaNetgate` egress | OK (`loginsim via netgate OS routing`) |
| Reuse captured pk | **FAILED code 10** |

## Conclusion

Infrastructure and timing were correct. Jagex rejects **replayed** `pk` regardless of speed and IP.

Wire-block value = capture **machine-info frame**, not preserve **pk** for reuse.
