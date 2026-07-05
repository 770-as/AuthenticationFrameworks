# v5 Status — mint-replay via netgate

| Item | Status |
|------|--------|
| Wire-block | OK |
| `-ViaNetgate` | OK |
| Mint fresh pk | OK (`minted fresh pk len=53 prefix=Y12ZJO...`) |
| Patch RSA + LoginFromCapture | Runs |
| Game login | **FAILED code 10** |

## Open

Mint succeeds but game server still rejects session id. Likely causes:

1. **Mint HTTPS egress** — uTLS mint may not match netgate path the same way game TCP does
2. **JX credentials stale** — RuneLite killed before replay; session may not match mint context
3. **RSA seed mismatch** — patching pk into capture RSA block while keeping old XTEA seeds may be invalid
4. **Need `-AllowWireLogin` once** — pk may require completed wire login to activate account session (hypothesis)

See [OPEN-ISSUES.md](OPEN-ISSUES.md).
