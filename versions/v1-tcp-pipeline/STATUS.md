# v1 Status — TCP Pipeline

| Item | Status |
|------|--------|
| Wire-block capture | Works |
| TCP handoff push | Works if Docker listening (else `Connection refused` in agent log) |
| Bot login after handoff | Not confirmed end-to-end in production run |
| code 10 on host replay | N/A — handoff intended to skip host loginsim |

**Note:** Requires Docker bot running **before** capture. `[HANDOFF] push failed: Connection refused` is expected if bot not up.
