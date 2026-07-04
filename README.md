# OAuthIdp Session Jagex — Host-to-Container Login Handoff

Three reference patterns for moving Jagex login state from a **Windows RuneLite capture** (JVM agent + wire-block) to a **headless Go bot in Docker**.

Parent implementation: [frm_headless](https://github.com/770-as/AuthenticationFrameworks) bot-farm (OSRS protocol client).

## The problem

Jagex account login uses short-lived tokens:

| Token | Name | Lifetime |
|-------|------|----------|
| `pk` | `GAME_SESSION_TOKEN` / client.pk | Seconds — must reach game server quickly |
| `gf` | `CLIENT_TOKEN` / fr.gf | Static per client build |
| Machine-info blob | XTEA zone telemetry | Must match capture environment |

Capture runs on **Windows** (RuneLite + JVM agent). The bot runs in **Linux Docker**. Something must bridge that gap.

## Three patterns (this repo)

| Folder | Handoff mechanism | Latency | Automation | Best for |
|--------|-------------------|---------|------------|----------|
| [`tcp-pipeline/`](tcp-pipeline/) | Live TCP JSON push (port 17494) | ~1–5 ms | High — bot listens, JVM pushes on wire-block | Production farm, pk expiry critical |
| [`env-file/`](env-file/) | Host `.env` updated from capture files | 30–90 s if manual | Medium — scripted deploy | Dev / batch re-capture |
| [`env-full-docker/`](env-full-docker/) | Full env injection via `docker-compose` + `env_file` | Same as env-file | Low — all vars in compose | Legacy / explicit config |

## Shared capture prerequisites (all patterns)

1. **Wire-block capture** (not `-AllowWireLogin`) — pk must not be sent by RuneLite
2. **Same proxy egress** — capture via netgate + bot via `PROXY_URL`
3. **JVM agent** — `-javaagent:login-agent.jar` in RuneLite settings
4. Files produced on wire-block:
   - `login_frame.txt` — plaintext login frame
   - `rsa_plaintext.txt` — RSA block + pk + XTEA seeds
   - `login_wire_blocked.txt` — proof pk was not burned

## Architecture overview

```
┌─────────────────────────────────────────────────────────────┐
│  WINDOWS HOST                                               │
│  Jagex Launcher → RuneLite → JVM Agent (wire-block)         │
│  windows-netgate → PROXY_URL (Marseille)                    │
└──────────────────────────┬──────────────────────────────────┘
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
    TCP JSON          .env file       compose env_file
    (tcp-pipeline)    (env-file)      (env-full-docker)
         │                 │                 │
         ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────┐
│  DOCKER (Linux)                                             │
│  Go bot → PROXY_URL → oldschool.runescape.com:43594         │
└─────────────────────────────────────────────────────────────┘
```

## Choosing a pattern

- **Use tcp-pipeline** when pk expiry causes code 10 and you need sub-second handoff.
- **Use env-file** when you capture in batch and deploy minutes later (tokens may be stale).
- **Use env-full-docker** when you want every variable visible in compose for ops/debugging.

## Related docs

- [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) — capture vs runtime split (parent repo)
- [AuthenticationFrameworks on GitHub](https://github.com/770-as/AuthenticationFrameworks)
