# Pattern C: `.env` + Full Environment Injection in Docker Compose

Every login-related variable is **explicitly listed** in `docker-compose.yml` `environment:` block **and** loaded from `env_file`. Docker injects the full surface into the container — nothing implicit.

## Flow

Same as Pattern B for capture/deploy, but ops sees **all variables** in compose for auditing, CI, and per-bot overrides.

```
capture → .env → docker compose (env_file + environment block) → container env
```

## Difference from Pattern B

| | Pattern B (env-file) | Pattern C (env-full-docker) |
|--|----------------------|----------------------------|
| compose `environment:` | Minimal (BOT_ID, guard) | **Every** login var listed |
| Visibility | Vars only in `.env` file | Vars in compose **and** `.env` |
| Override | Edit `.env` | Edit `.env` or compose defaults |
| Use case | Simple deploy | Fleet ops, CI matrices, documentation |

## Latency

Same as Pattern B — file-based, **not** suitable for sub-second pk handoff unless `.env` was updated seconds ago.

## Components

Uses same scripts as Pattern B plus explicit compose mapping (this folder's `docker-compose.yml`).

## Quick start

```powershell
powershell -File OAuthIdp_SessionJagex\env-full-docker\runbook.ps1 -DockerUp -WaitMin 15
```

## Guard rails

- `REQUIRE_CAPTURED_MACHINE_INFO=1` default
- Document which vars are session-hot vs static (RSA, CRCs = static; pk, machine-info = hot)

## Session-hot vs static variables

| Variable | Update frequency |
|----------|------------------|
| `RSA_MODULUS`, `CLIENT_REVISION`, `CLIENT_ARCHIVE_CRCS` | Per client update |
| `PROXY_URL` | Per bot / farm |
| `GAME_SESSION_TOKEN`, `RSA_PLAINTEXT_HEX` | **Every capture** (seconds TTL) |
| `MACHINE_INFO_HEX`, `PLATFORM_INFO_HEX` | **Every capture** |
| `CLIENT_TOKEN` | Static (jav_config param=9) |
