# v3 — `.env` + Full Docker Environment

## Strategy

Same as v2, but every login variable is listed explicitly in `docker-compose.yml` `environment:` for ops/CI visibility.

## Commands

```powershell
cd frm_headless
powershell -File OAuthIdp_SessionJagex/versions/v3-env-full-docker/runbook.ps1 -DockerUp -WaitMin 15
```

## Project files in `project/`

Same deploy scripts as v2 plus `docker-compose.yml` with full env block (in this folder root).

## Status

See [STATUS.md](STATUS.md). Same pk TTL constraints as v2.
