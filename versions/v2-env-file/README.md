# v2 — `.env` File Handoff

## Strategy

Capture files on Windows → `pull-capture-and-deploy.ps1` → update `.env` → Docker reads tokens at startup.

## Commands

```powershell
cd frm_headless
powershell -File OAuthIdp_SessionJagex/versions/v2-env-file/runbook.ps1 -DockerUp -WaitMin 15
```

## Project files in `project/`

| File | Role |
|------|------|
| `tools/agent/vm-capture/pull-capture-and-deploy.ps1` | Import capture-out → `.env` |
| `tools/agent/refresh-credentials.ps1` | Parse frame, upsert tokens |
| `tools/agent/vm-capture/capture-on-host.ps1` | Capture wrapper |
| `tools/agent/netns-capture/capture-netns.ps1` | netgate + capture |

## Latency problem

Deploy path includes framedump/logindiff + docker up (30–90s). `pk` often expires before bot connects → **code 10**.

## Status

See [STATUS.md](STATUS.md).
