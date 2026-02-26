---
summary: "CLI reference for `openclaw setup` (initialize config + workspace)"
read_when:
  - You’re doing first-run setup without the full onboarding wizard
  - You want to set the default workspace path
title: "setup"
---

# `openclaw setup`

Initialize `~/.openclaw/openclaw.json` and the agent workspace.

Related:

- Getting started: [Getting started](/start/getting-started)
- Wizard: [Onboarding](/start/onboarding)

## Examples

```bash
openclaw setup
openclaw setup --workspace ~/.openclaw/workspace
```

To run the wizard via setup:

```bash
openclaw setup --wizard
```

## Security and Monitoring Baseline

`openclaw setup` now seeds a baseline `security` + `monitoring` framework in config, including:

- security audit log settings (`security.audit`)
- secret resolver placeholders for env, keychain, and 1Password (`security.secrets`)
- scoped RBAC token map (`security.rbac.scopedTokens`)
- security-side rate-limit policy (`security.rateLimit`)
- sandbox permission gates (`security.sandbox`)
- daemon monitoring settings for heartbeat, queue pressure, resources, metrics endpoint, and alert delivery (`monitoring.*`)

After setup, review the generated config:

```bash
openclaw config get security --json
openclaw config get monitoring --json
```

Model defaults are set later during auth onboarding. For OpenAI and Codex auth flows, OpenClaw now keeps `openai/gpt-5.2-codex` in `agents.defaults.model.fallbacks` as a baseline coding fallback.
