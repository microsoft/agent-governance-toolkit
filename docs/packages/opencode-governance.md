---
title: OpenCode CLI governance package
description: AGT in-process plugin for the OpenCode CLI — enforce policy on prompts, tools, and tool output.
---

# OpenCode CLI governance package

`@microsoft/agent-governance-opencode` is the AGT governance plugin for
[OpenCode](https://github.com/anomalyco/opencode). It loads in-process inside
the OpenCode runtime and enforces AGT developer-protection policy on every
session, prompt, tool call, and tool output.

> **Public Preview.** The plugin API and policy schema may evolve.

## Why OpenCode gets in-process governance

OpenCode plugins are async TypeScript/JavaScript functions loaded directly into
the CLI process, unlike the subprocess hooks used by Claude Code and Antigravity.
That model lets this package:

- enforce policy on `tool.execute.before` without a subprocess round trip
- **redact** secrets from `tool.execute.after` output before the model sees it
  (a parity gain over Claude Code)
- register custom AGT tools the model can call directly (`agt_policy_status`,
  `agt_policy_check_text`)

## What the plugin enforces

| OpenCode hook | AGT behavior |
|---|---|
| `session.start` | Injects governance context describing the active policy and mode. |
| `event` (chat-style) | Scans the submitted prompt with the AGT prompt-defense backend. Throws on `deny`. |
| `tool.execute.before` | Runs `evaluateOpenCodeTool`. Throws on `deny`; marks args on `review`. |
| `tool.execute.after` | Scans tool output for AWS keys, GitHub PATs, OpenAI keys, Azure storage keys, JWTs, and PEM private keys. Redacts in enforce mode. |
| `tool.execute.error` | Records an audit entry without re-running policy. |

It also publishes a stdio MCP server (`server/agt-mcp.mjs`) for operators who
want to invoke `agt_policy_status` or `agt_policy_check_text` from external
workflows.

## Install

```powershell
npm install @microsoft/agent-governance-opencode
```

Then add the plugin to your project's `opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["@microsoft/agent-governance-opencode"]
}
```

## Configuration

The plugin loads policy from (first match wins):

1. `AGT_OPENCODE_POLICY_PATH` environment variable
2. `./.agt/policy.json` in the working directory
3. `~/.config/opencode/agt/policy.json`
4. The bundled `config/default-policy.json` (enforce, fail-closed)

Audit log defaults to `~/.config/opencode/agt/audit.json`; override via
`AGT_OPENCODE_AUDIT_PATH`.

A minimal review-heavy policy:

```json
{
  "schemaVersion": 1,
  "version": 1,
  "mode": "enforce",
  "denyOnPolicyError": true,
  "toolPolicies": {
    "allowedTools": ["read", "glob", "grep"],
    "blockedTools": [],
    "defaultEffect": "review",
    "reviewTools": ["bash", "webfetch", "write", "edit", "patch"]
  }
}
```

## Parity notes

- OpenCode's plugin contract does not expose a server-side "ask" decision from
  inside `tool.execute.before`. AGT `review` decisions annotate the args with
  `__agt_review_reason` and rely on OpenCode's normal permission UX. Set
  `toolPolicies.defaultEffect: "deny"` for hard-deny behaviour on review.
- Output redaction is intentionally conservative — only well-known credential
  patterns are touched. Audit entries record the redaction category, never the
  redacted value.

## Tutorials and examples

- [Tutorial: govern an OpenCode CLI session](../tutorials/54-opencode-cli-governance.md)
- [`examples/opencode-agt`](../../examples/opencode-agt/README.md)
