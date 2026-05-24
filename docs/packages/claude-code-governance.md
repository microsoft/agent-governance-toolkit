# @microsoft/agent-governance-claude-code — Claude Code governance package

[![CI](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](../../LICENSE)

`@microsoft/agent-governance-claude-code` is the first-party AGT package surface for local Claude
Code governance. It ships a Claude Code plugin root with deterministic command hooks for session,
prompt, and pre-tool checks plus a bundled MCP server for operator-facing inspection tools.

## What it is

- a first-party Claude Code plugin package for local developer protection
- a package built on `@microsoft/agent-governance-sdk`
- a repo-local plugin surface you can load directly with `claude --plugin-dir`

## What it is not

- not a Copilot-style in-process extension
- not a silent installer that mutates Claude settings on your behalf
- not a claim of full Copilot CLI parity, especially for post-tool output suppression

## Load it locally

From a repo checkout:

```powershell
cd <repo-root>
cd agent-governance-claude-code
npm install
cd ..
claude --plugin-dir .\agent-governance-claude-code
```

```bash
cd <repo-root>
cd agent-governance-claude-code
npm install
cd ..
claude --plugin-dir "$(pwd)/agent-governance-claude-code"
```

The package currently optimizes for direct plugin loading rather than a separate installer CLI.

## What it enforces

- `SessionStart` context injection
- `UserPromptSubmit` prompt-inspection and fail-closed blocking
- `PreToolUse` tool-call allow, deny, and review decisions

The bundled MCP server exposes:

- `agt_policy_status`
- `agt_policy_check_text`

Claude slash commands are markdown wrappers around those tools:

- `/agt-governance:agt-status`
- `/agt-governance:agt-check`

## Policy and audit paths

Policy resolution order:

1. `AGT_CLAUDE_POLICY_PATH`
2. `%USERPROFILE%\.claude\agt\policy.json`
3. `~/.claude/agt/policy.json`
4. bundled `agent-governance-claude-code/config/default-policy.json`

Audit log path:

- Windows: `%USERPROFILE%\.claude\agt\audit-log.json`
- macOS/Linux: `~/.claude/agt/audit-log.json`

Override with `AGT_CLAUDE_AUDIT_PATH`.

## Relationship to the example

For a scenario-driven walkthrough with a sample policy override and expected outcomes, see:

- [`examples/claude-code-agt`](../../examples/claude-code-agt/README.md)

## Validation

```powershell
cd agent-governance-claude-code
npm run check
npm test
```
