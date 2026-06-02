# AGT Claude Code Plugin

This package is the **production package surface** for Agent Governance Toolkit on Claude Code.

It ships a Claude Code plugin that uses:

- Claude hooks for deterministic session, prompt, and pre-tool governance
- a bundled MCP server for operator-facing AGT inspection tools
- the AGT TypeScript SDK for policy evaluation, prompt defense, and MCP threat scanning

## What this package is

- a first-party Claude Code plugin package
- an experimental parity layer for the existing Copilot CLI governance work
- a publishable npm package that can also be loaded locally with Claude Code

## What this package is not

- a Copilot-style in-process extension
- a universal governance layer for every Claude surface
- a guarantee of full Copilot CLI feature parity

## Current scope

This initial package enforces:

- `SessionStart` governance context injection
- `UserPromptSubmit` prompt inspection and fail-closed blocking
- `PreToolUse` tool-call inspection with allow, deny, or ask behavior

It also exposes two MCP tools:

- `agt_policy_status`
- `agt_policy_check_text`

## Important parity gaps

- Claude slash commands are markdown-driven, so `/agt-governance:agt-status` and `/agt-governance:agt-check` are thin wrappers around MCP tools rather than deterministic code handlers.
- `PostToolUse` in Claude cannot reliably redact tool output after the tool has already executed, so this package does not claim Copilot-style output suppression parity.
- Hook execution is out-of-process. The package keeps enforcement in command hooks so policy errors can fail closed.

## Local development

Run these commands from the **repository root** so the relative plugin path resolves correctly.

Install dependencies:

```powershell
cd agent-governance-claude-code
npm install
```

Load the plugin directly:

```powershell
claude --plugin-dir .\agent-governance-claude-code
```

```bash
claude --plugin-dir "$(pwd)/agent-governance-claude-code"
```

Inspect the active policy and command wiring:

```text
/agt-governance:agt-status
/agt-governance:agt-check suspicious text to inspect
```

Reload after edits:

```text
/reload-plugins
```

## Commands

The package provides two Claude commands:

- `/agt-governance:agt-status`
- `/agt-governance:agt-check`

## Example walkthrough

For a runnable repo-local walkthrough with a sample policy override, expected prompts, and cleanup
notes, see:

- [`examples/claude-code-agt`](../examples/claude-code-agt/README.md)
- [`docs/packages/claude-code-governance.md`](../docs/packages/claude-code-governance.md)

## Policy loading

The package loads policy in this order:

1. `AGT_CLAUDE_POLICY_PATH`
2. `%USERPROFILE%\.claude\agt\policy.json`
3. `~/.claude/agt/policy.json`
4. bundled `config/default-policy.json`

Audit entries are written to:

- Windows: `%USERPROFILE%\.claude\agt\audit-log.json`
- macOS/Linux: `~/.claude/agt/audit-log.json`

Override with `AGT_CLAUDE_AUDIT_PATH`.

## Validation

```powershell
cd agent-governance-claude-code
npm run check
npm test
```
