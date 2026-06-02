# AGT Claude Code Governance Walkthrough

This example is a **runnable repo-local walkthrough** for the first-party Claude Code governance
package at [`agent-governance-claude-code`](../../agent-governance-claude-code/README.md).

It demonstrates:

- Claude Code plugin loading with `--plugin-dir`
- prompt blocking through `UserPromptSubmit`
- tool review and deny decisions through `PreToolUse`
- AGT status and text-inspection slash commands backed by the packaged MCP server

## What this example is

- a self-contained walkthrough under `examples/`
- a sample policy override and prompt/tool scenario you can replay locally
- the usage story for the production package, not a separate implementation

## What this example is not

- a second plugin package
- a replacement for the package README
- a guarantee of Claude-hosted marketplace distribution

## Layout

```text
examples/claude-code-agt/
├── README.md
├── config/
│   └── review-heavy-policy.json
└── scenarios/
    └── guarded-session/
        └── README.md
```

## Quick start

Run these commands from the **repository root** so the relative plugin path resolves correctly.

### 1. Install the package dependencies

```powershell
cd agent-governance-claude-code
npm install
cd ..
```

### 2. Point Claude Code at the example policy

PowerShell:

```powershell
$env:AGT_CLAUDE_POLICY_PATH = (Resolve-Path .\examples\claude-code-agt\config\review-heavy-policy.json)
```

Bash:

```bash
export AGT_CLAUDE_POLICY_PATH="$(pwd)/examples/claude-code-agt/config/review-heavy-policy.json"
```

### 3. Start Claude Code with the package as a plugin root

```powershell
claude --plugin-dir .\agent-governance-claude-code
```

```bash
claude --plugin-dir "$(pwd)/agent-governance-claude-code"
```

### 4. Confirm the plugin is active

Inside Claude Code:

```text
/agt-governance:agt-status
```

Expected result:

- AGT reports the active policy path
- the prompt-defense status is shown
- audit-chain verification succeeds or reports any corruption explicitly

### 5. Exercise the guarded scenario

Follow the walkthrough in:

- [`scenarios/guarded-session/README.md`](./scenarios/guarded-session/README.md)

## Cleanup

Unset the example policy override when you are done:

PowerShell:

```powershell
Remove-Item Env:AGT_CLAUDE_POLICY_PATH
```

Bash:

```bash
unset AGT_CLAUDE_POLICY_PATH
```

If you want to discard the local audit log created by this walkthrough, remove:

- Windows: `%USERPROFILE%\.claude\agt\audit-log.json`
- macOS/Linux: `~/.claude/agt/audit-log.json`
