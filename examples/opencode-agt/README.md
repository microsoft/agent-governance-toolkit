# AGT OpenCode Governance Walkthrough

This example is a **runnable repo-local walkthrough** for the first-party
OpenCode governance package at
[`agent-governance-opencode`](../../agent-governance-opencode/README.md).

It demonstrates:

- loading the AGT plugin via a workspace `opencode.json`
- prompt blocking through the `event` hook
- tool review and deny decisions through `tool.execute.before`
- secret redaction on `tool.execute.after`
- AGT status and text-inspection tools via in-process custom tools and the
  bundled stdio MCP server

## What this example is

- a self-contained walkthrough under `examples/`
- a sample policy override and prompt/tool scenario you can replay locally
- the usage story for the production package, not a separate implementation

## What this example is not

- a second plugin package
- a replacement for the package README

## Layout

```text
examples/opencode-agt/
├── README.md
├── opencode.json
├── config/
│   └── review-heavy-policy.json
└── scenarios/
    └── guarded-session/
        └── README.md
```

## Quick start

Run these commands from the **repository root** so the relative plugin path
resolves correctly.

### 1. Install the package dependencies

```powershell
cd agent-governance-opencode
npm install
cd ..
```

### 2. Point OpenCode at the example policy

PowerShell:

```powershell
$env:AGT_OPENCODE_POLICY_PATH = (Resolve-Path .\examples\opencode-agt\config\review-heavy-policy.json)
```

Bash:

```bash
export AGT_OPENCODE_POLICY_PATH="$(pwd)/examples/opencode-agt/config/review-heavy-policy.json"
```

### 3. Start OpenCode from the example directory

```powershell
cd examples\opencode-agt
opencode
```

The included `opencode.json` loads the plugin from the repo-local path so no
npm publish is required.

### 4. Confirm the plugin is active

Inside OpenCode, ask:

```text
Show me the current AGT policy status.
```

OpenCode will invoke the in-process `agt_policy_status` tool. Expected result:

- AGT reports the active policy path
- the prompt-defense grade is shown
- audit-chain verification succeeds or reports any corruption explicitly

### 5. Exercise the guarded scenario

Follow the walkthrough in:

- [`scenarios/guarded-session/README.md`](./scenarios/guarded-session/README.md)

## Cleanup

Unset the example policy override when you are done:

PowerShell:

```powershell
Remove-Item Env:AGT_OPENCODE_POLICY_PATH
```

Bash:

```bash
unset AGT_OPENCODE_POLICY_PATH
```

If you want to discard the local audit log created by this walkthrough, remove:

- Windows: `%USERPROFILE%\.config\opencode\agt\audit.json`
- macOS/Linux: `~/.config/opencode/agt/audit.json`
