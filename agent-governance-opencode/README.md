# AGT OpenCode Plugin

This package is the **production package surface** for Agent Governance Toolkit
on [OpenCode](https://github.com/anomalyco/opencode).

It ships an OpenCode plugin that uses:

- OpenCode's in-process plugin hooks for deterministic session, prompt, tool,
  and output governance
- a bundled stdio MCP server (`server/agt-mcp.mjs`) for operator-facing AGT
  inspection tools
- the AGT TypeScript SDK for policy evaluation, prompt defense, and MCP threat
  scanning

> Public Preview — APIs and policy schema may change.

## What this package is

- a first-party OpenCode plugin package
- a parity layer for the existing Antigravity and Claude Code governance
  packages, adapted to OpenCode's richer in-process hook contract
- a publishable npm package (`@microsoft/agent-governance-opencode`) that can
  also be loaded locally from a workspace `.opencode/plugins/` directory

## What this package is not

- a Copilot-style extension
- a universal governance layer for every IDE surface
- a guarantee of full Copilot CLI feature parity

## Why OpenCode benefits from in-process governance

Unlike Claude Code (subprocess hooks) and Antigravity (subprocess hooks),
OpenCode loads plugins **in-process** as async TypeScript/JavaScript functions.
That means this package can:

- enforce policy on `tool.execute.before` without an extra subprocess round trip
- **redact** secrets from `tool.execute.after` output before the model sees it
  (a parity win over Claude Code, which cannot rewrite tool output)
- expose custom tools like `agt_policy_status` directly to the model without
  needing a separate MCP server

The stdio MCP server is still shipped for operators who want to invoke
governance tools from external workflows.

## Current scope

This initial package enforces:

- `session.start`           — injects AGT governance context into the session
- `event` (chat-style)      — scans submitted prompts; throws to block
- `tool.execute.before`     — allow / review / deny tool calls
- `tool.execute.after`      — scans tool output and redacts known secret
                              patterns (AWS, GitHub PAT, OpenAI, JWT, PEM
                              private keys, Azure storage keys)
- `tool.execute.error`      — records audit entry for failed tool calls

It also exposes two custom tools (in-process **and** via the stdio MCP server):

- `agt_policy_status` — return the active AGT policy snapshot
- `agt_policy_check_text` — inspect arbitrary text for prompt-injection and
  context-poisoning findings

## Local development

Run these commands from the package directory:

```powershell
cd agent-governance-opencode
npm install
npm run check
```

## Loading the plugin in OpenCode

OpenCode loads plugins from:

1. `opencode.json` `plugin` entries (npm specifiers)
2. `~/.config/opencode/plugins/*.{ts,js,mjs}` (user-global)
3. `.opencode/plugins/*.{ts,js,mjs}` (workspace-local)

### Option A — workspace `opencode.json`

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["@microsoft/agent-governance-opencode"]
}
```

### Option B — workspace plugin file (no install required)

Create `.opencode/plugins/agt.mjs`:

```js
export { default } from "../../agent-governance-opencode/src/index.mjs";
```

### Option C — install the bundled MCP server

In `opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "agt-governance": {
      "type": "local",
      "command": [
        "node",
        "./node_modules/@microsoft/agent-governance-opencode/server/agt-mcp.mjs"
      ]
    }
  }
}
```

## Configuration

The plugin loads policy from (in order):

1. `AGT_OPENCODE_POLICY_PATH` environment variable
2. `./.agt/policy.json` in the working directory
3. `~/.config/opencode/agt/policy.json`
4. The bundled `config/default-policy.json` (enforce mode, fail-closed)

Audit log path defaults to `~/.config/opencode/agt/audit.json` and can be
overridden via `AGT_OPENCODE_AUDIT_PATH`.

### Positive command and URL allowlists

Positive allowlists are opt-in, so existing policies keep their current
behavior. Set the relevant default effect to `deny` to make unmatched values
fail closed.

For command-bearing tool calls, configure `toolPolicies` with:

- `allowedCommandPatterns`: regex pattern objects with `source` and optional
  `flags`
- `commandDefaultEffect`: `allow` (default) or `deny`

Commands are normalized only for outer whitespace and CRLF line endings before
matching. Use anchored patterns when the whole command must match. Stateful
regex flags (`g` and `y`) are rejected because they make repeated evaluations
history-dependent.

For HTTP(S) resources, configure `directResourcePolicies` with:

- `allowedDomains`: exact hosts or `*.example.com` subdomain wildcards, with an
  optional explicit port such as `internal.example:8443`
- `allowedUrlPatterns`: regex pattern objects evaluated against the normalized
  full URL
- `urlDefaultEffect`: `allow` (default) or `deny`

A wildcard such as `*.example.com` does not include the apex `example.com`.
A domain without a port matches that host on any port; specifying a port
restricts the match to that effective port. Every HTTP(S) string found in tool
arguments is checked, so an allowed primary URL does not make a separate,
unapproved redirect-target argument acceptable. Runtime redirects that are not
surfaced to the plugin remain the responsibility of the HTTP client or host.

Existing deny and review rules keep their precedence. An allowlist match only
means the positive gate is satisfied; it cannot override a deny from
`blockedToolCalls`, `urlRules`, or another policy backend.

A complete opt-in example is provided at
`config/allowlist-policy.example.json`.

## Important parity notes

- OpenCode's in-process plugin contract does not currently expose a server-side
  "ask the user" decision from inside `tool.execute.before`. When AGT decides
  `review`, this plugin marks the args with `__agt_review_reason` and lets
  OpenCode's normal permission flow run. Operators who want hard-deny behaviour
  on review should set `toolPolicies.defaultEffect: "deny"` in their policy.
- Output redaction is conservative: only well-known credential patterns are
  redacted. The audit entry records that a redaction occurred but never the
  redacted value.
- AGT fails **closed** by default. If the policy file is corrupt or evaluation
  throws, requests are denied. Set `denyOnPolicyError: false` in policy to opt
  into advisory mode.
