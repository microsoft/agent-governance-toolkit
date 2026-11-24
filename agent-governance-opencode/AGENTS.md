# OpenCode plugin — contributor instructions

Scope: this folder publishes `@microsoft/agent-governance-opencode`, the AGT
governance plugin for [OpenCode](https://github.com/anomalyco/opencode).

## Architecture

OpenCode loads plugins **in-process**. The package root, `src/index.mjs`,
default-exports the `AgtGovernance` plugin function, which OpenCode 1.x calls;
keep every root export a plugin function, because 1.x before 1.3.4 calls each
one. The `./server` export, `src/server.mjs`, is `{ id, server, setup }`:
OpenCode 2.x, and 1.x from 1.3.4, load it before the root; 1.x calls `server`
and 2.x calls `setup` (which registers the same tool hooks through its
context). The root entry point:

- caches a single `loadPolicy()` state per OpenCode process
- maps AGT decisions (`allow` / `review` / `deny`) onto OpenCode's contract:
  - `deny` → `throw new Error(...)` from the hook
  - `review` → annotate `output.args.__agt_review_reason`
  - `allow` → return undefined
- exposes `agt_policy_status` and `agt_policy_check_text` as both in-process
  custom tools and stdio MCP server tools (`server/agt-mcp.mjs`)

The core policy library (`lib/policy.mjs`) is shared with the Claude Code
package and exposes both Claude-style hook helpers (kept for compatibility)
and OpenCode-native helpers:

- `evaluateOpenCodePrompt(state, { prompt, sessionId })`
- `evaluateOpenCodeTool(state, { tool, args, cwd, sessionId })`
- `evaluateOpenCodeToolOutput(state, { tool, output, sessionId })`

All three return `{ effect: "allow" | "review" | "deny", reason }` (the output
helper returns `{ redact, redactedOutput?, reason }`).

## Local commands

```powershell
cd agent-governance-opencode
npm install
npm run check    # node --check on every .mjs + node --test
npm test         # tests only
```

## Conventions

- MIT license header on every new `.mjs` / `.ts` / `.js` file
- Node engine `>=22.0.0` (matches Claude Code package; OpenCode targets modern
  runtimes)
- Version pinned to `3.6.0` to track the Claude Code package
- `@microsoft/agent-governance-sdk` is pinned at `3.7.0`
- Default policy uses OpenCode's **lowercase** tool names (`read`, `bash`,
  `webfetch`, etc.) — do not copy Claude's PascalCase tool names verbatim
- Fail-closed on every error path; never silently allow on policy load failure
- Never log a redacted secret value; only the pattern category id

## When to update what

- New OpenCode tool name → add to `config/default-policy.json`
  `allowedTools` / `reviewTools`
- New secret family to redact → add a pattern to `SECRET_PATTERNS` in
  `lib/policy.mjs` (bottom section) and add a test in
  `test/policy.test.mjs`
- New plugin hook surface from OpenCode → wire it in `src/index.mjs` (1.x hook
  object) or `src/server.mjs` (2.x `setup`) and add a shape assertion in
  `test/plugin.test.mjs`

## Out of scope

- Marketplace metadata: OpenCode does not have a Claude-style plugin
  marketplace, so there is **no** `.opencode-plugin/marketplace.json`
- Modifying `lib/audit.mjs` or `lib/poisoning.mjs` here — those are shared
  surface-agnostic libs; coordinate with the Claude Code package if changed
