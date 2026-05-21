# Claude Code Package - Coding Agent Instructions

## Project Overview

The `agent-governance-claude-code/` directory contains the first-party Claude Code plugin package
for Agent Governance Toolkit. It wires AGT policy evaluation into Claude-native hooks, markdown
commands, and a bundled MCP server.

## Key Commands

```powershell
cd agent-governance-claude-code
npm install
npm run check
npm test
```

## Package Boundaries

- Keep deterministic enforcement in Claude command hooks.
- Treat hook and MCP launch wiring as security-sensitive.
- Keep docs honest about parity gaps and Claude-specific limitations.
- Prefer updating the packaged default policy and tests together when enforcement behavior changes.

## Validation

- Re-run `npm run check` after hook/runtime changes.
- Re-run `npm test` after policy, audit, or MCP changes.
- Re-check docs and examples when plugin loading or local paths change.
