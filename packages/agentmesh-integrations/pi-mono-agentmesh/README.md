# @microsoft/agentmesh-pi-mono

Governance, policy enforcement, and audit hooks for [pi-mono](https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent) coding agents.

[![npm](https://img.shields.io/npm/v/@microsoft/agentmesh-pi-mono)](https://www.npmjs.com/package/@microsoft/agentmesh-pi-mono)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Overview

`@microsoft/agentmesh-pi-mono` adds AgentMesh governance to pi-mono's SDK path by:

- evaluating every `tool_call` against AgentMesh policy rules
- adding extra safety review and deny checks for high-risk `bash` commands
- recording prompts, tool results, and provider requests in an append-only audit log
- exposing a small session helper so SDK consumers can create governed pi sessions without rebuilding the extension plumbing

## Install

```bash
npm install @microsoft/agentmesh-pi-mono @mariozechner/pi-coding-agent @microsoft/agentmesh-sdk
```

## Quick Start

```typescript
import { createGovernedPiSession } from "@microsoft/agentmesh-pi-mono";

const session = await createGovernedPiSession({
  cwd: process.cwd(),
  governance: {
    agentId: "repo-helper",
    policyRules: [
      { action: "read", effect: "allow" },
      { action: "grep", effect: "allow" },
      { action: "bash", effect: "review" },
      { action: "*", effect: "deny" },
    ],
  },
});

await session.prompt("Inspect the repository and summarize the test layout.");

console.log(session.auditLog);
console.log(session.verifyAuditLog());
```

## API

### `PiAgentMeshGovernance`

Low-level policy and audit helper for pi-mono integrations.

- `evaluateToolCall(toolName, input)` returns `allow`, `deny`, or `review`
- `recordPrompt(prompt, hasImages)` adds prompt metadata to the audit trail
- `recordToolResult(toolName, input, result)` logs a summarized tool outcome
- `recordProviderRequest(payload)` logs outbound model request metadata
- `getAuditLog()` returns the in-memory audit records
- `verifyAuditLog()` validates the underlying audit chain

### `createGovernanceExtension(governance, logger?)`

Returns a pi-mono `ExtensionFactory` that:

- blocks `deny` and `review` tool calls before execution
- records every tool result after execution
- records every provider request before the model call

### `GovernedPiSession`

High-level session wrapper around pi-mono's SDK session creation.

- `start()` creates the governed session once and reuses it
- `prompt(text, options?)` records the prompt before delegating to `session.prompt()`
- `continueResponse()` delegates to `session.agent.continue()`
- `loadHistory(history)` hydrates simple `user` / `assistant` message histories
- `stop()` aborts an active stream and disposes the underlying session

## Default Bash Safety Rules

Even when policy allows `bash`, the adapter adds extra protection:

- `deny`: `rm -rf /`, `mkfs`, raw disk writes, fork bombs, shutdown commands, common exfiltration patterns
- `review`: `git push`, `npm publish`, `docker push`

This keeps the adapter conservative by default while still letting callers supply custom AgentMesh policy rules.

## Testing

```bash
npm test
npm run build
```

## License

MIT
