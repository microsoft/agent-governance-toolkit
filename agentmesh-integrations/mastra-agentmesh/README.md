# @agentmesh/mastra

Governance, trust verification, and audit middleware for [Mastra](https://mastra.ai) AI agents.

[![npm](https://img.shields.io/npm/v/@agentmesh/mastra)](https://www.npmjs.com/package/@agentmesh/mastra)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Overview

`@agentmesh/mastra` adds three security layers to Mastra tool execution:

| Layer | What It Does |
|-------|-------------|
| **Governance** | Rate limits, content filtering, PII redaction, tool allow/deny lists |
| **Trust** | Agent trust score verification (0-1000 scale) before tool execution |
| **Audit** | Tamper-evident SHA-256 hash chain logging of all tool invocations |

## Install

```bash
npm install @agentmesh/mastra
```

Peer dependencies: `@mastra/core >= 0.10.0`, `zod >= 3.22.0`

## Quick Start

### Wrap any Mastra tool with governance

```typescript
import { createTool } from "@mastra/core";
import { createGovernedTool } from "@agentmesh/mastra";
import { z } from "zod";

const searchTool = createTool({
  id: "web-search",
  description: "Search the web",
  inputSchema: z.object({ query: z.string() }),
  outputSchema: z.object({ results: z.array(z.string()) }),
  execute: async ({ query }) => ({ results: ["result1"] }),
});

// Add governance + trust + audit in one call
const governedSearch = createGovernedTool(searchTool, {
  governance: {
    rateLimitPerMinute: 30,
    blockedPatterns: ["(?i)ignore previous instructions"],
    piiFields: ["ssn", "credit_card"],
  },
  trust: {
    minTrustScore: 500,
    getTrustScore: async (agentId) => {
      // Query your trust registry / AgentMesh trust bridge
      return 750;
    },
  },
  audit: {
    captureData: true,
    sink: async (entry) => {
      console.log(`[AUDIT] ${entry.action} ${entry.toolId}`, entry.hash);
    },
  },
  agentId: "my-agent",
});
```

### Use middleware layers individually

```typescript
import { governanceMiddleware, trustGate, auditMiddleware } from "@agentmesh/mastra";

// Governance only
const gov = governanceMiddleware({
  rateLimitPerMinute: 60,
  blockedTools: ["shell_exec", "file_delete"],
  maxInputLength: 10000,
});

const result = await gov.check(userInput, "tool-id", "agent-id");
if (!result.allowed) {
  console.log("Blocked:", result.violations);
}

// Trust only
const trust = trustGate({
  minTrustScore: 700,
  getTrustScore: async (agentId) => fetchTrustScore(agentId),
});

const verification = await trust.verify("agent-42");
console.log(trust.getTier(verification.trustScore)); // "trusted"

// Audit only
const audit = auditMiddleware({ captureData: true, maxEntries: 10000 });
await audit.record({ toolId: "search", agentId: "bot-1", action: "invoke" });

const { valid } = await audit.verifyChain(); // true if no tampering
```

## API

### `governanceMiddleware(policy)`

| Option | Type | Description |
|--------|------|-------------|
| `rateLimitPerMinute` | `number` | Max tool calls per minute per agent |
| `blockedPatterns` | `string[]` | Regex patterns to block in inputs |
| `piiFields` | `string[]` | Field names to redact (e.g., `"ssn"`, `"email"`) |
| `maxInputLength` | `number` | Maximum input size in characters |
| `allowedTools` | `string[]` | Tool allowlist (empty = all allowed) |
| `blockedTools` | `string[]` | Tool denylist |
| `customCheck` | `function` | Custom async policy check |

### `trustGate(config)`

| Option | Type | Description |
|--------|------|-------------|
| `minTrustScore` | `number` | Minimum score (0-1000) to allow execution |
| `getTrustScore` | `function` | Async function returning agent's trust score |
| `onTrustFailure` | `function` | Optional callback when trust check fails |

### `auditMiddleware(config)`

| Option | Type | Description |
|--------|------|-------------|
| `captureData` | `boolean` | Include input/output in audit entries |
| `sink` | `function` | Custom async audit sink |
| `maxEntries` | `number` | Max in-memory entries (default: 10,000) |

### `createGovernedTool(tool, options)`

Wraps a Mastra tool with all three layers. Options: `governance`, `trust`, `audit`, `agentId`.

## Trust Score Tiers

| Score | Tier | Meaning |
|-------|------|---------|
| 900-1000 | Verified Partner | Cryptographically verified, full access |
| 700-899 | Trusted | Established track record |
| 500-699 | Standard | Default for new agents |
| 300-499 | Probationary | Limited access, under observation |
| 0-299 | Untrusted | Blocked from sensitive operations |

## Part of AgentMesh

This package is part of the [AgentMesh](https://github.com/microsoft/agent-governance-toolkit) ecosystem — a trust layer for multi-agent systems with cryptographic identity, zero-trust verification, and runtime governance.

## License

MIT
