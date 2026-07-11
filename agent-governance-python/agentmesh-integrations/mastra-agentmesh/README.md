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
import { AgentControl } from "agent-control-specification";
import { z } from "zod";

const searchTool = createTool({
  id: "web-search",
  description: "Search the web",
  inputSchema: z.object({ query: z.string() }),
  outputSchema: z.object({ results: z.array(z.string()) }),
  execute: async ({ query }) => ({ results: ["result1"] }),
});

const control = AgentControl.fromPath("./manifest.yaml");

// Add ACS policy enforcement + trust + audit in one call
const governedSearch = createGovernedTool(searchTool, {
  control,
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

The ACS manifest declares tool catalogs, intervention-point bindings, budgets,
content filters, and transforms. `createGovernedTool` uses
`AgentControl.runTool`, so deny, escalate, and transform behavior stays
consistent with every other ACS host.

### Use trust and audit individually

```typescript
import { trustGate, auditMiddleware } from "@agentmesh/mastra";

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

Wraps a Mastra tool with ACS policy enforcement, trust, and audit. `control` is
required. Optional fields are `trust`, `audit`, `agentId`, and `snapshot`.

## Migration from the removed local policy object

The package no longer accepts its local policy object. Move every constraint
into an ACS manifest and construct `AgentControl` from that manifest. Passing
the removed object is a TypeScript compile error rather than a best-effort
translation.

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
