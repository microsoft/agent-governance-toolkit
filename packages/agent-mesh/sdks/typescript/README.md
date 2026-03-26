# @agentmesh/sdk

> [!IMPORTANT]
> **Public Preview** — This npm package is a Microsoft-signed public preview release.
> APIs may change before GA.

TypeScript SDK for [AgentMesh](../../README.md) — a governance-first framework for multi-agent systems.

Provides agent identity (Ed25519 DIDs), trust scoring, policy evaluation, hash-chain audit logging, and a unified `AgentMeshClient`.

## Installation

```bash
npm install @agentmesh/sdk
```

## Quick Start

```typescript
import { AgentMeshClient } from '@agentmesh/sdk';

const client = AgentMeshClient.create('my-agent', {
  capabilities: ['data.read', 'data.write'],
  policyRules: [
    { action: 'data.read', effect: 'allow' },
    { action: 'data.write', effect: 'allow', conditions: { role: 'admin' } },
    { action: '*', effect: 'deny' },
  ],
});

// Execute an action through the governance pipeline
const result = await client.executeWithGovernance('data.read');
console.log(result.decision);   // 'allow'
console.log(result.trustScore); // { overall: 0.5, tier: 'Provisional', ... }

// Verify the audit chain
console.log(client.audit.verify()); // true
```

## API Reference

### `AgentIdentity`

Manage agent identities built on Ed25519 key pairs.

```typescript
import { AgentIdentity } from '@agentmesh/sdk';

const identity = AgentIdentity.generate('agent-1', ['read']);
const signature = identity.sign(new TextEncoder().encode('hello'));
identity.verify(new TextEncoder().encode('hello'), signature); // true

// Serialization
const json = identity.toJSON();
const restored = AgentIdentity.fromJSON(json);
```

### `TrustManager`

Track and score trust for peer agents.

```typescript
import { TrustManager } from '@agentmesh/sdk';

const tm = new TrustManager({ initialScore: 0.5, decayFactor: 0.95 });

tm.recordSuccess('peer-1', 0.05);
tm.recordFailure('peer-1', 0.1);

const score = tm.getTrustScore('peer-1');
// { overall: 0.45, tier: 'Provisional', dimensions: { ... } }
```

### `PolicyEngine`

Rule-based policy evaluation with conditions and YAML support.

```typescript
import { PolicyEngine } from '@agentmesh/sdk';

const engine = new PolicyEngine([
  { action: 'data.*', effect: 'allow' },
  { action: 'admin.*', effect: 'deny' },
]);

engine.evaluate('data.read');  // 'allow'
engine.evaluate('admin.nuke'); // 'deny'
engine.evaluate('unknown');    // 'deny' (default)

// Load additional rules from YAML
await engine.loadFromYAML('./policy.yaml');
```

### `AuditLogger`

Append-only audit log with hash-chain integrity verification.

```typescript
import { AuditLogger } from '@agentmesh/sdk';

const logger = new AuditLogger();

logger.log({ agentId: 'agent-1', action: 'data.read', decision: 'allow' });
logger.log({ agentId: 'agent-1', action: 'data.write', decision: 'deny' });

logger.verify();  // true — chain is intact
logger.getEntries({ agentId: 'agent-1' }); // filtered results
logger.exportJSON(); // full log as JSON string
```

### `AgentMeshClient`

Unified client tying identity, trust, policy, and audit together.

```typescript
import { AgentMeshClient } from '@agentmesh/sdk';

const client = AgentMeshClient.create('my-agent', {
  policyRules: [{ action: 'data.*', effect: 'allow' }],
});

const result = await client.executeWithGovernance('data.read', { user: 'alice' });
// result: { decision, trustScore, auditEntry, executionTime }
```

## Development

```bash
npm install
npm run build    # Compile TypeScript
npm test         # Run Jest tests
npm run lint     # Lint with ESLint
```

## License

Apache-2.0 — see [LICENSE](../../LICENSE).
