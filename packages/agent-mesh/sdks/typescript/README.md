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

### `McpSecurityScanner`

Scan MCP tool definitions for security threats — tool poisoning, typosquatting, hidden instructions, and rug-pull payloads.

```typescript
import { McpSecurityScanner } from '@agentmesh/sdk';

const scanner = new McpSecurityScanner();

const result = scanner.scan({
  name: 'read_file',
  description: 'Reads a file from disk.',
});
console.log(result.safe);       // true
console.log(result.risk_score); // 0

// Batch scan
const results = scanner.scanAll(tools);
const risky = results.filter((r) => !r.safe);
```

**Detected threat types:**

| Threat | Description |
|--------|-------------|
| `tool_poisoning` | Prompt-injection patterns (`<system>`, `ignore previous`, encoded payloads) |
| `typosquatting` | Tool names within edit-distance 2 of well-known tools |
| `hidden_instruction` | Zero-width Unicode characters or homoglyphs |
| `rug_pull` | Abnormally long descriptions containing instruction-like patterns |

### `LifecycleManager`

Govern agent state transitions with an enforced state machine and event log.

```typescript
import { LifecycleManager, LifecycleState } from '@agentmesh/sdk';

const lm = new LifecycleManager('agent-1');

lm.activate('Ready to serve');         // provisioning → active
lm.suspend('Scheduled maintenance');   // active → suspended
lm.activate('Back online');            // suspended → active
lm.quarantine('Trust violation');      // active → quarantined
lm.decommission('End of life');        // quarantined → decommissioning

console.log(lm.state);   // 'decommissioning'
console.log(lm.events);  // full transition history
```

**State machine:**

```
provisioning → active → suspended ↔ active
                     → rotating  → active | degraded
                     → degraded  → active | quarantined | decommissioning
                     → quarantined → active | decommissioning
                     → decommissioning → decommissioned
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
