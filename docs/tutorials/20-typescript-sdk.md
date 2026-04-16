# Tutorial 20 — TypeScript SDK (@microsoft/agentmesh-sdk)

> **Package:** `@microsoft/agentmesh-sdk` · **Time:** 30 minutes · **Prerequisites:** Node.js 18+

---

## What You'll Learn

- Identity and Ed25519 DIDs in TypeScript/Node.js
- Trust scoring and peer verification
- Declarative policy evaluation
- Hash-chain audit logging

---

Build governance-aware AI agents in TypeScript and Node.js.
The `@microsoft/agentmesh-sdk` package provides cryptographic identity (Ed25519 DIDs),
trust scoring, declarative policy evaluation, and hash-chain audit logging — all in
a single npm install.

**Prerequisites:** Node.js ≥ 18 · TypeScript ≥ 5.4
**Package:** `@microsoft/agentmesh-sdk` v1.0.0
**Modules:** `AgentIdentity`, `TrustManager`, `PolicyEngine`, `AuditLogger`, `AgentMeshClient`

---

**What you'll learn:**

| Section | Topic |
|---------|-------|
| [Quick Start](#quick-start) | Evaluate a policy in 5 lines of TypeScript |
| [AgentMeshClient](#agentmeshclient) | Unified governance pipeline — identity + trust + policy + audit |
| [PolicyEngine](#policyengine) | Declarative rules, YAML policies, conflict resolution |
| [AgentIdentity](#agentidentity) | Ed25519 key pairs, DIDs, delegation, capabilities |
| [TrustManager](#trustmanager) | Bayesian trust scoring, tiers, decay |
| [AuditLogger](#auditlogger) | Hash-chain audit logging and verification |
| [Framework Integration](#framework-integration) | LangChain.js, OpenAI Node SDK |
| [Configuration Reference](#configuration-reference) | Defaults, environment variables, tuning |
| [Error Handling](#error-handling) | TypeScript-specific patterns |
| [Cross-Reference](#cross-reference) | Equivalent Python tutorials |

---

## Installation

```bash
npm install @microsoft/agentmesh-sdk
```

The SDK has two runtime dependencies — `@noble/ed25519` for cryptography and
`js-yaml` for YAML policy parsing. Both are installed automatically.

For TypeScript projects, types are included — no separate `@types/` package is
needed.

```bash
# Verify the install
node -e "const sdk = require('@microsoft/agentmesh-sdk'); console.log(Object.keys(sdk))"
```

---

## Quick Start

Five lines to evaluate your first policy:

```typescript
import { PolicyEngine } from '@microsoft/agentmesh-sdk';

const engine = new PolicyEngine([
  { action: 'data.read',  effect: 'allow' },
  { action: 'data.write', effect: 'deny'  },
]);

console.log(engine.evaluate('data.read'));   // 'allow'
console.log(engine.evaluate('data.write'));  // 'deny'
console.log(engine.evaluate('data.delete')); // 'deny'  ← default when no rule matches
```

> **Tip:** The default decision when no rule matches is `'deny'` — secure by
> default.

Or use the unified `AgentMeshClient` for the full governance pipeline:

```typescript
import { AgentMeshClient } from '@microsoft/agentmesh-sdk';

const client = AgentMeshClient.create('my-agent', {
  capabilities: ['data.read', 'data.write'],
  policyRules: [
    { action: 'data.read',  effect: 'allow' },
    { action: 'data.write', effect: 'allow', conditions: { role: 'admin' } },
    { action: '*',           effect: 'deny'  },
  ],
});

const result = await client.executeWithGovernance('data.read');
console.log(result.decision);    // 'allow'
console.log(result.trustScore);  // { overall: 0.5, tier: 'Provisional', ... }
console.log(result.auditEntry);  // { hash: '3a7f...', previousHash: '0000...', ... }
```

---

## AgentMeshClient

The `AgentMeshClient` is the recommended entry point. It wires together identity,
trust, policy, and audit into a single governance-aware pipeline.

### Creating a Client

```typescript
import { AgentMeshClient } from '@microsoft/agentmesh-sdk';

// Quick creation with defaults
const client = AgentMeshClient.create('sales-agent', {
  capabilities: ['crm.read', 'crm.write', 'email.send'],
});

// Access individual components
console.log(client.identity.did);    // did:agentmesh:sales-agent:<fingerprint>
console.log(client.trust);           // TrustManager instance
console.log(client.policy);          // PolicyEngine instance
console.log(client.audit);           // AuditLogger instance
```

### Full Configuration

```typescript
import { AgentMeshClient, AgentMeshConfig } from '@microsoft/agentmesh-sdk';

const config: AgentMeshConfig = {
  agentId: 'analytics-agent',
  capabilities: ['data.read', 'report.generate'],
  trust: {
    initialScore: 0.6,
    decayFactor: 0.98,
    thresholds: {
      untrusted: 0.0,
      provisional: 0.3,
      trusted: 0.6,
      verified: 0.85,
    },
  },
  policyRules: [
    { action: 'data.read',        effect: 'allow' },
    { action: 'report.generate',  effect: 'allow' },
    { action: '*',                 effect: 'deny'  },
  ],
  audit: {
    maxEntries: 50_000,
  },
};

const client = new AgentMeshClient(config);
```

### The Governance Pipeline

`executeWithGovernance()` runs every action through a four-stage pipeline:

```
  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
  │ 1. Policy    │───▶│ 2. Trust     │───▶│ 3. Audit     │───▶│ 4. Trust     │
  │    Evaluate  │    │    Score     │    │    Log       │    │    Update    │
  └──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
```

```typescript
const result = await client.executeWithGovernance('data.read', {
  userId: 'alice',
  department: 'engineering',
});

// GovernanceResult
console.log(result.decision);       // 'allow' | 'deny' | 'review'
console.log(result.trustScore);     // TrustScore object
console.log(result.auditEntry);     // AuditEntry with hash chain
console.log(result.executionTime);  // milliseconds (e.g., 1.234)
```

**`GovernanceResult` shape:**

| Field | Type | Description |
|-------|------|-------------|
| `decision` | `'allow' \| 'deny' \| 'review'` | Policy evaluation outcome |
| `trustScore` | `TrustScore` | Current trust score after action |
| `auditEntry` | `AuditEntry` | Immutable audit record created |
| `executionTime` | `number` | Pipeline duration in milliseconds |

---

## PolicyEngine

The `PolicyEngine` supports two modes: **legacy flat rules** (simple action
matching) and **rich YAML/JSON policies** (expressions, rate limits, approvals,
conflict resolution).

### §4.1 Legacy Flat Rules

Flat rules match an `action` string and return an `effect`:

```typescript
import { PolicyEngine, PolicyRule } from '@microsoft/agentmesh-sdk';

const rules: PolicyRule[] = [
  { action: 'data.read',   effect: 'allow' },
  { action: 'data.write',  effect: 'allow', conditions: { role: 'admin' } },
  { action: 'data.*',      effect: 'deny'  },
  { action: '*',            effect: 'deny'  },
];

const engine = new PolicyEngine(rules);

engine.evaluate('data.read');                      // 'allow'
engine.evaluate('data.write', { role: 'admin' });  // 'allow'
engine.evaluate('data.write', { role: 'viewer' }); // 'deny' — conditions don't match
engine.evaluate('data.delete');                    // 'deny' — wildcard catch-all
```

**Evaluation order:** First matching rule wins. Place specific rules before
wildcards.

### §4.2 Loading Rules from YAML

```typescript
const engine = new PolicyEngine();

// Load from a YAML file on disk
await engine.loadFromYAML('./policies/production.yaml');

engine.evaluate('data.read');  // Uses loaded rules
```

### §4.3 Rich Policy Documents

Rich policies add expressions, rate limits, approval workflows, and conflict
resolution:

```typescript
import { PolicyEngine } from '@microsoft/agentmesh-sdk';

const engine = new PolicyEngine();

const policy = engine.loadYaml(`
apiVersion: governance.toolkit/v1
name: data-access-policy
description: Controls data operations for analytics agents
agents:
  - 'did:agentmesh:analytics-*'
scope: tenant

rules:
  - name: admin-full-access
    condition: "user.role == 'admin'"
    ruleAction: allow
    priority: 100

  - name: analyst-read-only
    condition: "user.role in ['analyst', 'viewer']"
    ruleAction: allow
    priority: 50

  - name: rate-limit-writes
    condition: "action == 'data.write'"
    ruleAction: allow
    priority: 75
    limit: '100/hour'

  - name: require-approval-for-delete
    condition: "action == 'data.delete'"
    ruleAction: require_approval
    priority: 90
    approvers:
      - 'did:agentmesh:security-team'
      - 'did:agentmesh:data-owner'

  - name: default-deny
    ruleAction: deny
    priority: 0

default_action: deny
`);

console.log(policy.name);  // 'data-access-policy'
```

### §4.4 Rich Policy Evaluation

```typescript
const result = engine.evaluatePolicy(
  'did:agentmesh:analytics-agent:abc123',
  { user: { role: 'admin' }, action: 'data.write' }
);

console.log(result.allowed);       // true
console.log(result.action);        // 'allow'
console.log(result.matchedRule);   // 'admin-full-access'
console.log(result.policyName);    // 'data-access-policy'
console.log(result.rateLimited);   // false
console.log(result.approvers);     // []
console.log(result.evaluationMs);  // 0.123
```

**`PolicyDecisionResult` shape:**

| Field | Type | Description |
|-------|------|-------------|
| `allowed` | `boolean` | Whether the action is permitted |
| `action` | `PolicyAction` | `'allow'` \| `'deny'` \| `'warn'` \| `'require_approval'` \| `'log'` |
| `matchedRule` | `string?` | Name of the rule that matched |
| `policyName` | `string?` | Name of the policy that matched |
| `reason` | `string?` | Human-readable explanation |
| `approvers` | `string[]` | Required approver DIDs (for `require_approval`) |
| `rateLimited` | `boolean` | Whether rate limiting is active |
| `evaluatedAt` | `Date` | Timestamp of evaluation |
| `evaluationMs` | `number?` | Duration of evaluation in ms |

### §4.5 Expression Syntax

Rich policy conditions use a simple expression language:

| Operator | Example | Description |
|----------|---------|-------------|
| `==` | `user.role == 'admin'` | Equality (string, number, boolean) |
| `!=` | `status != 'blocked'` | Not equal |
| `>` | `token_count > 2048` | Greater than |
| `<` | `risk_score < 0.5` | Less than |
| `>=` | `trust_level >= 0.85` | Greater than or equal |
| `<=` | `attempts <= 3` | Less than or equal |
| `in` | `role in ['admin', 'analyst']` | Membership in list |
| `not in` | `env not in ['prod']` | Not a member |
| `and` | `role == 'admin' and dept == 'eng'` | Logical AND |
| `or` | `level > 5 or isVerified` | Logical OR |
| *(truthy)* | `isVerified` | Property existence / truthiness |

**Nested path access:** Use dots to access nested properties — `user.role`,
`request.headers.authorization`, `agent.trust.tier`.

### §4.6 Rate Limiting

Add a `limit` field to any rule to enforce rate limits:

```yaml
rules:
  - name: throttle-api-calls
    condition: "action == 'api.call'"
    ruleAction: allow
    limit: '1000/minute'
```

Supported time windows:

| Format | Example |
|--------|---------|
| `N/second` | `100/second` |
| `N/minute` | `1000/minute` |
| `N/hour` | `10000/hour` |
| `N/day` | `100000/day` |

### §4.7 Conflict Resolution

When multiple policies apply to the same action, the `PolicyConflictResolver`
determines which rule wins:

```typescript
import {
  PolicyEngine,
  PolicyConflictResolver,
  ConflictResolutionStrategy,
} from '@microsoft/agentmesh-sdk';

const engine = new PolicyEngine([], ConflictResolutionStrategy.DenyOverrides);
```

**Strategies:**

| Strategy | Enum Value | Behaviour |
|----------|------------|-----------|
| **Deny Overrides** | `deny_overrides` | Any `deny` rule wins — safety first |
| **Allow Overrides** | `allow_overrides` | Any `allow` rule wins — permissive |
| **Priority First Match** | `priority_first_match` | Highest `priority` value wins (default) |
| **Most Specific Wins** | `most_specific_wins` | Most specific `scope` + highest `priority` wins |

```typescript
const resolver = new PolicyConflictResolver(
  ConflictResolutionStrategy.MostSpecificWins
);

const result = resolver.resolve([
  {
    action: 'allow',
    priority: 50,
    scope: PolicyScope.Global,
    policyName: 'global-policy',
    ruleName: 'allow-reads',
    reason: 'Global read access',
    approvers: [],
  },
  {
    action: 'deny',
    priority: 50,
    scope: PolicyScope.Agent,
    policyName: 'agent-policy',
    ruleName: 'deny-untrusted',
    reason: 'Agent-specific restriction',
    approvers: [],
  },
]);

console.log(result.winningDecision.action);   // 'deny' — agent scope is more specific
console.log(result.strategyUsed);             // 'most_specific_wins'
console.log(result.conflictDetected);         // true
console.log(result.resolutionTrace);          // step-by-step resolution log
```

**Scope specificity order** (most → least specific):

```
  Agent  >  Tenant  >  Global
```

### §4.8 Managing Multiple Policies

```typescript
const engine = new PolicyEngine();

// Load multiple policies
engine.loadYaml(securityPolicyYaml);
engine.loadYaml(compliancePolicyYaml);
engine.loadYaml(operationalPolicyYaml);

// List and inspect
console.log(engine.listPolicies());        // ['security', 'compliance', 'operational']
console.log(engine.getPolicy('security')); // Policy object

// Remove a policy
engine.removePolicy('operational');

// Clear all policies
engine.clearPolicies();
```

---

## AgentIdentity

Each agent gets a cryptographic identity backed by Ed25519 key pairs. The identity
produces a DID (Decentralized Identifier) and supports signing, verification,
delegation, and lifecycle management.

### §5.1 Generating an Identity

```typescript
import { AgentIdentity } from '@microsoft/agentmesh-sdk';

const agent = AgentIdentity.generate('sales-assistant', ['crm.read', 'email.send'], {
  name: 'Sales Assistant',
  description: 'Handles inbound sales inquiries',
  organization: 'Contoso',
  sponsor: 'alice@contoso.com',
  expiresAt: new Date('2026-01-01'),
});

console.log(agent.did);           // did:agentmesh:sales-assistant:<fingerprint>
console.log(agent.publicKey);     // Uint8Array (Ed25519 DER)
console.log(agent.capabilities);  // ['crm.read', 'email.send']
console.log(agent.status);        // 'active'
console.log(agent.organization);  // 'Contoso'
console.log(agent.sponsor);       // 'alice@contoso.com'
```

**DID format:** `did:agentmesh:<agentId>:<fingerprint>`

The fingerprint is derived from the public key, making each DID globally unique and
cryptographically verifiable.

### §5.2 Signing and Verification

```typescript
const message = new TextEncoder().encode('Transfer $500 to account 1234');

// Sign with private key
const signature = agent.sign(message);

// Verify with public key
const valid = agent.verify(message, signature);
console.log(valid);  // true

// Tampered data fails verification
const tampered = new TextEncoder().encode('Transfer $50000 to account 9999');
console.log(agent.verify(tampered, signature));  // false
```

> **Note:** Signing requires the private key. Identities imported via
> `fromJSON()` without a `privateKey` field can only verify, not sign.

### §5.3 Capability Checking

Capabilities support exact matching and wildcard patterns:

```typescript
const agent = AgentIdentity.generate('worker', [
  'data.read',
  'data.write',
  'report.generate',
]);

agent.hasCapability('data.read');         // true
agent.hasCapability('data.delete');       // false
agent.hasCapability('data.*');            // true  — wildcard matches data.read & data.write
agent.hasCapability('report.generate');   // true
```

### §5.4 Delegation

Create child identities with narrowed capabilities:

```typescript
const parent = AgentIdentity.generate('orchestrator', [
  'data.read', 'data.write', 'admin', 'deploy',
]);

// Child can only read and write — no admin or deploy
const child = parent.delegate('data-worker', ['data.read', 'data.write'], {
  description: 'Scoped worker for data pipeline',
  sponsor: 'pipeline-team@contoso.com',
});

console.log(child.parentDid);         // parent's DID
console.log(child.delegationDepth);   // 1
console.log(child.hasCapability('data.read'));   // true
console.log(child.hasCapability('admin'));       // false — not delegated

// Delegation chains
const grandchild = child.delegate('read-only', ['data.read']);
console.log(grandchild.delegationDepth);  // 2
```

### §5.5 Lifecycle Management

```typescript
const agent = AgentIdentity.generate('temp-agent', ['task.run']);

console.log(agent.isActive());  // true
console.log(agent.status);      // 'active'

// Suspend — temporary, reversible
agent.suspend('Under investigation');
console.log(agent.isActive());  // false
console.log(agent.status);      // 'suspended'

// Reactivate
agent.reactivate();
console.log(agent.isActive());  // true

// Revoke — permanent, irreversible
agent.revoke('Compromised credentials');
console.log(agent.status);      // 'revoked'

// Cannot reactivate a revoked identity
try {
  agent.reactivate();  // throws
} catch (e) {
  console.log(e.message);  // Cannot reactivate a revoked identity
}
```

**State machine:**

```
  generate()      suspend()           revoke()
      │               │                  │
      ▼               ▼                  ▼
  ┌────────┐     ┌───────────┐     ┌─────────┐
  │ active │────▶│ suspended │     │ revoked │
  └────────┘     └───────────┘     └─────────┘
       │          reactivate() │         ▲
       │              │                  │
       │              ▼                  │
       │          ┌────────┐             │
       └─────────▶│ active │─────────────┘
                  └────────┘  revoke()
```

### §5.6 Serialization

**JSON round-trip:**

```typescript
// Export
const json = agent.toJSON();
// {
//   did: 'did:agentmesh:sales-assistant:...',
//   publicKey: 'base64...',
//   privateKey: 'base64...',
//   capabilities: ['crm.read', 'email.send'],
//   name: 'Sales Assistant',
//   status: 'active',
//   createdAt: '2025-01-15T...',
//   ...
// }

// Import
const restored = AgentIdentity.fromJSON(json);
console.log(restored.did === agent.did);  // true
```

**JWK / JWKS (RFC 7517):**

```typescript
// Export as JWK (public key only)
const jwk = agent.toJWK(false);
// { kty: 'OKP', crv: 'Ed25519', x: '...', kid: 'did:agentmesh:...' }

// Export with private key
const jwkPrivate = agent.toJWK(true);

// JWK Set
const jwks = agent.toJWKS(false);
// { keys: [{ kty: 'OKP', crv: 'Ed25519', ... }] }

// Import from JWK
const fromJwk = AgentIdentity.fromJWK(jwk);

// Import from JWKS (picks first key, or by kid)
const fromJwks = AgentIdentity.fromJWKS(jwks, agent.did);
```

**W3C DID Document:**

```typescript
const didDoc = agent.toDIDDocument();
// {
//   '@context': 'https://www.w3.org/ns/did/v1',
//   id: 'did:agentmesh:sales-assistant:...',
//   verificationMethod: [...],
//   authentication: [...],
//   ...
// }
```

### §5.7 Identity Registry

Manage multiple identities with the `IdentityRegistry`:

```typescript
import { AgentIdentity, IdentityRegistry } from '@microsoft/agentmesh-sdk';

const registry = new IdentityRegistry();

const agent1 = AgentIdentity.generate('agent-1', ['read'], {
  sponsor: 'alice@contoso.com',
});
const agent2 = AgentIdentity.generate('agent-2', ['write'], {
  sponsor: 'alice@contoso.com',
});
const agent3 = AgentIdentity.generate('agent-3', ['admin'], {
  sponsor: 'bob@contoso.com',
});

registry.register(agent1);
registry.register(agent2);
registry.register(agent3);

console.log(registry.size);  // 3

// Look up by DID
const found = registry.get(agent1.did);
console.log(found?.did);  // agent1's DID

// Find all identities by sponsor
const aliceAgents = registry.getBySponsor('alice@contoso.com');
console.log(aliceAgents.length);  // 2

// List all active identities
console.log(registry.listActive().length);  // 3

// Revoke — cascades to all delegates
registry.revoke(agent1.did, 'Decommissioned');
console.log(registry.listActive().length);  // 2
```

---

## TrustManager

The `TrustManager` maintains a Bayesian-inspired trust score for each peer agent.
Scores decay over time and update based on interaction outcomes.

### §6.1 Creating a Trust Manager

```typescript
import { TrustManager, TrustConfig } from '@microsoft/agentmesh-sdk';

// Default configuration
const tm = new TrustManager();

// Custom configuration
const custom = new TrustManager({
  initialScore: 0.6,
  decayFactor: 0.98,
  thresholds: {
    untrusted: 0.0,
    provisional: 0.3,
    trusted: 0.6,
    verified: 0.85,
  },
});
```

**Default values:**

| Property | Default | Description |
|----------|---------|-------------|
| `initialScore` | `0.5` | Starting score for unknown agents |
| `decayFactor` | `0.95` | Hourly decay multiplier |
| `thresholds.untrusted` | `0.0` | Floor for untrusted tier |
| `thresholds.provisional` | `0.3` | Entry point for provisional trust |
| `thresholds.trusted` | `0.6` | Entry point for trusted tier |
| `thresholds.verified` | `0.85` | Entry point for verified tier |

### §6.2 Recording Interactions

```typescript
const tm = new TrustManager();

// Record successful interactions (default reward: 0.05)
tm.recordSuccess('peer-agent-1');
tm.recordSuccess('peer-agent-1');
tm.recordSuccess('peer-agent-1');

// Record failure (default penalty: 0.1)
tm.recordFailure('peer-agent-1');

// Custom reward / penalty values
tm.recordSuccess('peer-agent-2', 0.1);   // larger reward
tm.recordFailure('peer-agent-2', 0.2);   // harsher penalty
```

### §6.3 Reading Trust Scores

```typescript
const score = tm.getTrustScore('peer-agent-1');

console.log(score.overall);                // 0.55  (0-1, rounded to 3 decimals)
console.log(score.tier);                   // 'Provisional'
console.log(score.dimensions.reliability); // 0.75  (3 successes / 4 total)
console.log(score.dimensions.consistency); // 0.55  (current score after updates)
```

**`TrustScore` shape:**

```typescript
interface TrustScore {
  overall: number;       // 0-1, rounded to 3 decimals
  dimensions: {
    reliability: number; // success ratio: successes / total interactions
    consistency: number; // current running score
  };
  tier: TrustTier;       // 'Untrusted' | 'Provisional' | 'Trusted' | 'Verified'
}
```

### §6.4 Trust Tiers

Tiers map numeric scores to access levels:

| Tier | Score Range | Typical Access |
|------|------------|----------------|
| **Untrusted** | 0.00 – 0.29 | Blocked or heavily restricted |
| **Provisional** | 0.30 – 0.59 | Limited access, monitored |
| **Trusted** | 0.60 – 0.84 | Standard access |
| **Verified** | 0.85 – 1.00 | Full access, elevated privileges |

```
Untrusted      ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0.00 – 0.29
Provisional    ████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0.30 – 0.59
Trusted        ████████████████████████░░░░░░░░░░░░░░░░░░  0.60 – 0.84
Verified       ████████████████████████████████████████░░  0.85 – 1.00
```

### §6.5 Peer Verification

Verify another agent's identity and establish initial trust:

```typescript
import { AgentIdentity, TrustManager } from '@microsoft/agentmesh-sdk';

const tm = new TrustManager();
const peer = AgentIdentity.generate('remote-agent', ['data.read']);

const result = await tm.verifyPeer('remote-agent', peer);

console.log(result.verified);    // true — signature self-consistency checks passed
console.log(result.trustScore);  // initial TrustScore
console.log(result.reason);      // undefined when successful
```

### §6.6 Trust Decay

Trust scores decay over time when there are no interactions. The `decayFactor` is
applied hourly:

```typescript
// With decayFactor: 0.95
// After 1 hour of inactivity: score × 0.95
// After 2 hours: score × 0.95²
// After 24 hours: score × 0.95²⁴ ≈ score × 0.292

const tm = new TrustManager({ decayFactor: 0.95 });
tm.recordSuccess('agent-x');
tm.recordSuccess('agent-x');

// Score starts high, but decays if no further interactions
const score = tm.getTrustScore('agent-x');
console.log(score.overall);  // Score reflects elapsed time since last interaction
```

> **Tip:** Set `decayFactor` closer to `1.0` (e.g., `0.99`) for slower decay, or
> lower (e.g., `0.90`) for aggressive decay requiring frequent re-validation.

---

## AuditLogger

The `AuditLogger` provides an append-only, hash-chain-linked audit trail. Each
entry's SHA-256 hash incorporates the previous entry's hash, creating a tamper-evident
chain similar to a blockchain.

### §7.1 Logging Events

```typescript
import { AuditLogger } from '@microsoft/agentmesh-sdk';

const logger = new AuditLogger();

const entry = logger.log({
  agentId: 'sales-assistant',
  action: 'crm.read',
  decision: 'allow',
});

console.log(entry.timestamp);     // ISO 8601 string
console.log(entry.hash);          // SHA-256 of this entry
console.log(entry.previousHash);  // SHA-256 of previous entry (genesis: '0' × 64)
```

### §7.2 Hash-Chain Integrity

```typescript
const logger = new AuditLogger();

logger.log({ agentId: 'agent-1', action: 'data.read',   decision: 'allow' });
logger.log({ agentId: 'agent-1', action: 'data.write',  decision: 'deny'  });
logger.log({ agentId: 'agent-2', action: 'report.send', decision: 'allow' });

// Verify the entire chain
console.log(logger.verify());  // true — all hashes are consistent

console.log(logger.length);   // 3
```

**How the chain works:**

```
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  Entry 0            Entry 1            Entry 2                        │
  │  ┌──────────┐       ┌──────────┐       ┌──────────┐                   │
  │  │ hash: A  │──────▶│ prev: A  │──────▶│ prev: B  │                   │
  │  │ prev: 0⁶⁴│       │ hash: B  │       │ hash: C  │                   │
  │  └──────────┘       └──────────┘       └──────────┘                   │
  │                                                                       │
  │  Genesis hash = '000...000' (64 zeros)                                │
  │  Each hash = SHA-256(timestamp + agentId + action + decision + prev)  │
  └─────────────────────────────────────────────────────────────────────────┘
```

If any entry is tampered with, `verify()` returns `false` because the hash chain
breaks.

### §7.3 Querying the Log

```typescript
// All entries for a specific agent
const agentEntries = logger.getEntries({ agentId: 'agent-1' });
console.log(agentEntries.length);  // 2

// Filter by action
const reads = logger.getEntries({ action: 'data.read' });

// Filter by time
const recent = logger.getEntries({
  since: new Date('2025-01-15T00:00:00Z'),
});

// Combine filters
const agentReads = logger.getEntries({
  agentId: 'agent-1',
  action: 'data.read',
  since: new Date('2025-01-01'),
});
```

### §7.4 Exporting the Audit Trail

```typescript
// Export as JSON string
const json = logger.exportJSON();
console.log(json);
// [
//   {
//     "timestamp": "2025-01-15T10:30:00.000Z",
//     "agentId": "agent-1",
//     "action": "data.read",
//     "decision": "allow",
//     "hash": "3a7f...",
//     "previousHash": "0000...0000"
//   },
//   ...
// ]
```

### §7.5 Configuration

```typescript
// Limit log size (oldest entries evicted when limit reached)
const logger = new AuditLogger({ maxEntries: 50_000 });
```

| Option | Default | Description |
|--------|---------|-------------|
| `maxEntries` | `10,000` | Maximum entries before eviction |

---

## Framework Integration

### §8.1 LangChain.js

Wrap LangChain tool calls with governance checks:

```typescript
import { AgentMeshClient } from '@microsoft/agentmesh-sdk';
import { ChatOpenAI } from '@langchain/openai';
import { DynamicTool } from '@langchain/core/tools';

const client = AgentMeshClient.create('langchain-agent', {
  capabilities: ['search', 'calculate'],
  policyRules: [
    { action: 'search',    effect: 'allow' },
    { action: 'calculate', effect: 'allow' },
    { action: '*',          effect: 'deny'  },
  ],
});

// Governance-aware tool wrapper
function governedTool(name: string, fn: (input: string) => Promise<string>) {
  return new DynamicTool({
    name,
    description: `Governed: ${name}`,
    func: async (input: string) => {
      const gov = await client.executeWithGovernance(name, { input });

      if (gov.decision !== 'allow') {
        return `Action '${name}' denied by policy: ${gov.auditEntry.action}`;
      }
      return fn(input);
    },
  });
}

const searchTool = governedTool('search', async (query) => {
  // your search implementation
  return `Results for: ${query}`;
});
```

### §8.2 OpenAI Node SDK

Add governance to OpenAI function calls:

```typescript
import { AgentMeshClient } from '@microsoft/agentmesh-sdk';
import OpenAI from 'openai';

const client = AgentMeshClient.create('openai-agent', {
  capabilities: ['chat', 'function_call'],
  policyRules: [
    { action: 'chat',          effect: 'allow' },
    { action: 'function_call', effect: 'allow', conditions: { trusted: true } },
    { action: '*',              effect: 'deny'  },
  ],
});

const openai = new OpenAI();

async function governedCompletion(
  messages: OpenAI.ChatCompletionMessageParam[],
  tools?: OpenAI.ChatCompletionTool[]
) {
  // Check policy before calling OpenAI
  const gov = await client.executeWithGovernance('chat', {
    messageCount: messages.length,
    hasTools: !!tools,
  });

  if (gov.decision !== 'allow') {
    throw new Error(`Governance denied: ${gov.decision}`);
  }

  const response = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages,
    tools,
  });

  // If the model wants to call a function, check that too
  const toolCalls = response.choices[0]?.message?.tool_calls;
  if (toolCalls) {
    for (const call of toolCalls) {
      const fnGov = await client.executeWithGovernance('function_call', {
        functionName: call.function.name,
        trusted: true,
      });

      if (fnGov.decision !== 'allow') {
        console.warn(`Function call '${call.function.name}' denied`);
      }
    }
  }

  return response;
}
```

---

## Configuration Reference

### §9.1 Default Values

| Component | Property | Default |
|-----------|----------|---------|
| `PolicyEngine` | Conflict strategy | `PriorityFirstMatch` |
| `PolicyEngine` | Default action | `'deny'` |
| `PolicyRule` | `priority` | `0` |
| `PolicyRule` | `enabled` | `true` |
| `TrustManager` | `initialScore` | `0.5` |
| `TrustManager` | `decayFactor` | `0.95` |
| `TrustManager` | Success reward | `0.05` |
| `TrustManager` | Failure penalty | `0.1` |
| `AuditLogger` | `maxEntries` | `10,000` |
| `AuditLogger` | Genesis hash | `'0' × 64` |
| `AgentIdentity` | `status` | `'active'` |
| `AgentIdentity` | `delegationDepth` | `0` (root) |

### §9.2 Environment Variables

The SDK itself is configuration-object driven, but you can wire environment variables
into your configuration:

```typescript
import { AgentMeshClient } from '@microsoft/agentmesh-sdk';

const client = AgentMeshClient.create(
  process.env.AGENT_ID ?? 'default-agent',
  {
    capabilities: (process.env.AGENT_CAPABILITIES ?? 'read').split(','),
    trust: {
      initialScore: parseFloat(process.env.TRUST_INITIAL_SCORE ?? '0.5'),
      decayFactor: parseFloat(process.env.TRUST_DECAY_FACTOR ?? '0.95'),
    },
    audit: {
      maxEntries: parseInt(process.env.AUDIT_MAX_ENTRIES ?? '10000', 10),
    },
  }
);
```

**Recommended environment variables:**

| Variable | Example | Maps to |
|----------|---------|---------|
| `AGENT_ID` | `sales-assistant` | `agentId` |
| `AGENT_CAPABILITIES` | `read,write,search` | `capabilities` (comma-separated) |
| `TRUST_INITIAL_SCORE` | `0.6` | `trust.initialScore` |
| `TRUST_DECAY_FACTOR` | `0.98` | `trust.decayFactor` |
| `AUDIT_MAX_ENTRIES` | `50000` | `audit.maxEntries` |
| `POLICY_YAML_PATH` | `./policies/prod.yaml` | Path for `loadFromYAML()` |

### §9.3 TypeScript Configuration

The SDK targets ES2020 and uses Node16 module resolution. Ensure your `tsconfig.json`
includes:

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "Node16",
    "moduleResolution": "Node16",
    "strict": true,
    "esModuleInterop": true,
    "resolveJsonModule": true
  }
}
```

---

## Error Handling

### §10.1 Identity Errors

```typescript
import { AgentIdentity } from '@microsoft/agentmesh-sdk';

// Revoked identity cannot be reactivated
const agent = AgentIdentity.generate('temp', ['read']);
agent.revoke('Done');

try {
  agent.reactivate();
} catch (error) {
  console.error(error.message);  // Cannot reactivate a revoked identity
}

// Duplicate registration
const registry = new IdentityRegistry();
registry.register(agent);

try {
  registry.register(agent);  // same DID
} catch (error) {
  console.error(error.message);  // Identity already registered
}
```

### §10.2 Policy Errors

```typescript
import { PolicyEngine } from '@microsoft/agentmesh-sdk';

const engine = new PolicyEngine();

// Invalid YAML
try {
  engine.loadYaml('not: valid: yaml: {{');
} catch (error) {
  console.error('YAML parse error:', error.message);
}

// Missing policy file
try {
  await engine.loadFromYAML('./nonexistent.yaml');
} catch (error) {
  console.error('File not found:', error.message);
}
```

### §10.3 Governance Pipeline Errors

```typescript
import { AgentMeshClient } from '@microsoft/agentmesh-sdk';

const client = AgentMeshClient.create('agent', {
  policyRules: [{ action: '*', effect: 'deny' }],
});

// Wrap executeWithGovernance in try/catch
try {
  const result = await client.executeWithGovernance('risky.action');

  if (result.decision === 'deny') {
    console.log('Action denied — audit trail:', result.auditEntry.hash);
  } else if (result.decision === 'review') {
    console.log('Action requires review — trust:', result.trustScore.tier);
  }
} catch (error) {
  console.error('Governance pipeline error:', error);
}
```

### §10.4 TypeScript-Specific Patterns

Use type narrowing and discriminated unions for safe handling:

```typescript
import type {
  PolicyDecisionResult,
  GovernanceResult,
  TrustTier,
} from '@microsoft/agentmesh-sdk';

// Type guard for trust tiers
function requiresTrust(tier: TrustTier, minimum: TrustTier): boolean {
  const order: TrustTier[] = ['Untrusted', 'Provisional', 'Trusted', 'Verified'];
  return order.indexOf(tier) >= order.indexOf(minimum);
}

// Use with governance results
async function safeExecute(
  client: AgentMeshClient,
  action: string
): Promise<GovernanceResult> {
  const result = await client.executeWithGovernance(action);

  if (result.decision === 'deny') {
    throw new Error(`Denied: ${action} (audit: ${result.auditEntry.hash})`);
  }

  if (!requiresTrust(result.trustScore.tier, 'Trusted')) {
    console.warn(`Low trust for ${action}: ${result.trustScore.tier}`);
  }

  return result;
}
```

---

## Cross-Reference

The TypeScript SDK mirrors the Python packages. Use this table to find the
equivalent Python tutorial for each topic:

| TypeScript SDK | Python Package | Tutorial |
|---------------|---------------|----------|
| `PolicyEngine` | `agent_os.policies` | [Tutorial 01 — Policy Engine](./01-policy-engine.md) |
| `AgentIdentity`, `IdentityRegistry` | `agent_os.identity` | [Tutorial 02 — Trust & Identity](./02-trust-and-identity.md) |
| `TrustManager` | `agent_os.trust` | [Tutorial 02 — Trust & Identity](./02-trust-and-identity.md) |
| Framework integration | `agent_os.integrations` | [Tutorial 03 — Framework Integrations](./03-framework-integrations.md) |
| `AuditLogger` | `agent_os.audit` | [Tutorial 04 — Audit & Compliance](./04-audit-and-compliance.md) |

> **Note:** The TypeScript SDK wraps all governance features into a single
> `@microsoft/agentmesh-sdk` package, while the Python implementation splits
> them across separate `agent_os.*` modules. The APIs are designed for
> cross-language parity — policy YAML files work identically in both.

---

## Source Files

| Component | Location |
|-----------|----------|
| Main exports | `packages/agent-mesh/sdks/typescript/src/index.ts` |
| Type definitions | `packages/agent-mesh/sdks/typescript/src/types.ts` |
| `AgentIdentity` | `packages/agent-mesh/sdks/typescript/src/identity.ts` |
| `TrustManager` | `packages/agent-mesh/sdks/typescript/src/trust.ts` |
| `PolicyEngine` | `packages/agent-mesh/sdks/typescript/src/policy.ts` |
| `AuditLogger` | `packages/agent-mesh/sdks/typescript/src/audit.ts` |
| `AgentMeshClient` | `packages/agent-mesh/sdks/typescript/src/client.ts` |
| Tests | `packages/agent-mesh/sdks/typescript/tests/*.test.ts` |
| Package config | `packages/agent-mesh/sdks/typescript/package.json` |

---

## Next Steps

- **Run the tests** to see the SDK in action:
  ```bash
  cd packages/agent-mesh/sdks/typescript
  npm install && npm test
  ```
- **Load a YAML policy** from the repository's `policies/` directory and evaluate it
  against your agent
- **Build a multi-agent system** using `IdentityRegistry` + `TrustManager` to
  establish peer trust between cooperating agents
- **Add audit export** to your CI/CD pipeline — call `logger.exportJSON()` and
  persist the trail for compliance reviews
- **Explore the Python SDK** tutorials (01–04) for equivalent patterns in Python
