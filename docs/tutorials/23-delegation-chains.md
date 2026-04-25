<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Tutorial 23 — Multi-Agent Delegation Chains

Delegate capabilities from one agent to another with **monotonic scope
narrowing** — child agents can only receive a subset of their parent's
capabilities, never more. This tutorial shows how to build delegation chains
that enforce the principle of least privilege across multi-agent systems.

> **Package:** `@microsoft/agentmesh-sdk` (TypeScript) · `agentmesh` (Rust/Go)
> **Key class:** `AgentIdentity.delegate()`
> **Concept:** Authority can only decrease through a delegation chain

---

## What you'll learn

| Section | Topic |
|---------|-------|
| [What is Delegation?](#what-is-delegation) | Why agents need to delegate and the risks involved |
| [Monotonic Scope Narrowing](#monotonic-scope-narrowing) | Why authority can only decrease |
| [Creating a Delegation Chain](#creating-a-delegation-chain) | TypeScript package: `delegate()` with capability subsets |
| [Delegation Depth Tracking](#delegation-depth-tracking) | Tracking how many hops from the root authority |
| [Scope Chain Verification](#scope-chain-verification) | Validating the entire delegation chain |
| [Cross-Agent Trust Propagation](#cross-agent-trust-propagation) | How trust flows through delegation |
| [Full Example](#full-example-manager--researcher--reader) | Manager → Researcher → Data Reader pipeline |
| [Identity Registry](#identity-registry) | Managing and revoking delegated identities |
| [Cross-Reference](#cross-reference) | Related tutorials |

---

## Prerequisites

- **Node.js 18+** with TypeScript 5.4+
- `npm install @microsoft/agentmesh-sdk`
- Recommended: read [Tutorial 02 — Trust & Identity](02-trust-and-identity.md)
  and [Tutorial 20 — TypeScript package](20-typescript-sdk.md)

---

## What is Delegation?

In multi-agent systems, a parent agent delegates a **subset** of its
capabilities to a child agent. The child can then act on behalf of the parent
within that narrowed scope.

```
  Manager Agent                    Researcher Agent              Data Reader
  ┌────────────────┐              ┌────────────────┐            ┌──────────────┐
  │ capabilities:  │  delegate()  │ capabilities:  │ delegate() │ capabilities:│
  │  • data.read   │────────────▶ │  • data.read   │──────────▶ │  • data.read │
  │  • data.write  │              │  • search      │            │              │
  │  • search      │              │                │            │              │
  │  • deploy      │              │ depth: 1       │            │ depth: 2     │
  │                │              │ parent: Manager│            │ parent: Res. │
  │ depth: 0       │              └────────────────┘            └──────────────┘
  └────────────────┘
```

**Key constraints:**
- A child's capabilities must be a **strict subset** of the parent's
- The delegation `depth` increments at each level
- Each child records its `parentDid` for chain verification

---

## Monotonic Scope Narrowing

The word "monotonic" means "only moves in one direction." In delegation chains,
authority can only **decrease** — never increase.

### Why this matters

Without monotonic narrowing, a malicious or buggy agent could escalate its
own privileges by delegating more capabilities than it has:

```
  ❌ VIOLATION: Child has more capabilities than parent
  Parent: [data.read]
  Child:  [data.read, data.write, admin.delete]  ← NOT ALLOWED
```

The SDK enforces this at the API level — `delegate()` throws an error if the
requested capabilities are not a subset of the parent's capabilities.

### Wildcard matching

Capabilities support wildcard patterns. A parent with `data:*` can delegate
`data:read` or `data:write`, but a parent with only `data:read` cannot
delegate `data:*`:

```typescript
// Parent has broad wildcard
const parent = AgentIdentity.generate('parent', ['data:*', 'search']);

// ✅ Valid: 'data:read' is covered by 'data:*'
const child = parent.delegate('child', ['data:read']);

// ❌ Invalid: 'admin' is not covered by parent
const bad = parent.delegate('bad', ['admin']);  // throws Error
```

---

## Creating a Delegation Chain

### §3.1 Basic Delegation

```typescript
import { AgentIdentity } from '@microsoft/agentmesh-sdk';

// 1. Create the root identity (manager)
const manager = AgentIdentity.generate('manager', [
  'data.read',
  'data.write',
  'search',
  'deploy',
]);

console.log(manager.did);              // did:agentmesh:manager:a1b2...
console.log(manager.capabilities);     // ['data.read', 'data.write', 'search', 'deploy']
console.log(manager.delegationDepth);  // 0
console.log(manager.parentDid);        // null (root agent)

// 2. Delegate a subset to the researcher
const researcher = manager.delegate('researcher', ['data.read', 'search']);

console.log(researcher.did);              // did:agentmesh:researcher:c3d4...
console.log(researcher.capabilities);     // ['data.read', 'search']
console.log(researcher.delegationDepth);  // 1
console.log(researcher.parentDid);        // did:agentmesh:manager:a1b2...
```

### §3.2 Chained Delegation

The researcher can further delegate to a data reader, but only from its own
(narrowed) capabilities:

```typescript
// 3. Researcher delegates to a data reader
const reader = researcher.delegate('data-reader', ['data.read']);

console.log(reader.capabilities);     // ['data.read']
console.log(reader.delegationDepth);  // 2
console.log(reader.parentDid);        // did:agentmesh:researcher:c3d4...
```

### §3.3 Delegation with Metadata

Pass additional options when delegating:

```typescript
const worker = manager.delegate('worker', ['data.read'], {
  description: 'Read-only data worker for ETL pipeline',
  sponsor: 'platform-team',
  organization: 'data-engineering',
  expiresAt: new Date('2025-12-31'),
});

console.log(worker.description);   // 'Read-only data worker for ETL pipeline'
console.log(worker.sponsor);       // 'platform-team'
console.log(worker.expiresAt);     // 2025-12-31T00:00:00.000Z
```

### §3.4 Rejected Delegations

The SDK enforces scope narrowing at delegation time:

```typescript
try {
  // ❌ 'admin' is not in the researcher's capabilities
  const bad = researcher.delegate('bad-agent', ['admin']);
} catch (error) {
  console.error(error.message);
  // "Cannot delegate capability 'admin' — not in parent's capabilities"
}

try {
  // ❌ 'deploy' is in the manager's capabilities but NOT in the researcher's
  const bad = researcher.delegate('escalated', ['data.read', 'deploy']);
} catch (error) {
  console.error(error.message);
  // "Cannot delegate capability 'deploy' — not in parent's capabilities"
}
```

---

## Delegation Depth Tracking

Every identity tracks how many delegation hops separate it from the root
authority:

```typescript
const root = AgentIdentity.generate('root', ['*']);
console.log(root.delegationDepth);  // 0

const child = root.delegate('child', ['data.read']);
console.log(child.delegationDepth);  // 1

const grandchild = child.delegate('grandchild', ['data.read']);
console.log(grandchild.delegationDepth);  // 2
```

Use delegation depth to enforce policy rules like "only depth-0 agents can
deploy to production":

```typescript
function canDeployToProduction(identity: AgentIdentity): boolean {
  return identity.delegationDepth === 0
      && identity.hasCapability('deploy');
}
```

---

## Scope Chain Verification

### §5.1 Verifying Parent Links

Each delegated identity records its parent's DID. You can walk the chain to
verify the delegation hierarchy:

```typescript
function getDelegationChain(
  identity: AgentIdentity,
  registry: IdentityRegistry,
): AgentIdentity[] {
  const chain: AgentIdentity[] = [identity];
  let current = identity;

  while (current.parentDid) {
    const parent = registry.get(current.parentDid);
    if (!parent) break;
    chain.unshift(parent);
    current = parent;
  }

  return chain;
}

// Usage
import { IdentityRegistry } from '@microsoft/agentmesh-sdk';

const registry = new IdentityRegistry();
registry.register(manager);
registry.register(researcher);
registry.register(reader);

const chain = getDelegationChain(reader, registry);
console.log(chain.map(id => id.did));
// [manager.did, researcher.did, reader.did]
```

### §5.2 Verifying Capability Monotonicity

Confirm that capabilities only narrow through the chain:

```typescript
function verifyMonotonicNarrowing(chain: AgentIdentity[]): boolean {
  for (let i = 1; i < chain.length; i++) {
    const parent = chain[i - 1];
    const child = chain[i];

    // Every child capability must be in the parent's scope
    for (const cap of child.capabilities) {
      if (!parent.hasCapability(cap)) {
        console.error(
          `Violation: ${child.did} has '${cap}' not in parent ${parent.did}`
        );
        return false;
      }
    }
  }
  return true;
}

console.log(verifyMonotonicNarrowing(chain));  // true
```

### §5.3 Cryptographic Verification

Each identity can sign and verify data. Use this to prove delegation
authenticity:

```typescript
// Manager signs a delegation attestation
const attestation = Buffer.from(JSON.stringify({
  delegator: manager.did,
  delegatee: researcher.did,
  capabilities: researcher.capabilities,
  timestamp: new Date().toISOString(),
}));

const signature = manager.sign(attestation);

// Anyone with the manager's public key can verify
console.log(manager.verify(attestation, signature));  // true
```

---

## Cross-Agent Trust Propagation

Combine delegation with trust scoring to propagate trust through the chain:

```typescript
import { AgentMeshClient } from '@microsoft/agentmesh-sdk';

// Create a governed manager
const managerClient = AgentMeshClient.create('manager', {
  capabilities: ['data.read', 'data.write', 'search'],
  policyRules: [
    { action: 'data.read',  effect: 'allow' },
    { action: 'data.write', effect: 'allow' },
    { action: 'search',     effect: 'allow' },
    { action: '*',          effect: 'deny'  },
  ],
});

// Delegate to a researcher
const researcherIdentity = managerClient.identity.delegate(
  'researcher',
  ['data.read', 'search'],
);

// The researcher's trust score starts fresh (not inherited)
// but can be boosted by the manager's endorsement
const researcherClient = AgentMeshClient.create('researcher', {
  capabilities: ['data.read', 'search'],
  policyRules: [
    { action: 'data.read', effect: 'allow' },
    { action: 'search',    effect: 'allow' },
    { action: '*',         effect: 'deny'  },
  ],
});

// Manager vouches for researcher by recording trust
const result = await researcherClient.executeWithGovernance('data.read');
console.log(result.trustScore);
```

> **Design note:** Trust scores are **not** inherited through delegation.
> Each agent builds its own trust through successful interactions. This
> prevents a single compromise from propagating high trust scores.

---

## Full Example: Manager → Researcher → Reader

```typescript
import { AgentIdentity, IdentityRegistry, AgentMeshClient } from '@microsoft/agentmesh-sdk';

// ── Step 1: Create the root manager ──
const manager = AgentIdentity.generate('manager', [
  'data.read',
  'data.write',
  'search',
  'deploy',
], {
  name: 'Pipeline Manager',
  organization: 'data-engineering',
});

// ── Step 2: Delegate to researcher (data.read + search only) ──
const researcher = manager.delegate('researcher', ['data.read', 'search'], {
  description: 'Research agent for data analysis',
});

// ── Step 3: Researcher delegates to reader (data.read only) ──
const reader = researcher.delegate('data-reader', ['data.read'], {
  description: 'Read-only data access agent',
  expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
});

// ── Step 4: Register all identities ──
const registry = new IdentityRegistry();
registry.register(manager);
registry.register(researcher);
registry.register(reader);

// ── Step 5: Verify the chain ──
console.log('=== Delegation Chain ===');
console.log(`Manager:    ${manager.did} (depth: ${manager.delegationDepth})`);
console.log(`  caps:     ${manager.capabilities.join(', ')}`);
console.log(`Researcher: ${researcher.did} (depth: ${researcher.delegationDepth})`);
console.log(`  caps:     ${researcher.capabilities.join(', ')}`);
console.log(`  parent:   ${researcher.parentDid}`);
console.log(`Reader:     ${reader.did} (depth: ${reader.delegationDepth})`);
console.log(`  caps:     ${reader.capabilities.join(', ')}`);
console.log(`  parent:   ${reader.parentDid}`);
console.log(`  expires:  ${reader.expiresAt?.toISOString()}`);

// ── Step 6: Test capability checks ──
console.log('\n=== Capability Checks ===');
console.log(`Manager has 'deploy':     ${manager.hasCapability('deploy')}`);      // true
console.log(`Researcher has 'deploy':  ${researcher.hasCapability('deploy')}`);   // false
console.log(`Reader has 'search':      ${reader.hasCapability('search')}`);       // false
console.log(`Reader has 'data.read':   ${reader.hasCapability('data.read')}`);    // true

// ── Step 7: Test scope narrowing enforcement ──
console.log('\n=== Scope Narrowing ===');
try {
  reader.delegate('escalated', ['data.write']);
} catch (e) {
  console.log(`Prevented escalation: ${(e as Error).message}`);
}

// ── Step 8: Revoke the researcher (cascades to reader) ──
console.log('\n=== Revocation ===');
registry.revoke(researcher.did, 'Compromised credentials');
console.log(`Researcher status: ${researcher.status}`);  // revoked
console.log(`Reader status:     ${reader.status}`);       // revoked (cascaded)
console.log(`Active identities: ${registry.listActive().length}`);  // 1 (manager only)
```

**Expected output:**

```
=== Delegation Chain ===
Manager:    did:agentmesh:manager:a1b2c3d4 (depth: 0)
  caps:     data.read, data.write, search, deploy
Researcher: did:agentmesh:researcher:e5f6g7h8 (depth: 1)
  caps:     data.read, search
  parent:   did:agentmesh:manager:a1b2c3d4
Reader:     did:agentmesh:data-reader:i9j0k1l2 (depth: 2)
  caps:     data.read
  parent:   did:agentmesh:researcher:e5f6g7h8
  expires:  2025-07-16T10:30:00.000Z

=== Capability Checks ===
Manager has 'deploy':     true
Researcher has 'deploy':  false
Reader has 'search':      false
Reader has 'data.read':   true

=== Scope Narrowing ===
Prevented escalation: Cannot delegate capability 'data.write' — not in parent's capabilities

=== Revocation ===
Researcher status: revoked
Reader status:     revoked
Active identities: 1
```

---

## Identity Registry

The `IdentityRegistry` manages all agent identities and supports cascade
revocation:

```typescript
import { IdentityRegistry, AgentIdentity } from '@microsoft/agentmesh-sdk';

const registry = new IdentityRegistry();

// Register identities
const agent = AgentIdentity.generate('agent', ['read']);
registry.register(agent);
console.log(registry.size);  // 1

// Look up by DID
const found = registry.get(agent.did);

// Look up by sponsor
const sponsored = registry.getBySponsor('platform-team');

// List all active identities
const active = registry.listActive();

// Revoke (cascades to children)
registry.revoke(agent.did, 'Security incident');
```

### Cascade Revocation

When a parent identity is revoked, **all its delegates are automatically
revoked**:

```typescript
registry.revoke(manager.did, 'Compromised');
// researcher → revoked
// reader     → revoked
// Any further delegates of reader → also revoked
```

This ensures that a compromised parent cannot have active children operating
with delegated authority.

---

## Cross-Reference

| Concept | Tutorial |
|---------|----------|
| Ed25519 identity basics | [Tutorial 02 — Trust & Identity](./02-trust-and-identity.md) |
| TypeScript package overview | [Tutorial 20 — TypeScript package](./20-typescript-sdk.md) |
| Rust crate delegation | [Tutorial 21 — Rust crate](./21-rust-sdk.md) |
| Policy evaluation | [Tutorial 01 — Policy Engine](./01-policy-engine.md) |
| Liability & attribution | [Tutorial 12 — Liability & Attribution](./12-liability-and-attribution.md) |

---

## Source Files

| Component | Location |
|-----------|----------|
| `AgentIdentity` (TypeScript) | `agent-governance-typescript/src/identity.ts` |
| `IdentityRegistry` (TypeScript) | `agent-governance-typescript/src/identity.ts` |
| Tests | `agent-governance-typescript/tests/identity.test.ts` |

---

## Next Steps

- **Add policy rules** that check `delegationDepth` to restrict deep delegation
  chains
- **Combine with trust scoring** to require minimum trust before accepting
  delegated requests
- **Implement time-limited delegation** with `expiresAt` for temporary access
- **Use the `IdentityRegistry`** to track all agents and enable cascade
  revocation
- **Read Tutorial 12** ([Liability & Attribution](./12-liability-and-attribution.md))
  to understand how delegated actions are attributed
