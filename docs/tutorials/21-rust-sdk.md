<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Tutorial 21 — Rust SDK (`agent-governance-rust/` workspace)

Full agent governance in Rust lives in the top-level `agent-governance-rust/`
workspace. The main `agentmesh` crate now covers policy evaluation, trust
scoring, hash-chain audit logging, Ed25519 agent identity, governance helpers,
reward primitives, execution control, and lifecycle management. The companion
`agentmesh-mcp` crate keeps MCP-focused security functionality available as a
smaller standalone dependency.

> **Target runtime:** Rust 1.75+ (2021 edition)
> **Workspace:** `agent-governance-rust/`
> **Crates:** `agentmesh` and `agentmesh-mcp`
> **Dependencies:** `serde`, `serde_yaml`, `sha2`, `ed25519-dalek`, `thiserror`

---

## What you'll learn

| Section | Topic |
|---------|-------|
| [Quick Start](#quick-start) | Evaluate a policy in 5 lines of Rust |
| [AgentMeshClient](#agentmeshclient) | Unified governance pipeline — identity + trust + policy + audit |
| [Extended Crate Surface](#extended-crate-surface) | Governance, reward, and control-plane helpers beyond the core client |
| [PolicyEngine](#policyengine) | YAML rules, capability/approval/rate-limit types, conflict resolution |
| [TrustManager](#trustmanager) | 0–1000 trust scoring, tiers, decay, persistence |
| [AuditLogger](#auditlogger) | Hash-chain audit logging and verification |
| [AgentIdentity](#agentidentity) | Ed25519 key pairs, DIDs, signing, JSON export |
| [Loading Policies from YAML](#loading-policies-from-yaml) | File-based policy configuration |
| [Full Governance Pipeline](#full-governance-pipeline) | End-to-end example |
| [Cross-Reference](#cross-reference) | Equivalent Python and TypeScript tutorials |
| [Next Steps](#next-steps) | Where to go from here |

---

## Prerequisites

- **Rust 1.75+** with Cargo
- Familiarity with `cargo` and `Cargo.toml`
- Recommended: read [Tutorial 01 — Policy Engine](01-policy-engine.md) for
  governance concepts

---

## Installation

From the repository root, the Rust workspace lives in:

```text
agent-governance-rust/
  agentmesh/
  agentmesh-mcp/
```

Add the main governance crate to your project:

```bash
cargo add agentmesh
```

Or add it to your `Cargo.toml` directly:

```toml
[dependencies]
agentmesh = "3"
```

---

## Quick Start

Five lines to evaluate your first policy:

```rust
use agentmesh::AgentMeshClient;

fn main() {
    let client = AgentMeshClient::new("my-agent")
        .expect("failed to create client");

    let result = client.execute_with_governance("data.read", None);
    println!("Allowed: {}", result.allowed);     // true
    println!("Decision: {:?}", result.decision);  // Allow
}
```

When no policy is loaded, the engine defaults to **allow** — load a YAML policy
to enforce governance rules.

---

## AgentMeshClient

`AgentMeshClient` is the recommended entry point. It wires together identity,
trust, policy, and audit into a single governance-aware pipeline.

### Creating a Client

```rust
use agentmesh::{AgentMeshClient, ClientOptions};

// Default client — generates identity, empty policy (allow-all)
let client = AgentMeshClient::new("analyst-001")?;

// Client with options
let opts = ClientOptions {
    capabilities: vec!["data.read".into(), "data.write".into()],
    trust_config: None,    // use defaults
    policy_yaml: None,     // load later
};
let client = AgentMeshClient::with_options("analyst-001", opts)?;
```

### Accessing Components

Each subsystem is accessible as a public field:

```rust
// Identity (Ed25519 DID)
println!("DID: {}", client.identity.did);
println!("Capabilities: {:?}", client.identity.capabilities);

// Trust scores
let score = client.trust.get_trust_score(&client.identity.did);
println!("Trust: {} (tier: {:?})", score.score, score.tier);

// Audit trail
println!("Audit chain valid: {}", client.audit.verify());
println!("Entries: {}", client.audit.entries().len());
```

### The Governance Pipeline

`execute_with_governance()` runs the full pipeline: evaluate → log → trust
update.

```rust
use std::collections::HashMap;

let result = client.execute_with_governance("data.read", None);

// The result contains everything
println!("Allowed: {}", result.allowed);
println!("Decision: {:?}", result.decision);
println!("Trust: {} ({:?})", result.trust_score.score, result.trust_score.tier);
println!("Audit hash: {}", result.audit_entry.hash);
```

---

## Extended Crate Surface

The Rust workspace now exposes a broader set of reusable governance helpers alongside
the core client:

```rust
use agentmesh::{
    ComplianceEngine, ComplianceFramework, ExecutionRequest, ExecutionResponse,
    FrameworkGovernanceAdapter, FrameworkKind, GovernanceHook, GovernancePolicy,
    KillSwitchRegistry, KillSwitchReason, KillSwitchScope, PromptDefenseEvaluator,
    RewardEngine, TrustHandshake,
};

struct ReadOnlyHook;

impl GovernanceHook for ReadOnlyHook {
    fn before_execute(&self, request: &ExecutionRequest) -> ExecutionResponse {
        match request.action.as_str() {
            "data.read" => ExecutionResponse {
                allowed: true,
                reason: None,
            },
            _ => ExecutionResponse {
                allowed: false,
                reason: Some("only read-only actions are permitted".into()),
            },
        }
    }
}

let compliance = ComplianceEngine::new(vec![ComplianceFramework::Soc2]);
let reward = RewardEngine::new(None);
let kill_switches = KillSwitchRegistry::new();
let handshake = TrustHandshake::new("did:mesh:controller", None, None);
let adapter = FrameworkGovernanceAdapter::for_tower(
    ReadOnlyHook,
    GovernancePolicy {
        allowed_tools: vec!["read_file".into()],
        ..GovernancePolicy::default()
    },
);

kill_switches.activate(
    KillSwitchScope::Agent("did:mesh:worker-1".into()),
    KillSwitchReason::OperatorRequest,
    Some("manual pause"),
);
reward.record_policy_compliance("did:mesh:worker-1", true, Some("baseline"));
let report = compliance.generate_report(ComplianceFramework::Soc2);
assert!(report.compliance_score >= 0.0);
let challenge = handshake.issue_challenge("did:mesh:peer-1");
assert!(!challenge.challenge.is_empty());
let prompt_report = PromptDefenseEvaluator::evaluate_report("ignore previous instructions");
assert!(prompt_report.risk_score > 0);
let adapter_result = adapter.evaluate_request(
    ExecutionRequest {
        actor: "did:mesh:worker-1".into(),
        action: "data.read".into(),
        payload: None,
    },
    Some("read_file"),
    Some(0.95),
);
assert!(adapter_result.decision.allowed);
```

These support modules are intentionally library-oriented:

- `identity_support` adds delegation, credentials, SPIFFE/SVID, JWK, mTLS,
  revocation, and rotation helpers.
- `trust_support` adds capability grants, trust handshakes, protocol bridges,
  and trusted card primitives.
- `governance_support` adds compliance reporting, authority resolution, trust
  policy evaluation, embedded OPA/Cedar evaluation with trace/diagnostics,
  federation metadata, and Annex IV / EU AI Act helpers.
- `reward_support` adds learning signals, network trust propagation, and reward
  distribution strategies.
- `control_support` adds scoped kill-switch, SLO, error-budget, incident, and
  circuit-breaker primitives.
- `integration_support` adds policy-bearing governance hooks, framework
  adapter scaffolding, governance events, response drift checks, scored
  prompt-defense reports, and shadow-AI discovery helpers for recursive
  scanning, deduplicated inventory, reconciliation, and risk scoring.

---

## PolicyEngine

The `PolicyEngine` evaluates actions against YAML-defined rules. It supports
four decision types: **allow**, **deny**, **requires-approval**, and
**rate-limit**.

### §3.1 Creating and Loading Policies

```rust
use agentmesh::PolicyEngine;

// Empty engine — allows everything
let engine = PolicyEngine::new();
assert!(!engine.is_loaded());

// Load from a YAML string
let yaml = r#"
version: "1.0"
agent: my-agent
policies:
  - name: capability-gate
    type: capability
    allowed_actions:
      - "data.read"
      - "data.write"
    denied_actions:
      - "shell:*"
"#;

engine.load_from_yaml(yaml)?;
assert!(engine.is_loaded());
```

### §3.2 Evaluating Actions

```rust
use agentmesh::types::PolicyDecision;

let decision = engine.evaluate("data.read", None);
assert_eq!(decision, PolicyDecision::Allow);

let decision = engine.evaluate("shell:rm", None);
assert!(matches!(decision, PolicyDecision::Deny(_)));

// Actions outside the rule's scope fall through to Allow
let decision = engine.evaluate("admin.delete", None);
assert_eq!(decision, PolicyDecision::Allow);
```

### §3.3 Four Decision Types

```yaml
# policies/governance.yaml
version: "1.0"
agent: multi-decision-demo
policies:
  # 1. Capability — allow/deny by action pattern
  - name: data-gate
    type: capability
    allowed_actions:
      - "data.*"
    denied_actions:
      - "shell:*"

  # 2. Approval — require human sign-off
  - name: deploy-gate
    type: approval
    actions:
      - "deploy.*"
    min_approvals: 2

  # 3. Rate limit — cap call frequency
  - name: api-throttle
    type: rate_limit
    actions:
      - "api.*"
    max_calls: 10
    window: "60s"
```

```rust
let engine = PolicyEngine::new();
engine.load_from_file("policies/governance.yaml")?;

// Capability — allowed
assert_eq!(engine.evaluate("data.read", None), PolicyDecision::Allow);

// Capability — denied
assert!(matches!(engine.evaluate("shell:rm", None), PolicyDecision::Deny(_)));

// Approval required
assert!(matches!(
    engine.evaluate("deploy.prod", None),
    PolicyDecision::RequiresApproval(_)
));

// Rate limiting
for _ in 0..10 {
    assert_eq!(engine.evaluate("api.call", None), PolicyDecision::Allow);
}
assert!(matches!(
    engine.evaluate("api.call", None),
    PolicyDecision::RateLimited { .. }
));
```

### §3.4 Conditional Rules

Rules can include conditions that are matched against a context map:

```yaml
version: "1.0"
agent: conditional-demo
policies:
  - name: prod-gate
    type: capability
    denied_actions:
      - "deploy.*"
    conditions:
      environment: "production"
```

```rust
use std::collections::HashMap;
use serde_yaml::Value;

let engine = PolicyEngine::new();
engine.load_from_yaml(yaml)?;

// Without context — rule is skipped, action allowed
assert_eq!(engine.evaluate("deploy.app", None), PolicyDecision::Allow);

// With matching context — denied
let mut ctx = HashMap::new();
ctx.insert("environment".into(), Value::String("production".into()));
assert!(matches!(
    engine.evaluate("deploy.app", Some(&ctx)),
    PolicyDecision::Deny(_)
));
```

### §3.5 Conflict Resolution

When multiple policy candidates conflict, the engine resolves them using one of
four strategies:

```rust
use agentmesh::types::{CandidateDecision, ConflictResolutionStrategy, PolicyScope};

let engine = PolicyEngine::with_strategy(ConflictResolutionStrategy::DenyOverrides);

let candidates = vec![
    CandidateDecision {
        decision: PolicyDecision::Allow,
        priority: 10,
        scope: PolicyScope::Global,
        rule_name: "allow-rule".into(),
    },
    CandidateDecision {
        decision: PolicyDecision::Deny("blocked".into()),
        priority: 5,
        scope: PolicyScope::Global,
        rule_name: "deny-rule".into(),
    },
];

let result = engine.resolve_conflicts(&candidates);
assert!(matches!(result.winning_decision, PolicyDecision::Deny(_)));
assert!(result.conflict_detected);
```

| Strategy | Behaviour |
|----------|-----------|
| `DenyOverrides` | Any deny wins, regardless of priority |
| `AllowOverrides` | Any allow wins, regardless of priority |
| `PriorityFirstMatch` | Highest priority wins (default) |
| `MostSpecificWins` | Agent > Tenant > Global scope, then priority |

---

## TrustManager

The `TrustManager` tracks per-agent trust scores on a **0–1000** scale across
five tiers, with time-based decay and optional JSON persistence.

### §4.1 Trust Tiers

| Tier | Score Range | Description |
|------|-------------|-------------|
| `Untrusted` | 0–299 | Agent has failed validation or behaved maliciously |
| `Probationary` | 300–499 | New or recovering agent, limited access |
| `Standard` | 500–699 | Default starting point |
| `Trusted` | 700–899 | Established track record |
| `VerifiedPartner` | 900–1000 | Highest confidence level |

### §4.2 Basic Usage

```rust
use agentmesh::{TrustManager, TrustTier};

let tm = TrustManager::with_defaults();

// New agent starts at 500 (Standard)
let score = tm.get_trust_score("agent-x");
assert_eq!(score.score, 500);
assert_eq!(score.tier, TrustTier::Standard);

// Record successes — trust increases
tm.record_success("agent-x");
tm.record_success("agent-x");
let score = tm.get_trust_score("agent-x");
assert!(score.score > 500);

// Record failures — trust decreases (asymmetric: penalty > reward)
tm.record_failure("agent-x");
let score = tm.get_trust_score("agent-x");
println!("After failure: {} ({:?})", score.score, score.tier);
```

### §4.3 Custom Configuration

```rust
use agentmesh::TrustConfig;

let config = TrustConfig {
    initial_score: 800,
    threshold: 700,
    reward: 20,
    penalty: 100,
    persist_path: None,
    decay_rate: 0.95,
};
let tm = TrustManager::new(config);

let score = tm.get_trust_score("high-trust-agent");
assert_eq!(score.score, 800);
assert_eq!(score.tier, TrustTier::Trusted);
```

### §4.4 Decay

Trust scores decay over time if no interactions occur. The `decay_rate`
multiplier is applied per hour since the last update:

```
decayed_score = score × decay_rate ^ hours_elapsed
```

Set `decay_rate` closer to `1.0` for slower decay, or lower (e.g., `0.90`) for
aggressive decay requiring frequent re-validation.

### §4.5 Persistence

Enable JSON persistence to survive process restarts:

```rust
let config = TrustConfig {
    persist_path: Some("trust-scores.json".into()),
    ..Default::default()
};
let tm = TrustManager::new(config);

// Scores are saved on every update and loaded on construction
tm.record_success("agent-x");
// trust-scores.json now contains the score
```

---

## AuditLogger

The `AuditLogger` provides an append-only, hash-chain-linked audit trail. Each
entry's SHA-256 hash incorporates the previous entry's hash, creating a
tamper-evident chain.

### §5.1 Logging Events

```rust
use agentmesh::AuditLogger;

let logger = AuditLogger::new();

let entry = logger.log("agent-001", "data.read", "allow");
println!("Hash: {}", entry.hash);
println!("Prev: {}", entry.previous_hash);  // empty for genesis entry
println!("Seq:  {}", entry.seq);             // 0
```

### §5.2 Hash-Chain Integrity

```rust
let logger = AuditLogger::new();

logger.log("agent-1", "data.read",   "allow");
logger.log("agent-1", "data.write",  "deny");
logger.log("agent-2", "report.send", "allow");

// Verify the entire chain
assert!(logger.verify());

// Each entry links to the previous
let entries = logger.entries();
assert_eq!(entries.len(), 3);
assert_eq!(entries[1].previous_hash, entries[0].hash);
assert_eq!(entries[2].previous_hash, entries[1].hash);
```

**How the chain works:**

```
  Entry 0            Entry 1            Entry 2
  ┌──────────┐       ┌──────────┐       ┌──────────┐
  │ hash: A  │──────▶│ prev: A  │──────▶│ prev: B  │
  │ prev: "" │       │ hash: B  │       │ hash: C  │
  │ seq: 0   │       │ seq: 1   │       │ seq: 2   │
  └──────────┘       └──────────┘       └──────────┘
```

If any entry is tampered with, `verify()` returns `false` because the hash chain
breaks.

### §5.3 Filtering Entries

```rust
use agentmesh::types::AuditFilter;

let filter = AuditFilter {
    agent_id: Some("agent-1".into()),
    action: None,
    decision: None,
};

let filtered = logger.get_entries(&filter);
println!("Agent-1 entries: {}", filtered.len());
```

---

## AgentIdentity

The `AgentIdentity` provides Ed25519-based cryptographic identity with DID
identifiers, signing, and JSON serialisation.

### §6.1 Generating an Identity

```rust
use agentmesh::AgentIdentity;

let identity = AgentIdentity::generate(
    "researcher-agent",
    vec!["data.read".into(), "search".into()],
)?;

println!("DID: {}", identity.did);               // did:agentmesh:researcher-agent
println!("Capabilities: {:?}", identity.capabilities);
println!("Public key: {} bytes", identity.public_key.len());
```

### §6.2 Signing and Verifying

```rust
let data = b"important message";

// Sign
let signature = identity.sign(data)?;
println!("Signature: {} bytes", signature.len());  // 64 bytes

// Verify with the same identity
assert!(identity.verify(data, &signature));

// Tampered data fails verification
assert!(!identity.verify(b"wrong message", &signature));
```

### §6.3 JSON Serialisation

Export the public portion of an identity for sharing:

```rust
let json = identity.to_json()?;
println!("{}", json);
// {"did":"did:agentmesh:researcher-agent","public_key":"...","capabilities":["data.read","search"]}

// Reconstruct from JSON
let imported = AgentIdentity::from_json(&json)?;
assert_eq!(imported.did, identity.did);
```

### §6.4 Public Identity (Verification Only)

Share a `PublicIdentity` when you need verification without the private key:

```rust
use agentmesh::PublicIdentity;

let pub_id = PublicIdentity {
    did: identity.did.clone(),
    public_key: identity.public_key.to_bytes().to_vec(),
    capabilities: identity.capabilities.clone(),
};
assert!(pub_id.verify(b"important message", &signature));
```

---

## Loading Policies from YAML

The recommended pattern is to keep policies in versioned YAML files:

```yaml
# policies/security.yaml
version: "1.0"
agent: production-agent
policies:
  - name: data-access
    type: capability
    allowed_actions:
      - "data.read"
      - "data.write"
    denied_actions:
      - "shell:*"
      - "admin.*"

  - name: deploy-approval
    type: approval
    actions:
      - "deploy.*"
    min_approvals: 2

  - name: api-rate-limit
    type: rate_limit
    actions:
      - "api.*"
    max_calls: 100
    window: "1m"
```

```rust
use agentmesh::{AgentMeshClient, ClientOptions};

// Load policy at client creation
let yaml = std::fs::read_to_string("policies/security.yaml")?;
let client = AgentMeshClient::with_options("prod-agent", ClientOptions {
    policy_yaml: Some(yaml),
    ..Default::default()
})?;

// Or load into an existing engine
client.policy.load_from_file("policies/additional.yaml")?;
```

---

## Full Governance Pipeline

End-to-end example combining all subsystems:

```rust
use agentmesh::{AgentMeshClient, ClientOptions, TrustConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Configure the client
    let policy_yaml = r#"
version: "1.0"
agent: research-agent
policies:
  - name: data-gate
    type: capability
    allowed_actions:
      - "data.read"
      - "search.*"
    denied_actions:
      - "data.delete"
      - "shell:*"
  - name: api-throttle
    type: rate_limit
    actions:
      - "search.*"
    max_calls: 5
    window: "60s"
"#;

    let client = AgentMeshClient::with_options("research-agent", ClientOptions {
        capabilities: vec!["data.read".into(), "search.web".into()],
        trust_config: Some(TrustConfig {
            initial_score: 500,
            reward: 15,
            penalty: 75,
            ..Default::default()
        }),
        policy_yaml: Some(policy_yaml.into()),
    })?;

    println!("Agent DID: {}", client.identity.did);

    // 2. Execute governed actions
    let actions = ["data.read", "search.web", "data.delete", "shell:ls"];
    for action in &actions {
        let result = client.execute_with_governance(action, None);
        println!(
            "  {} → {} (trust: {}, tier: {:?})",
            action,
            if result.allowed { "✅ allowed" } else { "❌ denied" },
            result.trust_score.score,
            result.trust_score.tier,
        );
    }

    // 3. Verify audit chain
    let entries = client.audit.entries();
    println!("\nAudit trail: {} entries", entries.len());
    println!("Chain valid: {}", client.audit.verify());

    for entry in &entries {
        println!(
            "  [{}] {} → {} (hash: {}...)",
            entry.seq,
            entry.action,
            entry.decision,
            &entry.hash[..12],
        );
    }

    Ok(())
}
```

**Expected output:**

```
Agent DID: did:agentmesh:research-agent
  data.read   → ✅ allowed (trust: 510, tier: Trusted)
  search.web  → ✅ allowed (trust: 520, tier: Trusted)
  data.delete → ❌ denied  (trust: 445, tier: Neutral)
  shell:ls    → ❌ denied  (trust: 370, tier: Probationary)

Audit trail: 4 entries
Chain valid: true
  [0] data.read   → allow (hash: 3a7f2b8c91e4...)
  [1] search.web  → allow (hash: f1d9a2c38b71...)
  [2] data.delete → deny  (hash: 8e4c1a7d02f3...)
  [3] shell:ls    → deny  (hash: b5e7d3f9c128...)
```

---

## Cross-Reference

| Rust Crate Feature | Python Equivalent | Tutorial |
|------------------|-------------------|----------|
| `PolicyEngine` | `agent_os.policy` | [Tutorial 01 — Policy Engine](./01-policy-engine.md) |
| `TrustManager` | `agent_os.trust` | [Tutorial 02 — Trust & Identity](./02-trust-and-identity.md) |
| `AuditLogger` | `agent_os.audit` | [Tutorial 04 — Audit & Compliance](./04-audit-and-compliance.md) |
| `AgentIdentity` | `agent_os.identity` | [Tutorial 02 — Trust & Identity](./02-trust-and-identity.md) |
| `AgentMeshClient` | `AgentMeshClient` | [Tutorial 20 — TypeScript SDK](./20-typescript-sdk.md) |

> **Note:** The Rust `agentmesh` crate wraps all governance features into a single
> crate, while the Python implementation splits them across separate `agent_os.*`
> modules. Policy YAML files work identically across all SDKs.

---

## Source Files

| Component | Location |
|-----------|----------|
| Main exports | `agent-governance-rust/agentmesh/src/lib.rs` |
| Type definitions | `agent-governance-rust/agentmesh/src/types.rs` |
| `PolicyEngine` | `agent-governance-rust/agentmesh/src/policy.rs` |
| `TrustManager` | `agent-governance-rust/agentmesh/src/trust.rs` |
| `AuditLogger` | `agent-governance-rust/agentmesh/src/audit.rs` |
| `AgentIdentity` | `agent-governance-rust/agentmesh/src/identity.rs` |
| Unit tests | `agent-governance-rust/agentmesh/src/*.rs` |
| Package config | `agent-governance-rust/agentmesh/Cargo.toml` |

---

## Next Steps

- **Run the tests** to see the crate in action:
  ```bash
  cd agent-governance-rust
  cargo test --workspace
  ```
- **Load a YAML policy** from the repository's `policies/` directory and
  evaluate it against your agent
- **Enable trust persistence** with `persist_path` to retain trust scores across
  process restarts
- **Verify audit chains** in your CI/CD pipeline — call `audit.verify()` as a
  post-deployment check
- **Explore the TypeScript SDK** tutorial ([Tutorial 20](./20-typescript-sdk.md))
  for equivalent patterns in TypeScript
