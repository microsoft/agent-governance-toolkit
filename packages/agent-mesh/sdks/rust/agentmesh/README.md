# AgentMesh Rust SDK

Rust SDK for the [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) — policy evaluation, trust scoring, hash-chain audit logging, and Ed25519 agent identity.

> **Public Preview** — APIs may change before 1.0.

## Install

### Full SDK

```bash
cargo add agentmesh
```

```toml
[dependencies]
agentmesh = "3.0.2"
```

### Standalone MCP Package

If you only need the MCP governance/security surface, install the standalone crate:

```bash
cargo add agentmesh-mcp
```

```toml
[dependencies]
agentmesh-mcp = "3.0.2"
```

## Quick Start

```rust
use agentmesh::{AgentMeshClient, ClientOptions, PolicyDecision};

fn main() {
    // Create a client with a policy
    let opts = ClientOptions {
        policy_yaml: Some(r#"
version: "1.0"
agent: my-agent
policies:
  - name: capability-gate
    type: capability
    allowed_actions: ["data.read", "data.write"]
    denied_actions: ["shell:*"]
  - name: deploy-approval
    type: approval
    actions: ["deploy.*"]
    min_approvals: 2
"#.to_string()),
        ..Default::default()
    };

    let client = AgentMeshClient::with_options("my-agent", opts)
        .expect("failed to create client");

    // Run an action through the governance pipeline
    let result = client.execute_with_governance("data.read", None);
    println!("Decision: {:?}, Allowed: {}", result.decision, result.allowed);

    // Shell commands are denied
    let result = client.execute_with_governance("shell:rm", None);
    assert!(!result.allowed);

    // Audit chain is verifiable
    assert!(client.audit.verify());
}
```

## MCP-Only Quick Start

```rust
use agentmesh_mcp::{
    CredentialRedactor, InMemoryNonceStore, McpMessageSigner, SystemClock,
    SystemNonceGenerator,
};
use std::sync::Arc;
use std::time::Duration;

let signer = McpMessageSigner::new(
    b"top-secret-signing-key".to_vec(),
    Arc::new(SystemClock),
    Arc::new(SystemNonceGenerator),
    Arc::new(InMemoryNonceStore::default()),
    Duration::from_secs(300),
    Duration::from_secs(600),
)?;

let message = signer.sign("hello from mcp")?;
signer.verify(&message)?;

let redactor = CredentialRedactor::new()?;
let result = redactor.redact("Authorization: Bearer super-secret-token");
assert!(result.sanitized.contains("[REDACTED_BEARER_TOKEN]"));
# Ok::<(), agentmesh_mcp::McpError>(())
```

## API Overview

### Client (`lib.rs`)

Unified governance client combining all modules.

| Function / Method | Description |
|---|---|
| `AgentMeshClient::new(agent_id)` | Create a client with defaults |
| `AgentMeshClient::with_options(agent_id, opts)` | Create a client with custom config |
| `client.execute_with_governance(action, context)` | Run action through governance pipeline |

### Policy (`policy.rs`)

YAML-based policy engine with four-way decisions (allow / deny / requires-approval / rate-limit).

| Function / Method | Description |
|---|---|
| `PolicyEngine::new()` | Create an empty policy engine |
| `engine.load_from_yaml(yaml)` | Load rules from a YAML string |
| `engine.load_from_file(path)` | Load rules from a YAML file |
| `engine.evaluate(action, context)` | Evaluate an action against loaded policy |

### Trust (`trust.rs`)

Integer trust scoring (0–1000) across five tiers with optional JSON persistence.

| Function / Method | Description |
|---|---|
| `TrustManager::new(config)` | Create a trust manager |
| `TrustManager::with_defaults()` | Create with default config |
| `manager.get_trust_score(agent_id)` | Get current trust score |
| `manager.is_trusted(agent_id)` | Check against threshold |
| `manager.record_success(agent_id)` | Increase trust after success |
| `manager.record_failure(agent_id)` | Decrease trust after failure |

Trust tiers:

| Tier | Score Range |
|------|------------|
| VerifiedPartner | 900–1000 |
| Trusted | 700–899 |
| Standard | 500–699 |
| Probationary | 300–499 |
| Untrusted | 0–299 |

### Audit (`audit.rs`)

SHA-256 hash-chained audit log for tamper detection.

| Function / Method | Description |
|---|---|
| `AuditLogger::new()` | Create an audit logger |
| `logger.log(agent_id, action, decision)` | Append an audit entry |
| `logger.verify()` | Verify chain integrity |
| `logger.get_entries(filter)` | Query entries by filter |

### Identity (`identity.rs`)

Ed25519-based agent identity with DID support.

| Function / Method | Description |
|---|---|
| `AgentIdentity::generate(agent_id, capabilities)` | Create a new identity |
| `identity.sign(data)` | Sign data with private key |
| `identity.verify(data, sig)` | Verify a signature |
| `identity.to_json()` | Serialise public identity |
| `AgentIdentity::from_json(json)` | Deserialise public identity |

## Policy YAML Format

```yaml
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

  - name: deploy-approval
    type: approval
    actions:
      - "deploy.*"
    min_approvals: 2

  - name: api-rate-limit
    type: rate_limit
    actions:
      - "api.call"
    max_calls: 100
    window: "60s"
```

### Execution Rings (`rings.rs`)

Four-level privilege model inspired by hardware protection rings.

| Function / Method | Description |
|---|---|
| `RingEnforcer::new()` | Create a new enforcer with no assignments |
| `enforcer.assign(agent_id, ring)` | Assign an agent to a ring |
| `enforcer.get_ring(agent_id)` | Get assigned ring (if any) |
| `enforcer.check_access(agent_id, action)` | Check if action is permitted |
| `enforcer.set_ring_permissions(ring, actions)` | Configure allowed actions for a ring |

Ring levels:

| Ring | Level | Access |
|------|-------|--------|
| `Admin` | 0 | All actions allowed |
| `Standard` | 1 | Configurable actions |
| `Restricted` | 2 | Configurable actions |
| `Sandboxed` | 3 | All actions denied |

```rust
use agentmesh::{RingEnforcer, Ring};

let mut enforcer = RingEnforcer::new();
enforcer.set_ring_permissions(Ring::Standard, vec!["data.read".into(), "data.write".into()]);
enforcer.assign("my-agent", Ring::Standard);

assert!(enforcer.check_access("my-agent", "data.read"));
assert!(!enforcer.check_access("my-agent", "shell:rm"));
```

### Agent Lifecycle (`lifecycle.rs`)

Eight-state lifecycle model tracking an agent from provisioning through decommissioning.

| Function / Method | Description |
|---|---|
| `LifecycleManager::new(agent_id)` | Create a new manager (starts in `Provisioning`) |
| `manager.state()` | Get current lifecycle state |
| `manager.events()` | Get recorded transition events |
| `manager.transition(to, reason, initiated_by)` | Transition to a new state |
| `manager.can_transition(to)` | Check if a transition is valid |
| `manager.activate(reason)` | Convenience: transition to `Active` |
| `manager.suspend(reason)` | Convenience: transition to `Suspended` |
| `manager.quarantine(reason)` | Convenience: transition to `Quarantined` |
| `manager.decommission(reason)` | Convenience: transition to `Decommissioning` |

Lifecycle states: `Provisioning` -> `Active` <-> `Suspended` / `Rotating` / `Degraded` -> `Quarantined` -> `Decommissioning` -> `Decommissioned`

```rust
use agentmesh::{LifecycleManager, LifecycleState};

let mut mgr = LifecycleManager::new("my-agent");
mgr.activate("initial boot").unwrap();
assert_eq!(mgr.state(), LifecycleState::Active);

mgr.suspend("maintenance window").unwrap();
assert_eq!(mgr.state(), LifecycleState::Suspended);

mgr.activate("maintenance complete").unwrap();
assert_eq!(mgr.events().len(), 3);
```

## License

See repository root [LICENSE](../../../../LICENSE).
