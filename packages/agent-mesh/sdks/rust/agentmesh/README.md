# AgentMesh Rust SDK

Rust SDK for the [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) — policy evaluation, trust scoring, hash-chain audit logging, and Ed25519 agent identity.

> **Public Preview** — APIs may change before 1.0.

## Install

```toml
[dependencies]
agentmesh = "0.1"
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

## License

See repository root [LICENSE](../../../../LICENSE).
