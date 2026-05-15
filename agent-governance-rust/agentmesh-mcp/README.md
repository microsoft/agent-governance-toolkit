# AgentMesh MCP Rust crate

Standalone Rust crate for the [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) MCP governance/security surface — response scanning, message signing, session authentication, credential redaction, rate limiting, tool metadata scanning, gateway decisions, and categorical metrics.

> **Public Preview** — APIs may change before 1.0.

## Install

```toml
[dependencies]
agentmesh-mcp = "3.0.2"
```

## Quick Start

```rust
use agentmesh_mcp::{
    CredentialRedactor, InMemoryNonceStore, McpMessageSigner, McpSignedMessage,
    SystemClock, SystemNonceGenerator,
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

let signed: McpSignedMessage = signer.sign("hello from mcp")?;
signer.verify(&signed)?;

let redactor = CredentialRedactor::new();
let result = redactor.redact("Authorization: Bearer super-secret-token");
assert!(result.sanitized.contains("[REDACTED_BEARER_TOKEN]"));
# Ok::<(), agentmesh_mcp::McpError>(())
```

## Authenticated MCP Gateway

`McpGateway` no longer accepts caller-asserted agent identity on the
unauthenticated request path. Configure a session authenticator and call
`process_authenticated_request`.

```rust
use agentmesh_mcp::{
    CredentialRedactor, DeterministicNonceGenerator, FixedClock, InMemoryAuditSink,
    InMemoryRateLimitStore, InMemorySessionStore, McpGateway, McpGatewayConfig,
    McpGatewayRequest, McpMetricsCollector, McpResponseScanner,
    McpSessionAuthenticator, McpSlidingRateLimiter, SystemClock,
};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

let redactor = CredentialRedactor::new();
let audit = Arc::new(InMemoryAuditSink::new(redactor.clone()));
let metrics = McpMetricsCollector::default();
let scanner = McpResponseScanner::new(
    redactor,
    audit.clone(),
    metrics.clone(),
    Arc::new(SystemClock),
)?;
let limiter = McpSlidingRateLimiter::new(
    10,
    Duration::from_secs(60),
    Arc::new(SystemClock),
    Arc::new(InMemoryRateLimitStore::default()),
)?;
let session_authenticator = McpSessionAuthenticator::new(
    b"0123456789abcdef0123456789abcdef".to_vec(),
    Arc::new(FixedClock::new(SystemTime::UNIX_EPOCH)),
    Arc::new(DeterministicNonceGenerator::from_values(vec!["session-1".into()])),
    Arc::new(InMemorySessionStore::default()),
    Duration::from_secs(300),
    4,
)?;
let issued = session_authenticator.issue_session("did:agentmesh:gateway")?;
let gateway = McpGateway::new(
    McpGatewayConfig::default(),
    scanner,
    limiter,
    audit,
    metrics,
    Arc::new(SystemClock),
)
.with_session_authenticator(session_authenticator);

let decision = gateway.process_authenticated_request(
    &McpGatewayRequest {
        agent_id: "did:agentmesh:gateway".into(),
        tool_name: "db.read".into(),
        payload: serde_json::json!({"query": "select 1"}),
    },
    &issued.token,
)?;
assert!(decision.allowed);
# Ok::<(), agentmesh_mcp::McpError>(())
```

### Migration note

If you were using `McpGateway::process_request`, migrate to
`process_authenticated_request` and supply a session token from
`McpSessionAuthenticator`. Requests without verified session identity now fail
closed.

## Also Available in the Full SDK

If you also need trust, identity, policy, and audit primitives, install the full crate instead:

```bash
cargo add agentmesh
```

## License

See repository root [LICENSE](../../LICENSE).
