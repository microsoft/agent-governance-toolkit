# Agent Governance Rust Workspace

[![CI](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](../LICENSE)
[![agentmesh crate](https://img.shields.io/crates/v/agentmesh.svg)](https://crates.io/crates/agentmesh)
[![agentmesh downloads](https://img.shields.io/crates/d/agentmesh.svg)](https://crates.io/crates/agentmesh)
[![agentmesh-mcp crate](https://img.shields.io/crates/v/agentmesh-mcp.svg)](https://crates.io/crates/agentmesh-mcp)
[![agentmesh-mcp downloads](https://img.shields.io/crates/d/agentmesh-mcp.svg)](https://crates.io/crates/agentmesh-mcp)

Rust workspace for the [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit).

This top-level language home contains the Rust publishable crates:

- [`agentmesh/`](./agentmesh/) — the full Rust governance crate
- [`agentmesh-mcp/`](./agentmesh-mcp/) — the standalone MCP governance and security crate

## Add to Your Project

```bash
cargo add agentmesh
```

```rust
use agentmesh::AgentMeshClient;

let client = AgentMeshClient::new("my-agent")?;
let result = client.execute_with_governance("data.read", None);
println!("allowed: {}", result.allowed);
# Ok::<(), Box<dyn std::error::Error>>(())
```

See the full API docs at [docs.rs/agentmesh](https://docs.rs/agentmesh).

## Workspace Commands

```bash
cargo build --release --workspace
cargo test --release --workspace
```

## Contributing: Build, Test, and Lint

Install Rust 1.70 or newer, then run these checks from `agent-governance-rust/`:

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace
```

## Examples

Run the quickstart example to create a client, evaluate allowed and denied actions, and print the results:

```bash
cargo run -p agentmesh --example quickstart
```

## Crates

### `agentmesh`

Use `agentmesh` when you need the broader governance stack:
policy evaluation, trust scoring, audit logging, Ed25519 identity, execution rings,
lifecycle management, governance/compliance helpers, reward primitives, and
control-plane utilities such as kill-switch and SLO helpers.

### `agentmesh-mcp`

Use `agentmesh-mcp` when you only need the MCP-specific surface:
message signing, session authentication, credential redaction, rate limiting,
gateway decisions, and related MCP security helpers.

`agentmesh-mcp` is the **canonical home** for MCP types. The `agentmesh::mcp`
module is a verbatim copy that is now `#[deprecated]` and scheduled for removal
in the next major release. New code should import from `agentmesh_mcp::mcp::...`
directly — see
[#2013](https://github.com/microsoft/agent-governance-toolkit/issues/2013)
and
[#2088](https://github.com/microsoft/agent-governance-toolkit/issues/2088).

## MCP gateway migration note

The Rust MCP gateway now fails closed unless requests are processed through a
configured `McpSessionAuthenticator`. If you previously called
`McpGateway::process_request`, migrate to:

1. Create or inject an `McpSessionAuthenticator`
2. Attach it with `gateway.with_session_authenticator(authenticator)`
3. Call `gateway.process_authenticated_request(&request, session_token)`

The gateway no longer trusts caller-asserted agent identity for rate limiting or
audit decisions without a verified session token.
