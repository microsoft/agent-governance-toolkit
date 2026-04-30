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

## Workspace Commands

```bash
cargo build --release --workspace
cargo test --release --workspace
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

## MCP gateway migration note

The Rust MCP gateway now fails closed unless requests are processed through a
configured `McpSessionAuthenticator`. If you previously called
`McpGateway::process_request`, migrate to:

1. Create or inject an `McpSessionAuthenticator`
2. Attach it with `gateway.with_session_authenticator(authenticator)`
3. Call `gateway.process_authenticated_request(&request, session_token)`

The gateway no longer trusts caller-asserted agent identity for rate limiting or
audit decisions without a verified session token.
