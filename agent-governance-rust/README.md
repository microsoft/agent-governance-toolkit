# Agent Governance Rust Workspace

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
