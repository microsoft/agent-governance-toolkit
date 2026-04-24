# Agent Governance Rust SDK - Coding Agent Instructions

## Project Overview

`agent-governance-rust/` contains the Rust SDK workspace for Agent Governance Toolkit:
policy enforcement, trust, audit, identity, lifecycle, execution rings, and MCP security
surfaces for Rust applications.

## Build and Test Commands

```bash
cargo build --release --workspace
cargo test --release --workspace
```

## Key Paths

| Path | Purpose |
|------|---------|
| `Cargo.toml` | Workspace entry point |
| `Cargo.lock` | Shared dependency lockfile |
| `agentmesh/` | Full Rust governance SDK crate |
| `agentmesh-mcp/` | Standalone MCP governance and security crate |
| `README.md` | Workspace overview and crate routing |

## Coding Conventions

- Keep the workspace flat and Cargo-native: each publishable crate lives directly under the workspace root.
- Preserve the separation between the full `agentmesh` crate and the narrower `agentmesh-mcp` crate unless maintainers explicitly decide to merge them.
- Prefer shared workspace dependency/version management in the workspace `Cargo.toml`.
- Update README and docs when crate locations or public install guidance change.

## Boundaries

- Do not weaken governance checks, signing guarantees, or credential redaction behavior.
- Do not add unpublished or obscure dependencies without a clear OSS need.
- Keep crates.io metadata aligned with the repository and documentation.

## Validation

- Run `cargo test --release --workspace` after changes.
- Re-check any docs or pipeline paths that reference the workspace location.
