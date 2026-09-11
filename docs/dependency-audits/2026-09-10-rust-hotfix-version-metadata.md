---
title: Rust Hotfix Version Metadata
last_reviewed: 2026-09-10
owner: rust-maintainers
---

# Rust Hotfix Version Metadata

## Which Dependencies Changed And Why

- `agent-governance-rust/Cargo.lock` updates the first-party `agentmesh` and `agentmesh-mcp` workspace package records from 5.0.0 to 5.0.1.
- `agent-governance-rust/Cargo.toml` aligns the internal path dependency on `agentmesh-mcp` with the 5.0.1 workspace version.
- No third-party crate was added, removed, or version-bumped.

## Security Advisory Relevance

- No CVE or RustSec advisory applies because third-party dependency selection is unchanged.
- The hotfix security changes are implemented in first-party Python middleware code; the Rust edits keep repository-wide release metadata coherent.

## Breaking Change Risk Assessment

- Risk is low because the changes affect first-party workspace version metadata only.
- Public Rust APIs, serialized formats, and the resolved third-party dependency graph are unchanged.
- `cargo metadata --locked` succeeds with Rust 1.89.0 after the refresh.