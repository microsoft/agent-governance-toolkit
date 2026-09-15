---
title: Hotfix Lock Version Metadata
last_reviewed: 2026-09-15
owner: agt-maintainers
---

# Hotfix Lock Version Metadata

## Which Dependencies Changed And Why

- `agent-governance-rust/Cargo.lock` updates the first-party `agentmesh` and `agentmesh-mcp` workspace package records from 5.0.0 to 5.0.1.
- `agent-governance-rust/Cargo.toml` aligns the internal path dependency on `agentmesh-mcp` with the 5.0.1 workspace version.
- Six npm lockfiles update only their first-party root package records from 5.0.0 to 5.0.1: the TypeScript SDK, AgentMesh MCP proxy and API, Agent OS Copilot and MCP Server extensions, and Mastra integration.
- No third-party dependency was added, removed, or version-bumped.

## Security Advisory Relevance

- No CVE, RustSec advisory, or npm advisory applies because third-party dependency selection is unchanged.
- The hotfix security changes are implemented in first-party Python middleware code; the lockfile edits keep repository-wide release metadata coherent.

## Breaking Change Risk Assessment

- Risk is low because the changes affect first-party workspace and package-root version metadata only.
- Public APIs, serialized formats, and resolved third-party dependency graphs are unchanged.
- `cargo metadata --locked` succeeds with Rust 1.89.0 after the refresh, and the npm lockfile diffs contain only root-version substitutions.