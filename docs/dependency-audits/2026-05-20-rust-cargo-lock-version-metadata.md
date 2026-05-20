---
title: Rust Cargo Lockfile Version Metadata Refresh
last_reviewed: 2026-05-20
owner: rust-maintainers
---

# Rust Cargo Lockfile Version Metadata Refresh

## Which Dependencies Changed And Why

- `agent-governance-rust/Cargo.lock` updates the workspace package metadata for
  `agentmesh` and `agentmesh-mcp` from `3.6.0` to `3.7.0`.
- No third-party crate dependency was added, removed, or version-bumped by this
  lockfile change.
- The refresh keeps the lockfile aligned with the Rust workspace package version
  while the PR strengthens file-backed audit and federation store durability.

## Security Advisory Relevance

- No CVE, RustSec advisory, or dependency-review finding applies because this
  change does not alter third-party crate selections.
- The changed lockfile entries are first-party workspace crates only.

## Breaking Change Risk Assessment

- Risk is low: this is lockfile metadata for first-party workspace package
  versions, not a dependency graph change.
- Public Rust APIs and serialized JSON formats are unchanged by the lockfile
  refresh.
