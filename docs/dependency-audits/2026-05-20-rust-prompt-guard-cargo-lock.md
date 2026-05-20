---
title: Rust Prompt Guard Cargo Lockfile Metadata Refresh
last_reviewed: 2026-05-20
owner: rust-maintainers
---

# Rust Prompt Guard Cargo Lockfile Metadata Refresh

## Which Dependencies Changed And Why

- `agent-governance-rust/Cargo.lock` updates the first-party workspace package
  metadata for `agentmesh` and `agentmesh-mcp` from `3.6.0` to `3.7.0`.
- No third-party crate was added, removed, or version-bumped by this lockfile
  change.
- The refresh keeps the generated lockfile aligned with the Rust workspace
  package version while the PR adds opt-in prompt guard rule and threshold
  configuration.

## Security Advisory Relevance

- No CVE, RustSec advisory, or dependency-review finding applies because the
  third-party dependency graph is unchanged.
- The changed lockfile entries are first-party workspace crates only.

## Breaking Change Risk Assessment

- Risk is low for dependency behavior: the lockfile change is package metadata,
  not a dependency graph change.
- The prompt guard API change is documented separately in the changelog and
  preserves existing defaults for `DetectionConfig::default()` and YAML configs
  that omit the new fields.
