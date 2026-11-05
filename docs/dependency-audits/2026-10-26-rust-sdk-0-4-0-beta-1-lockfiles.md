---
title: Rust SDK 0.4.0-beta.1 lockfile refresh
last_reviewed: 2026-10-26
owner: MohammadHaroonAbuomar
---
# Rust SDK 0.4.0-beta.1 lockfile refresh

## Which dependencies changed and why

- `agent_control_specification` (the in-repo Rust SDK crate): 0.4.0-beta.0 -> 0.4.0-beta.1 in
  `policy-engine/Cargo.lock`, `agent-governance-rust/Cargo.lock` and
  `policy-engine/examples/coding_agent/app/Cargo.lock`. The crate is a path dependency; the
  version bump records the breaking change in #4416 (removal of `AgentControl::new`).
- `benchmarks/prompt-injection/harness/agt-rules-baseline/Cargo.lock`: refreshed so it resolves
  against the current tree. Besides the SDK bump it picks up `agent-control-spec` 0.4.0-alpha.4
  (already pinned by the workspace since #4224) with its `serde-saphyr`, `serde_path_to_error`
  and `tempfile` dependencies, moves `thiserror` 2.0.19 -> 2.0.21, and drops `serde_yaml` and
  `unsafe-libyaml`, which no crate in the tree uses any more.
- Reason: the lockfiles must agree with the bumped crate version and with the pins the workspace
  already carries. No new third-party dependency is introduced by this change.

## Security advisory relevance

- No known advisory addressed. `serde_yaml` and `unsafe-libyaml` are unmaintained upstream; removing
  them from the benchmark lockfile reduces the audit surface.

## Verification

- `cargo build --locked` succeeds for the policy-engine workspace, `agent-governance-rust`
  (`-p agentmesh`), the standalone `coding_agent` example and the benchmark harness.
- `cargo test --locked -p agent_control_specification` with the CI feature sets passes (see the PR body).

## Breaking change risk assessment

- The only semver-relevant change is the in-repo SDK crate moving to 0.4.0-beta.1, which is the
  intentional breaking change of #4416 and is recorded in BREAKING_CHANGES.md with migration steps.
- The benchmark harness refresh drops two unused crates and advances `thiserror` by two patch
  releases; no API the harness uses changed, and it builds with `--locked`.
- Validation: `cargo build --locked` and the CI test matrix on the branch, listed in the PR body.
