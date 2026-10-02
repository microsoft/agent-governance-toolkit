---
title: Policy Engine SHA1 0.10.7 Lockfile Update
last_reviewed: 2026-08-27
owner: agt-maintainers
---

# Policy Engine SHA1 0.10.7 Lockfile Update

## Which Dependencies Changed And Why

- `policy-engine/Cargo.lock` updates `sha1` from `0.10.6` to `0.10.7`.
- The checksum changes to the crates.io checksum for `sha1 0.10.7`.
- No manifest, source file, or other dependency version changes.

The patch keeps the policy-engine lockfile on the latest compatible `sha1`
release accepted by the existing transitive dependency constraints.

## Security Advisory Relevance

- S360 work item `246401` and Component Governance alert `16259049` report
  `MVS-2022-374v-6mvc` for `sha1 0.10.6` in the policy-engine dependency
  graph.
- This update removes `sha1 0.10.6` from the committed lockfile and resolves
  `sha1 0.10.7` instead.

## Breaking Change Risk Assessment

- Risk is low because this is a patch-level lockfile update within the
  existing `sha1 0.10.x` constraint.
- No public API, policy behavior, feature selection, or manifest constraint
  changes.
- `cargo check --workspace --locked`, `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets --locked -- -D warnings`, and
  `cargo test --workspace --locked` pass.