---
title: Rust SDK AES 0.9.2 Lockfile Update
last_reviewed: 2026-08-27
owner: agt-maintainers
---

# Rust SDK AES 0.9.2 Lockfile Update

<!-- cspell:ignore getrandom -->

## Which Dependencies Changed And Why

- `agent-governance-rust/Cargo.lock` updates `aes` from `0.9.1` to `0.9.2`.
- The checksum changes to the crates.io checksum for `aes 0.9.2`.
- Cargo also normalizes the existing target-specific `tempfile` dependency
  edge from the locked `getrandom 0.4.2` entry to the already locked
  `getrandom 0.3.4` entry. No `getrandom` package version is added or removed.
- No manifest, SDK source, or other package version changes.

The existing `aes-gcm 0.11.0` constraint accepts the patched `aes` release,
so no source or public dependency constraint change is required.

## Security Advisory Relevance

- S360 work item `329434` and Component Governance alert `17536943` report
  `MVS-2022-374v-6mvc` for `aes 0.9.1` in the Rust SDK dependency graph.
- `cargo tree --locked -i aes` confirms that `aes-gcm 0.11.0` now resolves
  `aes 0.9.2` and that `aes 0.9.1` is absent.

## Breaking Change Risk Assessment

- Risk is low because `aes` receives a patch-level update under the existing
  `aes-gcm` dependency constraint.
- No encryption API, credential-vault source, public API, or feature selection
  changes.
- `cargo build --release --workspace --locked` and
  `cargo test --release --workspace --locked` pass.