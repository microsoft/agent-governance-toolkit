---
title: Prompt Injection Benchmark AES Lockfile Refresh
last_reviewed: 2026-08-27
owner: agt-maintainers
---

# Prompt Injection Benchmark AES Lockfile Refresh

## Which Dependencies Changed And Why

- `benchmarks/prompt-injection/harness/agt-rules-baseline/Cargo.toml`
  aligns its exact `serde_json` pin from `1.0.150` to `1.0.151` with the
  current `agentmesh` workspace crate.
- The benchmark lockfile previously recorded `agentmesh` and `agentmesh-mcp`
  at `4.0.0`, although their path manifests are now `5.0.0`. Regenerating the
  lockfile updates those first-party entries to `5.0.0` and adds the current
  Agent Control Specification path dependencies.
- The security-relevant RustCrypto chain changes from `aes-gcm 0.10.3` and
  `aes 0.8.4` to `aes-gcm 0.11.0` and `aes 0.9.2`.
- Cargo also refreshes the transitive graph required by `agentmesh 5.0.0`.
  The main groups are Agent Control Specification manifest validation,
  Cedar policy evaluation, Unicode and URL handling, and the Rustls HTTP
  stack. In total, 37 existing package versions change, 70 package names are
  added, and the unused `opaque-debug` package is removed.

The wider lockfile change is required because Cargo cannot resolve the current
path manifests against the stale `agentmesh 4.0.0` metadata. This PR does not
change benchmark or runtime source code.

## Security Advisory Relevance

- S360 work item `256261` and Component Governance alert `16195383` report
  `MVS-2022-374v-6mvc` for `aes 0.8.4` in this benchmark lockfile.
- The refreshed graph resolves `aes 0.9.2`; `cargo tree --locked -i aes`
  confirms it is supplied by `aes-gcm 0.11.0` through `agentmesh 5.0.0`.
- The current Agent Control Specification dependency graph also resolves
  `ring 0.17.14` through Rustls. This PR does not claim to remediate the
  separate `ring` finding because `0.17.14` is the newest published release.

## Breaking Change Risk Assessment

- Risk is moderate because the stale benchmark lockfile crosses the
  first-party `agentmesh` 4.x to 5.x boundary and refreshes its transitive
  dependencies.
- Blast radius is limited to the non-published prompt-injection benchmark.
  No production manifest, SDK source, or public API changes.
- `cargo check --locked` and `cargo test --locked` pass with the regenerated
  graph. `cargo tree --locked -i aes` resolves only `aes 0.9.2`.
- `cargo fmt -- --check` reports pre-existing formatting drift in untouched
  `src/main.rs`; that unrelated cleanup is intentionally excluded.