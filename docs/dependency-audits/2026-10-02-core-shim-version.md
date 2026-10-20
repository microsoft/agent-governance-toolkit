---
title: "Dependency audit: separate core shim version"
last_reviewed: 2026-10-02
owner: 1aifanatic
---

<!-- cspell:words aifanatic arraydeque fastrand httparse multiversion nohash simdutf verus prettyplease vstd -->

# Separate core shim version

## Which dependencies changed and why

The local `agent_control_specification_core` compatibility shim changes from
`0.3.1-beta.0` to `0.3.2-beta.0` to avoid the already published version of the
previous embedded engine. The standalone Rust SDK pins that new version exactly.
No dependency manifest ranges other than that exact shim pin change.

The lockfiles in `policy-engine/`, `agent-governance-rust/`, and
`policy-engine/examples/coding_agent/app/` change only the shim version.
The benchmark harness lockfile in
`benchmarks/prompt-injection/harness/agt-rules-baseline/` was stale: it still
recorded the pre-migration embedded engine and SDK. Cargo regenerated it against
the current manifests, adding the already declared upstream dependencies and
refreshing their transitive resolution. Its complete package-version changes are:

| Package | Previous locked versions | New locked versions |
| --- | --- | --- |
| `aes-gcm` | 0.11.0 | 0.11.1 |
| `agent-control-spec` | (absent) | 0.4.0-alpha.3 |
| `agent-hooks-sdk` | (absent) | 0.1.0-alpha.5 |
| `agent_control_specification` | 0.3.1-beta.0 | 0.4.0-beta.0 |
| `agent_control_specification_core` | 0.3.1-beta.0 | 0.3.2-beta.0 |
| `annotate-snippets` | (absent) | 0.12.16 |
| `anstyle` | (absent) | 1.0.14 |
| `arraydeque` | (absent) | 0.5.1 |
| `async-trait` | (absent) | 0.1.92 |
| `base64ct` | 1.8.3 | (removed) |
| `cedar-policy` | 4.12.0 | 4.13.0 |
| `cedar-policy-core` | 4.12.0 | 4.13.0 |
| `cedar-policy-formatter` | 4.12.0 | 4.13.0 |
| `chacha20` | (absent) | 0.10.2 |
| `const-oid` | 0.9.6 | 0.10.2 |
| `convert_case` | (absent) | 0.4.0 |
| `core_detect` | (absent) | 1.0.0 |
| `curve25519-dalek` | 4.1.3 | 5.0.0 |
| `der` | 0.7.10 | (removed) |
| `digest` | 0.10.7 | 0.10.7, 0.11.3 |
| `ed25519` | 2.2.3 | 3.0.0 |
| `ed25519-dalek` | 2.2.0 | 3.0.0 |
| `encoding_rs` | (absent) | 0.8.42 |
| `encoding_rs_io` | (absent) | 0.1.8 |
| `errno` | (absent) | 0.3.14 |
| `fastrand` | (absent) | 2.5.0 |
| `fiat-crypto` | 0.2.9 | 0.3.0 |
| `granit-parser` | (absent) | 1.3.0 |
| `http` | (absent) | 1.5.0 |
| `httparse` | (absent) | 1.10.1 |
| `linux-raw-sys` | (absent) | 0.12.1 |
| `multiversion_no_op` | (absent) | 1.0.0 |
| `nohash-hasher` | (absent) | 0.2.0 |
| `pkcs8` | 0.10.2 | (removed) |
| `ppv-lite86` | 0.2.21 | (removed) |
| `rand` | 0.8.6 | 0.10.2 |
| `rand_chacha` | 0.3.1 | (removed) |
| `rand_core` | 0.10.1, 0.6.4 | 0.10.1 |
| `regorus` | 0.11.0 | 0.12.0 |
| `rustix` | (absent) | 1.1.5 |
| `ryu-js` | (absent) | 1.0.3 |
| `serde-saphyr` | (absent) | 1.2.0 |
| `sha2` | 0.10.9 | 0.10.9, 0.11.0 |
| `signature` | 2.2.0 | 3.0.0 |
| `simdutf8` | (absent) | 0.1.5 |
| `spki` | 0.7.3 | (removed) |
| `tempfile` | (absent) | 3.27.0 |
| `ureq` | 2.12.1 | 3.4.2 |
| `ureq-proto` | (absent) | 0.6.4 |
| `utf8-zero` | (absent) | 0.8.1 |
| `verus_builtin` | (absent) | 0.0.0-2026-08-09-0044 |
| `verus_builtin_macros` | (absent) | 0.0.0-2026-08-23-0033 |
| `verus_prettyplease` | (absent) | 0.0.0-2026-08-09-0044 |
| `verus_state_machines_macros` | (absent) | 0.0.0-2026-08-02-0125 |
| `verus_syn` | (absent) | 0.0.0-2026-08-02-0125 |
| `vstd` | (absent) | 0.0.0-2026-08-23-0033 |
| `webpki-roots` | 0.26.11, 1.0.9 | 1.0.9 |

## Security advisory relevance

This change resolves a package version collision, not a specific security
advisory. It does not claim to be a vulnerability audit or to remediate an
advisory. Registry dependencies retain Cargo-generated checksums; no vendored
source is added or changed.

## Breaking change risk assessment

The shim source and its public API are unchanged. Consumers using the exact SDK
pin resolve the distinct shim package version. The main compatibility risk is
the benchmark harness's refreshed transitive graph; the larger lockfile change
is confined to that harness rather than the production workspace locks.

Validation completed before submission: locked Cargo metadata for all four
workspaces, core packaging, 31 core tests, policy-engine formatting and Clippy
with warnings denied, the policy-engine workspace suite with OPA 0.70.0, and
the standalone Rust release workspace suite. Compiled checks used WSL because
the native Windows MSVC linker was unavailable. The harness was checked with
locked Cargo metadata; its runtime benchmark was not executed.
