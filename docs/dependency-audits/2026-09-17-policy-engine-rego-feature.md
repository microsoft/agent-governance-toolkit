---
title: "Dependency audit: optional core Rego feature"
last_reviewed: 2026-09-17
owner: 1aifanatic
---

<!-- cspell:words aifanatic bstr chrono foldhash globset micromap outref vsimd -->

# Optional core Rego feature

## Which dependencies changed and why

PR #4014 forwards the `rego` and `streaming` features from the core compatibility
shim to the pinned `agent-control-spec` 0.4.0-alpha.3 dependency. Enabling `rego`
adds the upstream in-process `regorus` 0.11.0 engine. Its dependency tree includes
`jsonschema` 0.47.0 and `fluent-uri` 0.4.1. The `streaming` feature adds no
dependencies. Existing package versions remain in the workspace lockfile.

The 29 new package/version entries in `policy-engine/Cargo.lock` are

| Package | Version |
| --- | --- |
| allocator-api2 | 0.2.21 |
| borrow-or-share | 0.2.4 |
| bstr | 1.12.1 |
| chrono-tz | 0.10.4 |
| cobs | 0.3.0 |
| email_address | 0.2.9 |
| embedded-io | 0.4.0, 0.6.1 |
| fancy-regex | 0.18.0 |
| fluent-uri | 0.4.1 |
| foldhash | 0.2.0 |
| fraction | 0.15.4 |
| globset | 0.4.19 |
| jsonschema | 0.47.0 |
| jsonschema-regex | 0.47.0 |
| lru | 0.18.4 |
| micromap | 0.3.0 |
| msvc_spectre_libs | 0.1.3 |
| num-bigint | 0.5.1 |
| outref | 0.5.2 |
| phf | 0.12.1 |
| phf_shared | 0.12.1 |
| postcard | 1.1.3 |
| referencing | 0.47.0 |
| regorus | 0.11.0 |
| spin | 0.12.3 |
| unicode-general-category | 1.1.0 |
| uuid-simd | 0.8.0 |
| vsimd | 0.8.0 |

`borrow-or-share` 0.2.4 is licensed MIT-0, the MIT license with the attribution
paragraph removed, as documented by SPDX at `https://spdx.org/licenses/MIT-0.html`.
The dependency-review exception is scoped to `pkg:cargo/borrow-or-share`, alongside
the existing `futures-timer` exception. The general license allow list is unchanged.

## Security advisory relevance

The initial feature resolution selected `lru` 0.18.0 through the Regorus cache
feature. Review identified RUSTSEC-2026-0253, a potential use-after-free in
`LruCache::pop()`. The lockfile now selects 0.18.4, above the advisory's patched
minimum of 0.18.2. Advisory source is
`https://rustsec.org/advisories/RUSTSEC-2026-0253.html`.
The targeted update changed only that entry's version and checksum.

## Breaking change risk assessment

Both forwarded features are opt-in. The default feature set and the legacy host's
explicit OPA dispatcher are unchanged. Rego and streaming APIs are exposed through
their modules, not additional root-level type exports. No existing dependency
version is removed or upgraded relative to the PR base.

Validation with the updated lockfile passed all 10 core tests with
`--no-default-features --features rego,streaming`, plus Clippy with `--all-targets`
and `-D warnings`. CI now runs both commands with `--locked` so the optional tests
execute and dependency resolution uses the reviewed versions.
