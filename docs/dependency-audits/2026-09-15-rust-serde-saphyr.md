---
title: Rust YAML parser migration to serde-saphyr
last_reviewed: 2026-09-15
owner: agt-maintainers
---

# Rust YAML parser migration

## Which dependencies changed and why

AGT's Rust workspace and policy-engine core replace their direct `serde_yaml`
dependency with `serde-saphyr = "=1.2.0"`. The parser deserializes typed
configuration without exposing a YAML DOM as the policy-context API.
The lockfiles retain `granit-parser` 1.2.0 and `encoding_rs` 0.8.35 rather
than adopting releases less than seven days old.

The parser is registered on crates.io, maintained at
`https://github.com/bourumir-wyngs/serde-saphyr`, and licensed MIT OR
Apache-2.0. Version 1.2.0 was published August 30, 2026 and requires Rust 1.89.
The dependency-age check passes. The hosted OSSF Scorecard service has no
entry for this project.

The repository's dependency-confusion checker does not include this
registered package in its static list. That check remains a release/review
gate. This change does not alter the scanner or bypass its decision.

## Security advisory relevance

No known advisory addressed. This is a parser and dependency migration, not
a claim that the old parser's use of unsafe code demonstrates an exploitable
vulnerability. The tests cover malformed input, alias expansion, byte/depth
limits and error propagation.

The registry graph still includes `serde_yaml` and `unsafe-libyaml` through
`agent-control-spec 0.4.0-alpha.3`. The companion change is
`https://github.com/responsibleai/agent-control-spec/pull/75`. The tested
combined code removes those packages, and the renamed `yaml_serde` and
`libyaml-rs` implementations, from AGT's default and all-features graphs.
Optional Regorus YAML configurations are outside this consumer scope.

## Breaking change risk assessment

This targets the pending Rust 5.0 major release. Policy values and custom
protocol callbacks move to JSON-compatible types, and YAML error payloads
change to `YamlError`. Non-string keys, non-finite numbers, duplicate keys
and unsupported tags are errors. Numeric-looking strings must be quoted.
The policy-engine Rust compiler floor rises from 1.85 to 1.89.

Validation includes 561 optimized workspace tests, 21 core tests, Rust 1.89
checking, and 561 workspace tests with the companion ACS code. The
[migration guide](../../agent-governance-rust/YAML-MIGRATION.md) describes the
API changes and the required upstream, core, host SDK and Rust package
release order. No unpublished version or permanent local patch is committed.
