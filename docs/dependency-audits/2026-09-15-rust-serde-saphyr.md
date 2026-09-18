---
title: Rust YAML parser migration to serde-saphyr
last_reviewed: 2026-09-18
owner: agt-maintainers
---

# Rust YAML parser migration

## Which dependencies changed and why

AGT's Rust workspace and policy-engine core replace their direct `serde_yaml`
dependency with `serde-saphyr = "=1.2.0"`. The parser deserializes typed
configuration without exposing a YAML DOM as the policy-context API.
The lockfiles select `granit-parser` 1.2.1 and retain `encoding_rs` 0.8.35.
Granit 1.2.1 was published September 11, 2026 at 09:25 UTC, more than seven
days before this update. It fixes plain values following a colon and tab.
It also accepts space-then-tab indentation, tabs after sequence dashes and
reserved directives such as `%FOO bar`, which libyaml rejected. These
relaxations are intentional and covered by value and authorization regressions.
Tab-first indentation remains invalid. AGT retains its exact direct-dependency
convention; the transitive parser is selected by the lockfiles, not pinned
by the `serde-saphyr` requirement.

The parser is registered on crates.io, maintained at
`https://github.com/bourumir-wyngs/serde-saphyr`, and licensed MIT OR
Apache-2.0. Version 1.2.0 was published August 30, 2026 and requires Rust 1.89.
The dependency-age check passes. The hosted OSSF Scorecard service has no
entry for this project.

The repository's dependency-confusion checker recognizes registered packages
through `REGISTERED_CARGO_PACKAGES`. This change adds only the verified
`serde-saphyr` name to that list. Tests confirm that the registered name passes
and an unregistered name still fails in dependency, development and build
sections. Detection logic and the dependency-age requirement are unchanged.

## Security advisory relevance

No known advisory addressed. This is a parser and dependency migration, not
a claim that the old parser's use of unsafe code demonstrates an exploitable
vulnerability. The tests cover malformed input, alias expansion, byte/depth
limits and error propagation.

The registry graph still includes `serde_yaml` and `unsafe-libyaml` through
`agent-control-spec 0.4.0-alpha.3`. The companion change is
`https://github.com/responsibleai/agent-control-spec/pull/75`. The tested
combined code removes those packages, and the renamed `yaml_serde` and
`libyaml-rs` implementations, from the standalone Rust workspace's default
and all-features graphs. The policy-engine workspace's all-features graph
now includes the core shim's optional `rego` forwarding. With the companion
engine, that graph still contains Regorus's `yaml_serde` and `libyaml-rs`
dependencies. The optional backend and its YAML builtins remain enabled.

## Breaking change risk assessment

This targets the pending Rust 5.0 major release. Policy values and custom
protocol callbacks move to JSON-compatible types, and YAML error payloads
change to `YamlError`. Non-string keys, non-finite numbers, duplicate keys
and unsupported tags are errors. Legacy numeric string forms retain their
types, and numeric fields reject strings rather than coercing them.
Typed strings also reject unquoted numbers, booleans and null, including
`version: 1`; quote those values and mapping keys. Non-specific `!` tags
are rejected consistently. The core shim and agentmesh share one
scalar-normalization implementation, with separate bounded decoders.
The policy-engine Rust compiler floor rises from 1.85 to 1.89.

Validation includes authorization and bounded-parser regressions, Rust 1.89
checking, and workspace tests with the companion ACS code. Python validation
also checks duplicate-key diagnostics and schema paths for invalid limits. The
[migration guide](../../agent-governance-rust/YAML-MIGRATION.md) describes the
API changes and the required upstream, core, host SDK and Rust package
release order. No unpublished version or permanent local patch is committed.
