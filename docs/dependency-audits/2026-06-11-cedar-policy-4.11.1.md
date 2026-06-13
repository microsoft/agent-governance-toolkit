# Dependency Audit: cedar-policy 4.11.0 to 4.11.1

**Date:** 2026-06-11
**PR:** #2961
**Lockfiles changed:** `agent-governance-rust/Cargo.lock`

## Dependencies changed

| Package | From | To | Reason |
|---|---|---|---|
| `cedar-policy` | 4.11.0 | 4.11.1 | Routine patch bump by Dependabot |

## Security advisory relevance

No CVEs or RustSec advisories associated with this change. Patch release within the same minor series of the Cedar policy engine.

## Breaking change risk

**Risk: low.** Patch bump within the same minor. No public API changes expected; semver-compatible bug-fix release.

## Rollback plan

Revert `agent-governance-rust/Cargo.lock` (and the matching `Cargo.toml` requirement) to the prior version and re-run `cargo build` in `agent-governance-rust`.
