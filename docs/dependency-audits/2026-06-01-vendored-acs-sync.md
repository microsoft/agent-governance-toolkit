# Dependency audit — vendored ACS (policy-engine) sync to eeaa83b

## Which dependencies changed and why

This PR vendors the Agent Control Specification (ACS) policy engine into AGT
under `policy-engine/` and syncs it to upstream ACS `eeaa83b`. ACS is
third-party MIT-licensed software (Copyright (c) 2026 responsibleai, see
`policy-engine/LICENSE.acs`); its dependency lockfiles are vendored verbatim
from upstream rather than resolved by AGT. The following lockfiles are brought
in or updated:

- `policy-engine/Cargo.lock`
  - The Rust workspace lock for the ACS core, SDK, and dispatchers (serde,
    serde_json, sha2, regex, thiserror, and the optional Cedar/OPA integration
    crates). Pinned as published upstream.
- `policy-engine/examples/coding_agent/app/Cargo.lock`
  - Lockfile for the self-contained `coding_agent` example application. Scoped
    entirely to that example; not part of any shipped AGT runtime.
- `policy-engine/sdk/node/package-lock.json`
  - The Node SDK lock (TypeScript build/test toolchain: typescript, the test
    runner, and `@napi-rs` bindings used by the native core). Pinned upstream.
- `policy-engine/benchmarks/agentdojo/requirements.txt`
  - Python requirements for the optional AgentDojo benchmark harness. Used only
    for local/benchmark runs, not for the shipped SDK.

## Security advisory relevance

- No advisory-driven upgrade is introduced by AGT here. The lockfiles are
  vendored at the exact versions published by upstream ACS `eeaa83b`.
- No CVE-specific remediation is claimed. Ongoing advisory tracking for these
  pinned versions follows upstream ACS and AGT's existing dependency scanning.
- The locked packages are standard serialization, hashing, regex, and
  policy/runtime dependencies; no ad hoc or unpinned additions were made.

## Breaking change risk assessment

- The vendored lockfiles are additive to AGT: they introduce the `policy-engine/`
  module's dependency graph but do not replace or alter the dependency graph of
  any previously shipped AGT package.
- Runtime impact is bounded to the vendored ACS module and its opt-in SDKs,
  examples, and benchmarks.
- Example- and benchmark-scoped lockfiles
  (`examples/coding_agent/app/Cargo.lock`, `benchmarks/agentdojo/requirements.txt`)
  carry no production runtime risk.
- Overall assessment: acceptable for this PR. The lockfiles are required for
  deterministic, reproducible builds and tests of the vendored policy engine and
  are pinned to a known upstream commit.
