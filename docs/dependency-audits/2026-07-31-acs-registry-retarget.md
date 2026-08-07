---
title: Policy engine retargets onto the published agent-control-spec crate
last_reviewed: 2026-07-31
owner: liamcrumm
---

# Policy engine retargets onto the published agent-control-spec crate

## Which Dependencies Changed And Why

AGT carried its own copy of the policy engine under `policy-engine/`. That
engine was extracted upstream, rebased onto the agent-hooks control contract,
and published, so this change depends on the registry build instead of the
fork. Three lockfiles move: `policy-engine/Cargo.lock`,
`agent-governance-rust/Cargo.lock`, and the standalone
`policy-engine/examples/coding_agent/app/Cargo.lock`.

Two first-party crates are added, both exact-pinned:

| Crate | Version | Why |
| --- | --- | --- |
| `agent-control-spec` | 0.4.0-alpha.1 | The extracted engine, replacing `policy-engine/core` |
| `agent-hooks-sdk` | 0.1.0-alpha.3 | The control contract that defines the verdicts, interception points, and reserved reason namespaces |

Both are published on crates.io. Verified against the registry API at the
versions above rather than assumed, which is also why they are added to
`REGISTERED_CARGO_PACKAGES` in `scripts/check_dependency_confusion.py`.

`agent-hooks-sdk` is pinned one alpha behind the newest release. `agent-control-spec`
requires only `^0.1.0-alpha.3`, and 0.1.0-alpha.4 was published two days ago, inside
the seven day cooling off window. The 0.1.0-alpha.3 release is fourteen days old, so
it satisfies both the dependency and the rule. The workspace builds and its 108 tests
pass against it.

The third-party movement is net negative in `agent-governance-rust` and close
to flat in `policy-engine`.

**`policy-engine/Cargo.lock`** adds seven third-party crates and drops
twenty-four. The additions are `tempfile` 3.27.0 with its `rustix` 1.1.4,
`errno` 0.3.14, and `linux-raw-sys` 0.12.1 support, plus `ryu-js` 1.0.3,
`const-oid` 0.10.2, and `hybrid-array` 0.4.13 arriving through the engine. The
removals are the `criterion` benchmark cluster (`criterion`, `criterion-plot`,
`plotters*`, `rayon*`, `crossbeam-*`, `ciborium*`, `clap*`, `half`, `cast`,
`anes`, `anstyle`, `oorandom`, `tinytemplate`, `crunchy`, `zmij`), which left
with the vendored engine's benchmarks.

**`agent-governance-rust/Cargo.lock`** adds `agent-control-spec`,
`agent-hooks-sdk`, `async-trait`, and `ryu-js`, and drops fourteen: the
first-party `agent_control_specification_core` plus the manifest-validation
cluster that came with it (`jsonschema`, `fancy-regex`, `fraction`, `num*`,
`nom`, `bytecount`, `ahash`, `iso8601`, `uuid`). That workspace no longer
validates manifests directly, so it no longer carries the validator.

`tempfile` is pinned to `=3.27.0` rather than a newer release specifically to
match the pin `agent-governance-rust` already held. The two workspaces share a
path dependency, and disagreeing exact pins fail resolution outright.

## Security Advisory Relevance

No CVE or RustSec advisory is addressed by this change, and none of the added
crates is pulled in to remediate one.

The dependency surface shrinks rather than grows. The engine that previously
lived in-tree is now consumed as a pinned release, so its source is fixed at a
known version instead of moving with every edit to this repository.

One security property did not survive extraction, and it is recorded rather
than papered over. The upstream crate dropped the `url_sourced` provenance gate
that withheld host environment credentials from a manifest fetched over the
network, while still supporting URL `extends`. This change therefore puts the
bundled annotator dispatcher, which resolves `api_key_env` against the host
environment, behind an off-by-default `bundled-dispatchers` feature.

That gate is narrower than it sounds, and the limit is documented in
`policy-engine/docs/acs-retarget.md`. A manifest supplies the Rego query, which
reaches `opa eval` as an arbitrary expression, and Rego reads the inherited
environment through `opa.runtime().env`. So a manifest is trusted input to the
policy plane. That predates this change, since the previous embedded engine
spawned `opa` the same way, but it means the annotator gate must not be read as
a credential boundary.

## Breaking Change Risk Assessment

High, and deliberate. The contract moves from five verdict decisions to three:
`warn` becomes `allow` carrying a `warnings[]` entry, and `escalate` becomes a
`deny` carrying an `approval` block. Applying a transform, honouring
`evaluate_only`, resolving approvals, and deriving identities all become host
obligations.

Two manifest changes have no compatibility path. The engine accepts exactly one
value for `agent_control_specification_version` and rejects every other at parse
time, and the path root `$policy_target` becomes `$target` with no alias in the
manifest grammar. Every manifest in the tree moves with this change, including
those embedded in test and example sources.

The blast radius is bounded by keeping `policy-engine/core` as a deprecation
shim over the registry crate for one release cycle, so every symbol AGT
exported still imports. Note that Rust silently ignores `#[deprecated]` on a
`pub use` re-export, so the shim uses type aliases and wrapper functions, which
do warn at the call site.

Phase 1 covers Rust, Python, and Node. The .NET SDK is not retargeted: it is
still five-verdict and reaches the engine through the C ABI this change
removes, so its CI job fails on this branch. That and four other open gaps are
listed in `policy-engine/docs/acs-retarget.md` rather than left implicit.
