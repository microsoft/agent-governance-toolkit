# Retarget onto agent-control-spec

AGT's policy decision runtime is no longer vendored here. It ships from the registry as
`agent-control-spec`, rebased on the [agent-hooks](https://github.com/responsibleai/agent-hooks)
control contract. This note records what changed, what is still open, and what a
contributor needs to know before touching the policy plane.

Pinned versions: `agent-control-spec = "=0.4.0-alpha.1"` and
`agent-hooks-sdk = "=0.1.0-alpha.3"`. These remain the versions selected and
reviewed for this migration. Their cooling-off windows have elapsed. Updating
to newer upstream releases is a separate dependency change, not a prerequisite
for repairing this host implementation.

As of September 8, 2026, ACS 0.4.0-alpha.3 and agent-hooks 0.1.0-alpha.5 are
published. ACS's newer bindings provide manifest and artifact tooling, host
dispatchers and streaming APIs, and its default Rego backend runs in process.
Those releases invalidate the original assumption that bindings expose only
`AcsInterceptor`, but do not make them drop-in replacements for AGT's
`AgentControl` and `HostSession` APIs. This PR retains AGT's native bindings
over the pinned Rust engine.

## What moved

| Was | Now |
| --- | --- |
| `policy-engine/core/src` (the engine) | the `agent-control-spec` crate |
| `InterventionPoint` | `agent_hooks::InterceptionPoint` |
| `InterventionPointRequest` | `runtime::EvaluationRequest` |
| `InterventionPointResult` | `runtime::EvaluationResult` |
| `verdict::normalize_policy_output` | `policy_output::normalize_policy_output` |
| `verdict::{Decision, Evidence, Transform, Verdict}` | `agent_hooks::{...}` |
| the effects plane | gone. `transform` is the only value changing decision |
| the C ABI in `core/src/ffi.rs` | moved to `sdk/rust/src/ffi.rs`. See "The .NET SDK" below |

`policy-engine/core` survives as a deprecation shim for one release cycle. Rust ignores
`#[deprecated]` on a `pub use` re-export, so the shim declares deprecated type aliases and
wrapper functions instead, which do warn at the call site. Preserving a name
does not preserve its old signatures, manifest grammar or verdict semantics.
Traits cannot be aliased on stable Rust, so trait re-exports carry the notice
in documentation only.

## Verdicts are three, not five

`Decision` is `Allow`, `Deny`, `Transform`. Translate as follows.

| Old | New |
| --- | --- |
| `warn` | `allow` plus `warnings[]`. `Verdict::warn` is the constructor sugar |
| `escalate` | a liftable `deny` carrying an `approval` block |

Reason namespaces are split. The engine emits `runtime_error:*`. The `host_error:*`
namespace is reserved for hosts and an interceptor must never emit it. AGT's host SDK is a
host, so it does synthesize `host_error:*` for approval resolver failure, approval identity
mismatch, unresolved approval, and streaming refusal. These names come from the
agent-hooks reserved set.

## Host obligations

Under AGENT-HOOKS-0.1 sections 8 to 10 the engine returns a verdict and nothing else. The
host applies transforms, honours `evaluate_only`, resolves approvals, and computes
identity. In this tree that is `sdk/rust/src/host/evaluation.rs`, which turns an
`EvaluationResult` into a `HostEvaluation` carrying `transformed_policy_target` and the
identity trio. Never push that logic back into the policy plane.

Before returning a transform, the host reconstructs the complete effective
snapshot using `policy_target.path` and validates its byte and depth limits.
This check runs in both enforcement and evaluate-only mode. Validating only
the replacement target would omit ambient state and permit oversized actions.
The shared helper serves Rust, Python, Node and the .NET C ABI.

## Manifests

Two breaking changes, both already applied across this repository.

1. `agent_control_specification_version` must be `0.4.0-alpha.1`. The engine accepts no
   other value and rejects at parse time.
2. The path root `$policy_target` is now `$target`. The manifest grammar ships no alias
   and rejects the old root as `unknown path root`. Note that agent-hooks does accept
   `$policy_target` as a deprecated alias on *transform* paths, so the two layers differ.

`SUPPORTED_MANIFEST_VERSIONS` in `core/src/manifest_yaml.rs` mirrors the private list in
`agent-control-spec`. Keep it in step when the upstream pin moves.

## Gaps in the pinned upstream release

The compatibility code and limitations below describe 0.4.0-alpha.1, not every
later release. Recheck both source and published artifacts before updating a pin.

| Gap | Issue |
| --- | --- |
| URL sourced manifests can read host environment credentials | [#20](https://github.com/responsibleai/agent-control-spec/issues/20) |
| `Limits` do not reach the bundled dispatchers | [#21](https://github.com/responsibleai/agent-control-spec/issues/21) |
| Telemetry sink cannot be set after `Runtime` construction | [#22](https://github.com/responsibleai/agent-control-spec/issues/22) |
| `from_url`, `policy_labels`, `validate_overlay` have no equivalent | [#23](https://github.com/responsibleai/agent-control-spec/issues/23) |
| Original binding validation gap, resolved upstream after alpha.1 | [#14](https://github.com/responsibleai/agent-control-spec/issues/14) |
| Publisher provenance and organization ownership review condition | [#24](https://github.com/responsibleai/agent-control-spec/issues/24) |

### Security, unresolved

`agent-control-spec` 0.4.0-alpha.1 dropped the `url_sourced` provenance gate. AGT used it
to withhold host environment credentials from a manifest fetched over the network, in
three places in the old `dispatchers/llm.rs`. The crate still supports URL sourced
`extends` through `ManifestUrlExtends`, so the capability that creates the risk survived
while the mitigation did not.

The credential-reading path is the bundled *annotator* dispatcher, which resolves
`api_key_env` against the host environment. `sdk/rust` therefore installs it only under
the off-by-default `bundled-dispatchers` feature; without that feature a manifest that
declares annotators fails closed with a message naming the feature, and a manifest that
declares none gets a fail-closed no-op. The bundled *policy* dispatcher stays on by
default so the zero-config Rego path keeps working.

The production Python wheel and default Rust SDK leave bundled annotators
disabled. The .NET native build and Node test build explicitly enable
`bundled-dispatchers` for their existing zero-config integrations. These builds
require trusted manifests and trusted transitive configuration. The feature
switch is not a substitute for the missing provenance gate. Do not enable it
for manifests supplied by an untrusted party.

Leaving the policy dispatcher on is a narrower guarantee than "the policy plane is safe".
`agent-control-spec` spawns `opa` without clearing the environment, and Rego reads the
inherited environment through `opa.runtime().env`, so a manifest that controls the query
can read a host secret:

```console
$ ACS_SENTINEL=x opa eval --format json --stdin-input 'opa.runtime().env.ACS_SENTINEL' <<<'{}'
... "value": "x" ...
```

This is not a retarget regression: the previous embedded engine spawned `opa` the same
way. Closing it needs `env_clear` at the spawn site upstream, so raise it there.

Do not read the annotator gate as a credential boundary. It is not. The gated annotator
path reaches one named variable through `api_key_env`; the ungated policy path reaches
the whole environment, because a manifest supplies the `query` string and
`agent-control-spec` passes it to `opa eval` as an arbitrary Rego expression
(`src/opa.rs`, `command.arg(&invocation.query)`). That needs no bundle, no annotators and
no `bundled-dispatchers` feature:

```console
$ OPENAI_API_KEY=sk-SECRET123 opa eval --format json --stdin-input \
    '{"decision":"allow","reason":opa.runtime().env.OPENAI_API_KEY}' <<<'{}'
... "value": {"decision": "allow", "reason": "sk-SECRET123"} ...
```

That output normalizes into a valid `allow` verdict, and the secret does not stop at the
verdict. `safe_telemetry_reason_code` passes any reason under 96 bytes made of
alphanumerics and `_-.:/` through unchanged, which most API key formats satisfy, so the
value is written verbatim to every telemetry sink as `reason_code`. A caller that never
reads `verdict.reason` still exports it.

The practical consequence is a constraint on `manifest_from_url`: under the default
feature set, do not point it at a URL you do not control. A manifest is trusted input to
the policy plane, which was equally true before this change but is easier to reach now
that loading one over the network is a first class API.

### Capability gaps

- The alpha.1 Python, Node and .NET ACS packages exposed only `AcsInterceptor`.
  Manifest validation landed upstream in #15, closing #14, and later releases
  added further tooling. AGT's PyO3 and napi bindings instead consume its Rust
  host SDK, preserving the richer legacy host API. Replacing those bindings
  with the standalone packages requires a separate consumer migration.
- `Manifest::from_url` and `Runtime::policy_labels` are gone. `sdk/rust` reimplements
  both over the public surface: `manifest_from_url` writes a synthetic one-entry
  `extends` manifest to a temp dir and loads it with `Manifest::from_path_with_limits`,
  which reuses the crate's own fetcher, redirect and size limits, and sha256 pin
  verification rather than adding an HTTP client here; `policy_labels` reads
  `manifest.intervention_points`.
- `Manifest::validate_overlay` is not exported. `core/src/manifest_yaml.rs` reimplements
  the overlay safe subset over the public manifest surface.
- `TelemetrySink` has no `force_flush`, and `TelemetryEvent` has no `to_json`.
  `core/src/telemetry_sinks.rs` carries both.
- `Runtime` takes its telemetry sink at construction, has private fields, and exposes no
  accessors or setter. `AgentControl::with_telemetry` therefore rebuilds the runtime from
  retained construction inputs, which only works for manifest based constructors.
- `Limits` does not reach the bundled dispatchers, so a tightened URL fetch budget does
  not apply to a dispatch time fetch; their own defaults govern it. The engine resource
  budget it also carries (snapshot size, policy input size, annotators per point) does
  reach the runtime, via `Runtime::with_limits`.

Raise these as issues or proposals on the upstream repositories rather than forking
contract semantics here. See `docs/proposals/README.md` in the agent-hooks repository for
the process.

## Work remaining in this repository

`SPECIFICATION.md` sections beyond the verdict set, host obligations, approval
path and reason tables were retargeted alongside them, so the normative document
now describes the implemented contract throughout. The AgentDojo benchmark policy
computes its own redacted value and returns a single `transform`. The transform a
host applies is revalidated against `Limits`, and `manifest_from_url` refuses
loopback and link-local destinations again.

That last guard covers the URL a caller passes and nothing deeper. A nested
`extends` URL inside a fetched manifest resolves through the loader in
`agent-control-spec`, which has no equivalent check, and the guard resolves the
host once rather than revalidating after DNS resolution or a redirect. Both sit
in the same upstream gap as issue #20, so treat the guard as a barrier against
the obvious case and not as a boundary.

### Before this merges

The review required trusted publishing, repository metadata and an organization
or team co-owner for `agent-control-spec`. Registry APIs checked on September 8,
2026 show repository metadata and trusted publication for alpha.2 and alpha.3,
but still one individual owner. The pinned alpha.1 artifact has no trusted
publication record. The historical source comparison does not waive the
reviewer's ownership condition. Upstream
[#24](https://github.com/responsibleai/agent-control-spec/issues/24) remains open.
Merge still requires that condition to be satisfied or an explicit maintainer
decision changing it.

### Release and upgrade order

The Python SDK and generator are versioned 0.4.0b0, and `agt-policies` 5.1.0
requires `agent-control-specification>=0.4.0b0,<0.5.0`. The old 0.3.1b1 wheel
cannot satisfy this requirement. Publish the new SDK distribution before
publishing its generator and migration-tool consumers. The consolidated core
requires `agt-policies>=5.1.0,<6.0`, so its CLI cannot pull in the old engine
through the previous migration-tool release. Release that core change with the
next repository-wide version bump, after publishing the policy dependencies.
CI builds these dependencies from this checkout rather than requiring an
unpublished release from PyPI.

The .NET package family moves to 0.4.0-beta.0. ESRP builds
`agent_control_specification` with `opa,bundled-dispatchers` for all five RIDs,
matching the local MSBuild target. Package the complete native asset matrix
before publishing the managed SDK and adapters.

Rust's core shim and npm's package family still need coordinated release
preparation. Do not publish their modified code under existing 0.3.1 versions.
Publish a newly versioned core shim, then update the SDK's exact registry
requirement and publish dependent Rust crates. For npm, publish newly versioned
native and OPA platform packages, then update and publish the wrapper with
matching exact optional dependencies. The supply-chain checks must accept those
versions before the dependency updates merge. Do not bypass them or confuse a
successful workspace build with a registry-install test.

## The .NET SDK

`sdk/dotnet` retains AGT's C ABI and `AgentControl` host API. The original
alpha.1 NuGet package did not expose its needed policy-plane functions. Newer
NuGet releases add APIs and native assets, but migrating the legacy host API
to them is outside this pinned-engine retarget.

The ABI lives in `sdk/rust/src/ffi.rs` and ships as
`libagent_control_specification.so`. It belongs in the SDK rather than the core
shim for two reasons. It discharges the host obligations through `HostEvaluation`
before crossing the boundary, so the managed side receives a verdict that has
already had its transform applied and its identities derived. And a core that
depended on the SDK could not be packaged, since the SDK version it would pin is
not on any registry.

The managed side carries the three-verdict contract: `Verdict` gained `Warnings`
and `Approval`, and enforcement routes on a deny that holds an approval block.
`Decision.Warn` and `Decision.Escalate` remain declared and keep their documented
meanings, so a caller still holding one gets the behaviour it expects rather than
a refusal.

A liftable deny without an approval resolver returns
`host_error:approval_unresolved` before execution. The blocked result preserves
the original policy input and identity for host-side records.

## Rebuild the Python wheel after retargeting

The manifests in this repository now pin `0.4.0-alpha.1`, which the previously published
`agent_control_specification` wheel (0.3.1b1, built from the old engine) rejects at parse
time. A stale copy in `site-packages` shadows the retargeted tree and makes suites in
`agt-policies`, `agent-compliance` and `agent-os` fail with `unsupported
agent_control_specification_version '0.4.0-alpha.1'`. Rebuild and reinstall the wheel
from `sdk/python` before reading those results.
