# AGT and the upstream ACS engine

AGT used to carry its own policy decision engine in `policy-engine/core`.
That engine now lives in
[`responsibleai/agent-control-spec`](https://github.com/responsibleai/agent-control-spec).
AGT depends on its published crate instead of maintaining a second copy.
Engine fixes can ship upstream and reach AGT through a dependency update.
AGT still owns its host APIs, framework adapters and policy authoring tools.

[Agent Hooks](https://github.com/responsibleai/agent-hooks) defines the
interception contract. ACS makes the policy decision. The host applies
transforms, resolves approvals and decides whether the guarded action runs.
Moving the engine did not move those host responsibilities out of AGT.

## Versions and package names

| Surface | Version |
| --- | --- |
| `agent-control-spec` Rust dependency | `=0.4.0-alpha.4` |
| `agent-hooks-sdk` Rust dependency | `=0.1.0-alpha.5` |
| Existing manifest contract | `0.4.0-alpha.1` |
| Opt-in annotator dependency contract | `0.5.0-alpha.1` |

Package versions and manifest versions are independent. Keep existing
manifests on `0.4.0-alpha.1` unless they need annotator chaining. Move an entire
`extends` chain together when adopting `0.5.0-alpha.1`. In that contract,
`needs` on an annotation binding declares dependencies, and a dependent
annotator can read their outputs through `$pi.annotations`.

The upstream packages are `agent-control-spec` on crates.io and PyPI,
`@responsibleai/agent-control-spec` on npm, and
`ResponsibleAI.AgentControlSpec` on NuGet. The upstream Python import is
`agent_control_spec`.

AGT keeps `agent_control_specification` for its Rust host crate and Python
import, `agent-control-specification` for its Python and Node distributions,
and `AgentControlSpecification` for its .NET package. These packages preserve
AGT's `AgentControl` and adapter APIs. Installing an upstream package is not
a drop-in replacement for them.

The [upstream specification](https://github.com/responsibleai/agent-control-spec/blob/main/spec/SPECIFICATION.md)
defines engine behavior. AGT's [compatibility profile](../spec/SPECIFICATION.md)
records the host contract and local restrictions. The
[Python SDK guide](../sdk/python/README.md),
[Node SDK guide](../sdk/node/README.md) and
[.NET SDK guide](../sdk/dotnet/README.md) describe the retained APIs.

## Compatibility

| Historical name or behavior | Current equivalent |
| --- | --- |
| `InterventionPoint` | `agent_hooks::InterceptionPoint` |
| `InterventionPointRequest` | ACS `EvaluationRequest` |
| Engine `InterventionPointResult` | ACS `EvaluationResult` |
| `verdict::normalize_policy_output` | `policy_output::normalize_policy_output` |
| Engine verdict types | Agent Hooks verdict types |
| `warn` | `allow` with `warnings[]` |
| `escalate` | A liftable `deny` with `approval` |
| The effects plane | A single `transform` verdict |

The core shim retains deprecated aliases for one release cycle. A preserved
name does not preserve the old signature, manifest grammar or verdict
semantics. Rust deprecation attributes on plain re-exports do not warn at
the call site, so the shim uses type aliases and wrapper functions where
possible. Trait re-exports carry their notice in documentation.

`SUPPORTED_VERSIONS` is the engine's complete manifest-version list.
`SUPPORTED_MANIFEST_VERSIONS` retains its historical `[&str; 1]` type and
contains only the legacy `0.4.0-alpha.1` contract. Validators use the complete
list. New callers should do the same.

Manifest paths use `$target`, not `$policy_target`. Agent Hooks still accepts
the latter on transform paths, but that does not make it a manifest-path
alias. Legacy host `WARN` and `ESCALATE` enum members remain available where
the SDK already exposed them. The engine returns only three decisions.

## Backend and host behavior

AGT's legacy host, Python/Node bindings and .NET C ABI explicitly select OPA
for their default Rego dispatcher. Enabling upstream in-process Rego elsewhere
in a Cargo dependency graph must not change that selection. An explicit
`ACS_OPA_PATH` remains authoritative.

The core shim forwards opt-in `rego` and `streaming` modules to ACS.
These features do not switch the legacy host backend. Direct upstream
`AcsInterceptor` and `ActivatedPolicy` consumers follow upstream feature
selection instead.

Alpha.4 fixes the upstream no-backend compilation defect. The compatibility
core and telemetry crate no longer force the OPA feature for data-only builds.

`HostEvaluation` applies transforms and derives AGT's identity fields. Before
returning a transform, it reconstructs the complete effective snapshot and
checks its size and depth limits. Evaluate-only mode validates the proposed
transform but does not apply it. AGT retains its historical policy-input
digests rather than claiming the Agent Hooks default context identity profile.

The C ABI lives in `sdk/rust/src/ffi.rs` and builds
`libagent_control_specification.so` on Linux. It belongs to the host SDK because
it applies host behavior before returning a result to .NET. A liftable deny
without an approval resolver fails closed with `host_error:approval_unresolved`.
An adapter reaching the engine is not, by itself, an Agent Hooks conformance
claim. Such a claim still needs the host CTK.

## Restored source fields and download limits

Alpha.4 implements `bundle_url` for the OPA dispatcher and
`system_prompt_url` for LLM annotators. Both require HTTPS and exactly one
SHA-256 or SRI integrity pin. A bundle cannot specify both `bundle` and
`bundle_url`. A prompt cannot specify a URL together with `system_prompt`
or its `prompt` alias. The upstream engine validates these combinations.

`system_prompt_file` is still unsupported. AGT rejects it in declarations
and bindings instead of allowing a judge to use its default prompt.
The historical `reject_removed_manifest_fields` helper now rejects that
field only. `REMOVED_MANIFEST_FIELDS` keeps its original array for source
compatibility and describes the initial retarget, not the current support set.

AGT passes host download limits to its default OPA and annotator dispatchers.
The C ABI's `acs_builder_set_url_fetch_limits` configures pinned bundle and
prompt downloads after construction. It cannot retroactively constrain a
manifest fetch that already happened. Inference POST requests retain their
provider timeout settings, and custom dispatchers own their I/O limits.

Schema validation, typed validation and actual downloads are separate checks.
Accepting a pinned URL in an authoring report does not fetch the artifact or
prove that the remote bundle compiles.

## URL provenance and destination checks

Alpha.4 restores the URL provenance checks tracked in
[#20](https://github.com/responsibleai/agent-control-spec/issues/20).
The upstream loader retains provenance through `extends` and merging. It
rejects fetched documents that request local files, host environment
credentials, approval configuration or arbitrary executable Rego queries.
Bundled annotators also check provenance before reading host credentials.
Remote bundle and prompt URLs require a pinned manifest chain.

Keep manifests typed through construction. Serializing a fetched manifest
and parsing it again as host-authored text loses provenance. A host that
fetches a document itself must use upstream `mark_url_sourced` before
composing it. That API has stricter constraints than the upstream URL loader.

These checks do not make arbitrary network destinations safe. AGT's
`manifest_from_url` also rejects blocked IP literals and local hostnames using
the same `url` parser as the fetcher. It blocks loopback, unspecified,
broadcast, link-local, private, shared-address and local IPv6 ranges, including
supported embedded-IPv4 forms. Internal hosting by a private IP literal is
therefore rejected.

The destination guard covers the caller's URL, not DNS resolution or nested
URL parents. AGT continues to disable redirects on this entry point because
the fetcher offers no AGT per-hop destination callback. A zero redirect budget
does not contact the redirect target. Local manifests, custom dispatchers and
their endpoints still require a host trust decision.

The legacy top-level URL helper creates a `0.4.0-alpha.1` wrapper manifest.
For a `0.5.0-alpha.1` URL parent, use a local root manifest declaring that
version and its `extends` reference, then load it through `from_path`.
This keeps version selection explicit and uses upstream composition without
rewriting fetched content.

## What still belongs in AGT

The compatibility layer retains generic bounded YAML-to-JSON tooling,
overlay checks, source-located OPA artifact diagnostics and legacy telemetry
projection. Upstream now has bounded typed parsing too, but those APIs do not
all return the same shape or diagnostics as AGT's tooling. A replacement needs
behavioral parity, not just a matching function name.

Runtime manifest and policy-dispatcher getters avoid duplicate construction
state. The host still retains the inputs needed to rebuild a runtime with a
telemetry sink. The remaining upstream API requests are
[#22](https://github.com/responsibleai/agent-control-spec/issues/22) and
[#23](https://github.com/responsibleai/agent-control-spec/issues/23).
The old binding-validation gap
[#14](https://github.com/responsibleai/agent-control-spec/issues/14) and
dispatcher-limit gap
[#21](https://github.com/responsibleai/agent-control-spec/issues/21) are resolved.

The legacy Quint model still describes five decisions. It is labelled as
historical and is not evidence of conformance to the current engine.

## Publication and provenance

The alpha.4 crate has a trusted-publishing record bound to upstream commit
`e56d0050c5c1f462be6bde3b389e56ae4f04fdc8`. Its registry checksum is
`ce7cef7009046fda4752cf68911b6fa4076b6a7dcb5f6e0ef629b45dab7006f8`.
Organization ownership remains tracked in
[#24](https://github.com/responsibleai/agent-control-spec/issues/24).
The landed retarget recorded the maintainer's acceptance of the ownership
state. A dependency update does not resolve that registry-side request.

AGT's compatibility packages have their own release order. The Python SDK and
generator are `0.4.0b0`; `agt-policies` requires the new SDK. Publish the SDK
before those consumers and the consolidated core. The core shim is
`0.3.2-beta.0`, separate from the upstream engine version. Do not republish
changed code under an existing version.

The .NET packages require the complete native asset matrix before release.
The npm wrapper requires matching native and OPA platform packages.
Existing ESRP dependency ordering, single-package GitHub publication and
supply-chain checks remain in place. This update does not publish packages.

As checked October 3, PyPI's `agent-control-specification` is still `0.3.1b1`.
Build and install the wheel from this checkout before testing AGT's host API.
A stale installed wheel can reject the new manifest grammar even when the
source tree is correct.
