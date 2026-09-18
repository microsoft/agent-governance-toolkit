# Retarget onto agent-control-spec

AGT's policy decision runtime is no longer vendored here. It ships from the registry as
`agent-control-spec`, rebased on the [agent-hooks](https://github.com/responsibleai/agent-hooks)
control contract. This note records what changed, what is still open, and what a
contributor needs to know before touching the policy plane.

Pinned versions are `agent-control-spec = "=0.4.0-alpha.3"` and
`agent-hooks-sdk = "=0.1.0-alpha.5"`, the latest published releases verified on
September 8, 2026. The same pair is resolved in the policy workspace, the
standalone Rust consumer and the coding-agent example.

As of September 8, 2026, ACS 0.4.0-alpha.3 and agent-hooks 0.1.0-alpha.5 are
published. ACS's newer bindings provide manifest and artifact tooling, host
dispatchers and streaming APIs, and its default Rego backend runs in process.
Those releases invalidate the original assumption that bindings expose only
`AcsInterceptor`, but do not make them drop-in replacements for AGT's
`AgentControl` and `HostSession` APIs. This PR retains AGT's native bindings
over the pinned Rust engine.

### Backend compatibility

AGT's legacy `AgentControl`, Python/Node bindings and .NET ABI explicitly use
the OPA dispatcher. All direct ACS dependencies disable upstream default
features, and the host constructs `OpaPolicyDispatcher` rather than calling
the feature-dependent upstream default factory. Enabling in-process Rego
elsewhere in a consumer's Cargo graph therefore cannot silently change these
APIs' executable selection, bundle handling or policy behavior.

Alpha.3 has a compile-time feature-gating defect when neither `opa` nor `rego`
is enabled. The core shim and telemetry crate therefore enable the lightweight
OPA feature even in isolated, data-only builds. This does not pull in Regorus
or require an OPA executable for telemetry. CI checks these
crates independently so sibling workspace features cannot hide the defect.

Direct users of ACS's `AcsInterceptor` and `ActivatedPolicy` follow ACS's own
feature selection. Switching the legacy host's default backend is a separate
behavior change, not a side effect of upgrading its dependency.

The core compatibility shim forwards the optional `rego` and `streaming`
features to ACS. Enable `rego` to use the in-process dispatcher through
`agent_control_specification_core::rego`, or `streaming` to use
`agent_control_specification_core::stream_session`. Both are disabled by
default. Only these module paths are forwarded, not the upstream root-level
Rego and streaming type re-exports.
The shim retains its OPA dependency feature for alpha.3 compatibility,
and these opt-ins do not change the legacy host's explicit OPA dispatcher.

The committed lockfiles retain `ureq` 3.4.0 and `ureq-proto` 0.6.1, both
published August 8. Their September 6 successors are inside the seven-day
cooling-off window and are not used in these builds.

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

The compatibility identity fields retain AGT's historical policy-input
digests. They are not a claim to implement agent-hooks' default context
identity profile.

## Manifests

Three breaking changes, all already applied across this repository.

1. `agent_control_specification_version` must be `0.4.0-alpha.1`. The engine accepts no
   other value and rejects at parse time.
2. The path root `$policy_target` is now `$target`. The manifest grammar ships no alias
   and rejects the old root as `unknown path root`. Note that agent-hooks does accept
   `$policy_target` as a deprecated alias on *transform* paths, so the two layers differ.
3. `bundle_url`, `system_prompt_file` and `system_prompt_url` are removed. See the next
   section.

### Removed manifest fields

The embedded engine implemented three fields that `agent-control-spec`
0.4.0-alpha.3 never had (`git log -S bundle_url` on the upstream engine is
empty): a rego `bundle_url` (remote bundle, fetched and pin-checked at
dispatch), and the `llm` annotator's `system_prompt_file` and
`system_prompt_url` prompt sources. Upstream's `RegoPolicyConfig::adapter_config`,
`PolicyBinding::adapter_config`, `AnnotatorConfig::fields` and
`AnnotationConfig::fields` are open maps, so a manifest declaring one of these
keys parsed and validated cleanly while the feature was silently absent: the
annotator ran with `DEFAULT_SYSTEM_PROMPT`, and the rego policy denied every
request with `runtime_error:policy_invocation_failed` and no diagnostic. Every
fail-closed check the old engine had for them (`bundle` with `bundle_url`, an
unpinned or non-HTTPS URL, inline and file prompt together) had turned into a
silent accept.

AGT now fails closed instead. `agent_control_specification_core::reject_removed_manifest_fields`
walks each policy definition, each annotator declaration, and each intervention
point's policy binding and annotation bindings, and returns
`runtime_error:manifest_invalid` naming the location and the field. It runs in
`validate_manifest_yaml`, `validate_manifest_overlay_yaml`, every `AgentControl`
constructor, `manifest_from_url`, every C ABI `acs_builder_from_*` loader, and
the Python and Node `from_*` constructors. Both copies of `manifest.schema.json`
keep the three keys as `not: {}` properties (on the rego policy, the policy
binding, the annotator and the annotation binding), because the enclosing
objects allow additional properties and dropping the keys would accept them
silently.

Migration: inline the value. A `system_prompt_file` becomes `system_prompt`
with the file's text; a `system_prompt_url` becomes `system_prompt` as well; a
`bundle_url` becomes a local `bundle` path shipped with the manifest, or a host
supplied policy dispatcher that fetches the bundle itself. Restoring a remote
prompt or bundle source is an upstream proposal against `agent-control-spec`.
`SPECIFICATION.md` sections 2.3, 10 and 12.1 and the schema record the removal.

`core/src/manifest_yaml.rs` re-exports the engine's public `SUPPORTED_VERSIONS`.
Its legacy `SUPPORTED_MANIFEST_VERSIONS` array is derived from that list, with
a compile-time cardinality check to prevent drift while preserving its type.
URL-loader scaffolding uses the upstream list directly. Package version alpha.3
does not imply manifest version alpha.3; the accepted grammar remains alpha.1.

## Gaps in the pinned upstream release

These limitations were rechecked against the published alpha.3 crate. New
upstream APIs replace compatibility code only when their behavior and wire
shapes match the legacy consumer contract.

| Gap | Issue |
| --- | --- |
| URL sourced manifests can read host environment credentials | [#20](https://github.com/responsibleai/agent-control-spec/issues/20) |
| The selected `agent-control-spec` release cannot pass `Limits` to bundled dispatchers | [#21](https://github.com/responsibleai/agent-control-spec/issues/21), resolved upstream but not yet eligible for adoption |
| Telemetry sink cannot be set after `Runtime` construction | [#22](https://github.com/responsibleai/agent-control-spec/issues/22) |
| `from_url`, `policy_labels`, `validate_overlay` have no equivalent | [#23](https://github.com/responsibleai/agent-control-spec/issues/23) |
| Original binding validation gap, resolved upstream after alpha.1 | [#14](https://github.com/responsibleai/agent-control-spec/issues/14) |
| Publisher provenance and organization ownership review condition | [#24](https://github.com/responsibleai/agent-control-spec/issues/24) |
| `bundle_url`, `system_prompt_file`, `system_prompt_url` have no implementation; AGT rejects them | none filed; restoring them is a proposal, see "Removed manifest fields" |

### Security, unresolved

`agent-control-spec` 0.4.0-alpha.1 dropped the `url_sourced` provenance gate. AGT used it
to withhold host environment credentials from a manifest fetched over the network, in
three places in the old `dispatchers/llm.rs`. The crate still supports URL sourced
`extends` through `ManifestUrlExtends`, so the capability that creates the risk survived
while the mitigation did not.
The alpha.3 dispatchers still do not carry that provenance gate.

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
  the overlay safe subset over the public manifest surface. The bounded YAML
  parser also remains because upstream parsing does not provide AGT's expanded
  node and byte limits.
- `TelemetrySink` has no `force_flush`, and `TelemetryEvent` has no `to_json`.
  Alpha.3 provides `wire::telemetry_event_json`, but it lowercases Rust debug
  names, losing underscores in interception points and evaluate-only mode.
  `core/src/telemetry_sinks.rs` therefore retains the canonical legacy wire
  projection and its flush methods.
- `Runtime` now exposes its manifest, policy dispatcher and performance
  telemetry. The host uses those getters rather than retaining duplicate
  construction state. Annotator and limit accessors and a telemetry setter are
  still absent, so `with_telemetry` retains those inputs and still requires a
  manifest-based constructor.
- Upstream artifact diagnostics use the in-process backend and a different
  shape. AGT retains its bounded, source-located OPA lint diagnostics and
  explicit executable selection rather than silently changing that API.
- The selected `agent-control-spec` release does not expose limits-aware bundled
  dispatchers. `acs_builder_set_url_fetch_limits` therefore fails closed instead of
  reporting a successful configuration it cannot enforce. The C ABI retains the symbol
  for compatibility until AGT can adopt the upstream fix after its supply-chain
  stabilization period.

Raise these as issues or proposals on the upstream repositories rather than forking
contract semantics here. See `docs/proposals/README.md` in the agent-hooks repository for
the process.

## Work remaining in this repository

`SPECIFICATION.md` sections beyond the verdict set, host obligations, approval
path and reason tables were retargeted alongside them, and sections 2.3, 10 and
12.1 now record the removed remote prompt and bundle fields. One gap remains in
section 2.3: the pinned engine skips relative path resolution for a URL sourced
manifest but does not reject its filesystem path fields (`bundle`, `data`,
`data_paths`), so a remote manifest can name local files; that needs an
upstream fix and is tracked as an issue rather than patched here. The AgentDojo benchmark policy
computes its own redacted value and returns a single `transform`. The transform a
host applies is revalidated against `Limits`, and `manifest_from_url` runs an
SSRF guard over the URL before anything is fetched.

### The `manifest_from_url` guard

The guard parses the URL with the `url` crate, the same parser the upstream
loader canonicalizes the fetch target with, and evaluates `Url::host()`. An
earlier port hand-split the authority and called `str::parse::<IpAddr>`, which
accepts only dotted-quad literals; `127.1`, `2130706433`, `0x7f000001`,
`0177.0.0.1` and `127.0.0<TAB>.1` passed it and were then canonicalized to
`127.0.0.1` by the fetcher, which connected. The test
`manifest_from_url_blocks_ssrf_targets` now carries every one of those forms,
and `manifest_from_url_never_connects_to_a_blocked_literal` binds a loopback
listener and asserts no connection arrives.

Blocked destinations: loopback, the unspecified address and `0.0.0.0/8`,
broadcast, link-local (`169.254.0.0/16`, `fe80::/10`), RFC 1918 private
ranges, the shared address space `100.64.0.0/10`, IPv6 unique-local
`fc00::/7` and site-local `fec0::/10`, and the names `localhost`,
`*.localhost` and `*.local`. IPv4-mapped, IPv4-compatible and NAT64
well-known-prefix IPv6 literals are checked on their embedded IPv4 address.
The pre-retarget engine allowed RFC 1918 and unique-local literals so a policy
could be hosted on an internal HTTPS server by IP; that is no longer allowed,
and internal hosting must use a hostname.

What the guard does not do, all of it the same upstream gap as issue #20:

- Hostnames other than the three blocked patterns are not resolved. A name that
  resolves into a blocked range, and DNS rebinding between the check and the
  connect, need a resolution-time check inside the fetcher.
- Redirect hops are not re-checked. `agent-control-spec` 0.4.0-alpha.3 hands
  redirect following to its HTTP client (`max_redirects` from
  `Limits::max_manifest_url_redirects`, default 5) and exposes no hook to
  intercept a hop, so a vetted public URL can redirect to a blocked address.
  The pre-retarget engine followed redirects itself and re-ran each hop through
  the guard. A host that needs the guard to hold across redirects must pass
  `max_manifest_url_redirects: 0` (`max_url_redirects=0` in Python,
  `maxRedirects: 0` in Node). The C ABI `acs_builder_from_url` fetches with
  the default budget and rejects attempts to configure URL fetch limits.
- A nested `extends` URL inside the fetched manifest resolves through the
  upstream loader with no destination check at all.

Treat the guard as a barrier against the obvious case and not as a boundary.

### Registry ownership decision

The review asked for trusted publishing, repository metadata and an
organization or team co-owner for `agent-control-spec`. Registry APIs checked on
September 13, 2026 show repository metadata and a trusted-publishing attestation
for the pinned alpha.3 artifact (GitHub Actions, `responsibleai/agent-control-spec`,
commit `4c47b57033b98c0d2ccf1b94624f058815db0a9c`), and the downloaded crate
checksum and unpacked source match the registry and that commit. The same holds
for `agent-hooks-sdk` 0.1.0-alpha.5.

Both crates still list one individual owner and no team. In August 2026 the
maintainer accepted that as the state to merge on: the
sole owner is the same account that maintains this integration, publication is
bound to a public commit through trusted publishing rather than to that
account's token, and adding an organization owner is a registry-side change
that does not alter any byte this tree builds against. Adding the team owner
stays tracked upstream in
[#24](https://github.com/responsibleai/agent-control-spec/issues/24); revisit
this paragraph when it closes.

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

ESRP's PyPI jobs wait for prerequisites selected in the same run before
publishing consumers. If a prerequisite is omitted, it must already be
published. GitHub publication accepts one Python package per manual publish
run, in the same dependency order. Bulk GitHub dry-runs still build all
artifacts, but actual bulk PyPI publication must use the ordered ESRP pipeline.

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
