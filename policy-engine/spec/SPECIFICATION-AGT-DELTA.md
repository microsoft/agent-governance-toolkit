# SPECIFICATION-AGT-DELTA.md — AGT divergences from upstream ACS

This document lists the AGT-owned deltas applied to the vendored ACS spec
(`policy-engine/spec/SPECIFICATION.md`, snapshot at upstream commit
`responsibleai/AgentControlSpecification@318dbca`). The deltas are normative.
When `SPECIFICATION.md` and this file disagree, this file wins. M2 will inline
these deltas into `SPECIFICATION.md`; until then both files MUST be read
together.

The deltas reflect user decisions captured in
`/home/mhabuomar/code/agt/architecture-exploration.md` (Q1–Q14).

## D1. Verdict and effects (replaces §13.1 and §14)

### What changes
- **Effects are removed from the verdict.** The `effects` array member on the
  verdict object MUST NOT appear. Implementations MUST reject a dispatcher
  output that contains `effects` with `runtime_error:policy_output_invalid`.
- **A fifth decision value, `transform`, is added.** A `transform` verdict
  permits the action and applies a single, validated replacement to the policy
  target before the action proceeds. `transform` replaces the prior
  `allow` + effects pattern.

### Verdict members (replacing §13 table)

| Member | Required | Type | Constraint |
| --- | --- | --- | --- |
| `decision` | yes | string | One of `allow`, `deny`, `warn`, `escalate`, `transform`. |
| `reason` | no | string | MUST NOT start with `runtime_error:`. |
| `message` | no | string | Free form text for a caller. |
| `transform` | required when `decision == "transform"`; forbidden otherwise | object | `{ path: string, value: any }`. See §D1.1. |
| `evidence` | no | object | See §D2. |

### D1.1 `transform` verdict body

When `decision == "transform"`:

| Field | Required | Type | Constraint |
| --- | --- | --- | --- |
| `path` | yes | string | MUST be rooted at `$policy_target` (see §3.2). |
| `value` | yes | any | New JSON value to set at `path`. |

Application semantics:

- The runtime resolves `path` against the current policy target and replaces
  the value at that location with `value`.
- The runtime MUST NOT change the snapshot, the annotations, the projected
  tool, or any host state. The transformation is confined to the policy target.
- A `transform` verdict with a `path` outside `$policy_target` MUST fail closed
  with `runtime_error:transform_target_forbidden`.
- A `transform` verdict whose `path` does not resolve, or whose `value` cannot
  be set (path type mismatch), MUST fail closed with
  `runtime_error:transform_invalid`.
- In `evaluate_only` mode the transformation is validated but not applied
  (matches today's `effects` behaviour in §5).

### D1.2 Decision semantics (replacing §13.1)

`allow` permits the action with no change to the policy target.
`warn` permits the action with no change to the policy target and records a
warning event.
`transform` permits the action and replaces the policy target as defined in
§D1.1.
`deny` refuses the action.
`escalate` defers the action to the host approval path per §17.1.

`warn` no longer applies effects (there are none). Hosts that previously used
`warn` + effects for "permit with redaction" MUST now express that as
`transform` + a reason of their choosing, or as an annotator that performs the
transformation upstream of the policy.

### D1.3 Why this matters

Effects on `warn` and `allow` blurred the line between "the policy approved
the action as submitted" and "the policy substituted something else". A
`transform` verdict makes the substitution explicit, makes it the only
permitted form of value rewriting, and removes the array-of-effects surface.
Multi-step rewriting is achieved by chaining intervention points (e.g., an
annotator at `pre_model_call` produces a sanitized text under
`annotations.pii_scrub.text`, and the bound policy reads from that
annotation) rather than by emitting multiple effects from a single policy.

A future `D1.4 pre_transformers` extension MAY be added if real workloads
require declarative multi-step transformation at a single intervention point.
Until then, hosts that need multi-step rewriting MUST use annotators.

### D1.4 Action identity (replacing §13)

Action identity remains the SHA-256 digest of the canonical policy input
JSON, prefixed with `sha256:`. The identity is unchanged by the verdict; for
`transform` verdicts the identity reflects the input the policy evaluated, not
the post-transform value. Hosts that require the post-transform identity
SHOULD compute it themselves over the transformed snapshot.

---

## D2. Verdict `evidence` field (additions to §13 and §19)

A verdict MAY carry an optional `evidence` field:

```json
"evidence": {
  "artefact": "sha256:<hex>",
  "verification_pointers": {
    "issuer_pubkey": "https://example.com/keys/2026.pem",
    "policy_registry": "https://example.com/policies/v1/"
  }
}
```

| Field | Required | Type | Constraint |
| --- | --- | --- | --- |
| `artefact` | no | string | Content address of an offline-verifiable proof. SHOULD be `sha256:<lowercase-hex>` or a URI. |
| `verification_pointers` | no | object | Map of named URLs that an auditor MAY consult to re-verify the decision. |

The runtime treats `evidence` as opaque. It does not validate `artefact` or
fetch `verification_pointers`. A dispatcher that emits a non-object `evidence`
MUST fail closed with `runtime_error:policy_output_invalid`.

The runtime MUST propagate `evidence` into telemetry events (§19). Specifically
the `policy.invoked` and `intervention_point.decided` events carry the
verbatim `artefact` value and the keys of `verification_pointers` (not their
URLs, to keep cardinality bounded) when `evidence` is present.

### Rationale

High-assurance dispatchers (SMT-verified gates, mechanised-proof PDPs,
TEE-attested PDPs) need a way to ship offline-verifiable evidence with their
decision. The field is additive; existing dispatchers ignore it.

This is the AGT realisation of the prior AGT `BackendDecision.proof_artefact`
and `verification_pointers` fields (see CHANGELOG of the v4
`agent_os.policies.backends` module), promoted to the verdict level.

---

## D3. Cedar as a built-in policy type (replaces §12.1)

The set of built-in policy types is extended from `{rego, test, custom}` to
`{rego, cedar, test, custom}`.

### D3.1 Cedar policy

A `cedar` policy targets the Cedar policy language (https://www.cedarpolicy.com).

Policy definition fields:

| Field | Required | Type | Meaning |
| --- | --- | --- | --- |
| `type` | yes | string | MUST be `"cedar"`. |
| `policy_set` | exactly one of `policy_set` / `policy_path` | string | Inline Cedar policy text. |
| `policy_path` | exactly one of `policy_set` / `policy_path` | string | Filesystem path to a `.cedar` policy file or directory. |
| `entities_path` | no | string | Path to a Cedar entities JSON file. |
| `schema_path` | no | string | Path to a Cedar schema JSON file. |
| `query` | no | object | Cedar request template, see D3.2. |

Binding fields (§12.2) MAY include `principal`, `action`, `resource`, and
`context` JSONPath-style accessors that build the Cedar `Request` from the
policy input.

### D3.2 Cedar request mapping

The Cedar runtime requires a `Request{principal, action, resource, context}`.
The default mapping when no explicit binding is given is:

| Cedar field | Policy input source | Type |
| --- | --- | --- |
| `principal` | `$pi.snapshot.agent.id` resolved to `Agent::"<id>"` | `Agent` entity |
| `action` | The intervention point name, mapped as `Action::"<ip>"` (e.g., `Action::"pre_tool_call"`) | `Action` entity |
| `resource` | `$pi.tool` projected as `Tool::"<name>"` for tool intervention points, otherwise `$pi.policy_target` projected as `PolicyTarget::"<kind>"` | entity |
| `context` | `$pi.snapshot` (excluding `agent.id`) plus `$pi.annotations` | record |

Hosts MAY override the mapping via the `query` member on either the policy
definition or the binding.

### D3.3 Cedar verdict mapping

Cedar's authorization result is mapped to a verdict per:

| Cedar decision | ACS verdict |
| --- | --- |
| `Allow` | `{decision: "allow"}` |
| `Deny` | `{decision: "deny", reason: <first policy id that contributed>}` |

The Cedar policy author MAY produce `warn`, `escalate`, or `transform` by
attaching an `advice` annotation to a Cedar policy and returning a structured
result the dispatcher normalizes per §13. Cedar advice that does not match the
verdict shape MUST fail closed with `runtime_error:policy_output_invalid`.

### D3.4 Dispatcher

The runtime offers an optional `cedar` dispatcher that links the Cedar Rust
crate when the `cedar` feature is enabled at build time. A host MAY supply its
own dispatcher instead. Dispatcher errors fail closed with
`runtime_error:policy_invocation_failed` (matching §12.3).

### D3.5 Rationale

The prior AGT Cedar backend lived as a `CedarBackend` in
`agent_os.policies.backends`. Promoting it to a built-in policy type unifies
the developer experience (same `policies.{id}.type` slot for Rego and Cedar)
and lets the `agt-core-cedar` Cargo feature deliver Cedar evaluation in every
SDK without per-SDK adapter code.

---

## D4. AGT-side resolution layer (additions to §2.2)

ACS engines MAY receive a manifest with non-empty `extends` and resolve it per
§2.2 (file-based loader behaviour). AGT hosts SHOULD instead pre-resolve the
chain on the host side, in a layer above the engine, and pass a flat manifest
with `extends: []`.

This delta is non-normative for the engine itself — the engine continues to
support both modes. The host-side resolution layer is described in
`spec/agt/AGT-RESOLUTION-1.0.md`.

### Rationale

AGT preserves folder discovery and scope filtering (Q6), features that have no
analog in ACS's `extends` model. Doing the resolution on the host side keeps
the engine's contract simple and unchanged while letting AGT hosts continue to
discover `governance.yaml` files from the action path up to the workspace
root, filter by scope glob, and merge them.

---

## D5. `approval` top-level manifest section (new §22)

A manifest MAY include a top-level `approval` section that configures the
escalation backend used for `escalate` verdicts. The schema for that section
is:

```yaml
approval:
  default_resolver: webhook   # or local | callback | <custom-name>
  timeout_seconds: 300
  on_timeout: deny             # or allow | suspend
  fatigue_threshold: 5         # max approvals per agent per fatigue_window_seconds
  fatigue_window_seconds: 3600
  resolvers:
    webhook:
      type: webhook
      url: https://example.com/approve
      auth:
        type: bearer
        env: AGT_APPROVAL_TOKEN
    local:
      type: local
      file: /var/lib/agt/approvals/
```

| Field | Required | Type | Meaning |
| --- | --- | --- | --- |
| `default_resolver` | no | string | Name of the resolver consulted by default. Defaults to `deny` (no resolver). |
| `timeout_seconds` | no | integer | Max wait before `on_timeout` triggers. |
| `on_timeout` | no | enum | `deny` (default), `allow`, `suspend`. |
| `fatigue_threshold` | no | integer | Soft cap; the resolver MAY reject further escalations beyond this. |
| `fatigue_window_seconds` | no | integer | Window for the fatigue counter. |
| `resolvers` | no | object | Named resolver configurations. Resolver types are host-extensible. |

The runtime treats `approval` as opaque host configuration: it validates the
shape per the JSON schema but does not consult it. The SDKs' approval-resolver
plumbing reads it.

### Rationale

The user decision in Q13 places this in the policy layer because `approval`
is policy-shaped configuration: it tells the engine's caller how to satisfy
the `escalate` verdict the engine produces. Keeping it in the manifest means
a manifest is fully self-describing for both policy decisions and the
out-of-band human-approval channel.

---

## D6. Reserved reasons (additions to §16)

Three reserved reasons are added:

| Reason | Cause |
| --- | --- |
| `runtime_error:transform_target_forbidden` | A `transform` verdict carried a `path` outside `$policy_target`. |
| `runtime_error:transform_invalid` | A `transform` verdict's path did not resolve, the value could not be set, or `value` was missing. |
| `runtime_error:approval_resolver_missing` | An `escalate` verdict was returned but no resolver matched the manifest's `approval.default_resolver`. |

Effects-related reasons (`runtime_error:effect_invalid`,
`runtime_error:effect_target_forbidden`) are removed by §D1.

---

## D7. Cargo feature split (build-only delta, no spec impact)

The `core/` crate is split into:

- `agt-core` — runtime, manifest, verdict, telemetry, FFI. Always required.
- `agt-core-opa` — bundled OPA dispatcher. Optional feature `opa`.
- `agt-core-cedar` — bundled Cedar dispatcher. Optional feature `cedar`.

Default features for the workspace include `opa` and `cedar`. Language SDK
crates (`sdk/python`, `sdk/node`, `sdk/dotnet`, `sdk/go`) MUST always enable
both features.

This delta has no impact on the spec; it documents the M2 workspace shape.

---

## Summary of section impacts

| Upstream section | Status after delta |
| --- | --- |
| §1 Model | Unchanged. |
| §2 Manifest | Unchanged; D4 adds host-layer guidance. |
| §3 Paths | Unchanged. |
| §4 Intervention points | Unchanged. |
| §5 Modes | Unchanged. |
| §6 Evaluation order | Step 9 ("validate effects") becomes "apply transform if any". |
| §7 Policy input | Unchanged. |
| §8 Canonical serialization | Unchanged. |
| §9 Tools | Unchanged. |
| §10 Annotators | Unchanged. |
| §11 IFC | Unchanged. |
| §12 Policies | **Extended** — adds `cedar` type per D3. |
| §13 Verdicts | **Replaced** by D1 + D2. |
| §14 Effects | **Replaced** by D1. The §14 effects section is removed wholesale. |
| §15 Resource limits | Unchanged. |
| §16 Reserved reasons | **Extended** per D6. |
| §17 Host obligations | §17 unchanged; §17.1 now references `approval` section per D5. |
| §18 Streaming and parallel tools | Unchanged. |
| §19 Telemetry and audit | **Extended** per D2 (carries `evidence`). |
| §20 Conformance | Conformance text reads against the deltas. |
| §21 Security considerations | Unchanged in principle. The `transform` verdict is bounded to `$policy_target`, preserving the security boundary §21 established for effects. |
| §22 Approval (new) | **Added** per D5. |
