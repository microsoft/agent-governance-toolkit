# AGT-EVIDENCE-1.0.md — Proof artefacts and verification pointers

**Status:** Draft. **Version:** `1.0.0-alpha`. **Layer:** policy dispatcher contract + telemetry.

This document defines how high-assurance policy dispatchers communicate
offline-verifiable evidence with the rest of AGT. It complements
`SPECIFICATION.md` §13.3 and §19.

## 1. Motivation

Three classes of dispatchers want to ship evidence alongside their decisions:

1. **SMT-verified gates** — a Z3 / CVC5 proof script generated offline whose
   hash is bundled with the verdict so an auditor can re-derive it.
2. **Mechanised-proof PDPs** — Coq / Lean / F* derivations of the decision
   stored in a registry.
3. **TEE-attested PDPs** — an SGX / TDX / AMD-SEV attestation token over the
   binary that produced the decision.

In all three cases the evidence is opaque to the runtime and bounded in size.

## 2. Verdict-level evidence

Per `SPECIFICATION.md` §13.3, a verdict MAY carry:

```json
"evidence": {
  "artefact": "sha256:<hex> | uri",
  "verification_pointers": {
    "<role>": "<url>"
  }
}
```

Implementation requirements:

- `artefact` MUST be either `sha256:<lowercase-hex>` (content address) or an
  RFC-3986 URI.
- `verification_pointers` keys are short identifiers documented per-dispatcher
  (e.g., `issuer_pubkey`, `policy_registry`, `attestation_endpoint`).
  Values are URIs an auditor may consult.
- Total evidence object MUST NOT exceed 4 KiB serialised. A dispatcher that
  produces a larger evidence object MUST be considered to have failed and the
  runtime MUST emit `runtime_error:policy_output_invalid`.

## 3. Telemetry-level evidence

The runtime always propagates evidence to telemetry events when present. The
events that MAY carry evidence are the upstream ACS-named events listed below;
the names match `SPECIFICATION.md` §19.

| Event | Carries evidence when |
| --- | --- |
| `policy.invoked` | Always when the verdict has `evidence`. |
| `intervention_point.allowed` | Originating verdict carried `evidence`. |
| `intervention_point.denied` | Originating verdict carried `evidence`. |
| `intervention_point.warned` | Originating verdict carried `evidence`. |
| `intervention_point.escalated` | Originating verdict carried `evidence`. |
| `intervention_point.transformed` | Originating verdict carried `evidence`. |

On each event the runtime emits:

- `evidence_artefact`: the verbatim `artefact` string from the verdict.
- `evidence_verification_pointer_keys`: the sorted list of
  `verification_pointers` keys, not their URL values.

The URL values are deliberately omitted from telemetry to keep telemetry
cardinality bounded. Auditors retrieve the full pointer map from the audit
log (per §4).

## 4. Audit record

An AGT audit record MUST store:

| Field | Source |
| --- | --- |
| `evidence_artefact` | verbatim from verdict, when the verdict carried `evidence.artefact` |
| `verification_pointers` | full map from verdict, when the verdict carried `evidence.verification_pointers` |
| `input_identity` | `SPECIFICATION.md` §13.1 |
| `enforced_identity` | `SPECIFICATION.md` §13.1 |
| `intervention_point` | request |
| `policy_id` | manifest |
| `mode` | request |
| `verdict` | runtime |
| `reason` | verdict |
| `dispatcher` | configured for the policy |

The MUST applies to every audit record an AGT host writes for an engine
evaluation. `input_identity` and `enforced_identity` are equal for
non-transform verdicts but the record carries both fields anyway, so audit
consumers can rely on a stable schema.

The verification flow for an auditor is:

1. Read `evidence_artefact` and `verification_pointers` from the audit record.
2. Fetch the proof blob from the pointer URL or content registry.
3. Verify the proof corresponds to `input_identity` (what the policy saw) and,
   when the verdict was `transform`, that the published proof covers the
   `enforced_identity` (what the host actually executed).
4. If the proof verifies, the decision is reproducible.

## 5. Backwards-compat note

This is the v5 equivalent of the v4 `BackendDecision.proof_artefact` and
`BackendDecision.verification_pointers` fields shipped in
`agent_os.policies.backends` (changelog entry under "Added"). The semantics
are unchanged; the carrier moves from a backend-decision wrapper to the
verdict and telemetry directly.

The v4-to-v5 migration tool MUST translate:

- Any `BackendDecision` with non-empty `proof_artefact` or
  `verification_pointers` → ACS verdict with the same data under `evidence`.

## 6. Reference dispatchers

AGT ships reference dispatchers for the three motivating classes under
`integrations/dispatchers/`:

| Dispatcher | Crate / package |
| --- | --- |
| `agt-dispatcher-smt-z3` | Rust + Python; emits `artefact: sha256:` of a Z3 script. |
| `agt-dispatcher-tee-sgx` | Rust + Python; emits `artefact` and `verification_pointers.attestation_endpoint`. |
| `agt-dispatcher-static-proof` | Reads a pre-generated proof from disk and attaches it. |

These reference dispatchers are scheduled for M5 / post-5.0 and are not
required for 5.0 GA.

## 7. Conformance

An AGT SDK conforms to this spec when it:

1. Round-trips the `evidence` field on the verdict without loss.
2. Emits `evidence_artefact` and `evidence_verification_pointer_keys` on
   telemetry events that carry an evidenced verdict.
3. Persists the full `evidence` object in any audit record the SDK writes.
