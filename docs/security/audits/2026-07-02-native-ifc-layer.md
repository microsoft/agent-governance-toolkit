# 2026-07-02 - Native Information Flow Control Layer

PR: microsoft/agent-governance-toolkit#3245

> These are the author's own security design notes and threat model for the
> change -- a **self-review, not an independent security audit**. The "Test
> coverage" section references tests and examples that ship in this same PR.

## What changed and why

Adds a native Agent Governance Toolkit information-flow-control (IFC) layer for
governed Agent OS tool execution and a first AgentMesh distributed IFC receipt
proof for native agent-to-agent message handoff.

The Agent OS change introduces:

- `agent_os.policies.information_flow`, a native IFC model with confidentiality
  and integrity labels, FIDES-compatible metadata normalization, sink policy
  parsing, reveal/declassification/endorsement helpers, quarantine handles, and
  ACS annotation projection.
- Runtime enforcement in `BaseIntegration.pre_execute_check()` and
  `post_execute_check()` so configured or explicitly marked sinks are denied
  before execution when accumulated context is untrusted or too confidential for
  the sink policy.
- Context-envelope propagation of accumulated confidentiality and sticky
  untrusted integrity.
- A new `INFORMATION_FLOW` policy violation category and decision helper for
  structured fail-closed denials.

The AgentMesh proof introduces signed IFC receipts that bind sender, recipient,
message subject, payload hash, envelope reference, workflow continuity, nonce,
expiration, and aggregate IFC labels. Verification rejects tampering, replay,
recipient/subject mismatch, expired or overlong receipts, workflow mismatch, and
confidentiality/integrity downgrades.

The purpose is to close the documented knowledge-governance gap where retrieved
or tool-produced content can influence later allowed actions without
deterministic provenance, integrity, and confidentiality tracking.

## Threat model impact

This PR adds a new governance control over sensitive content flow. The relevant
security risk is whether IFC can fail open, silently downgrade labels, or create
a claim that operators rely on outside the implemented boundary.

| Risk | Mitigation | Test coverage |
|------|------------|---------------|
| Unlabeled or malformed IFC metadata bypasses sink policy | Strict mode treats unlabeled external output as untrusted/public and denies malformed integrity, role, and sink-policy fields | `test_from_metadata_rejects_unknown_integrity`, malformed metadata denial coverage, `test_sink_policy_rejects_malformed_accepts_untrusted` |
| Public or external sinks receive untrusted content | Sinks must opt in to untrusted input with `accepts_untrusted=True`; policy-configured `sink_tools` make enforcement independent of caller-supplied metadata | `test_strict_ifc_denies_untrusted_context_to_sink`, `test_policy_configured_sink_tools_do_not_require_request_role_metadata`, `test_malicious_untrusted_content_exfiltration_is_blocked` |
| Confidential content is sent to a lower-classification sink | Sink policy enforces `max_allowed_confidentiality` before tool execution | `test_enforce_sink_blocks_confidentiality_over_limit`, `test_pre_execute_check_enforces_information_flow_sink_policy` |
| Derived content lowers the running context label | `ContextEnvelope.with_ifc_label()` uses max-lattice confidentiality and sticky untrusted integrity | `test_with_ifc_label_tracks_integrity_and_confidentiality`, `test_with_ifc_label_untrusted_is_sticky` |
| Sensitive raw values leak through quarantine references | Quarantine stores raw values behind opaque bounded `ifcvar://` handles and preserves source labels on reveal unless explicitly authorized | `test_quarantine_store_round_trips_label_without_exposing_value`, `test_reveal_preserves_original_label_by_default` |
| Declassification or endorsement happens implicitly | Reveal, declassification, and endorsement require authority, reason, and authorization reference or approved authorizer callback | `test_declassify_requires_authority_reason_and_authorization`, `test_endorse_requires_authority_reason_and_authorization`, `test_reveal_requires_authority_and_reason` |
| Distributed receipts are replayed or rebound to a different message | Receipt verification requires expected recipient, expected subject, payload hash, nonce cache, expiration, and bounded TTL | `test_verify_rejects_wrong_recipient`, `test_verify_rejects_wrong_subject`, `test_verify_rejects_replayed_nonce`, `test_verify_rejects_tampered_payload` |
| Distributed handoff downgrades confidentiality or restores trust | Child receipts are checked against parent receipt hash, workflow ID, monotone confidentiality, and no untrusted-to-trusted integrity restoration | `test_verify_rejects_child_downgrade`, `test_verify_rejects_child_integrity_restore`, `test_verify_rejects_workflow_mismatch` |

### Security boundaries

The native Agent OS IFC claim is limited to instrumented governed tool
execution. Broad distributed IFC across arbitrary mesh topologies is explicitly
out of scope until durable nonce storage, remote envelope resolution, relay-side
policy integration, and encrypted payload lifecycle semantics exist.

The distributed AgentMesh change is a proof slice for one message handoff, not a
complete distributed IFC substrate. Replay protection is in-memory only in this
PR and must be backed by durable storage before production cross-session claims.

### Existing security properties preserved

- IFC is additive and disabled unless `GovernancePolicy.information_flow.enabled`
  is set.
- Legacy tool checks continue to return the same tuple-shaped API; IFC denials
  add structured reasons without weakening existing policy checks.
- The new code does not add subprocess execution, filesystem writes for policy
  decisions, network calls, deserialization of untrusted code, or new package
  dependencies.
- Documentation and limitations pages state the implemented boundary and avoid
  claiming broad arbitrary distributed IFC.

## Test coverage

- 28 focused Agent OS IFC tests cover label parsing, FIDES-compatible metadata
  aliases, malformed metadata, strict boolean parsing, sink enforcement, reveal,
  declassification, endorsement, quarantine, ACS annotation projection, and
  runtime pre/post execution behavior.
- 13 AgentMesh receipt tests cover valid receipt acceptance and rejection of
  tampered payloads, replayed nonces, expired or future-issued receipts,
  excessive TTLs, wrong recipient/subject, workflow mismatch, downgrade, and
  integrity restoration.
- `examples/information-flow-control/demo.py` proves deterministic blocking of
  malicious untrusted content from an external email sink, with bounded reveal
  and quarantine behavior.
- `examples/distributed-information-flow-control/demo.py` proves valid
  AgentMesh receipt acceptance and tamper/downgrade/replay denial.
- Documentation in `docs/security/native-ifc-layer.md` and `docs/LIMITATIONS.md`
  links the claim to shipped code, tests, examples, and the remaining
  distributed IFC boundary.
