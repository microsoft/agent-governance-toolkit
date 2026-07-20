---
title: "ADR 0032: AGT emits TRACE v0.1 Trust Records"
last_reviewed: 2026-06-17
owner: agt-maintainers
---

# ADR 0032: AGT emits TRACE v0.1 Trust Records

- Status: accepted
- Date: 2026-06-16

## Context

AGT records every tool call via a Merkle-chained audit log (`MerkleAuditChain`,
`AuditEntry`). Entries are signed with HMAC-SHA256 and chained by hash. The
chain is tamper-evident within a deployment but not portable: verifying it
requires the shared HMAC secret, which means only the operator can verify. A
regulator, auditor, or downstream principal cannot check the evidence without
trusting the operator's key management.

TRACE v0.1 (agentrust-io/trace-spec) is an EAT-profile (RFC 9711) signed claim
that any holder of the public key can verify offline. It defines eleven required
fields covering agent identity, runtime measurement, policy binding, data
classification, build provenance, and tool transcript. It is the portable
evidence format that makes AGT's governance decisions inspectable outside the
deployment boundary.

AGT already has the raw data for most TRACE fields: the Merkle chain tip covers
`tool_transcript.hash`, `SessionState` carries the monotonic `data_class`,
`PolicyInterceptor` evaluates and records Cedar policy decisions. The gap is the
TRACE envelope, the EdDSA signature over the payload, and a handful of fields
(model, runtime, build provenance) that must be injected from configuration.

Phase 2 of TRACE (hardware attestation: TEE-measured policy bundle, TEE-bound
key in `cnf.jwk`, SCITT receipt in `transparency`) is explicitly out of scope
for AGT. cMCP and other runtimes that embed AGT handle TEE attestation at their
own boundary. When cMCP emits a TRACE record, it supersedes AGT's software-only
claim for that session. AGT's Phase 1 record is the baseline evidence for
deployments that do not run inside a TEE.

Subject identity: TRACE v0.2 accepts both `spiffe://` and `did:` URIs in
`subject` (agentrust-io/trace-spec#35, merged in trace-spec v0.2.0). AGT uses
`did:` identities and emits them directly in `subject`. No parallel SPIFFE
identity is required.

## Decision

AGT emits one TRACE v0.1 Trust Record per session, at session close, via a new
**`TRACEAuditSink`** driven by `GovernedCallable.close_session()`.

**Scope of AGT's TRACE record (Phase 1, Level 0 software-only):**

- `eat_profile`: constant `"tag:agentrust.io,2026:trace-v0.1"`
- `iat`: Unix epoch seconds taken from the last `AuditEntry` timestamp
- `subject`: `agent_did` passed to `govern()` (must be a DID or SPIFFE URI;
  a bare identifier like `"*"` emits a warning and skips the record)
- `model`, `runtime`, `build_provenance`: injected from `TraceConfig`;
  `runtime.platform` is `"software-only"`, `runtime.measurement` is
  SHA-256 of the Merkle root hash
- `policy.bundle_hash`: SHA-256 of the Cedar policy bytes, captured at
  `GovernedCallable` construction time
- `policy.enforcement_mode`: `"enforce"` (Phase 1; advisory mode is a future
  extension)
- `data_class`: taken from `TraceConfig.data_class` (defaults to `"internal"`)
- `appraisal.status`: `"affirming"` for Phase 1
- `transparency`: empty string for Phase 1
- `tool_transcript.hash`: SHA-256 of the sort-keys canonical JSON of the
  `AuditEntry` list for the session
- `tool_transcript.call_count`: total number of entries in the chain

**Wire format:**

The record is a signed JSON object (not a compact JWT). `agentrust-trace`'s
`sign_record()` embeds the Ed25519 signature as `signature` (base64url, no
padding) and the public key as `cnf.jwk` directly in the JSON dict.
`TRACEAuditSink` calls `TrustRecord.model_validate()` on the signed dict before
writing to catch schema violations at emit time. The output is written to a
UTF-8 JSON file at `TraceConfig.output_path`.

**Key management:**

Key loading is delegated entirely to `agentrust_trace.load_signing_key()`. AGT
does not manage key material directly. The `agentrust-trace` package documents
the expected environment variable for key injection; AGT does not re-expose it.

**Config surface:**

`TraceConfig` is a dataclass with: `output_path`, `model_provider`, `model_id`,
`model_version`, `build_provenance_slsa_level`, `build_provenance_digest`,
`appraisal_verifier`, `data_class`. Pass it as `trace=TraceConfig(...)` to
`govern()` or as `GovernanceConfig.trace`. The feature is default-off: omitting
`trace=` leaves the existing audit sinks unchanged.

`GovernedCallable.close_session()` triggers emission and returns the path of
the written file, or `None` if the audit log is empty or the agent ID is not a
DID/SPIFFE URI.

**Implementation:**

- `agentmesh/governance/trace_sink.py`: `TraceConfig`, `session_to_trust_record()`,
  `TRACEAuditSink`
- `agentmesh/governance/govern.py`: `GovernanceConfig.trace`, `GovernedCallable.close_session()`
- Runtime dependency: `agentrust-trace>=0.2.0` (imported inside `emit()` to
  keep the import optional at load time)

**What does not change:**

`AuditEntry`, `MerkleAuditChain`, `PolicyInterceptor`, and `SessionState` are
unchanged. `TRACEAuditSink` is an adapter over the existing chain. No existing
sink is affected. The HMAC-chained audit log continues to be written in parallel.

## Consequences

- AGT sessions produce a signed, portable evidence record verifiable by any
  holder of the public key -- no shared secret, no operator trust required for
  verification.
- Deployments that do not pass `trace=TraceConfig(...)` are unaffected. The
  feature is additive and default-off.
- `tool_transcript.hash` and the Merkle chain tip are independently derivable
  from the same `AuditEntry` list, making the TRACE record and the audit log
  mutually verifiable without a shared secret.
- Phase 2 (hardware attestation) requires no AGT changes. When cMCP or another
  TEE runtime emits a Level 2 TRACE record over the same session, it carries a
  TEE-measured `policy.bundle_hash` and a TEE-bound `cnf.jwk` that supersede
  AGT's software-only fields. The two records are linked by the shared `subject`
  and `tool_transcript.hash`.
- `did:` identities are emitted directly in `subject` -- no SPIFFE SVID
  required. TRACE v0.2 (agentrust-io/trace-spec#35) accepts `did:` natively.
- CBOR-COSE wire format is deferred to a future ADR if constrained-device
  deployments require it.

## References

- ADR-0017 (Merkle chain for audit tamper-evidence) -- the chain this sink reads.
- ADR-0019 (OTel BatchSpanProcessor pattern for event sink) -- sink protocol.
- ADR-0025 (structural typing for sink and source protocols) -- the Protocol
  this sink implements.
- ADR-0009 (RFC 9334 RATS architecture alignment) -- the attestation framing
  TRACE extends.
- agentrust-io/trace-spec v0.2.0 -- the claim schema and conformance tests.
- agentrust-trace v0.2.0 (PyPI) -- `TrustRecord`, `sign_record`, `load_signing_key`.
- agentrust-io/cmcp#124 -- Phase 2 TEE enforcement; the runtime that will
  supersede this record for TEE deployments.
