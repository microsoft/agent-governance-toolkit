# ADR 0032: AGT emits TRACE v0.1 Trust Records

- Status: proposed
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
TRACE envelope, the EdDSA signature over a JCS-canonical payload, and a handful
of fields (model, runtime, build provenance) that must be injected from
configuration.

Phase 2 of TRACE (hardware attestation: TEE-measured policy bundle, TEE-bound
key in `cnf.jwk`, SCITT receipt in `transparency`) is explicitly out of scope
for AGT. cMCP and other runtimes that embed AGT handle TEE attestation at their
own boundary. When cMCP emits a TRACE record, it supersedes AGT's software-only
claim for that session. AGT's Phase 1 record is the baseline evidence for
deployments that do not run inside a TEE.

Subject identity: TRACE v0.1 requires a `spiffe://` URI in `subject`. AGT uses
`did:mesh:` identities. For Phase 1, deployments configure `TRACE_AGENT_SVID`
explicitly. A spec issue is filed against trace-spec to add DID support in
TRACE v0.2 so that DID-native deployments do not require a parallel SPIFFE
identity.

## Decision

AGT emits one TRACE v0.1 Trust Record per session, at session close, via a new
**`TRACEAuditSink`** that follows the pluggable-sink protocol of ADR-0025.

**Scope of AGT's TRACE record (Phase 1, Level 0 software-only):**

- `eat_profile`: constant `"tag:agentrust.io,2026:trace-v0.1"`
- `iat`: session-close Unix epoch seconds
- `subject`: value of `TRACE_AGENT_SVID` config; fail-fast at startup if
  `TRACE_EMIT=true` but the field is absent
- `model`, `runtime`, `build_provenance`: config-injected; `runtime.platform`
  is `"software-only"` and `runtime.measurement` is zero-filled for Phase 1
- `policy.bundle_hash`: SHA-256 of the Cedar policy bundle bytes, captured at
  `PolicyInterceptor` load time and carried through to the sink
- `policy.enforcement_mode`: `"enforce"` or `"advisory"` from config
- `data_class`: `SessionState.monotonic_data_class` (highest classification
  reached in the session)
- `appraisal.status`: `"affirming"` if the session had zero deny decisions,
  `"contraindicated"` if any deny was recorded
- `transparency`: empty string for Phase 1
- `cnf.jwk`: Ed25519 public key derived from `TRACE_PRIVATE_KEY_PEM` env var;
  ephemeral key generated with a startup warning if the var is absent
- `tool_transcript.hash`: SHA-256 of RFC 8785 JCS-canonical JSON of the
  `AuditEntry` list for the session (same preimage as the Merkle chain tip,
  making the two independently verifiable against each other)
- `tool_transcript.call_count`: count of `tool_invocation` entries in the chain

The record is serialized as a compact JWT, signed with EdDSA over the
JCS-canonical payload. The JWT is written by `TRACEAuditSink` to a configured
path or POSTed to a configured endpoint.

**What does not change:**

`AuditEntry`, `MerkleAuditChain`, `PolicyInterceptor`, and `SessionState` are
unchanged. `TRACEAuditSink` is an adapter over the existing chain: it reads the
chain at session close and maps fields to the TRACE model. No existing sink is
affected. The HMAC-chained audit log continues to be written by existing sinks
in parallel.

**Config surface:**

New top-level `trace:` config block with: `emit` (bool, default false),
`agent_svid`, `output_path`, `endpoint`, `model`, `build_provenance`. Key
material via `TRACE_PRIVATE_KEY_PEM` env var only (never in config files).

## Consequences

- AGT sessions produce a signed, portable evidence record verifiable by any
  holder of the public key -- no shared secret, no operator trust required for
  verification.
- Deployments that do not set `TRACE_EMIT=true` are unaffected. The feature
  is additive and default-off.
- `tool_transcript.hash` being derived from the Merkle chain tip means the
  TRACE record and the audit log are mutually verifiable: a verifier can
  recompute the hash from the log and confirm it matches the claim.
- Phase 2 (hardware attestation) requires no AGT changes. When cMCP or another
  TEE runtime emits a Level 2 TRACE record over the same session, it carries a
  TEE-measured `policy.bundle_hash` and a TEE-bound `cnf.jwk` that supersede
  AGT's software-only fields. The two records are linked by the shared
  `subject` SVID and `tool_transcript.hash`.
- `did:mesh:` deployments must configure a parallel SPIFFE SVID for Phase 1.
  This is resolved at the protocol level in TRACE v0.2 (filed as
  agentrust-io/trace-spec#35).
- EAT wire format is JWT for Phase 1. CBOR-COSE is deferred to a future ADR if
  constrained-device deployments require it.

## References

- ADR-0017 (Merkle chain for audit tamper-evidence) -- the chain this sink reads.
- ADR-0019 (OTel BatchSpanProcessor pattern for event sink) -- sink protocol.
- ADR-0025 (structural typing for sink and source protocols) -- the Protocol
  this sink implements.
- ADR-0009 (RFC 9334 RATS architecture alignment) -- the attestation framing
  TRACE extends.
- agentrust-io/trace-spec v0.1 -- the claim schema and conformance tests.
- agentrust-io/cmcp#124 -- Phase 2 TEE enforcement; the runtime that will
  supersede this record for TEE deployments.
