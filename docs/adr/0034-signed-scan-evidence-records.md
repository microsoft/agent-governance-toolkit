# ADR 0034: Signed scan evidence records and a pre-tool-use verification gate

- Status: proposed
- Date: 2026-07-08
- Related issue: [#3111](https://github.com/microsoft/agent-governance-toolkit/issues/3111)

## Context

AGT already produces security-scan results on several surfaces: the compliance scanner
(`agent-governance-python/agent-compliance/.../security/scanner.py`) emits findings on a
`critical|high|medium|low` scale with critical/high blocking merges, and the TypeScript SDK's
`McpSecurityScanner.scan()` returns `{ tool_name, threats[], risk_score, safe }` for MCP tool
definitions. These results are **self-asserted and ephemeral**: they exist in the process that ran
the scan, and no downstream party — a `PreToolUse` gate on another machine, a different agent
runtime, an auditor — can verify after the fact *what* was scanned, *what* was found, or *whether
the result is authentic*, without re-running the scanner and trusting its operator.

Discussion in #3111 converged on the gap: policy today can gate on a "trust-me flag," not on
evidence. The nearest existing mechanism, `minimumPromptDefenseGrade`, is currently surfaced as
status (`agt_policy_status`) but not enforced at the `PreToolUse` seam, and its input is likewise
unsigned.

Prior ADRs provide all the required building blocks: Ed25519 identity (ADR-0001), external JWKS
federation (ADR-0007), fail-closed policy evaluation (ADR-0013), tamper-evident audit (ADR-0017),
RFC 8785 (JCS) content-addressing (ADR-0030), and Ed25519-signed JSON records with an embedded
`cnf.jwk` (ADR-0032). This ADR composes them; it introduces no new cryptographic primitives.

## Decision

### 1. Scan evidence record (wire format)

A **scan evidence record** is a JSON object:

```json
{
  "record_type": "scan-evidence",
  "schema_version": 1,
  "issuer": "https://scanner.example.com",
  "subject": {
    "tool_name": "github_search",
    "tool_definition_digest": "9f2c…e1",
    "source_digest": "3ab0…77"
  },
  "scan": {
    "scanner": "agent-compliance/2.4.0",
    "profile": "mcp-tool",
    "findings_summary": { "critical": 0, "high": 0, "medium": 1, "low": 2 },
    "risk_score": 12
  },
  "issued_at": "2026-07-08T17:00:00Z",
  "expires_at": "2026-08-07T17:00:00Z",
  "record_digest": "c41d…9a",
  "signature": "base64url…",
  "cnf": { "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "…" } }
}
```

- `subject.tool_definition_digest` MUST be the lowercase-hex SHA-256 digest of the RFC 8785 (JCS)
  serialization of the tool definition that was scanned (the same canonicalization discipline as
  ADR-0030's `action_digest`). `source_digest` is OPTIONAL (content digest of scanned source, for
  `plugin-source` profiles).
- `scan.profile` enumerates the scan surface: `mcp-tool` | `plugin-source` | `dependency`.
  `scan.findings_summary` (severity counts on the existing `critical|high|medium|low` scale) is
  REQUIRED; `scan.risk_score` (0–100, per `McpScanResult`) and `scan.scanner` are informational.
- `record_digest` MUST be the lowercase-hex SHA-256 of the JCS serialization of the record with
  `record_digest`, `signature`, and `cnf` omitted. `signature` MUST be an Ed25519 signature
  (ADR-0001) over those same JCS bytes, base64url without padding, with the public key embedded in
  `cnf.jwk` — the signed-JSON pattern established by ADR-0032, not a compact JWT/JWS.
- The schema is deliberately **scanner-agnostic**: any scanner (first-party or external) that can
  produce severity counts over a content-addressed subject can emit it. Nothing in the format is
  specific to one vendor or one scanning methodology.

### 2. Key distribution, trust, and revocation

- Verifiers resolve issuer keys per ADR-0007 (external JWKS federation, existing TTL semantics).
  Policy MAY additionally pin keys inline (below) for air-gapped or test use.
- `cnf.jwk` names the signing key; verification MUST confirm that key is present in the issuer's
  currently published JWKS (or the pinned set) — the embedded key is a locator, not a root of trust.
- Revocation is by expiry and key rotation: records carry a mandatory `expires_at` (issuers SHOULD
  default to ≤30 days); removing a key from the published JWKS invalidates all records signed by
  it at next TTL refresh. No CRL mechanism is introduced.

### 3. Emission (opt-in)

- The compliance scanner and `McpSecurityScanner` gain an opt-in flag (`--emit-signed-evidence` /
  `emitSignedEvidence`) that writes a record alongside their current output. Default remains
  current behavior; no output changes when the flag is off.
- Signing/verification implementations MUST live in the designated crypto modules and reuse the
  existing SDK identity APIs (`scripts/ci/no-custom-crypto.sh` boundary); the gate calls them, it
  does not implement primitives.

### 4. Policy surface

Three new OPTIONAL top-level policy keys, siblings of `minimumPromptDefenseGrade`:

```json
{
  "requireSignedScanEvidence": false,
  "minimumToolEvidenceGrade": "C",
  "trustedScanEvidenceIssuers": [
    { "issuer": "https://scanner.example.com", "jwksUrl": "https://scanner.example.com/.well-known/jwks.json" },
    { "issuer": "urn:local-ci", "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "…" } }
  ]
}
```

- `requireSignedScanEvidence` defaults to **false** (default-off, consistent with new-feature
  posture). When false, evidence records — if present — contribute advisory context only.
- `minimumToolEvidenceGrade` reuses the existing A–F grade order (`{A:5, B:4, C:3, D:2, F:1}`,
  default `"C"`, same semantics as `isBlocking`). A record's grade is derived deterministically
  from `findings_summary`: any `critical` → F; else any `high` → D; else any `medium` → C; else
  any `low` → B; else A. Deriving from severity counts (not trusting a self-declared grade field)
  keeps grading policy-side and deterministic (ADR-0004).
- `trustedScanEvidenceIssuers` is the allowlist; an empty or absent list with
  `requireSignedScanEvidence: true` is a policy configuration error (deny per ADR-0013 +
  `denyOnPolicyError`).

### 5. PreToolUse verification flow

Evidence records are discovered from a policy-configured `scanEvidencePaths` list (local
directories and/or HTTPS URLs), keyed by `tool_name`, with remote lookups cached by
`record_digest`.

When `requireSignedScanEvidence` is true, `evaluatePreToolUse` performs, after the existing
`toolPolicies` / `blockedToolCalls` checks and before returning `allow`:

1. Compute the JCS digest of the live tool definition.
2. Locate an evidence record for that `tool_name` whose `subject.tool_definition_digest` matches.
   **A digest mismatch is treated as no evidence** — a tool definition that changed after it was
   scanned is unverified by construction.
3. Verify: signature against a trusted issuer key; `issued_at`/`expires_at` window; recompute
   `record_digest`.
4. Derive the grade and compare to `minimumToolEvidenceGrade`.

Decision mapping follows the existing `allow | review | deny` contract: missing, drifted,
expired, unverifiable, or below-grade evidence → `deny` in `enforce` mode, `review` in
`advisory` mode. Any evaluation exception fails closed per ADR-0013 (subject to the existing
`denyOnPolicyError` opt-out). Every verification outcome is appended to the audit log via the
existing `appendAuditEntry` path with the record's `record_digest`, giving the ADR-0017 chain a
verifiable pointer to the exact evidence used.

**Composition with the existing grade gate:** `minimumPromptDefenseGrade` and
`minimumToolEvidenceGrade` are independent axes (the prompt's defense posture vs. the tool's
scanned safety); both use the same grade algebra, and this ADR does not change prompt-defense
behavior or promote it from status to enforcement.

### What does not change

- Default behavior everywhere: all new keys default off/absent; scanners emit nothing new without
  the flag; `PreToolUse` behavior is byte-identical for policies that do not opt in.
- No new crypto primitives, no new dependency on any external service or vendor, no change to
  `agt_policy_status` / `agt_policy_check_text` contracts (status output MAY additionally report
  evidence verification state).
- No letter-grade changes to `PromptDefenseEvaluator` or `McpSecurityScanner` outputs.

## Acceptance criteria

- A record emitted by the compliance scanner verifies offline (signature, digests, window) with
  no network access when the issuer key is pinned in policy.
- Byte-for-byte reproducibility: two independent implementations of §1 produce identical
  `record_digest` for the same record (JCS discipline, as in ADR-0030).
- A modified tool definition (any semantic change to the JCS serialization) causes step-2 digest
  mismatch → `deny` in enforce mode, with the mismatch reason in the audit entry.
- An expired record, an unknown issuer, and a tampered `findings_summary` each independently
  cause verification failure with distinct audit reasons.
- With `requireSignedScanEvidence: false`, the full existing policy test suite passes unchanged.

## Consequences

- Positive: scan results become portable, attributable, independently verifiable evidence; the
  `PreToolUse` seam can enforce "this exact tool definition was scanned and graded ≥ X" without
  trusting the scanner's operator or re-running the scan; drift after scanning is caught
  structurally; auditors get content-addressed pointers from the ADR-0017 chain to the evidence.
- Negative / accepted: policy evaluation gains a signature verification on the tool path
  (Ed25519 verify is sub-millisecond; records are cacheable by `record_digest`). The hot path
  meets the ADR-0004 budget only with a warm JWKS cache (existing ADR-0007 TTL semantics) —
  implementations SHOULD resolve issuer JWKS at session start, keeping `PreToolUse` itself to
  digest compare + signature verify with no network dependency; operators who
  enable enforcement must run or trust at least one issuer; a new schema surface must be
  versioned (`schema_version`, following the `schemaVersion` precedent).
- Deferred (future ADRs): evidence transparency/append-only publication, richer finding taxonomies
  in the record, per-finding (rather than summary) disclosure, external envelope encodings.

## Alternatives considered

### Compact JWS/JWT envelope
Rejected for the primary format. ADR-0032 established signed-JSON-with-`cnf.jwk` as the house
pattern; a second envelope style would fragment verification code. Because the record is
JCS-canonicalized, a detached JWS carrying the same bytes remains possible as an external interop
encoding without changing this schema — deferred.

### Gate on a live scanner service instead of signed records
Rejected. Couples policy evaluation to a runtime dependency and a trusted operator — exactly the
"trust-me flag" #3111 argues against — and violates the offline-verifiable requirement. Fails
ADR-0004's determinism intent.

### Re-scan at invocation time
Rejected as the enforcement primitive. Scanning in the `PreToolUse` hot path is slow,
non-deterministic across scanner versions, and still self-asserted. Re-scanning remains how
records are *refreshed*.

### Trust a self-declared grade field in the record
Rejected. Deriving the grade policy-side from severity counts keeps grading deterministic and
uniform across issuers (ADR-0004) and shrinks the trusted surface of the record.

## References

- [#3111](https://github.com/microsoft/agent-governance-toolkit/issues/3111) — discussion that
  motivated this ADR
- [ADR-0001](0001-use-ed25519-for-agent-identity.md) — Ed25519 identity
- [ADR-0004](0004-keep-policy-evaluation-deterministic.md) — deterministic policy evaluation
- [ADR-0007](0007-external-jwks-federation-for-cross-org-identity.md) — JWKS federation
- [ADR-0013](0013-fail-closed-on-policy-evaluation-errors.md) — fail-closed convention
- [ADR-0017](0017-merkle-chain-for-audit-tamper-evidence.md) — tamper-evident audit
- [ADR-0030](0030-action-bound-approval-protocol.md) — RFC 8785 content-addressing precedent
- [ADR-0032](0032-agt-emits-trace-v01-trust-records.md) — signed JSON record pattern
- RFC 8785 (JSON Canonicalization Scheme), RFC 7517 (JWK)
