---
title: Trust Handshake Attestation Security Audit
last_reviewed: 2026-07-31
owner: agt-maintainers
---

# Security Audit: Trust Handshake Attestation

**Date:** 2026-05-29
**PR:** feat(trust): add optional handshake attestation
**Scope:** `agentmesh.identity.attestation`, `agentmesh.identity.attestation_collector`, `agentmesh.trust.handshake`

## What changed and why

Added a provider-neutral ADR 0010 attestation request/binding shape and optional
attestation fields to the trust handshake response and result models. When configured,
the verifier validates cached startup attestation evidence and a fresh Ed25519 signature
over the Layer 2 challenge transcript. Legacy handshakes remain unchanged when no attestation
evidence is supplied and attestation is not required. Once a peer supplies evidence, the complete
attestation bundle must verify even in optional mode.

## Threat model impact

### New attack surface

1. **Replay of attested responses**: An attacker could reuse a previously valid attestation
   response for the same challenge.

   **Mitigation:** Successful attested challenge tuples are retained through the local challenge
   validity window and rejected on reuse. Expired entries are purged, but an unexpired full replay
   cache rejects new reservations instead of evicting replay history. Failed verification attempts
   do not consume the challenge.

2. **Token swapping**: An attacker could pair a valid signature with unrelated attestation
   evidence.

   **Mitigation:** The Layer 2 transcript includes a SHA-256 hash of the attestation token.
   The handshake computes the expected provider-neutral report-data binding, passes it to the
   attestation verifier, and checks that the attestation public key hash matches the evidence
   binding.

3. **Silent local-key downgrade**: A peer could provide local-key evidence where a TEE-bound
   key is required.

   **Mitigation:** Evidence, signed response metadata, and verifier-normalized claims must agree
   on `key_origin`. `require_tee_bound_key=True` then rejects verifier claims whose origin is not
   `skr` or `tee_generated`.

4. **Hot-path provider dependency**: A production verifier could accidentally put remote
   attestation collection in the handshake path.

   **Mitigation:** The handshake accepts already-collected evidence and performs only local
   transcript signing and verifier validation. Provider-specific network acquisition remains
   outside PR 4.

5. **Provider-specific binding leakage**: A collector interface that requires AGT handshake
   fields or Azure-specific concepts could make Azure C-ACI the accidental base API.

   **Mitigation:** Collectors accept `AttestationRequest(binding=...)`, where `binding` is
   opaque provider-neutral bytes. Future providers decide whether to carry those bytes in
   runtime data, Nitro user data, TDX report data, or OIDC/EAT nonce inputs. This binding is
   distinct from Azure ACI `HostData`, which represents the confidential computing enforcement
   policy digest.

6. **Peer-controlled freshness or policy no-ops**: Future-dated evidence or incompletely
   configured image policies could bypass intended freshness and image checks.

   **Mitigation:** Verifiers reject evidence timestamps later than verifier time.
   `SIGNING_IDENTITY` requires a non-empty signer allowlist, and the unimplemented
   `STABLE_CLAIMS` mode is rejected during configuration.

### Existing security properties preserved

- Registry membership and active-status checks still run before trust succeeds.
- The existing Ed25519 identity signature over the handshake payload is still required.
- Registry-authoritative trust score and capabilities are still used instead of self-reported
  response values.
- Missing attestation does not affect legacy handshakes unless explicitly required.
- Presented evidence cannot downgrade to an unattested handshake when its verifier, signature,
  or public key is missing.

## Mitigations

| Risk | Mitigation | Verified by |
|------|------------|-------------|
| Missing evidence accepted in required mode | Required mode fails closed | `test_required_attestation_rejects_missing_evidence` |
| Incomplete evidence accepted in optional mode | Presented evidence always requires a verifier, signature, and public key | `test_optional_attestation_rejects_evidence_without_verifier`, `test_optional_attestation_rejects_incomplete_bundle` |
| Local key accepted as TEE-bound | Key-origin check rejects local claims | `test_required_tee_bound_key_rejects_local_origin` |
| Provider-specific binding required | Collector accepts opaque binding bytes | `test_mock_attestation_collector_accepts_opaque_provider_bindings` |
| Provider evidence not bound to the expected agent key | Verifier receives and validates the expected provider-neutral report-data hash | `test_required_attestation_rejects_unexpected_report_data_hash` |
| Tampered Layer 2 signature accepted | Ed25519 verification over canonical transcript | `test_attestation_signature_tampering_is_rejected` |
| Challenge replay accepted | Successful attested challenges are single-use | `test_attestation_replay_is_rejected_after_success` |
| Replay history evicted under load | Unexpired full replay cache fails closed | `test_attestation_replay_cache_fails_closed_at_capacity` |
| Replay cache grows forever | Entries are removed only after challenge expiry | `test_attestation_replay_cache_purges_expired_entries` |
| Future-dated evidence accepted | Handshake and verifier reject timestamps later than verifier time | `test_future_attestation_evidence_is_rejected_by_handshake_layer`, `test_mock_attestation_verifier_rejects_future_dated_evidence` |
| Inconsistent key-origin metadata accepted | Evidence, response, and claims must agree | `test_required_attestation_rejects_evidence_key_origin_mismatch` |
| Empty or unsupported image policy silently passes | Configuration validation fails closed | `test_rejects_signing_identity_without_allowed_signers`, `test_rejects_unsupported_stable_claims_policy` |

## Test coverage

- Optional mode preserves legacy behavior when no evidence is supplied, but fully validates any
  evidence that is supplied.
- Provider-neutral startup bindings and legacy full ADR bindings are passed to the verifier for
  validation against provider-authenticated report data.
- Mock collectors accept opaque Azure/Nitro/TDX/GCP-style binding bytes.
- Required mode validates attestation evidence, three-way key-origin agreement, evidence time,
  reference-policy configuration, and Layer 2 signatures.
- Replay capacity, expiry, and tampering tests run in normal CI using mock keystore and verifier
  components.
