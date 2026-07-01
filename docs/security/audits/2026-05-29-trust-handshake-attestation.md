# Security Audit: Trust Handshake Attestation

**Date:** 2026-05-29
**PR:** feat(trust): add optional handshake attestation
**Scope:** `agentmesh.identity.attestation`, `agentmesh.identity.attestation_collector`, `agentmesh.trust.handshake`

## What changed and why

Added a provider-neutral ADR 0010 attestation request/binding shape and optional
attestation fields to the trust handshake response and result models. When configured,
the verifier validates cached startup attestation evidence and a fresh Ed25519 signature
over the Layer 2 challenge transcript. Legacy handshakes remain unchanged when attestation
is not configured or required.

## Threat model impact

### New attack surface

1. **Replay of attested responses**: An attacker could reuse a previously valid attestation
   response for the same challenge.

   **Mitigation:** Successful attested challenge tuples are recorded and rejected on reuse.
   Failed verification attempts do not consume the challenge.

2. **Token swapping**: An attacker could pair a valid signature with unrelated attestation
   evidence.

   **Mitigation:** The Layer 2 transcript includes a SHA-256 hash of the attestation token,
   and the verifier checks that the attestation public key hash matches the evidence binding.

3. **Silent local-key downgrade**: A peer could provide local-key evidence where a TEE-bound
   key is required.

   **Mitigation:** `require_tee_bound_key=True` rejects claims whose `key_origin` is not
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
   runtime data, Nitro user data, TDX report data, or OIDC/EAT nonce inputs.

### Existing security properties preserved

- Registry membership and active-status checks still run before trust succeeds.
- The existing Ed25519 identity signature over the handshake payload is still required.
- Registry-authoritative trust score and capabilities are still used instead of self-reported
  response values.
- Missing attestation does not affect legacy handshakes unless explicitly required.

## Mitigations

| Risk | Mitigation | Verified by |
|------|------------|-------------|
| Missing evidence accepted in required mode | Required mode fails closed | `test_required_attestation_rejects_missing_evidence` |
| Local key accepted as TEE-bound | Key-origin check rejects local claims | `test_required_tee_bound_key_rejects_local_origin` |
| Provider-specific binding required | Collector accepts opaque binding bytes | `test_mock_attestation_collector_accepts_opaque_provider_bindings` |
| Tampered Layer 2 signature accepted | Ed25519 verification over canonical transcript | `test_attestation_signature_tampering_is_rejected` |
| Challenge replay accepted | Successful attested challenges are single-use | `test_attestation_replay_is_rejected_after_success` |

## Test coverage

- Optional mode preserves legacy behavior when no evidence is supplied.
- Provider-neutral startup bindings and legacy full ADR bindings both validate.
- Mock collectors accept opaque Azure/Nitro/TDX/GCP-style binding bytes.
- Required mode validates attestation evidence, key origin, and Layer 2 signatures.
- Replay and tampering tests run in normal CI using mock keystore and verifier components.
