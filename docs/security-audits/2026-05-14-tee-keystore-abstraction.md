# Security Audit: TEE Keystore Abstraction

**Date:** 2026-05-14
**PR:** feat(identity): add TEE keystore abstraction
**Scope:** `agentmesh.identity.tee_keystore`, `agentmesh.exceptions.KeyAcquisitionError`
**Author:** Pawan Khandavilli

## What changed and why

Added an async TEE-aware key acquisition layer (ADR 0010, PR 3) that supports
Secure Key Release and TEE-generated keys alongside the existing synchronous
`KeyStore`. New types:

- `TEEKeyHandle` (ABC): opaque signer handle with expiry enforcement
- `SoftwareKeyHandle`: concrete in-memory Ed25519 implementation for development/test adapters
- `TEEKeyStore` (ABC): async key acquisition interface
- `LocalTEEKeyStore`: development/test non-TEE adapter (key_origin=LOCAL)
- `MockSKRKeyStore`: CI-safe mock for Secure Key Release
- `require_tee_bound_key()`: policy helper for fail-closed enforcement
- `KeyAcquisitionError`: new exception for TEE key failures

## Threat model impact

### New attack surface

1. **Key handle expiry bypass**: If callers bypass `sign()` and access
   `_private_key` directly on `SoftwareKeyHandle`, they skip the expiry check.

   **Mitigation:** `_private_key` is a private attribute (underscore-prefixed,
   not exposed in any public interface). The `TEEKeyHandle` ABC does not expose
   raw key material. Future real TEE implementations will use opaque signers
   where the key is not extractable at all.

2. **Silent downgrade from TEE to local keys**: If the handshake or policy
   layer fails to check `key_origin`, an agent could claim TEE-bound identity
   while using a local key.

   **Mitigation:** `require_tee_bound_key()` helper provided for policy
   enforcement. PR 5 (policy integration) will wire this into the trust policy
   engine. The `KeyOrigin.is_tee_bound` property makes the check explicit.

3. **Dev/test adapter used in production**: `MockSKRKeyStore` or `LocalTEEKeyStore` could
   be deployed instead of a real TEE store.

   **Mitigation:** These stores honestly report `key_origin=LOCAL` or the
   configured mock origin. The policy engine (PR 5) will reject non-TEE origins
   when attestation is required. There is no silent fallback. The module
   docstrings explicitly mark both classes as development/test adapters.

4. **In-process private key cache**: `LocalTEEKeyStore` and `MockSKRKeyStore`
   cache generated Ed25519 private keys in normal Python dictionaries so tests
   can run without confidential hardware.

   **Mitigation:** These classes are development/test adapters only and expose
   `key_origin=LOCAL` or a configured mock origin. Production TEE/SKR providers
   must return opaque signer handles backed by the TEE, HSM, or provider SDK so
   raw key material is not retained in Python process memory. If a future
   provider must handle software key bytes temporarily, it should use
   backend-supported memory locking and zeroization patterns before exposing a
   `TEEKeyHandle`.

### Existing security properties preserved

- Existing `KeyStore`, `SoftwareKeyStore`, and `PKCS11KeyStore` are unchanged.
- No new network calls or cloud dependencies introduced.
- No new secrets or credentials handled (real SKR is PR 6).
- All new code is testable without confidential hardware.

## Mitigations

| Risk | Mitigation | Verified by |
|------|-----------|-------------|
| Expired handle used for signing | `sign()` checks `is_expired()` before signing | `test_sign_rejects_expired_handle` |
| Local key accepted as TEE-bound | `require_tee_bound_key()` raises `KeyAcquisitionError` | `TestRequireTEEBoundKey` |
| KeyAcquisitionError not raised on SKR failure | MockSKRKeyStore wraps errors in `KeyAcquisitionError` | `test_error_injection_wraps_in_key_acquisition_error` |
| Key origin misreported | All stores declare `key_origin()` matching actual behavior | `test_key_origin_*` tests |
| Dev/test store mistaken for production TEE storage | Local and mock stores are documented as non-production adapters | Docstring and audit review |

## Test coverage

- 30+ test cases covering: handle signing, expiry, key_origin propagation,
  store acquire/cache semantics, error injection, latency simulation,
  fail-closed policy enforcement, ABC contract verification.
- All tests run in standard CI without TEE hardware.
- No mocked exceptions escape without proper wrapping.
