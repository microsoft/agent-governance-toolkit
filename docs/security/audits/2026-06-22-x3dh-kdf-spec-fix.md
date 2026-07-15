---
title: "2026-06-22 - X3DH KDF Signal-spec fix (TypeScript SDK)"
last_reviewed: 2026-06-24
owner: agt-maintainers
---

# 2026-06-22 - X3DH KDF Signal-spec fix (TypeScript SDK)

PR: microsoft/agent-governance-toolkit#3128

## What changed and why

The TypeScript X3DH key-derivation function in
`agent-governance-typescript/src/encryption/x3dh.ts` derived the root key
with the wrong HKDF inputs:

```ts
// before — F used as the HKDF salt, bare DH concat as IKM
const FF_SALT = new Uint8Array(32).fill(0xff);
function kdf(ikm: Uint8Array) {
  return hkdf(sha256, ikm, FF_SALT, X3DH_INFO, KEY_LEN);
}
```

The Signal X3DH specification (§2.2) requires:

```
IKM  = F || DH_concat      where F = 0xFF × 32
salt = 0x00 × 32           (the HKDF salt is the zero block, NOT F)
info = "AgentMesh_X3DH_v1"
```

The fix passes `F` as a **prefix to the IKM** and uses a **zero salt**:

```ts
const F_PREFIX = new Uint8Array(32).fill(0xff);
const ZERO_SALT = new Uint8Array(32);
export function kdf(ikm: Uint8Array) {
  return hkdf(sha256, concat(F_PREFIX, ikm), ZERO_SALT, X3DH_INFO, KEY_LEN);
}
```

The **Python SDK was already corrected** to this spec behavior in #1926
(`agent-governance-python/.../encryption/x3dh.py`). The TypeScript SDK was
never aligned, so a Python initiator and a TypeScript responder (or vice
versa) completed the X3DH handshake / KNOCK but then derived **different**
root keys and failed to decrypt the first encrypted message with
`invalid tag`. This change brings TypeScript to parity with Python and the
spec.

`kdf` is now exported (via the module deep path, not the public package
barrel) solely so the test suite can pin the exact derived key against a
cross-runtime known-answer vector.

## Threat model impact

This change corrects a **cryptographic correctness / interoperability**
defect on the session-establishment path. It does not add identity, trust,
or new attack surface.

| Dimension | Direction |
|---|---|
| Confidentiality | **Neutral to strengthened.** Both the old and new KDFs are HKDF-SHA256 over the same DH secret material, so neither is weaker; the old one simply derived a *different*, non-spec key. The fix removes a silent cross-runtime divergence. |
| Key agreement secrecy | **Preserved.** The DH operations (X25519 over identity / signed-pre / one-time keys) are unchanged; only the final HKDF parameterization changed. |
| Interoperability | **Fixed.** Python↔TypeScript sessions now derive identical keys. |
| New attack surface | **None.** No new inputs, network exposure, or trust decisions. |
| Backward compatibility | **Wire-incompatible with peers still running the pre-fix TypeScript KDF.** Sessions established under the legacy derivation cannot continue with a spec-compliant peer and must renegotiate. Because the legacy derivation only ever agreed with *other* legacy TypeScript peers (it never agreed with Python), the practical break is limited to TypeScript↔TypeScript sessions, which renegotiate transparently on reconnect. |

### Specific considerations

- **No downgrade path.** There is no negotiation that could let an attacker
  force the legacy derivation; both peers compute the KDF locally from the
  same spec, so a mismatched peer simply fails closed (decryption fails)
  rather than falling back to a weaker key.
- **Deterministic, audited derivation.** The KDF is now covered by a
  known-answer test so a future regression to the legacy salt/IKM ordering
  fails CI instead of silently breaking interop.

## Test coverage

Added to `agent-governance-typescript/tests/encryption.test.ts`
(`describe("X3DH KDF")`):

| Test | Purpose |
|---|---|
| `matches the cross-runtime spec known-answer vector` | Pins `kdf(fixedIkm)` to `f8682588…705a5bfa`, a vector computed independently from the spec formula and verified byte-for-byte against the AGT Python SDK. Catches any drift from the spec / Python. |
| `does not derive the legacy (FF-salt) key` | Negative guard asserting the output is **not** the pre-fix vector `4d1a12fa…9552e22b`, so the spec vector can never silently equal the buggy one. |
| `derives a 32-byte key` | Length invariant. |
| `is deterministic for a given input` | Same input → same key. |

The pre-existing `describe("X3DHKeyManager")` exchange tests still pass; they
only assert intra-runtime consistency (alice's secret == bob's secret),
which is why the cross-runtime divergence was invisible before this
known-answer vector was added.
