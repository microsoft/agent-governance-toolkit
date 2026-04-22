# Cognitive Attestation + AGT

**Status:** experimental, community-driven.

Demonstrates layering [Cognitive Attestation](https://doi.org/10.5281/zenodo.19646276) on top of AGT policy enforcement. AGT decides whether an action is allowed based on policy. Cognitive Attestation signs an interpretable decomposition of the model state that drove that decision, so downstream auditors can inspect what the reasoning substrate looked like when the action fired, not just whether the policy rule matched.

**AGT enforces policy. Cognitive Attestation explains the reasoning.**

## What this adds

Policy enforcement answers whether an action is permitted. It does not explain the internal model state that produced the action. Cognitive Attestation captures that layer with a small signed envelope:

- `action_ref`: content-addressed hash of the action being attested
- `feature_activations`: sparse-autoencoder features with activation statistics, canonically sorted
- `dictionary_ref`: which SAE dictionary produced the features (reproducibility pointer)
- `timestamp`: ISO 8601 UTC timestamp, bound into the signature for replay defence
- `canonical_hash`: [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785) JCS canonicalization over the envelope
- Ed25519 signature over the canonical form

The envelope is small (~1-3 KB), JCS-canonical, and verifiable offline with a single Ed25519 public key.

## What this example shows

1. AGT evaluates a policy (allow/deny) before execution
2. If allowed, the agent produces an action
3. A Cognitive Attestation envelope is built over that action, carrying SAE feature activations that represent the decomposed model state
4. The envelope is Ed25519-signed and JCS-canonicalized with timestamp bound into the signature
5. A second party verifies the envelope offline using only the public key and the canonical schema
6. A tampered envelope is rejected by the verifier with the reason surfaced
7. A stale envelope (older than `max_age_seconds`) is rejected by the freshness check, demonstrating replay defence

## Install

```bash
pip install agent-governance-toolkit cryptography
```

The Cognitive Attestation primitive used here is a small self-contained implementation of the published spec. Reference implementation and normative schema live at [github.com/aeoess/agent-passport-system](https://github.com/aeoess/agent-passport-system) (see `src/v2/cognitive-attestation/`) under Apache 2.0.

## Run

```bash
python getting_started.py
```

Expected output: an AGT-style policy decision, signed envelope, passing offline verification, tamper rejection with reason, and a replay rejection when the envelope is verified 10 minutes after signing against a 300-second freshness window.

## How it composes

```
Agent action
    |
    +-> AGT policy engine      (allow / deny)
    |
    +-> Cognitive Attestation  (signed feature decomposition
                                of the reasoning substrate)
            |
            v
     Offline verifier
     (public key + JCS + schema)
```

Policy and attestation are separate layers. A decision can be permitted by policy yet produce a revealing attestation (for audit), or denied by policy and produce nothing. The two are complementary.

## Security notes

The Ed25519 private key in `getting_started.py` is generated on the fly for demonstration. Production deployments MUST store signing keys securely. Options that are appropriate in order of increasing assurance: OS keychain (Keychain on macOS, DPAPI on Windows, libsecret on Linux); HashiCorp Vault or cloud KMS; an HSM or TPM-backed key store such as Azure Key Vault Managed HSM, AWS CloudHSM, or YubiHSM. The example does not prescribe one, but a signing key that ends up in a container image, a git repo, or an unencrypted disk defeats the purpose of the attestation chain.

The minimal JCS implementation in `getting_started.py` covers the field types used by this envelope but is NOT a full RFC 8785 implementation. Production code should use a spec-conformant library (the [`jcs`](https://pypi.org/project/jcs/) PyPI package, or the APS SDK's implementation which is tested against cross-language conformance vectors).

The policy evaluator in the example is a minimal placeholder to keep the example self-contained. It is NOT a substitute for AGT's real policy engine.

## Prior art and attribution

- Paper: *Cognitive Attestation: Signing Interpretable Decompositions of Latent Model State in AI Agent Governance*, Zenodo DOI [10.5281/zenodo.19646276](https://doi.org/10.5281/zenodo.19646276), April 2026.
- Reference implementation: [aeoess/agent-passport-system](https://github.com/aeoess/agent-passport-system) (Apache 2.0, v2.2.0 on npm and PyPI). Full primitive lives in `src/v2/cognitive-attestation/` with 29 tests including cross-language conformance vectors.
- Schema: `papers/paper-4/poc/schema/cognitive_attestation.schema.json` in the reference repo.
- Canonicalization: [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785) (JCS).
- Signature: Ed25519 via standard libraries.

## Limitations

- Interpretability depends on the underlying SAE dictionary. Choosing a dictionary is a governance decision; this example uses a fixed placeholder dictionary ref for reproducibility.
- Feature labels are dictionary-author-assigned and not independently verified by the attestation itself. A v1.1 validation pass is on the reference-implementation roadmap.
- The minimal JCS here does not handle Unicode normalization edge cases or all IEEE 754 special values. See the "Security notes" above.
- This example is community-contributed, not part of AGT's core runtime. Treat outputs as experimental.
