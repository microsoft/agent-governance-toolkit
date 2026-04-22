# Cognitive Attestation + AGT

**Status:** experimental, community-driven.

Demonstrates layering [Cognitive Attestation](https://doi.org/10.5281/zenodo.19646276) on top of AGT policy enforcement. AGT decides whether an action is allowed based on policy. Cognitive Attestation signs an interpretable decomposition of the model state that drove that decision, so downstream auditors can inspect what the reasoning substrate looked like when the action fired, not just whether the policy rule matched.

**AGT enforces policy. Cognitive Attestation explains the reasoning.**

## What this adds

Policy enforcement answers whether an action is permitted. It does not explain the internal model state that produced the action. Cognitive Attestation captures that layer with a small signed envelope:

- `action_ref`: content-addressed hash of the action being attested
- `feature_activations`: sparse-autoencoder features with activation statistics, canonically sorted
- `dictionary_ref`: which SAE dictionary produced the features (reproducibility pointer)
- `canonical_hash`: RFC 8785 JCS canonicalization over the envelope
- Ed25519 signature over the canonical form

The envelope is small (~1-3 KB), JCS-canonical, and verifiable offline with a single Ed25519 public key.

## What this example shows

1. AGT evaluates a policy (allow/deny) before execution
2. If allowed, the agent produces an action
3. A Cognitive Attestation envelope is built over that action, carrying SAE feature activations that represent the decomposed model state
4. The envelope is Ed25519-signed and JCS-canonicalized
5. A second party verifies the envelope offline using only the public key and the canonical schema
6. A tampered envelope is rejected by the verifier

## Install

```bash
pip install agent-governance-toolkit cryptography
```

The Cognitive Attestation primitive used here is a small self-contained implementation of the published spec. Reference implementation and normative schema live at [github.com/aeoess/agent-passport-system](https://github.com/aeoess/agent-passport-system) (see `src/v2/cognitive-attestation/`) under Apache 2.0.

## Run

```bash
python getting_started.py
```

Expected output: an AGT-style policy decision, then a signed Cognitive Attestation envelope, then a passing offline verification, then a passing tamper rejection.

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

## Prior art and attribution

- Paper: *Cognitive Attestation: Signing Interpretable Decompositions of Latent Model State in AI Agent Governance*, Zenodo DOI [10.5281/zenodo.19646276](https://doi.org/10.5281/zenodo.19646276), April 2026.
- Reference implementation: [aeoess/agent-passport-system](https://github.com/aeoess/agent-passport-system) (Apache 2.0, v2.1.0 on npm and PyPI).
- Schema: `papers/paper-4/poc/schema/cognitive_attestation.schema.json` in the reference repo.
- Canonicalization: RFC 8785 (JCS).
- Signature: Ed25519 via standard libraries.

## Limitations

- Interpretability depends on the underlying SAE dictionary. Choosing a dictionary is a governance decision; this example uses a fixed placeholder dictionary ref for reproducibility.
- Feature labels are dictionary-author-assigned and not independently verified by the attestation itself. A v1.1 validation pass is on the reference-implementation roadmap.
- This example is community-contributed, not part of AGT's core runtime. Treat outputs as experimental.
