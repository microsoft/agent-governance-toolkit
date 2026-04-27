# Reasoning Attestation Governed (Example)

This example demonstrates a first-party **reasoning attestation** pattern for AGT:

- captures a sparse autoencoder (SAE) feature activation slice
- builds a **JCS-canonical envelope** (RFC 8785 style constraints)
- signs the envelope with **Ed25519**
- binds reasoning state to both:
  - a governed **action reference** (`action_ref`)
  - a governed **policy decision** (`policy_sha256`)
- supports offline verification and tamper detection

This is a runnable example for learning and prototyping, not a production API contract.

## Architecture

1. Create an action reference from governed action inputs
2. Evaluate governance policy and record policy attestation
3. Capture interpretable SAE feature activations
4. Build a deterministic JSON envelope (canonical serialization)
5. Sign with Ed25519 and compute envelope hash
6. Verify offline:
   - envelope hash integrity
   - signature authenticity
   - policy hash binding
   - action reference binding

## Files

- `getting_started.py` - end-to-end generation + verification script
- `requirements.txt` - cryptography dependency for Ed25519

## Setup

From repo root:

```bash
cd examples/reasoning-attestation-governed
python -m pip install -r requirements.txt
```

## Run

Normal run:

```bash
python getting_started.py --output reasoning_attestation.json
```

Expected output:

```text
Wrote reasoning envelope to reasoning_attestation.json
offline verification: PASS (ok)
```

## Tamper Detection Demo

Intentional post-sign mutation:

```bash
python getting_started.py --output reasoning_attestation_tampered.json --tamper
```

Expected output:

```text
Wrote reasoning envelope to reasoning_attestation_tampered.json
offline verification: FAIL (envelope_sha256 mismatch)
```

## Reproducibility Notes

The envelope includes `dictionary_reference` metadata so auditors can trace the exact SAE dictionary source and version used to interpret the reasoning state.

## Security Notes (Example Scope)

This example includes:
- signer key pinning during offline verification
- policy hash + action reference binding checks

Production systems should additionally implement secure key distribution,
rotation/revocation, and centralized policy provenance controls.

## Cleanup

```bash
rm -f reasoning_attestation.json reasoning_attestation_tampered.json
```
