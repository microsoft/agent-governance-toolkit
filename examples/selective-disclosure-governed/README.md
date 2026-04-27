# Selective-Disclosure Governed Example

> Decision receipts where each field is independently committed via an
> RFC 6962-style Merkle tree, so the issuer can reveal specific fields to
> specific auditors and prove the rest are unchanged without exposing them.
> Same Ed25519 + JCS signing pipeline as
> [`protect-mcp-governed/`](../protect-mcp-governed/), with one extra
> field on the receipt envelope (`committed_fields_root`) and a separate
> disclosure-proof artifact for per-auditor scoping.

## Quick Start (< 2 minutes)

```bash
pip install "agent-governance-toolkit[full]>=0.6.0"
python examples/selective-disclosure-governed/getting_started.py
```

The script mints a multi-field receipt in commitment mode, then issues
three different disclosure proofs against the same signed envelope (one
per auditor profile), then verifies each end-to-end. Output:

```
Tutorial 46 round-trip self-test
============================================================
1. Envelope signature: ok
2. Article 12 (every field):                    ok
3. GDPR (process metadata only):                ok
4. Counterparty (auth scope only):              ok
5. Tampered (value swapped):                    rejected as expected
6. Tampered envelope (decision flipped):        rejected as expected
7. Chained receipt (rcpt-0001 -> rcpt-0002):    ok

All 7 assertions passed.
```

Zero dependencies beyond Python 3.10+ and the `cryptography` package.

## What This Shows

| Scenario | What Happens | Construction |
|----------|--------------|--------------|
| **1. Envelope signature** | Receipt verifies against the public key with no disclosures attached. The auditor sees `committed_fields_root` but learns nothing about hidden fields. | Tutorial 33's Ed25519 + JCS path, with a single extra field |
| **2. Article 12 disclosure** | Every committed field (including `user_id` and `tool_args`) is revealed to a market-surveillance authority. | All 7 leaves disclosed with Merkle proofs |
| **3. GDPR disclosure** | Only process metadata (`tool_name`, `decision`, `policy_id`, `timestamp`) revealed to the data controller. Personal-data fields stay hidden. | 4-field disclosure subset |
| **4. Counterparty disclosure** | Cross-org delegation check sees authorization scope only. Customer payload stays hidden. | 3-field disclosure subset |
| **5. Tampered value** | Issuer attempts to swap a hidden field's value after signing. Verifier catches it via the Merkle proof failing. | Soundness demonstration |
| **6. Tampered envelope** | Public field modified after signing. Verifier catches it via the Ed25519 signature failing. | Tutorial 33-style integrity check |
| **7. Chained receipt** | Selective-disclosure receipts compose with Tutorial 33's `parent_receipt_hash` chain. | Field-level Merkle + receipt-level chain |

Each scenario is a deterministic assertion in `getting_started.py`. The script
exits 0 if every check passes and non-zero on any failure, which makes it
suitable as a CI smoke test.

## How the Construction Differs from Tutorial 33

| | Tutorial 33 | Tutorial 46 (this example) |
|---|---|---|
| Receipt envelope | Public fields signed directly | Public fields + `committed_fields_root` signed |
| Hidden fields | Not supported | Each field independently committed via Merkle leaf |
| Disclosure granularity | All-or-nothing | Per-field, per-auditor |
| Verifier dependencies | Public key | Public key + per-field disclosure proof |
| Salt management | Not needed | 16-byte salt per committed field, stored in side store |
| Wire format | Single receipt JSON | Receipt JSON + optional disclosure JSON |

The two formats are forward-compatible: a receipt with no committed fields is
identical to a Tutorial 33 receipt. A verifier that doesn't understand
`committed_fields_root` ignores it and still validates the envelope signature.

## Architecture

```
                    Issuer side                       Auditor side

  ┌─────────────────────────────────┐      ┌──────────────────────────┐
  │ Compute per-field commitments   │      │  Receipt envelope (JSON) │
  │ leaf_i = SHA-256(0x00 ||         │      │  + committed_fields_root │
  │   JCS({name, salt, value}))     │      └──────────────────────────┘
  │                                 │                   +
  │ Build RFC 6962 Merkle tree      │      ┌──────────────────────────┐
  │  internal = SHA-256(0x01 ||     │ ───> │  Disclosure proof (JSON) │
  │    left || right)                │      │   for fields A, C, D     │
  │                                 │      └──────────────────────────┘
  │ Sign envelope with Ed25519 over │                   ↓
  │  JCS canonical bytes including  │      ┌──────────────────────────┐
  │  committed_fields_root           │      │  Verify off line         │
  └─────────────────────────────────┘      │  npx @veritasacta/verify │
                ↓                          │   --disclosure-file ...  │
        ┌───────────────────┐              └──────────────────────────┘
        │  Side store       │
        │  (salts + values  │
        │   for later       │
        │   disclosure)     │
        └───────────────────┘
```

The side store holds the salts and committed-but-undisclosed values keyed by
`receipt_id`. Losing a salt makes a field permanently undisclosable. Some
implementers treat this as a privacy primitive: deliberately destroy salts
on the data-minimization horizon (e.g., 90-day retention) so the field
stays committed but is never recoverable.

## Disclosure Profiles

The script ships three preset profiles. Custom profiles are one function
call away:

```python
from selective_disclosure import make_disclosure

# Reveal a custom subset of fields by name
def disclose_custom(side_store, names_to_reveal):
    indices = [
        i for i, f in enumerate(side_store["fields"])
        if f["name"] in names_to_reveal
    ]
    return make_disclosure(side_store, indices)

# Article 12: complete operational record
article_12 = disclose_custom(side_store, {
    "tool_name", "decision", "policy_id", "trust_tier",
    "user_id", "tool_args", "timestamp",
})

# GDPR data-minimization: process metadata only
gdpr = disclose_custom(side_store, {
    "tool_name", "decision", "policy_id", "timestamp",
})

# Cross-org delegation check: auth scope only
counterparty = disclose_custom(side_store, {
    "tool_name", "decision", "trust_tier",
})
```

Each disclosure is delivered out-of-band to the specific auditor. The
signed receipt itself can be published widely. An auditor who receives
the receipt without a disclosure sees the public fields and the
commitment root, but cannot recover the hidden fields.

## Cross-Implementation Verification

The Merkle construction follows RFC 6962 with no implementation-defined
choices. Receipts and disclosures produced by this Python reference verify
against the Node-side
[`@veritasacta/verify@0.6.0`](https://www.npmjs.com/package/@veritasacta/verify)
CLI, the Rust reference, and the Go reference, all of which round-trip
against the same fixtures in
[github.com/ScopeBlind/agent-governance-testvectors](https://github.com/ScopeBlind/agent-governance-testvectors).

```bash
# Same receipt, three independent verifiers, byte-identical results
python examples/selective-disclosure-governed/getting_started.py \
    --emit receipt.json --emit-disclosure article-12.json

npx @veritasacta/verify@0.6.0 \
    receipt.json --disclosure-file article-12.json
# exit 0

# Equivalently in Rust / Go (see testvectors repo)
```

## Standards

- **Ed25519** (RFC 8032) for receipt signatures
- **JCS** (RFC 8785) for deterministic canonicalization before signing
- **SHA-256** for per-field commitments and the Merkle tree
- **RFC 6962** for the Merkle tree construction (leaf prefix `0x00`,
  node prefix `0x01`, non-power-of-two leaf handling)
- **IETF Internet-Draft** ([draft-farley-acta-signed-receipts](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/)) §5 for the commitment-mode profile

## Related

- [Tutorial 46 — Selective-Disclosure Receipts](../../docs/tutorials/46-selective-disclosure-receipts.md) — Full walkthrough of the construction, the Article 12 + GDPR composition, and the cross-implementation conformance flow
- [Tutorial 33 — Offline-Verifiable Receipts](../../docs/tutorials/33-offline-verifiable-receipts.md) — Direct prerequisite (Ed25519 + JCS + chain receipts)
- [`examples/protect-mcp-governed/`](../protect-mcp-governed/) — Tutorial 33's worked example with 8 scenarios
- [`examples/physical-attestation-governed/`](../physical-attestation-governed/) — Same receipt format extended to hardware sensors
- [protect-mcp](https://www.npmjs.com/package/protect-mcp) — MCP gateway with Cedar policies + commitment-mode receipt signing (npm, MIT)
- [@veritasacta/verify](https://www.npmjs.com/package/@veritasacta/verify) — Offline receipt + disclosure verification CLI (npm, Apache-2.0)

## Notes on Production Use

- **Salt persistence is a hard requirement.** Without the salt, a field's
  Merkle commitment cannot be reopened, and the auditor cannot verify the
  field's value. Persist salts in the same store as the committed values,
  keyed by `receipt_id`.
- **Public-field choice is governance, not cryptography.** The construction
  does not prescribe which fields are public and which are committed-only.
  Implementations should default operational fields (tool name, decision,
  policy ID, timestamp, trust tier) to public so a basic verifier can read
  them without disclosure proofs.
- **Article 12 minimum scope.** EU AI Act Article 12 mandates retention of
  operational logs. Implementations targeting Article 12 should keep all
  operational fields disclosable for the regulatory retention window
  (six months minimum).
- **GDPR right to erasure.** Salts are the privacy primitive. Destroying a
  salt makes the corresponding field cryptographically unrecoverable while
  preserving the integrity of the rest of the receipt and the chain.
