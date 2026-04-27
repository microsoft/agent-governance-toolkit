# Crypto Attestation Governed (Example)

This example demonstrates a first-party cryptographic attestation layer for governed tool calls:

- **Ed25519 signing** for every allowed action receipt
- **Policy attestation proof** embedded in each receipt
- **Hash-chained audit trail** (`previous_receipt_hash`) for tamper evidence
- **Offline verification** of signatures, receipt hashes, and chain integrity

This is an example implementation for learning and prototyping. It is not a production API contract.

## Architecture

For each governed action:

1. Policy is evaluated and returns an `allow` decision
2. A `PolicyAttestation` object is created:
   - policy id/version
   - policy content hash (`policy_sha256`)
   - decision + reason
3. A receipt payload is created and signed with Ed25519
4. A `receipt_hash` is computed over signed payload content
5. The next receipt points to this one via `previous_receipt_hash`

This creates a tamper-evident chain:

`receipt[n].previous_receipt_hash == receipt[n-1].receipt_hash`

## Files

- `getting_started.py` - runnable script (generation + offline verify)
- `requirements.txt` - minimal dependency for Ed25519 support

## Setup

From repo root:

```bash
cd examples/crypto-attestation-governed
python -m pip install -r requirements.txt
```

## Run

Generate receipts and verify offline:

```bash
python getting_started.py --output receipts.jsonl
```

Expected output (example):

```text
Wrote 3 receipts to receipts.jsonl
receipt[0] verification: PASS (ok)
receipt[1] verification: PASS (ok)
receipt[2] verification: PASS (ok)
chain verification: PASS (ok)
```

## Tamper Detection Demo

Run with intentional mutation of one recorded action argument:

```bash
python getting_started.py --output receipts_tampered.jsonl --tamper
```

Expected output includes a failure like:

```text
receipt[1] verification: FAIL (receipt_hash mismatch)
```

## What This Proves

- Receipts cannot be modified without breaking hash or signature validation
- Chain links detect deletion/reordering/mutation attempts
- Policy decision context can be audited independently of runtime services

## Cleanup

```bash
rm -f receipts.jsonl receipts_tampered.jsonl
```
