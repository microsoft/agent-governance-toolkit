# AgentMesh Parmana Trust Verify

A community integration that checks a Parmana execution trust record before an
AgentMesh workflow acts on it. It uses the offline
[`parmana-verifier`](https://pypi.org/project/parmana-verifier/) package, makes no
network calls, and denies on any failure.

> Community extension. It is not part of the core Agent Governance Toolkit. See
> [GOVERNANCE.md](../../../GOVERNANCE.md) for the core versus extension boundary.

## Quick start

```python
from parmana_trust_verify import verify_record

verdict = verify_record(record, trust_document)
if not verdict.allowed:
    raise PermissionError(verdict.errors)
```

- `record` is a Parmana execution trust record, as a dictionary.
- `trust_document` is a trust set with a `keys` array. You choose which keys to
  pin. The verifier trusts only those keys.

## What it checks

- The record hash over the canonical JSON of the record.
- The Ed25519 signature, against a pinned key that is valid at the record's
  creation time and not marked compromised.
- A malformed trust set, a non-object record, or any exception during
  verification returns a denial with a reason.

## Limits

- It cannot prove that a pinned key belongs to Parmana. The caller decides which
  keys to trust.
- It does not check ML-DSA-65 (post-quantum) signatures. Those need the Node
  verifier.
- It does not confirm that the recorded action was executed, or the state of any
  external system.

## Development

```bash
pip install -e ".[test]"
pytest -q
python examples/basic_usage.py
```

The tests build real signed records with the verifier's canonicalization, so
they exercise the actual checks, not a mock.
