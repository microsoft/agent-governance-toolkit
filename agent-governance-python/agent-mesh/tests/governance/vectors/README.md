# FileAuditSink test vectors

Reference data for anyone writing a verifier for `FileAuditSink` output without
importing AGT.

`file_audit_sink_v1.jsonl` is four signed entries produced by `FileAuditSink`
itself, with the HMAC key, entry ids and timestamps pinned so the file is
reproducible. Regenerate with:

```bash
python agent-governance-python/agent-mesh/tests/governance/vectors/generate.py
```

## The key

```
agt-file-audit-sink-test-vectors-v1
```

A fixture, not a secret. It is committed so the signatures below can be
recomputed by anyone, which is the entire purpose.

## The algorithm

Three details are needed to verify a file and none are visible in the file
itself. See issue #3643.

**1. `content_hash` covers exactly fourteen fields**

```
entry_id, timestamp, event_type, agent_did, action, resource, target_did,
data, outcome, policy_decision, matched_rule, trace_id, session_id,
previous_hash
```

serialised with `json.dumps(payload, sort_keys=True, default=str)`, then
SHA-256, hex-encoded.

`sandbox_id`, `environment` and `compute_driver` appear in the file and are
**excluded** from the hash, so that execution context can be added to entries
without invalidating chains already written. Vector 4 carries all three
populated; hashing the fields you can see produces a mismatch on that entry and
nothing in the file explains why.

Optional fields that are unset are hashed as JSON `null`, not omitted. Vector 3
covers that case.

**2. `previous_hash` chains to the previous entry's `content_hash`**

Not to its `signature`, which is the plausible wrong guess since the signature
is the outermost value. The genesis entry uses `""`, not the hash of an empty
string.

**3. The signature is HMAC-SHA256 over the hex string of the content hash**

```python
hmac.new(secret_key, content_hash.encode(), hashlib.sha256).hexdigest()
```

Not over the raw 32 bytes.

## A complete verifier

Standard library only, no AGT import. This is the code
`test_a_stdlib_verifier_agrees` runs against these vectors.

```python
import hashlib, hmac, json

FIELDS = ["entry_id", "timestamp", "event_type", "agent_did", "action",
          "resource", "target_did", "data", "outcome", "policy_decision",
          "matched_rule", "trace_id", "session_id", "previous_hash"]

def verify(path, secret_key):
    previous_hash = ""
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            row = json.loads(line)
            payload = {field: row[field] for field in FIELDS}
            content_hash = hashlib.sha256(
                json.dumps(payload, sort_keys=True, default=str).encode()
            ).hexdigest()
            if not hmac.compare_digest(content_hash, row["content_hash"]):
                return False, f"content hash mismatch at {row['entry_id']}"
            signature = hmac.new(
                secret_key, content_hash.encode(), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(signature, row["signature"]):
                return False, f"signature mismatch at {row['entry_id']}"
            if row["previous_hash"] != previous_hash:
                return False, f"chain break at {row['entry_id']}"
            previous_hash = row["content_hash"]
    return True, None
```

## What the vectors cover

| Vector | Case |
|--------|------|
| 1 | Genesis entry. `previous_hash` is `""`. |
| 2 | Every optional field populated, including nested `data`. |
| 3 | Optional fields left unset, hashed as `null`. |
| 4 | `sandbox_id` / `environment` / `compute_driver` populated and excluded from the hash. |

## Keeping them honest

`tests/governance/test_audit_vectors.py` verifies these against the reference
implementation, against a standard-library reimplementation, and asserts that
regenerating produces the committed bytes.

That last check is the point. If the hashed payload ever changes, it fails in
this repository's CI rather than surfacing later as somebody else's verifier
quietly disagreeing about whether a file is genuine. If the change is
deliberate, rerun `generate.py`, commit the result, and treat it as a format
change external implementers need to hear about.
