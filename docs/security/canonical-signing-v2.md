---
title: "Security Design Notes: MCP Canonical Signing v2, Cross SDK"
last_reviewed: 2026-10-15
owner: agt-maintainers
---

# Security Design Notes: MCP Canonical Signing v2, Cross SDK

**Date:** 2026-10-15
**Issues:** #4199 (Rust parity), #4132 (Python v2 encoding)

## Why the previous encodings were unsafe

The Python signer joined fields with `|` and the Rust signer joined fields
with `:`. Neither escaping nor length framing was applied, so a field value
containing the separator could merge two distinct field tuples into one
identical HMAC input. Concretely, with a fixed timestamp, Rust
`{timestamp_secs}:{nonce}:{payload}` produced the same bytes for:

| nonce | payload | canonical input |
| --- | --- | --- |
| `n` | `x:y` | `{timestamp}:n:x:y` |
| `n:x` | `y` | `{timestamp}:n:x:y` |

An attacker holding a legitimately signed envelope for the first tuple could
reframe its fields to the second tuple and keep the original signature. A
verifier with an independent nonce store accepted the reframed envelope.
The Python v1 delimiter encoding had the same class of ambiguity.

## The shared v2 representation

Both SDKs now sign one canonical encoding, defined by #4132:

```text
["agent-os:mcp-message:v2", <nonce>, <timestamp>, <sender>, <payload>]
```

serialized as compact JSON (`separators=(",", ":")`, `ensure_ascii=False`),
UTF-8 encoded before HMAC-SHA256. Properties:

- JSON arrays give every field a fixed position, and JSON string escaping
  makes each element unambiguous: no two distinct field tuples produce the
  same byte string.
- `timestamp` is UTC RFC 3339 with exactly six fractional digits and a
  `+00:00` offset, matching Python's
  `datetime.isoformat(timespec="microseconds")` after `astimezone(UTC)`.
- An absent sender is JSON `null` and is distinct from an empty string, so a
  relay cannot flip a signed message between "no sender" and "empty sender"
  without breaking the MAC.
- Signatures are standard padded base64 in both SDKs.
- The Rust `write_json_string` helper mirrors Python's
  `json.dumps(ensure_ascii=False)` escaping exactly: quotes, backslashes,
  and control characters are escaped; every other character, including all
  non-ASCII text, is emitted as raw UTF-8.

Signature verification still happens before the nonce store is consulted,
and replay protection is unchanged in both SDKs.

## Shared fixed test vectors

Secret (UTF-8 bytes):
`mcp-sig-v2-cross-sdk-vector-key-000001`

Timestamps: `2023-11-14T22:13:20.123456+00:00` and
`2023-11-14T22:13:20.999999+00:00` (Unix microseconds 1700000000123456 and
1700000000999999).

| ID | nonce | sender | payload | signature (base64) |
| --- | --- | --- | --- | --- |
| V1 | `n` | null | `x:y` | `ulKQJ88YmF6olg4ML3ekYf7vTA2jh7m434nn/bh59ns=` |
| V2 | `n:x` | null | `y` | `4LV3y6oukPpuK7KicYSjmRejFuDmA2q2NiDgocNtUZs=` |
| V3 | `a\|b` | `s\|t` | `p\|q` | `JYCranEAW75tG9xotPxrynub4VUm1JJ04Pn5jrwPknc=` |
| V4 | `நி` | null | `🚀 {"json":[1,2]}` | `OfjfnaSRytNHOrwwVGIjfVI9+KshmVKThfmw+ZJILDE=` |
| V5 | `n` | `""` | `hello` | `VFK/y1V5v3BpfZ92s+XbfBDpcJ37hC7obDb5qGAhDU4=` |
| V6 | `n` | null | `hello` | `jNdf63ZaaLmvYOoPhwKDDwYjZOXgImRYAyFsny+UK5I=` |
| V7 | `q"uote\slash` | `a\u0001b` | `line\n\u0000end` | `RMaggh8DnjNCnfsfMmC41aOUSl5z0rvj+U+pMp6PMK4=` |
| V8 | `n` | null | a whole canonical string | `z449mTVpVmzBmacGaEUecnunNGj49iOevfdpBeqyqPk=` |
| V9 | `n` | `agent-1` | `hello` | `VdH7Z13r4EVkC8PZsl7qrnu9Na/vDEyzvKjyCU2SuWE=` |

Notes on the vector set:

- V1 and V2 are the reframing pair from #4199: distinct tuples, distinct
  signatures. The regression test in both SDKs re-signs V1, rewrites the
  envelope to the V2 fields while keeping the V1 signature, and asserts
  verification fails. There is no legacy fallback.
- V5 and V6 prove that an empty-string sender and an absent sender produce
  different signatures, closing the relay flip reported during review.
- V4 and V7 cover Unicode text, JSON-looking payloads, quotes, backslashes,
  control characters, and a NUL byte, which is where escaping conventions
  most often diverge between languages.
- V8 signs a payload that is itself a complete canonical string, guarding
  against a decoder that re-parses signed input.
- V9 pins microsecond precision; sub-second digits are part of the signed
  input and must survive transport.

The Python vector suite lives in
`agent-governance-python/agent-os/tests/test_mcp_signature_cross_sdk.py`;
the Rust suite is `matches_python_v2_shared_vectors` in
`agent-governance-rust/agentmesh-mcp/src/mcp/signing.rs`. Both assert the
identical table, so a change to either canonical encoder fails the other
SDK's tests.

## Breaking changes and coordinated migration

- Rust: `McpSignedMessage.timestamp_secs` becomes `timestamp_us`, the
  struct gains `sender_id: Option<String>`, `McpMessageSigner::sign` takes
  `sender_id: Option<&str>`, and the base64 alphabet moves to the standard
  padded alphabet.
- Python: unchanged from #4132; the v2 JSON encoding replaces the
  delimiter-based encodings and legacy signatures are never accepted.
- Envelopes signed with any older encoding fail verification on both SDKs.
  Deploy both SDKs in the same maintenance window. See
  `docs/specs/MCP-SECURITY-GATEWAY-1.0.md` section 7.4 for the Python v2
  specification and integrity-versus-authorization boundary: a valid
  signature proves possession of the shared key, not permission to execute
  the payload.
