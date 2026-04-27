<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Tutorial 46 — Selective-Disclosure Receipts

[Tutorial 33](33-offline-verifiable-receipts.md) showed how every tool call an
agent makes can leave behind an Ed25519-signed, JCS-canonical receipt that any
party with the public key can verify offline. That works cleanly for receipts
where every field can be shown to every auditor.

In regulated environments, that assumption breaks. An EU AI Act Article 12
auditor wants the full record of what a high-risk system did. A GDPR
data-minimization controller wants the auditor to see as little personal data
as possible. A counterparty wants to verify a delegation chain without seeing
the customer payload. A regulator in one jurisdiction needs different fields
than a regulator in another.

This tutorial covers **selective-disclosure receipts**: receipts where each
field is independently committed via a Merkle tree, so the receipt issuer can
reveal specific fields to specific auditors and prove the rest are unchanged
without exposing them. The construction follows RFC 6962 (Certificate
Transparency), which is the same Merkle tree shape used by transparency logs
and `git` itself.

> **Packages:** `agent-governance-toolkit[full]` (Python) · `protect-mcp@0.6.0` (npm, signing) · `@veritasacta/verify@0.6.0` (npm, verification)
> **Standards:** Ed25519 (RFC 8032) · JCS (RFC 8785) · SHA-256 · RFC 6962 (Merkle Tree construction) · IETF [draft-farley-acta-signed-receipts](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/) §5
> **Reference example:** [`examples/selective-disclosure-governed/`](../../examples/selective-disclosure-governed/)

---

## What You'll Learn

| Section | Topic |
|---------|-------|
| [Why Selective Disclosure?](#why-selective-disclosure) | The gap between full-disclosure and zero-disclosure receipts |
| [The Commitment Construction](#the-commitment-construction) | RFC 6962 Merkle tree over per-field commitments |
| [§1 Committing a Receipt](#1--committing-a-receipt) | Sign a receipt in commitment mode |
| [§2 Generating a Disclosure](#2--generating-a-disclosure) | Reveal specific fields with Merkle proofs |
| [§3 Verifying a Disclosure Offline](#3--verifying-a-disclosure-offline) | Walk the proof, no signing key needed |
| [§4 Composing with Tutorial 33's Chain](#4--composing-with-tutorial-33s-chain) | Per-field disclosure on chained receipts |
| [§5 Article 12 + GDPR Composition](#5--article-12--gdpr-composition) | Multi-auditor disclosure scoping |
| [§6 Cross-Implementation Interop](#6--cross-implementation-interoperability) | Verifying across protect-mcp / sb-runtime / others |
| [CI/CD Integration](#cicd-integration) | Gating merges on disclosure verification |
| [Cross-Reference](#cross-reference) | Related tutorials |

---

## Prerequisites

- **Python 3.10+**
- **Node.js 18+** for the verifier CLI (`npx @veritasacta/verify@0.6.0`)
- Completion of [Tutorial 33 — Offline-Verifiable Receipts](33-offline-verifiable-receipts.md).
  This tutorial assumes you understand the JCS-plus-Ed25519 signing path and
  the parent-hash chain construction.
- Recommended: skim [RFC 6962 §2](https://datatracker.ietf.org/doc/html/rfc6962#section-2)
  for the Merkle tree definition. The construction here uses the same hash
  prefix discipline (`0x00` for leaves, `0x01` for internal nodes) so test
  vectors interop directly with CT verifiers.

Install:

```bash
pip install "agent-governance-toolkit[full]>=0.6.0"
```

The signing-side npm package (`protect-mcp@0.6.0`) and the verification-side
package (`@veritasacta/verify@0.6.0`) ship the matching commitment-mode
implementations referenced throughout this tutorial.

---

## Why Selective Disclosure?

Tutorial 33's receipts are **all-or-nothing**. The signature covers the entire
JCS-canonical payload, so the verifier needs every field to compute the hash
and check the signature. Hide one field and the signature no longer verifies.
That is the right shape when every auditor sees the same record.

Three real-world settings break that assumption:

| Setting | What's hidden | What's revealed |
|---------|---------------|-----------------|
| EU AI Act Article 12 audit | Customer-identifying fields | Tool name, policy ID, decision, timestamp, chain link |
| GDPR data-minimization request | Personal data fields | Process metadata only |
| Cross-org delegation check | Counterparty payload | Authorization scope and signature only |
| Vendor debugging without PII | Tool args, tool result | Tool name, decision, error class |

For each, you need three properties at once:

1. **Selective disclosure**: the issuer chooses which fields to reveal to a
   specific auditor.
2. **Soundness**: the auditor cannot be tricked into accepting a different
   value for a hidden field.
3. **Completeness proof**: the auditor knows what the issuer is claiming about
   the hidden fields (their structural shape) without learning their content.

A naive approach is to publish two receipts: one full, one redacted. That
defeats the receipt's signature, since the redacted receipt no longer hashes
to the signed bytes. The right construction commits to each field
independently, then signs the root commitment. The verifier walks a small
Merkle proof to confirm a revealed field's value, and accepts the root
signature as evidence that every other field is fixed even if invisible.

This is the same construction Certificate Transparency uses to commit to
millions of certificates while still allowing per-certificate inclusion proofs.
It is the same construction `git` uses internally to commit to a tree of
files. The novelty here is applying it to per-call agent decisions rather than
to certificates or files.

---

## The Commitment Construction

A Tutorial 33 receipt is signed over the JCS-canonical bytes of the entire
payload object. A Tutorial 46 receipt instead signs over a single 32-byte
**root commitment** computed from the receipt's fields:

```
field_1 = (name_1, value_1)        \
field_2 = (name_2, value_2)         |
   ...                              |  per-field commitments
field_n = (name_n, value_n)         |
                                   /

leaf_i = SHA-256(0x00 || JCS({"name": name_i, "salt": salt_i, "value": value_i}))

         ┌──── inner ────┐
        / \            / \
     leaf_1 leaf_2  leaf_3 leaf_4   <-- Merkle tree, RFC 6962-style
        \      \    /     /
         \      \  /     /
          \    inner    /
           \    |      /
            ─── root ──
                 │
                 ▼
       Ed25519 sign over root
```

Three details from RFC 6962 are worth flagging:

1. **Domain-separation prefix bytes.** Leaves hash with a `0x00` prefix;
   internal nodes hash with a `0x01` prefix. This prevents a second-preimage
   attack where an adversary might find a leaf that collides with an internal
   node's hash.

2. **Per-leaf salt.** Each leaf includes a fresh 16-byte random salt before
   hashing. Without the salt, low-entropy field values (`"decision": "allow"`)
   would let an attacker brute-force the leaf hash. With the salt, hidden
   field values are computationally hidden even if the field's domain is
   small.

3. **Padding.** When the leaf count is not a power of two, RFC 6962 specifies
   that the rightmost subtree is built with the available leaves rather than
   duplicating the last leaf. This avoids a known second-preimage class for
   `git`-style trees.

The signed receipt looks like Tutorial 33's, with one extra field:

```json
{
  "receipt_id":               "rcpt-3f2a9c81",
  "tool_name":                "file_system:read_file",
  "decision":                 "allow",
  "policy_id":                "autoresearch-safe",
  "trust_tier":               "evidenced",
  "timestamp":                "2026-04-25T12:34:56Z",
  "parent_receipt_hash":      "sha256:a8f3c9d2e1b7465f",
  "committed_fields_root":    "sha256:c5f1...d4a3",
  "signature":                "ed25519:7b4a...",
  "public_key":               "ed25519:cafebabe..."
}
```

The fields named in the table (e.g. `tool_name`, `decision`, `policy_id`) are
revealed in the signed receipt. Other fields the issuer chose to commit but
not reveal in the signed envelope (e.g. `tool_args`, `tool_result`, `user_id`,
`request_payload`) live only as commitment leaves in the Merkle tree. Their
values are recoverable only via a disclosure proof.

A disclosure proof is a small JSON object the issuer hands to a specific
auditor:

```json
{
  "disclosed": [
    {
      "name": "user_id",
      "value": "u_8492",
      "salt": "base64-of-16-random-bytes",
      "proof": [
        "sha256:sibling_at_depth_0",
        "sha256:sibling_at_depth_1",
        "sha256:sibling_at_depth_2"
      ]
    }
  ]
}
```

Given the signed receipt and a disclosure proof, the verifier:

1. Recomputes the leaf hash from `(name, value, salt)`.
2. Walks up the Merkle tree using the sibling hashes in `proof`.
3. Compares the recomputed root to the receipt's `committed_fields_root`.
4. Verifies the receipt's Ed25519 signature over the JCS-canonical envelope.

If all four pass, the auditor knows that the disclosed field's value was
fixed at the moment the receipt was signed, and that the issuer cannot
substitute a different value for it. They learn nothing about the undisclosed
fields beyond their position in the tree.

---

## 1 — Committing a Receipt

The reference implementation lives in
[`examples/selective-disclosure-governed/`](../../examples/selective-disclosure-governed/).
Below is the standalone path so you can run it without the protect-mcp
adapter, then replace the `DEMO_KEY` with a managed key in production.

```python
# tutorial_46/01_commit_receipt.py
import hashlib, json, os, time
from typing import List, Tuple

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

def jcs(obj) -> bytes:
    """Minimal JCS: sort keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")

def commit_field(name: str, value, salt: bytes) -> bytes:
    """Per-field commitment: SHA-256(0x00 || JCS({name, salt, value}))."""
    leaf_obj = {"name": name, "salt": salt.hex(), "value": value}
    return hashlib.sha256(LEAF_PREFIX + jcs(leaf_obj)).digest()

def merkle_root(leaves: List[bytes]) -> bytes:
    """RFC 6962-style Merkle root. Odd-leaf handling: rightmost subtree."""
    if len(leaves) == 1:
        return leaves[0]
    # Find the largest power of two strictly less than len(leaves).
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    left = merkle_root(leaves[:k])
    right = merkle_root(leaves[k:])
    return hashlib.sha256(NODE_PREFIX + left + right).digest()

def commit_receipt(fields: List[Tuple[str, object]]):
    """Returns (committed_fields_root, leaves, salts)."""
    salts = [os.urandom(16) for _ in fields]
    leaves = [commit_field(name, value, salt)
              for (name, value), salt in zip(fields, salts)]
    return merkle_root(leaves), leaves, salts


# ---- Mint a receipt with selective fields committed ----
fields = [
    ("tool_name",   "file_system:read_file"),
    ("decision",    "allow"),
    ("policy_id",   "autoresearch-safe"),
    ("trust_tier",  "evidenced"),
    ("user_id",     "u_8492"),                 # will hide from public auditor
    ("tool_args",   {"path": "/etc/passwd"}),  # will hide from public auditor
    ("timestamp",   "2026-04-25T12:34:56Z"),
]

root, leaves, salts = commit_receipt(fields)

receipt_envelope = {
    "receipt_id":            f"rcpt-{root.hex()[:8]}",
    "tool_name":             "file_system:read_file",
    "decision":              "allow",
    "policy_id":             "autoresearch-safe",
    "trust_tier":            "evidenced",
    "timestamp":             "2026-04-25T12:34:56Z",
    "parent_receipt_hash":   None,
    "committed_fields_root": "sha256:" + root.hex(),
}

# ---- Sign the envelope (Tutorial 33's Ed25519 path) ----
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

key = Ed25519PrivateKey.generate()
payload = jcs(receipt_envelope)
signature = key.sign(payload)
receipt_envelope["signature"]  = "ed25519:" + signature.hex()
receipt_envelope["public_key"] = "ed25519:" + key.public_key().public_bytes_raw().hex()

print(json.dumps(receipt_envelope, indent=2))
```

The receipt envelope is what gets stored, distributed, and chained into other
receipts. The hidden fields (`user_id`, `tool_args`) appear only as
commitment leaves in the Merkle tree under `committed_fields_root`. The
issuer keeps the `(name, value, salt)` triples in a side store so it can
emit disclosures later.

In the protect-mcp adapter, this is automatic:

```python
from protect_mcp.governance import GovernedTool

tool = GovernedTool.wrap(
    fn=read_file,
    cedar_policy="autoresearch-safe",
    receipt_mode="commitment",
    public_fields={"tool_name", "decision", "policy_id", "trust_tier", "timestamp"},
    private_fields={"user_id", "tool_args", "tool_result"},
)
```

---

## 2 — Generating a Disclosure

A disclosure proof is the path from a leaf up to the root, naming the sibling
hashes the verifier needs to recompute the root. With `n` committed fields,
the proof is `ceil(log2(n))` sibling hashes.

```python
# tutorial_46/02_generate_disclosure.py
def merkle_proof(leaves: List[bytes], target_index: int) -> List[bytes]:
    """Returns sibling hashes from leaf up to root (bottom-up order).

    proof[0] is the deepest sibling (closest to the target leaf);
    proof[-1] is the root-level sibling (closest to the root).
    This matches the order in which a verifier walking from leaf to
    root consumes the proof.
    """
    siblings_top_down = []
    nodes = list(leaves)
    index = target_index
    while len(nodes) > 1:
        # RFC 6962 split: largest power of two strictly less than len(nodes).
        k = 1
        while k * 2 < len(nodes):
            k *= 2
        if index < k:
            siblings_top_down.append(merkle_root(nodes[k:]))
            nodes = nodes[:k]
        else:
            siblings_top_down.append(merkle_root(nodes[:k]))
            nodes = nodes[k:]
            index -= k
    # Reverse so the verifier consumes leaf-to-root.
    return list(reversed(siblings_top_down))

def make_disclosure(fields, salts, leaves, indices_to_reveal):
    disclosed = []
    for i in indices_to_reveal:
        name, value = fields[i]
        proof = merkle_proof(leaves, i)
        disclosed.append({
            "name":  name,
            "value": value,
            "salt":  salts[i].hex(),
            "proof": ["sha256:" + s.hex() for s in proof],
            "index": i,
            "leaf_count": len(leaves),
        })
    return {"disclosed": disclosed}

# ---- Reveal user_id (index 4) and timestamp (index 6) to a regulator ----
disclosure = make_disclosure(fields, salts, leaves, indices_to_reveal=[4, 6])
print(json.dumps(disclosure, indent=2))
```

Note that the disclosure structure is **separate from the signed envelope**.
The receipt itself can be published widely; the disclosure is delivered only
to specific auditors. An auditor receiving the receipt without the disclosure
sees the public fields, the root commitment, and the signature, but cannot
recover the hidden fields.

A few practical notes on disclosure scope:

- **Per-auditor disclosures**: the issuer can hand different auditors
  different subsets of the same receipt. The Article 12 auditor might receive
  every field; the GDPR controller might receive only `tool_name` and
  `decision`.
- **Field-granularity locks**: once committed, a field's value is fixed. The
  issuer cannot retroactively change `user_id` from `"u_8492"` to `"u_9999"`,
  because that would change the leaf hash and break the Merkle root.
- **Salt management**: the issuer must persist the per-field salts to emit
  disclosures later. Losing a salt means the field is permanently
  undisclosable.

In production, salts and committed-but-undisclosed values are stored in a
separate side store keyed by `receipt_id`. The receipt envelope itself stays
small (~500 bytes regardless of how many fields are committed).

---

## 3 — Verifying a Disclosure Offline

The verifier needs three things: the signed receipt envelope, the disclosure
proof, and the issuer's public key. Nothing else. No issuer cooperation, no
network calls.

```python
# tutorial_46/03_verify_disclosure.py
import hashlib, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

def jcs(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")

def _path_positions(leaf_count, target_index):
    """Replays the top-down recursion to recover, for each level, whether
    the target was in the left half (True) or right half (False) of the
    current subtree. Returned in bottom-up order to match the proof.
    """
    positions_top_down = []
    n = leaf_count
    index = target_index
    while n > 1:
        k = 1
        while k * 2 < n:
            k *= 2
        if index < k:
            positions_top_down.append(True)
            n = k
        else:
            positions_top_down.append(False)
            index -= k
            n = n - k
    return list(reversed(positions_top_down))


def verify_proof(name, value, salt_hex, proof, index, leaf_count, expected_root):
    """Walk the Merkle proof from leaf to root, compare to expected root."""
    leaf_obj = {"name": name, "salt": salt_hex, "value": value}
    current = hashlib.sha256(LEAF_PREFIX + jcs(leaf_obj)).digest()

    positions = _path_positions(leaf_count, index)
    if len(positions) != len(proof):
        return False

    for sibling_str, target_was_left in zip(proof, positions):
        sibling = bytes.fromhex(sibling_str.removeprefix("sha256:"))
        if target_was_left:
            current = hashlib.sha256(NODE_PREFIX + current + sibling).digest()
        else:
            current = hashlib.sha256(NODE_PREFIX + sibling + current).digest()

    actual_root = "sha256:" + current.hex()
    return actual_root == expected_root

def verify_receipt_with_disclosure(receipt: dict, disclosure: dict):
    # 1. Verify Ed25519 signature on the envelope.
    pub_hex = receipt["public_key"].removeprefix("ed25519:")
    sig_hex = receipt["signature"].removeprefix("ed25519:")
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
    envelope = {k: v for k, v in receipt.items()
                if k not in ("signature", "public_key")}
    try:
        pub.verify(bytes.fromhex(sig_hex), jcs(envelope))
    except InvalidSignature:
        return False, "envelope signature invalid"

    # 2. Verify each disclosed field's Merkle proof against the root.
    expected_root = receipt["committed_fields_root"]
    for d in disclosure["disclosed"]:
        ok = verify_proof(
            d["name"], d["value"], d["salt"], d["proof"],
            d["index"], d["leaf_count"], expected_root
        )
        if not ok:
            return False, f"merkle proof failed for {d['name']}"

    return True, "ok"

# ---- Auditor side ----
ok, reason = verify_receipt_with_disclosure(receipt_envelope, disclosure)
print(f"verification: {ok} ({reason})")
```

In Node, the same verification is one CLI call:

```bash
npx @veritasacta/verify@0.6.0 \
  --receipt receipt.json \
  --disclosure-file disclosure.json \
  --public-key ed25519-pub.pem
```

Exit codes match Tutorial 33's verifier:

| Exit code | Meaning |
|-----------|---------|
| `0` | Receipt valid, all disclosed fields verify against the committed root |
| `1` | Tampering detected: signature or Merkle proof failed |
| `2` | Malformed receipt or disclosure JSON |
| `3` | Disclosure references a field outside `leaf_count` |

The verifier returns the same exit code regardless of which language the
receipt was signed in. A receipt minted by a Python `protect-mcp` adapter
verifies under the Node `@veritasacta/verify` CLI, and vice versa, because
the canonical bytes the signature covers are JCS-deterministic and the
Merkle construction follows RFC 6962 with no implementation-defined choices.

---

## 4 — Composing with Tutorial 33's Chain

Selective disclosure composes orthogonally with Tutorial 33's hash chain:

- The chain provides **temporal integrity**: receipt 5's
  `parent_receipt_hash` references the JCS-canonical hash of receipt 4, so
  inserting or removing a receipt breaks the chain.
- The Merkle commitment provides **field-level integrity**: each receipt's
  `committed_fields_root` covers all committed fields, so the issuer cannot
  substitute a different value for a hidden field after signing.

A chained receipt with selective disclosure carries both:

```json
{
  "receipt_id":            "rcpt-9d4e6a12",
  "tool_name":             "ledger:debit",
  "decision":              "allow",
  "timestamp":             "2026-04-25T12:35:01Z",
  "parent_receipt_hash":   "sha256:b2c1...e5a6",
  "committed_fields_root": "sha256:f8a4...c3d1",
  "signature":             "ed25519:...",
  "public_key":            "ed25519:..."
}
```

The auditor walking the chain verifies each receipt's signature, then verifies
that each receipt's `parent_receipt_hash` matches the JCS-canonical hash of
the previous receipt. They do not need any disclosures to verify chain
integrity itself; that runs entirely on public fields.

If a specific receipt in the chain has hidden fields the auditor needs to
inspect, the issuer attaches the disclosure proof for just that receipt. The
chain remains verifiable for an auditor who has zero disclosures (chain
integrity only) and for an auditor who has full disclosures (chain integrity
plus complete decision history). Both views are valid simultaneously.

```python
# Walking a chain with mixed-disclosure auditors.
def walk_chain(chain, disclosures_for_auditor=None):
    disclosures_for_auditor = disclosures_for_auditor or {}
    prior_hash = None
    for receipt in chain:
        # Always: signature + chain link.
        ok, _ = verify_receipt_envelope_signature(receipt)
        if not ok:
            return False, f"signature on {receipt['receipt_id']}"
        if receipt["parent_receipt_hash"] != prior_hash:
            return False, f"chain break at {receipt['receipt_id']}"
        # Conditionally: per-receipt disclosure proofs.
        if receipt["receipt_id"] in disclosures_for_auditor:
            for d in disclosures_for_auditor[receipt["receipt_id"]]["disclosed"]:
                if not verify_proof(d["name"], d["value"], d["salt"],
                                    d["proof"], d["index"], d["leaf_count"],
                                    receipt["committed_fields_root"]):
                    return False, f"proof on {receipt['receipt_id']}/{d['name']}"
        prior_hash = "sha256:" + hashlib.sha256(
            jcs({k: v for k, v in receipt.items()
                 if k not in ("signature", "public_key")})
        ).hexdigest()
    return True, "ok"
```

This is the pattern an Article 12 auditor uses to verify an agent's complete
operational history while a parallel GDPR controller verifies the same chain
with reduced disclosure scope.

---

## 5 — Article 12 + GDPR Composition

EU AI Act Article 12 requires high-risk AI systems to maintain
**automatically generated logs** of "events relevant for the identification
of national-level risks and substantial modifications throughout the system's
lifetime." Article 12(2) calls for these logs to be retained for at least six
months and made available to market-surveillance authorities and notified
bodies on request.

GDPR Article 5(1)(c) requires personal data to be **adequate, relevant, and
limited to what is necessary**. Article 6 requires a lawful basis for each
processing purpose. Article 32 requires processing activities to be protected
by appropriate technical measures.

The composition challenge: the same agent action might generate evidence
that needs to be **completely visible** to the AI Act auditor (every field
including the policy that authorized it, the tool result, and chain links to
related decisions) and **minimally visible** to a GDPR data subject access
request response (process metadata only, no inferred personal data).

Selective-disclosure receipts let one signed artifact serve both:

```python
# tutorial_46/05_compose_audits.py
def disclosure_for_article_12(receipt_id, all_fields, salts, leaves):
    """Article 12: every field of operational relevance."""
    indices = [i for i, (name, _) in enumerate(all_fields)
               if name not in ("internal_debug_trace",)]
    return make_disclosure(all_fields, salts, leaves, indices)

def disclosure_for_gdpr_request(receipt_id, all_fields, salts, leaves):
    """GDPR data minimization: process metadata only."""
    public_set = {"tool_name", "decision", "policy_id", "timestamp"}
    indices = [i for i, (name, _) in enumerate(all_fields) if name in public_set]
    return make_disclosure(all_fields, salts, leaves, indices)

def disclosure_for_counterparty(receipt_id, all_fields, salts, leaves):
    """Cross-org verification: delegation scope plus authorization, no payload."""
    public_set = {"tool_name", "decision", "policy_id", "trust_tier",
                  "delegation_chain_root"}
    indices = [i for i, (name, _) in enumerate(all_fields) if name in public_set]
    return make_disclosure(all_fields, salts, leaves, indices)
```

Each auditor verifies the same signed receipt against the same root
commitment. They each see different subsets of the underlying fields. The
issuer never has to maintain three separate signed audit trails.

A few governance points worth flagging:

- **Salt retention as a privacy primitive**. If the issuer wants to make a
  field permanently undisclosable (for example, a 90-day retention horizon on
  personal data), the issuer simply destroys the salt for that field. The
  Merkle root remains valid, the signature remains valid, but the field is
  cryptographically hidden forever. This is the data-minimization-at-rest
  primitive Article 5(1)(c) calls for.

- **Disclosure-policy attestation**. The disclosure itself can be wrapped in
  another receipt that records "this disclosure was issued to auditor X on
  date Y under legal basis Z." This produces a receipted audit trail of who
  saw what, useful for accountability but not for data subject access
  requests.

- **Article 12 minimum-data scope**. Implementations should default to
  committing operational fields (tool name, decision, policy ID, timestamp,
  trust tier) as **public** fields rather than committed-and-hidden. Article
  12 audits should never require the auditor to chase down disclosure proofs
  for fields the regulation explicitly mandates be retained.

The receipt format sets the floor for what's possible. The applied governance
model decides which fields are public, which are committed-and-disclosable,
and which are committed-and-permanently-hidden.

---

## 6 — Cross-Implementation Interoperability

The commitment construction is fully specified in
[draft-farley-acta-signed-receipts §5](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/),
including the leaf and node prefixes, the salt format, the JCS canonicalization
rules for leaf objects, and the RFC 6962 odd-leaf handling. Any conformant
implementation produces byte-identical commitment roots for the same
`(name, value, salt)` triples.

Cross-implementation conformance is checkable via the open Apache-2.0 test
suite at
[github.com/ScopeBlind/agent-governance-testvectors](https://github.com/ScopeBlind/agent-governance-testvectors).
The suite includes commitment-mode fixtures with:

- **Single-field commitments** (smallest receipt)
- **Multi-field commitments with all combinations of public + private**
- **Receipts with 1, 2, 4, 5, 8, 13, 16 committed fields** (covers RFC 6962
  power-of-two and odd-leaf branches)
- **Disclosure proofs for every leaf in each fixture**
- **Negative fixtures** (tampered salts, swapped values, modified roots)

Running the fixtures:

```bash
git clone https://github.com/ScopeBlind/agent-governance-testvectors
cd agent-governance-testvectors

# Run AGT's reference implementation against the commitment-mode suite.
python -m agent_governance_toolkit.testvectors verify \
  --suite commitment-mode \
  --fixtures fixtures/commitment/ \
  --report report.json
```

A passing report confirms that the AGT-side implementation produces
byte-identical commitment roots, byte-identical signed envelopes, and
byte-identical Merkle proofs to the reference fixtures. The same fixtures
verify against `protect-mcp` (Python and Node), `sb-runtime`, and 10+
other implementations covering Rust, Go, and the OCaml reference.

For a new implementation, the conformance checklist is short:

1. Implement RFC 8785 JCS canonicalization (or use a library that does).
2. Implement RFC 6962 Merkle tree with the prefix discipline (`0x00` for
   leaves, `0x01` for internal nodes).
3. Generate per-field 16-byte salts from a CSPRNG.
4. Compute `committed_fields_root` as the Merkle root of leaves.
5. Sign the JCS-canonical envelope (including
   `committed_fields_root` but not `signature` or `public_key`) with Ed25519.
6. Run the testvectors suite and confirm zero diffs.

If the testvectors pass, your implementation interoperates with the others
without further coordination.

---

## CI/CD Integration

Gate merges on disclosure verification so that a regulatory disclosure cannot
land in a release branch unless every receipt's commitment chain verifies.

```yaml
# .github/workflows/verify-selective-disclosure.yml
name: Verify Selective-Disclosure Receipts
on: [push, pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - uses: actions/setup-python@v5
        with:
          python-version: '3.10'

      - name: Run governed agent in commitment mode
        run: |
          python examples/selective-disclosure-governed/run.py \
            --output receipts.jsonl \
            --side-store side-store.json

      - name: Verify chain (signature + parent-hash)
        run: |
          npx @veritasacta/verify@0.6.0 receipts.jsonl

      - name: Generate Article 12 disclosure
        run: |
          python examples/selective-disclosure-governed/disclose.py \
            --receipts receipts.jsonl \
            --side-store side-store.json \
            --profile article-12 \
            --output article-12-disclosure.json

      - name: Verify Article 12 disclosure end-to-end
        run: |
          npx @veritasacta/verify@0.6.0 \
            receipts.jsonl \
            --disclosure-file article-12-disclosure.json
        # exit 0 = chain + every disclosed field's Merkle proof verifies
        # exit 1 = tamper detected
        # exit 2 = malformed
        # exit 3 = disclosure references unknown field
```

In combination with Tutorial 33's CI gates, this gives you four production
gates:

1. **SBOM present and signed** (Tutorial 26)
2. **Audit log integrity** (Tutorial 04)
3. **Decision receipt chain verifies** (Tutorial 33)
4. **Selective-disclosure proofs verify** (this tutorial)

Foundation auditors and regulators can verify the same artifacts offline
using only the public key and the disclosure profile relevant to their
jurisdiction.

---

## Cross-Reference

| Related Tutorial | What it covers | Relationship |
|------------------|----------------|--------------|
| [Tutorial 04 — Audit & Compliance](04-audit-and-compliance.md) | Internal Merkle-chained audit log | Per-receipt Merkle here is a sibling construction at the field level |
| [Tutorial 08 — OPA/Rego & Cedar Policies](08-opa-rego-cedar-policies.md) | Cedar as policy backend | The `policy_id` committed in the receipt indexes into Cedar's policy decisions |
| [Tutorial 12 — Liability & Attribution](12-liability-and-attribution.md) | Causal attribution | Selective disclosure lets attribution be granular per auditor |
| [Tutorial 18 — Compliance Verification](18-compliance-verification.md) | Regulatory framework mapping | Article 12 / GDPR composition is the canonical use case here |
| [Tutorial 23 — Delegation Chains](23-delegation-chains.md) | Cross-org delegation | The `delegation_chain_root` field can be selectively disclosed to counterparties |
| [Tutorial 26 — SBOM & Signing](26-sbom-and-signing.md) | Artifact signing | Same Ed25519 primitives, different artifact |
| [Tutorial 33 — Offline-Verifiable Receipts](33-offline-verifiable-receipts.md) | Per-tool-call receipts (full disclosure) | Direct prerequisite |

**Reference code:**
[`examples/selective-disclosure-governed/`](../../examples/selective-disclosure-governed/)
demonstrates the complete signing, disclosure, and verification flow against
five preset disclosure profiles (Article 12, GDPR, counterparty,
vendor-debug, public).

**Standards:** RFC 8032 (Ed25519) · RFC 8785 (JCS) · SHA-256 ·
RFC 6962 (Merkle Tree construction) · Cedar (AWS) ·
IETF [draft-farley-acta-signed-receipts](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/) §5
