# Copyright (c) Microsoft Corporation. Licensed under the MIT License.
"""
Reference implementation of Tutorial 46 selective-disclosure receipts.

Single-file Python reference that produces and verifies receipts in
commitment-mode (RFC 6962-style Merkle tree over per-field commitments).
This file serves as both the worked example referenced in Tutorial 46 and
the round-trip self-test that confirms the construction is internally
consistent.

Run:
    pip install cryptography
    python selective_disclosure.py
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any, List, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


# ---------------------------------------------------------------------------
# RFC 6962 Merkle tree primitives
# ---------------------------------------------------------------------------

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def jcs(obj: Any) -> bytes:
    """Minimal RFC 8785 JCS canonicalization.

    Sorts keys, strips whitespace, UTF-8 encodes. Sufficient for the
    ASCII-only field names used in Tutorial 46. For full RFC 8785 compliance
    with arbitrary Unicode, use a dedicated JCS library.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def commit_field(name: str, value: Any, salt: bytes) -> bytes:
    """Per-field commitment leaf.

    leaf = SHA-256(0x00 || JCS({"name": name, "salt": hex(salt), "value": value}))
    """
    leaf_obj = {"name": name, "salt": salt.hex(), "value": value}
    return hashlib.sha256(LEAF_PREFIX + jcs(leaf_obj)).digest()


def merkle_root(leaves: List[bytes]) -> bytes:
    """RFC 6962-style Merkle root with non-power-of-two leaf handling."""
    if len(leaves) == 1:
        return leaves[0]
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    left = merkle_root(leaves[:k])
    right = merkle_root(leaves[k:])
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def merkle_proof(leaves: List[bytes], target_index: int) -> List[bytes]:
    """Returns sibling hashes from leaf up to root (bottom-up order).

    Proof[0] is the deepest sibling (closest to the leaf). Proof[-1] is the
    root-level sibling (closest to the root). This matches the order in
    which a verifier walking from leaf to root consumes them.
    """
    siblings_top_down: List[bytes] = []
    nodes = list(leaves)
    index = target_index
    while len(nodes) > 1:
        k = 1
        while k * 2 < len(nodes):
            k *= 2
        if index < k:
            sibling = merkle_root(nodes[k:])
            siblings_top_down.append(sibling)
            nodes = nodes[:k]
        else:
            sibling = merkle_root(nodes[:k])
            siblings_top_down.append(sibling)
            nodes = nodes[k:]
            index -= k
    # Reverse to get bottom-up (leaf-to-root) order.
    return list(reversed(siblings_top_down))


def _path_positions(leaf_count: int, target_index: int) -> List[bool]:
    """Recompute, top-down, whether at each level the target is in the left
    half (True) or right half (False) of the current subtree. Returned in
    bottom-up order to match merkle_proof()'s output order.
    """
    positions_top_down: List[bool] = []
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


def verify_proof(
    name: str,
    value: Any,
    salt_hex: str,
    proof: List[str],
    index: int,
    leaf_count: int,
    expected_root_hex: str,
) -> bool:
    """Walk the Merkle proof to recompute the root, compare to expected.

    proof is in bottom-up order: proof[0] is the deepest sibling, proof[-1]
    is the root-level sibling.
    """
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

    expected = expected_root_hex.removeprefix("sha256:")
    return current.hex() == expected


# ---------------------------------------------------------------------------
# Receipt construction
# ---------------------------------------------------------------------------


def commit_receipt(
    fields: List[Tuple[str, Any]],
) -> Tuple[bytes, List[bytes], List[bytes]]:
    """Returns (committed_fields_root, leaves, salts)."""
    salts = [os.urandom(16) for _ in fields]
    leaves = [
        commit_field(name, value, salt)
        for (name, value), salt in zip(fields, salts)
    ]
    return merkle_root(leaves), leaves, salts


def make_receipt(
    fields: List[Tuple[str, Any]],
    public_field_names: set,
    private_key: Ed25519PrivateKey,
    receipt_id: str,
    parent_receipt_hash: str | None = None,
):
    """Mints a commitment-mode receipt.

    Returns:
        (receipt_envelope, side_store) where side_store carries the
        salts and field values needed to emit disclosures later.
    """
    root, leaves, salts = commit_receipt(fields)

    public_payload = {name: value for name, value in fields if name in public_field_names}

    receipt_envelope = {
        "receipt_id": receipt_id,
        **public_payload,
        "parent_receipt_hash": parent_receipt_hash,
        "committed_fields_root": "sha256:" + root.hex(),
    }

    payload = jcs(receipt_envelope)
    signature = private_key.sign(payload)
    public_bytes = private_key.public_key().public_bytes_raw()
    receipt_envelope["signature"] = "ed25519:" + signature.hex()
    receipt_envelope["public_key"] = "ed25519:" + public_bytes.hex()

    side_store = {
        "receipt_id": receipt_id,
        "fields": [{"name": n, "value": v} for n, v in fields],
        "salts": [s.hex() for s in salts],
        "leaf_count": len(leaves),
    }
    return receipt_envelope, side_store


# ---------------------------------------------------------------------------
# Disclosure
# ---------------------------------------------------------------------------


def make_disclosure(side_store: dict, indices_to_reveal: List[int]) -> dict:
    """Builds a disclosure proof for the requested field indices."""
    fields = [(f["name"], f["value"]) for f in side_store["fields"]]
    salts = [bytes.fromhex(s) for s in side_store["salts"]]
    leaves = [
        commit_field(name, value, salt)
        for (name, value), salt in zip(fields, salts)
    ]
    leaf_count = len(leaves)

    disclosed = []
    for i in indices_to_reveal:
        name, value = fields[i]
        proof = merkle_proof(leaves, i)
        disclosed.append({
            "name": name,
            "value": value,
            "salt": salts[i].hex(),
            "proof": ["sha256:" + s.hex() for s in proof],
            "index": i,
            "leaf_count": leaf_count,
        })
    return {"receipt_id": side_store["receipt_id"], "disclosed": disclosed}


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def verify_envelope_signature(receipt: dict) -> Tuple[bool, str]:
    """Verifies the Ed25519 signature on the receipt envelope."""
    if "signature" not in receipt or "public_key" not in receipt:
        return False, "missing signature or public_key"

    pub_hex = receipt["public_key"].removeprefix("ed25519:")
    sig_hex = receipt["signature"].removeprefix("ed25519:")
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
    except Exception as e:
        return False, f"public key decode: {e}"

    envelope = {
        k: v for k, v in receipt.items() if k not in ("signature", "public_key")
    }
    try:
        pub.verify(bytes.fromhex(sig_hex), jcs(envelope))
        return True, "ok"
    except InvalidSignature:
        return False, "envelope signature invalid"


def verify_receipt_with_disclosure(
    receipt: dict, disclosure: dict
) -> Tuple[bool, str]:
    """Verifies (1) the envelope signature, then (2) each disclosed field."""
    ok, reason = verify_envelope_signature(receipt)
    if not ok:
        return False, reason

    expected_root = receipt["committed_fields_root"]
    for d in disclosure["disclosed"]:
        ok = verify_proof(
            d["name"],
            d["value"],
            d["salt"],
            d["proof"],
            d["index"],
            d["leaf_count"],
            expected_root,
        )
        if not ok:
            return False, f"merkle proof failed for {d['name']}"

    return True, "ok"


# ---------------------------------------------------------------------------
# Round-trip self-test
# ---------------------------------------------------------------------------


def _roundtrip_self_test():
    """Demonstrates the full Tutorial 46 flow end-to-end with assertions."""
    print("Tutorial 46 round-trip self-test")
    print("=" * 60)

    fields: List[Tuple[str, Any]] = [
        ("tool_name", "file_system:read_file"),
        ("decision", "allow"),
        ("policy_id", "autoresearch-safe"),
        ("trust_tier", "evidenced"),
        ("user_id", "u_8492"),
        ("tool_args", {"path": "/etc/passwd"}),
        ("timestamp", "2026-04-25T12:34:56Z"),
    ]
    public_set = {
        "tool_name", "decision", "policy_id", "trust_tier", "timestamp"
    }

    key = Ed25519PrivateKey.generate()
    receipt, side_store = make_receipt(
        fields=fields,
        public_field_names=public_set,
        private_key=key,
        receipt_id="rcpt-test-0001",
    )

    print("Receipt envelope:")
    print(json.dumps(receipt, indent=2))
    print()

    # 1. Receipt with no disclosure: signature verifies on its own.
    ok, reason = verify_envelope_signature(receipt)
    assert ok, f"envelope signature failed: {reason}"
    print(f"1. Envelope signature: {reason}")

    # 2. Article 12 disclosure: every field including private user_id and tool_args.
    article_12 = make_disclosure(
        side_store, indices_to_reveal=[0, 1, 2, 3, 4, 5, 6]
    )
    ok, reason = verify_receipt_with_disclosure(receipt, article_12)
    assert ok, f"article 12 disclosure failed: {reason}"
    print(f"2. Article 12 (every field):                    {reason}")

    # 3. GDPR disclosure: process metadata only.
    gdpr = make_disclosure(side_store, indices_to_reveal=[0, 1, 2, 6])
    ok, reason = verify_receipt_with_disclosure(receipt, gdpr)
    assert ok, f"gdpr disclosure failed: {reason}"
    print(f"3. GDPR (process metadata only):                {reason}")

    # 4. Counterparty disclosure: minimal fields.
    counterparty = make_disclosure(side_store, indices_to_reveal=[0, 1, 3])
    ok, reason = verify_receipt_with_disclosure(receipt, counterparty)
    assert ok, f"counterparty disclosure failed: {reason}"
    print(f"4. Counterparty (auth scope only):              {reason}")

    # 5. Tampered disclosure: switching user_id to a different value should fail.
    tampered = make_disclosure(side_store, indices_to_reveal=[4])
    tampered["disclosed"][0]["value"] = "u_DIFFERENT"
    ok, reason = verify_receipt_with_disclosure(receipt, tampered)
    assert not ok, "tampered disclosure should have failed!"
    print(f"5. Tampered (value swapped):                    rejected as expected ({reason})")

    # 6. Tampered envelope: changing decision should break signature.
    tampered_receipt = dict(receipt)
    tampered_receipt["decision"] = "deny"
    ok, reason = verify_envelope_signature(tampered_receipt)
    assert not ok, "tampered envelope should have failed!"
    print(f"6. Tampered envelope (decision flipped):        rejected as expected ({reason})")

    # 7. Cross-receipt chain: parent_receipt_hash links into a second receipt.
    receipt_canonical_hash = (
        "sha256:"
        + hashlib.sha256(
            jcs(
                {
                    k: v
                    for k, v in receipt.items()
                    if k not in ("signature", "public_key")
                }
            )
        ).hexdigest()
    )
    fields_2 = fields + [("ledger_op", "debit_account_42")]
    receipt_2, side_store_2 = make_receipt(
        fields=fields_2,
        public_field_names=public_set,
        private_key=key,
        receipt_id="rcpt-test-0002",
        parent_receipt_hash=receipt_canonical_hash,
    )
    ok, reason = verify_envelope_signature(receipt_2)
    assert ok, f"chained receipt signature failed: {reason}"
    assert receipt_2["parent_receipt_hash"] == receipt_canonical_hash
    print(f"7. Chained receipt (rcpt-0001 -> rcpt-0002):    {reason}")

    print()
    print("All 7 assertions passed.")
    return True


if __name__ == "__main__":
    _roundtrip_self_test()
