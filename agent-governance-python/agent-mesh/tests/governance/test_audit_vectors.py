# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Committed test vectors for the FileAuditSink on-disk format.

The value of a signed hash chain is that somebody *not* running AGT can check
it. Today that requires importing this package or reading its source, and a
verifier that depends on the thing it verifies is a weak verifier (issue #3643,
discussion #276).

These vectors pin the three details an external implementer cannot guess from a
`.jsonl` file:

1. the fourteen fields covered by ``content_hash``, and that
   ``sandbox_id`` / ``environment`` / ``compute_driver`` are written to the file
   but excluded from the hash;
2. that ``previous_hash`` chains to the previous entry's ``content_hash``, not
   to its ``signature``;
3. that the signature is HMAC-SHA256 over the *hex string* of the content hash,
   not over its raw bytes.

``test_a_stdlib_verifier_agrees`` is the one that matters. It reimplements
verification using only the standard library, the way an integrator would, and
asserts it reaches the same verdict as the reference. Without it these are just
bytes that the implementation agrees with itself about.

``test_the_vectors_are_current`` is what makes the file self-enforcing: change
the hashed payload and this fails here, in AGT's own CI, rather than silently in
somebody else's verifier months later.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import pytest

from agentmesh.governance.audit_backends import HashChainVerifier, SignedAuditEntry

VECTORS_DIR = Path(__file__).parent / "vectors"
VECTORS_PATH = VECTORS_DIR / "file_audit_sink_v1.jsonl"

#: Fixture, not a secret. See vectors/README.md.
SECRET_KEY = b"agt-file-audit-sink-test-vectors-v1"

#: The canonical field set, in the order documented for external implementers.
#: Duplicated from ``SignedAuditEntry._canonical_payload`` on purpose: if the
#: two ever disagree, that is the drift these vectors exist to catch, and a test
#: importing the private method would not catch it.
CANONICAL_FIELDS = [
    "entry_id",
    "timestamp",
    "event_type",
    "agent_did",
    "action",
    "resource",
    "target_did",
    "data",
    "outcome",
    "policy_decision",
    "matched_rule",
    "trace_id",
    "session_id",
    "previous_hash",
]

EXCLUDED_FROM_HASH = ["sandbox_id", "environment", "compute_driver"]


def _rows() -> list[dict]:
    return [
        json.loads(line)
        for line in VECTORS_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _stdlib_content_hash(row: dict) -> str:
    """Recompute ``content_hash`` using only the standard library."""
    payload = {field: row[field] for field in CANONICAL_FIELDS}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode()
    ).hexdigest()


def _stdlib_signature(content_hash: str) -> str:
    return hmac.new(SECRET_KEY, content_hash.encode(), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# The vectors verify against the implementation that produced them
# ---------------------------------------------------------------------------


def test_the_vectors_file_exists_and_is_not_empty():
    assert VECTORS_PATH.is_file(), f"missing vectors at {VECTORS_PATH}"
    assert len(_rows()) >= 4


@pytest.mark.parametrize("index", range(4))
def test_each_vector_verifies(index: int):
    entry = SignedAuditEntry(**_rows()[index])
    assert entry.verify(SECRET_KEY) is True


def test_the_whole_file_verifies_as_a_chain():
    is_valid, errors = HashChainVerifier().verify_file(VECTORS_PATH, SECRET_KEY)
    assert is_valid, f"chain did not verify: {errors}"


# ---------------------------------------------------------------------------
# An external implementer can reach the same verdict
# ---------------------------------------------------------------------------


def test_a_stdlib_verifier_agrees():
    """The whole point. If this fails, the vectors do not document the format.

    Written the way an integrator writes one: no AGT import in the computation,
    only the field list and the two primitives.
    """
    previous_hash = ""
    for row in _rows():
        content_hash = _stdlib_content_hash(row)
        assert content_hash == row["content_hash"], row["entry_id"]
        assert _stdlib_signature(content_hash) == row["signature"], row["entry_id"]
        assert row["previous_hash"] == previous_hash, row["entry_id"]
        previous_hash = row["content_hash"]


def test_the_chain_links_to_content_hash_not_signature():
    """The plausible wrong guess, since the signature is the outermost value."""
    rows = _rows()
    for earlier, later in zip(rows, rows[1:]):
        assert later["previous_hash"] == earlier["content_hash"]
        assert later["previous_hash"] != earlier["signature"]


def test_the_signature_covers_the_hex_string_not_the_raw_digest():
    """`hmac(key, content_hash.encode())`, not `hmac(key, bytes.fromhex(...))`."""
    row = _rows()[0]
    over_raw = hmac.new(
        SECRET_KEY, bytes.fromhex(row["content_hash"]), hashlib.sha256
    ).hexdigest()
    assert row["signature"] == _stdlib_signature(row["content_hash"])
    assert row["signature"] != over_raw


def test_the_genesis_entry_chains_to_empty_string():
    """Not to sha256(b""), which would fail on entry two rather than entry one."""
    assert _rows()[0]["previous_hash"] == ""


# ---------------------------------------------------------------------------
# The exclusion that costs an afternoon
# ---------------------------------------------------------------------------


def test_execution_context_is_written_to_the_file():
    row = _rows()[3]
    assert [row[field] for field in EXCLUDED_FROM_HASH] == [
        "sandbox-42",
        "staging",
        "firecracker",
    ]


def test_execution_context_is_excluded_from_the_hash():
    """Vector 4 carries the context fields; vector 3 does not.

    Both hash the same canonical payload apart from entry_id and timestamp, so
    an implementer who includes the fields they can see gets a mismatch with
    nothing in the file to indicate why. This asserts the exclusion directly
    rather than trusting the comment in the source.
    """
    row = _rows()[3]
    naive = {field: row[field] for field in CANONICAL_FIELDS}
    naive.update({field: row[field] for field in EXCLUDED_FROM_HASH})
    naive_hash = hashlib.sha256(
        json.dumps(naive, sort_keys=True, default=str).encode()
    ).hexdigest()

    assert naive_hash != row["content_hash"]
    assert _stdlib_content_hash(row) == row["content_hash"]


def test_optional_fields_are_hashed_as_null_not_omitted():
    """Vector 3 leaves most optionals unset; dropping the keys changes the digest."""
    row = _rows()[2]
    assert row["resource"] is None

    pruned = {
        field: row[field] for field in CANONICAL_FIELDS if row[field] is not None
    }
    pruned_hash = hashlib.sha256(
        json.dumps(pruned, sort_keys=True, default=str).encode()
    ).hexdigest()
    assert pruned_hash != row["content_hash"]


# ---------------------------------------------------------------------------
# Tampering, and staying current
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("field,value", [("action", "exfiltrate"), ("outcome", "success")])
def test_editing_a_hashed_field_breaks_verification(field: str, value: str):
    row = dict(_rows()[1])
    row[field] = value
    assert SignedAuditEntry(**row).verify(SECRET_KEY) is False


def test_editing_an_excluded_field_does_not_break_verification():
    """Which is the documented intent: context can be added to old chains.

    Worth pinning as a property rather than leaving implicit, because it is the
    reason for the exclusion and the reason the exclusion surprises people.
    """
    row = dict(_rows()[3])
    row["environment"] = "production"
    assert SignedAuditEntry(**row).verify(SECRET_KEY) is True


def test_the_vectors_are_current():
    """Regenerating on an unchanged implementation reproduces the file exactly.

    This is what makes the vectors self-enforcing. A change to the hashed
    payload fails here, in this repository's CI, instead of surfacing months
    later as an external verifier quietly disagreeing about whether a file is
    genuine.
    """
    import sys

    sys.path.insert(0, str(VECTORS_DIR))
    import generate  # noqa: PLC0415

    before = VECTORS_PATH.read_bytes()
    try:
        generate.main()
        assert VECTORS_PATH.read_bytes() == before, (
            "the committed vectors no longer match what FileAuditSink produces. "
            "If the format changed deliberately, rerun "
            "tests/governance/vectors/generate.py and commit the result, then "
            "note the change for external implementers."
        )
    finally:
        VECTORS_PATH.write_bytes(before)
