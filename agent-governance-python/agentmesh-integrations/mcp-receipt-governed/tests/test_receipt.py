# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for GovernanceReceipt, ReceiptStore, signing/verification, and hash chaining.

These tests run without any external SDK. They validate the receipt model,
canonical serialization, Ed25519 sign/verify round-trip, hash chaining for
insertion detection, and SLSA provenance emission in isolation.
"""

import json
from urllib.parse import urlparse

import pytest

from mcp_receipt_governed.receipt import (
    GovernanceReceipt,
    ReceiptStore,
    hash_tool_args,
    sign_receipt,
    verify_receipt,
    verify_receipt_chain,
)


# ── Receipt Model ──


class TestGovernanceReceipt:
    """Core receipt dataclass behavior."""

    def test_default_fields(self):
        r = GovernanceReceipt()
        assert r.receipt_id  # UUID generated
        assert r.cedar_decision == "deny"
        assert r.tool_name == ""
        assert r.agent_did == ""
        assert r.timestamp > 0
        assert r.parent_receipt_hash is None

    def test_canonical_payload_deterministic(self):
        r = GovernanceReceipt(
            receipt_id="test-id",
            tool_name="ReadData",
            agent_did="did:mesh:agent-1",
            cedar_policy_id="policy:v1",
            cedar_decision="allow",
            args_hash="abc123",
            timestamp=1700000000.0,
        )
        payload1 = r.canonical_payload()
        payload2 = r.canonical_payload()
        assert payload1 == payload2
        # Verify it's valid JSON with sorted keys
        parsed = json.loads(payload1)
        assert list(parsed.keys()) == sorted(parsed.keys())

    def test_canonical_payload_excludes_signature(self):
        r = GovernanceReceipt(
            receipt_id="test-id",
            tool_name="ReadData",
            timestamp=1700000000.0,
        )
        payload = r.canonical_payload()
        assert "signature" not in payload
        assert "signer_public_key" not in payload

    def test_payload_hash_consistent(self):
        r = GovernanceReceipt(
            receipt_id="test-id",
            tool_name="ReadData",
            timestamp=1700000000.0,
        )
        assert r.payload_hash() == r.payload_hash()

    def test_payload_hash_changes_with_content(self):
        r1 = GovernanceReceipt(receipt_id="id-1", timestamp=1.0)
        r2 = GovernanceReceipt(receipt_id="id-2", timestamp=1.0)
        assert r1.payload_hash() != r2.payload_hash()

    def test_to_dict_includes_all_fields(self):
        r = GovernanceReceipt(
            receipt_id="test-id",
            tool_name="ReadData",
            agent_did="did:mesh:a1",
            cedar_policy_id="policy:v1",
            cedar_decision="allow",
            args_hash="hash123",
            timestamp=1700000000.0,
        )
        d = r.to_dict()
        assert d["receipt_id"] == "test-id"
        assert d["tool_name"] == "ReadData"
        assert d["agent_did"] == "did:mesh:a1"
        assert d["cedar_policy_id"] == "policy:v1"
        assert d["cedar_decision"] == "allow"
        assert d["args_hash"] == "hash123"
        assert d["payload_hash"]  # computed
        assert d["parent_receipt_hash"] is None
        assert d["signature"] is None
        assert d["error"] is None


# ── JCS Canonicalization (RFC 8785) ──


class TestJCSCanonicalization:
    """Verify RFC 8785 JSON Canonicalization Scheme compliance."""

    def test_unicode_preserved_not_escaped(self):
        """JCS § 3.2.2.2 requires raw UTF-8 instead of \\uXXXX escapes."""
        r = GovernanceReceipt(
            receipt_id="test-id",
            tool_name="ReadDäta",
            timestamp=1700000000.0,
        )
        payload = r.canonical_payload()
        assert "ReadDäta" in payload
        assert "\\u" not in payload

    def test_no_whitespace_in_canonical(self):
        """JCS uses compact separators with no trailing whitespace."""
        r = GovernanceReceipt(receipt_id="test-id", timestamp=1.0)
        payload = r.canonical_payload()
        assert " " not in payload.replace("test-id", "x")

    def test_keys_sorted_alphabetically(self):
        r = GovernanceReceipt(
            receipt_id="test-id",
            tool_name="ReadData",
            agent_did="did:mesh:a1",
            timestamp=1700000000.0,
        )
        parsed = json.loads(r.canonical_payload())
        keys = list(parsed.keys())
        assert keys == sorted(keys)

    def test_emoji_unicode_preserved(self):
        """Emoji (astral plane) codepoints are preserved in canonical form."""
        r = GovernanceReceipt(
            receipt_id="test-id",
            tool_name="Send\U0001f600Message",
            timestamp=1.0,
        )
        payload = r.canonical_payload()
        assert "\U0001f600" in payload
        assert "\\u" not in payload

    def test_cjk_characters_preserved(self):
        """CJK ideographs are emitted as raw UTF-8."""
        r = GovernanceReceipt(
            receipt_id="test-id",
            tool_name="\u8bfb\u53d6\u6570\u636e",
            timestamp=1.0,
        )
        payload = r.canonical_payload()
        assert "\u8bfb\u53d6\u6570\u636e" in payload

    def test_empty_string_fields(self):
        """Empty strings are valid and canonical."""
        r = GovernanceReceipt(
            receipt_id="",
            tool_name="",
            timestamp=1.0,
        )
        payload = r.canonical_payload()
        parsed = json.loads(payload)
        assert parsed["receipt_id"] == ""
        assert parsed["tool_name"] == ""


# ── Session ID ──


class TestSessionId:
    """Test session_id for replay attack prevention."""

    def test_session_id_in_canonical_payload(self):
        r = GovernanceReceipt(
            receipt_id="test-id",
            timestamp=1.0,
            session_id="session-abc",
        )
        payload = r.canonical_payload()
        assert "session-abc" in payload

    def test_session_id_absent_when_none(self):
        r = GovernanceReceipt(receipt_id="test-id", timestamp=1.0)
        payload = r.canonical_payload()
        assert "session_id" not in payload

    def test_session_id_affects_payload_hash(self):
        r_a = GovernanceReceipt(
            receipt_id="test-id",
            timestamp=1.0,
            session_id="session-1",
        )
        r_b = GovernanceReceipt(
            receipt_id="test-id",
            timestamp=1.0,
            session_id="session-2",
        )
        assert r_a.payload_hash() != r_b.payload_hash()

    def test_session_id_in_to_dict(self):
        r = GovernanceReceipt(
            receipt_id="test-id",
            timestamp=1.0,
            session_id="session-xyz",
        )
        d = r.to_dict()
        assert d["session_id"] == "session-xyz"


# ── Hash Chaining ──


class TestHashChaining:
    """Test receipt-level hash chaining for insertion/deletion detection."""

    def test_first_receipt_has_no_parent(self):
        r = GovernanceReceipt(receipt_id="first", timestamp=1.0)
        assert r.parent_receipt_hash is None
        assert "parent_receipt_hash" not in r.canonical_payload()

    def test_chained_receipt_includes_parent(self):
        r1 = GovernanceReceipt(receipt_id="first", timestamp=1.0)
        h1 = r1.payload_hash()

        r2 = GovernanceReceipt(
            receipt_id="second",
            timestamp=2.0,
            parent_receipt_hash=h1,
        )
        assert r2.parent_receipt_hash == h1
        assert "parent_receipt_hash" in r2.canonical_payload()
        assert h1 in r2.canonical_payload()

    def test_parent_hash_affects_payload_hash(self):
        """Changing the parent hash changes the receipt's own hash."""
        r_a = GovernanceReceipt(
            receipt_id="test",
            timestamp=1.0,
            parent_receipt_hash="aaa",
        )
        r_b = GovernanceReceipt(
            receipt_id="test",
            timestamp=1.0,
            parent_receipt_hash="bbb",
        )
        assert r_a.payload_hash() != r_b.payload_hash()

    def test_to_dict_includes_parent_hash(self):
        r = GovernanceReceipt(
            receipt_id="test",
            timestamp=1.0,
            parent_receipt_hash="deadbeef",
        )
        d = r.to_dict()
        assert d["parent_receipt_hash"] == "deadbeef"

    def test_three_receipt_chain(self):
        r1 = GovernanceReceipt(receipt_id="r1", timestamp=1.0)
        r2 = GovernanceReceipt(
            receipt_id="r2",
            timestamp=2.0,
            parent_receipt_hash=r1.payload_hash(),
        )
        r3 = GovernanceReceipt(
            receipt_id="r3",
            timestamp=3.0,
            parent_receipt_hash=r2.payload_hash(),
        )
        # Verify chain links
        assert r2.parent_receipt_hash == r1.payload_hash()
        assert r3.parent_receipt_hash == r2.payload_hash()
        # Each receipt has a unique hash
        assert len({r1.payload_hash(), r2.payload_hash(), r3.payload_hash()}) == 3


# ── SLSA Provenance ──


class TestSLSAProvenance:
    """Test SLSA v1.0 provenance predicate emission."""

    def test_slsa_statement_structure(self):
        r = GovernanceReceipt(
            receipt_id="test-id",
            tool_name="ReadData",
            agent_did="did:mesh:a1",
            cedar_policy_id="policy:v1",
            cedar_decision="allow",
            args_hash="hash123",
            timestamp=1700000000.0,
        )
        slsa = r.to_slsa_provenance()
        assert slsa["_type"] == "https://in-toto.io/Statement/v1"
        assert slsa["predicateType"] == "https://slsa.dev/provenance/v1"

    def test_slsa_subject(self):
        r = GovernanceReceipt(
            receipt_id="test-id",
            tool_name="ReadData",
            args_hash="hash123",
        )
        slsa = r.to_slsa_provenance()
        subject = slsa["subject"][0]
        assert subject["name"] == "pkg:agentmesh/tool/ReadData"
        assert subject["digest"]["sha256"] == "hash123"

    def test_slsa_includes_parent_dependency(self):
        r = GovernanceReceipt(
            receipt_id="test-id",
            tool_name="ReadData",
            args_hash="hash123",
            parent_receipt_hash="parent-hash-456",
        )
        slsa = r.to_slsa_provenance()
        deps = slsa["predicate"]["buildDefinition"]["resolvedDependencies"]
        assert len(deps) == 1
        assert deps[0]["digest"]["sha256"] == "parent-hash-456"

    def test_slsa_no_parent_empty_deps(self):
        r = GovernanceReceipt(receipt_id="test-id", tool_name="ReadData")
        slsa = r.to_slsa_provenance()
        deps = slsa["predicate"]["buildDefinition"]["resolvedDependencies"]
        assert deps == []

    def test_slsa_run_details(self):
        r = GovernanceReceipt(
            receipt_id="test-id",
            tool_name="ReadData",
            timestamp=1700000000.0,
        )
        slsa = r.to_slsa_provenance()
        run = slsa["predicate"]["runDetails"]
        assert run["metadata"]["invocationId"] == "test-id"
        builder_host = urlparse(run["builder"]["id"]).hostname
        assert builder_host and (
            builder_host == "agent-governance.org" or builder_host.endswith(".agent-governance.org")
        )


# ── Hash Tool Args ──


class TestHashToolArgs:
    def test_none_args(self):
        h = hash_tool_args(None)
        assert len(h) == 64  # SHA-256 hex

    def test_empty_args(self):
        h = hash_tool_args({})
        assert h == hash_tool_args(None)  # both produce "{}"

    def test_deterministic(self):
        args = {"path": "/data/report.csv", "limit": 100}
        assert hash_tool_args(args) == hash_tool_args(args)

    def test_key_order_independent(self):
        """Canonical JSON sorts keys, so order shouldn't matter."""
        args1 = {"b": 2, "a": 1}
        args2 = {"a": 1, "b": 2}
        assert hash_tool_args(args1) == hash_tool_args(args2)

    def test_different_args_different_hash(self):
        h1 = hash_tool_args({"path": "/a"})
        h2 = hash_tool_args({"path": "/b"})
        assert h1 != h2


# ── Sign / Verify ──


class TestSignVerify:
    @pytest.fixture()
    def ed25519_keypair(self):
        """Generate a fresh Ed25519 keypair for tests."""
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

            private_key = Ed25519PrivateKey.generate()
            seed = private_key.private_bytes_raw().hex()
            pub = private_key.public_key().public_bytes_raw().hex()
            return seed, pub
        except ImportError:
            pytest.skip("cryptography not installed")

    def test_sign_populates_signature(self, ed25519_keypair):
        seed, pub = ed25519_keypair
        r = GovernanceReceipt(
            receipt_id="test-id",
            tool_name="ReadData",
            agent_did="did:mesh:a1",
            timestamp=1700000000.0,
        )
        sign_receipt(r, seed)
        assert r.signature is not None
        assert r.signer_public_key == pub

    def test_sign_verify_roundtrip(self, ed25519_keypair):
        seed, _pub = ed25519_keypair
        r = GovernanceReceipt(
            receipt_id="test-id",
            tool_name="ReadData",
            agent_did="did:mesh:a1",
            cedar_policy_id="policy:v1",
            cedar_decision="allow",
            timestamp=1700000000.0,
        )
        sign_receipt(r, seed)
        assert verify_receipt(r) is True

    def test_tampered_receipt_fails_verification(self, ed25519_keypair):
        seed, _pub = ed25519_keypair
        r = GovernanceReceipt(
            receipt_id="test-id",
            tool_name="ReadData",
            agent_did="did:mesh:a1",
            timestamp=1700000000.0,
        )
        sign_receipt(r, seed)
        # Tamper with the receipt
        r.cedar_decision = "allow"
        assert verify_receipt(r) is False

    def test_unsigned_receipt_fails_verification(self):
        r = GovernanceReceipt(receipt_id="test-id")
        assert verify_receipt(r) is False

    def test_invalid_signature_fails(self, ed25519_keypair):
        seed, _pub = ed25519_keypair
        r = GovernanceReceipt(
            receipt_id="test-id",
            tool_name="ReadData",
            timestamp=1700000000.0,
        )
        sign_receipt(r, seed)
        r.signature = "deadbeef" * 16  # invalid sig
        assert verify_receipt(r) is False


# ── Chain Verification ──


class TestVerifyReceiptChain:
    """Test the verify_receipt_chain() function for offline verification."""

    def test_empty_chain_valid(self):
        assert verify_receipt_chain([]) == []

    def test_single_unsigned_receipt_flagged(self):
        r = GovernanceReceipt(receipt_id="only", timestamp=1.0)
        errors = verify_receipt_chain([r])
        assert len(errors) == 1
        assert "Unsigned" in errors[0]

    def test_single_receipt_unexpected_parent(self):
        r = GovernanceReceipt(
            receipt_id="only",
            timestamp=1.0,
            parent_receipt_hash="surprise",
        )
        errors = verify_receipt_chain([r])
        # Expect both: unexpected parent + unsigned
        assert any("First receipt" in e for e in errors)
        assert any("Unsigned" in e for e in errors)

    def test_valid_three_receipt_chain(self):
        r1 = GovernanceReceipt(receipt_id="r1", timestamp=1.0)
        r2 = GovernanceReceipt(
            receipt_id="r2",
            timestamp=2.0,
            parent_receipt_hash=r1.payload_hash(),
        )
        r3 = GovernanceReceipt(
            receipt_id="r3",
            timestamp=3.0,
            parent_receipt_hash=r2.payload_hash(),
        )
        # All errors should be unsigned warnings only (chain is contiguous)
        errors = verify_receipt_chain([r1, r2, r3])
        assert all("Unsigned" in e for e in errors)
        assert not any("Hash chain broken" in e for e in errors)

    def test_broken_chain_detected(self):
        r1 = GovernanceReceipt(receipt_id="r1", timestamp=1.0)
        r2 = GovernanceReceipt(
            receipt_id="r2",
            timestamp=2.0,
            parent_receipt_hash="wrong-hash",
        )
        errors = verify_receipt_chain([r1, r2])
        chain_errors = [e for e in errors if "Unsigned" not in e]
        assert len(chain_errors) == 1
        assert "Hash chain broken" in chain_errors[0]

    def test_deleted_receipt_detected(self):
        """Removing a receipt from the middle breaks the chain."""
        r1 = GovernanceReceipt(receipt_id="r1", timestamp=1.0)
        r2 = GovernanceReceipt(
            receipt_id="r2",
            timestamp=2.0,
            parent_receipt_hash=r1.payload_hash(),
        )
        r3 = GovernanceReceipt(
            receipt_id="r3",
            timestamp=3.0,
            parent_receipt_hash=r2.payload_hash(),
        )
        # Delete r2 from the chain
        errors = verify_receipt_chain([r1, r3])
        chain_errors = [e for e in errors if "Unsigned" not in e]
        assert len(chain_errors) == 1
        assert "Hash chain broken" in chain_errors[0]

    @pytest.fixture()
    def signing_key(self):
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

            key = Ed25519PrivateKey.generate()
            return key.private_bytes_raw().hex()
        except ImportError:
            pytest.skip("cryptography not installed")

    def test_signed_chain_verified(self, signing_key):
        r1 = GovernanceReceipt(receipt_id="r1", timestamp=1.0)
        sign_receipt(r1, signing_key)
        r2 = GovernanceReceipt(
            receipt_id="r2",
            timestamp=2.0,
            parent_receipt_hash=r1.payload_hash(),
        )
        sign_receipt(r2, signing_key)
        assert verify_receipt_chain([r1, r2]) == []

    def test_tampered_signed_chain_detected(self, signing_key):
        r1 = GovernanceReceipt(receipt_id="r1", timestamp=1.0)
        sign_receipt(r1, signing_key)
        r2 = GovernanceReceipt(
            receipt_id="r2",
            timestamp=2.0,
            parent_receipt_hash=r1.payload_hash(),
        )
        sign_receipt(r2, signing_key)
        # Tamper with r2 after signing
        r2.tool_name = "TAMPERED"
        errors = verify_receipt_chain([r1, r2])
        assert any("signature" in e.lower() for e in errors)

    def test_trusted_keys_accepted(self, signing_key):
        """Receipts signed by a trusted key pass validation."""
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

            key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(signing_key))
            pub_hex = key.public_key().public_bytes_raw().hex()
        except ImportError:
            pytest.skip("cryptography not installed")

        r = GovernanceReceipt(receipt_id="r1", timestamp=1.0)
        sign_receipt(r, signing_key)
        errors = verify_receipt_chain([r], trusted_keys=[pub_hex])
        assert errors == []

    def test_untrusted_key_flagged(self, signing_key):
        """Receipts signed by an untrusted key are flagged."""
        r = GovernanceReceipt(receipt_id="r1", timestamp=1.0)
        sign_receipt(r, signing_key)
        errors = verify_receipt_chain([r], trusted_keys=["deadbeef" * 4])
        assert any("not in trusted key set" in e for e in errors)


# ── Receipt Store ──


class TestReceiptStore:
    def test_add_and_count(self):
        store = ReceiptStore()
        assert store.count == 0
        store.add(GovernanceReceipt(receipt_id="r1"))
        assert store.count == 1

    def test_query_by_agent(self):
        store = ReceiptStore()
        store.add(GovernanceReceipt(receipt_id="r1", agent_did="did:mesh:a1"))
        store.add(GovernanceReceipt(receipt_id="r2", agent_did="did:mesh:a2"))
        store.add(GovernanceReceipt(receipt_id="r3", agent_did="did:mesh:a1"))

        results = store.query(agent_did="did:mesh:a1")
        assert len(results) == 2
        assert all(r.agent_did == "did:mesh:a1" for r in results)

    def test_query_by_tool(self):
        store = ReceiptStore()
        store.add(GovernanceReceipt(receipt_id="r1", tool_name="ReadData"))
        store.add(GovernanceReceipt(receipt_id="r2", tool_name="DeleteFile"))

        results = store.query(tool_name="ReadData")
        assert len(results) == 1
        assert results[0].tool_name == "ReadData"

    def test_query_by_decision(self):
        store = ReceiptStore()
        store.add(GovernanceReceipt(receipt_id="r1", cedar_decision="allow"))
        store.add(GovernanceReceipt(receipt_id="r2", cedar_decision="deny"))
        store.add(GovernanceReceipt(receipt_id="r3", cedar_decision="allow"))

        allowed = store.query(cedar_decision="allow")
        assert len(allowed) == 2

        denied = store.query(cedar_decision="deny")
        assert len(denied) == 1

    def test_query_combined_filters(self):
        store = ReceiptStore()
        store.add(
            GovernanceReceipt(
                receipt_id="r1",
                agent_did="did:mesh:a1",
                tool_name="ReadData",
                cedar_decision="allow",
            )
        )
        store.add(
            GovernanceReceipt(
                receipt_id="r2",
                agent_did="did:mesh:a1",
                tool_name="DeleteFile",
                cedar_decision="deny",
            )
        )
        store.add(
            GovernanceReceipt(
                receipt_id="r3",
                agent_did="did:mesh:a2",
                tool_name="ReadData",
                cedar_decision="allow",
            )
        )

        results = store.query(agent_did="did:mesh:a1", cedar_decision="allow")
        assert len(results) == 1
        assert results[0].receipt_id == "r1"

    def test_export(self):
        store = ReceiptStore()
        store.add(GovernanceReceipt(receipt_id="r1", tool_name="ReadData"))
        exported = store.export()
        assert len(exported) == 1
        assert exported[0]["receipt_id"] == "r1"
        assert "payload_hash" in exported[0]

    def test_clear(self):
        store = ReceiptStore()
        store.add(GovernanceReceipt(receipt_id="r1"))
        store.add(GovernanceReceipt(receipt_id="r2"))
        assert store.count == 2
        store.clear()
        assert store.count == 0

    def test_get_stats(self):
        store = ReceiptStore()
        store.add(
            GovernanceReceipt(
                agent_did="did:mesh:a1",
                tool_name="read",
                cedar_decision="allow",
            )
        )
        store.add(
            GovernanceReceipt(
                agent_did="did:mesh:a1",
                tool_name="write",
                cedar_decision="allow",
            )
        )
        store.add(
            GovernanceReceipt(
                agent_did="did:mesh:a2",
                tool_name="delete",
                cedar_decision="deny",
            )
        )
        stats = store.get_stats()
        assert stats["total"] == 3
        assert stats["allowed"] == 2
        assert stats["denied"] == 1
        assert stats["unique_agents"] == 2
        assert stats["unique_tools"] == 3
