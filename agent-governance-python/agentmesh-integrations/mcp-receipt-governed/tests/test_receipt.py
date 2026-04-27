# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for GovernanceReceipt, ReceiptStore, and signing/verification.

These tests run without any external SDK. They validate the receipt model,
canonical serialization, and Ed25519 sign/verify round-trip in isolation.
"""

import json

import pytest

from mcp_receipt_governed.receipt import (
    GovernanceReceipt,
    ReceiptStore,
    hash_tool_args,
    sign_receipt,
    verify_receipt,
)


class TestGovernanceReceipt:
    def test_default_fields(self):
        r = GovernanceReceipt()
        assert r.receipt_id  # UUID generated
        assert r.cedar_decision == "deny"
        assert r.tool_name == ""
        assert r.agent_did == ""
        assert r.timestamp > 0

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
        assert d["signature"] is None
        assert d["error"] is None


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
        store.add(GovernanceReceipt(
            receipt_id="r1", agent_did="did:mesh:a1",
            tool_name="ReadData", cedar_decision="allow",
        ))
        store.add(GovernanceReceipt(
            receipt_id="r2", agent_did="did:mesh:a1",
            tool_name="DeleteFile", cedar_decision="deny",
        ))
        store.add(GovernanceReceipt(
            receipt_id="r3", agent_did="did:mesh:a2",
            tool_name="ReadData", cedar_decision="allow",
        ))

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
        store.add(GovernanceReceipt(
            agent_did="did:mesh:a1", tool_name="read", cedar_decision="allow",
        ))
        store.add(GovernanceReceipt(
            agent_did="did:mesh:a1", tool_name="write", cedar_decision="allow",
        ))
        store.add(GovernanceReceipt(
            agent_did="did:mesh:a2", tool_name="delete", cedar_decision="deny",
        ))
        stats = store.get_stats()
        assert stats["total"] == 3
        assert stats["allowed"] == 2
        assert stats["denied"] == 1
        assert stats["unique_agents"] == 2
        assert stats["unique_tools"] == 3
