# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for GovernanceReceipt, ReceiptStore, signing/verification, and hash chaining."""

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


# ── Fixtures ──


@pytest.fixture()
def ed25519_key():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.generate()
        return key.private_bytes_raw().hex(), key.public_key().public_bytes_raw().hex()
    except ImportError:
        pytest.skip("cryptography not installed")


@pytest.fixture()
def signing_key(ed25519_key):
    return ed25519_key[0]


def _make_chain(*receipt_ids, sign_with=None):
    """Build a valid hash-chained list of receipts, optionally signed."""
    receipts = []
    for i, rid in enumerate(receipt_ids):
        parent = receipts[-1].payload_hash() if receipts else None
        r = GovernanceReceipt(receipt_id=rid, timestamp=float(i + 1), parent_receipt_hash=parent)
        if sign_with:
            sign_receipt(r, sign_with)
        receipts.append(r)
    return receipts


# ── Receipt Model ──


class TestGovernanceReceipt:
    def test_default_fields(self):
        r = GovernanceReceipt()
        assert r.receipt_id
        assert r.cedar_decision == "deny"
        assert r.timestamp > 0
        assert r.parent_receipt_hash is None

    def test_canonical_payload_deterministic_and_sorted(self):
        r = GovernanceReceipt(receipt_id="id", tool_name="T", agent_did="did:mesh:a1",
                               cedar_policy_id="p:v1", cedar_decision="allow",
                               args_hash="abc", timestamp=1700000000.0)
        p1, p2 = r.canonical_payload(), r.canonical_payload()
        assert p1 == p2
        parsed = json.loads(p1)
        assert list(parsed.keys()) == sorted(parsed.keys())

    def test_canonical_payload_excludes_signature_fields(self):
        r = GovernanceReceipt(receipt_id="id", timestamp=1.0, signature="sig", signer_public_key="key")
        payload = r.canonical_payload()
        assert "signature" not in payload
        assert "signer_public_key" not in payload

    def test_payload_hash_stable_and_content_sensitive(self):
        r = GovernanceReceipt(receipt_id="id", timestamp=1.0)
        assert r.payload_hash() == r.payload_hash()
        assert r.payload_hash() != GovernanceReceipt(receipt_id="other", timestamp=1.0).payload_hash()

    def test_to_dict_includes_all_fields(self):
        r = GovernanceReceipt(receipt_id="id", tool_name="T", agent_did="a",
                               cedar_policy_id="p", cedar_decision="allow",
                               args_hash="h", timestamp=1700000000.0)
        d = r.to_dict()
        assert d["receipt_id"] == "id"
        assert d["payload_hash"]
        assert d["parent_receipt_hash"] is None
        assert d["signature"] is None


# ── JCS Canonicalization (RFC 8785) ──


class TestJCSCanonicalization:
    def test_unicode_raw_utf8_not_escaped(self):
        for name in ["ReadDäta", "Send\U0001f600Msg", "读取数据", "قراءة", "bad�tool"]:
            r = GovernanceReceipt(receipt_id="id", tool_name=name, timestamp=1.0)
            payload = r.canonical_payload()
            assert name in payload
            assert "\\u" not in payload

    def test_no_whitespace_compact_separators(self):
        r = GovernanceReceipt(receipt_id="id", timestamp=1.0)
        assert " " not in r.canonical_payload().replace("id", "x")

    def test_empty_string_fields_valid(self):
        r = GovernanceReceipt(receipt_id="", tool_name="", timestamp=1.0)
        parsed = json.loads(r.canonical_payload())
        assert parsed["receipt_id"] == ""


# ── Session ID ──


class TestSessionId:
    def test_session_id_in_payload_when_set(self):
        r = GovernanceReceipt(receipt_id="id", timestamp=1.0, session_id="s-abc")
        assert "s-abc" in r.canonical_payload()

    def test_session_id_absent_when_none(self):
        assert "session_id" not in GovernanceReceipt(receipt_id="id", timestamp=1.0).canonical_payload()

    def test_session_id_affects_hash(self):
        base = dict(receipt_id="id", timestamp=1.0)
        assert (GovernanceReceipt(**base, session_id="s1").payload_hash() !=
                GovernanceReceipt(**base, session_id="s2").payload_hash())


# ── Hash Chaining ──


class TestHashChaining:
    def test_first_receipt_no_parent(self):
        r = GovernanceReceipt(receipt_id="r1", timestamp=1.0)
        assert r.parent_receipt_hash is None
        assert "parent_receipt_hash" not in r.canonical_payload()

    def test_chained_receipt_links_parent(self):
        r1 = GovernanceReceipt(receipt_id="r1", timestamp=1.0)
        r2 = GovernanceReceipt(receipt_id="r2", timestamp=2.0, parent_receipt_hash=r1.payload_hash())
        assert r2.parent_receipt_hash == r1.payload_hash()
        assert r1.payload_hash() in r2.canonical_payload()

    def test_parent_hash_changes_own_hash(self):
        base = dict(receipt_id="id", timestamp=1.0)
        assert (GovernanceReceipt(**base, parent_receipt_hash="aaa").payload_hash() !=
                GovernanceReceipt(**base, parent_receipt_hash="bbb").payload_hash())

    def test_three_receipt_chain_unique_hashes(self):
        r1, r2, r3 = _make_chain("r1", "r2", "r3")
        assert r2.parent_receipt_hash == r1.payload_hash()
        assert r3.parent_receipt_hash == r2.payload_hash()
        assert len({r1.payload_hash(), r2.payload_hash(), r3.payload_hash()}) == 3


# ── SLSA Provenance ──


class TestSLSAProvenance:
    def test_statement_structure(self):
        r = GovernanceReceipt(receipt_id="id", tool_name="T", agent_did="a",
                               cedar_policy_id="p", cedar_decision="allow",
                               args_hash="h", timestamp=1700000000.0)
        slsa = r.to_slsa_provenance()
        assert slsa["_type"] == "https://in-toto.io/Statement/v1"
        assert slsa["predicateType"] == "https://slsa.dev/provenance/v1"

    def test_subject_and_digest(self):
        r = GovernanceReceipt(receipt_id="id", tool_name="ReadData", args_hash="h123")
        s = r.to_slsa_provenance()["subject"][0]
        assert s["name"] == "pkg:agentmesh/tool/ReadData"
        assert s["digest"]["sha256"] == "h123"

    def test_parent_dependency_included_when_set(self):
        r = GovernanceReceipt(receipt_id="id", tool_name="T", args_hash="h", parent_receipt_hash="phash")
        deps = r.to_slsa_provenance()["predicate"]["buildDefinition"]["resolvedDependencies"]
        assert len(deps) == 1
        assert deps[0]["digest"]["sha256"] == "phash"

    def test_no_parent_empty_deps(self):
        r = GovernanceReceipt(receipt_id="id", tool_name="T")
        assert r.to_slsa_provenance()["predicate"]["buildDefinition"]["resolvedDependencies"] == []

    def test_run_details_and_schema_fields(self):
        r = GovernanceReceipt(receipt_id="id", tool_name="T", agent_did="a",
                               cedar_policy_id="p", cedar_decision="deny",
                               args_hash="h", timestamp=1700000000.0)
        slsa = r.to_slsa_provenance()
        run = slsa["predicate"]["runDetails"]
        assert run["metadata"]["invocationId"] == "id"
        assert urlparse(run["builder"]["id"]).hostname == "agent-governance.org"
        assert run["metadata"]["startedOn"].endswith("Z")
        params = slsa["predicate"]["buildDefinition"]["externalParameters"]
        assert params["agent_did"] == "a"
        assert params["cedar_decision"] == "deny"


# ── Hash Tool Args ──


class TestHashToolArgs:
    def test_none_and_empty_produce_same_hash(self):
        assert hash_tool_args(None) == hash_tool_args({})

    def test_deterministic_and_key_order_independent(self):
        args = {"b": 2, "a": 1}
        assert hash_tool_args(args) == hash_tool_args({"a": 1, "b": 2})

    def test_different_args_different_hash(self):
        assert hash_tool_args({"path": "/a"}) != hash_tool_args({"path": "/b"})


# ── Sign / Verify ──


class TestSignVerify:
    def test_sign_verify_roundtrip(self, ed25519_key):
        seed, pub = ed25519_key
        r = GovernanceReceipt(receipt_id="id", tool_name="T", agent_did="a", timestamp=1.0)
        sign_receipt(r, seed)
        assert r.signer_public_key == pub
        assert verify_receipt(r) is True

    def test_tampered_receipt_fails(self, signing_key):
        r = GovernanceReceipt(receipt_id="id", tool_name="T", timestamp=1.0)
        sign_receipt(r, signing_key)
        r.cedar_decision = "allow"
        assert verify_receipt(r) is False

    def test_unsigned_and_invalid_sig_fail(self, signing_key):
        assert verify_receipt(GovernanceReceipt(receipt_id="id")) is False
        r = GovernanceReceipt(receipt_id="id", timestamp=1.0)
        sign_receipt(r, signing_key)
        r.signature = "deadbeef" * 16
        assert verify_receipt(r) is False


# ── Chain Verification ──


class TestVerifyReceiptChain:
    def test_empty_chain_valid(self):
        assert verify_receipt_chain([]) == []

    def test_single_unsigned_flagged(self):
        errors = verify_receipt_chain([GovernanceReceipt(receipt_id="r1", timestamp=1.0)])
        assert any("Unsigned" in e for e in errors)

    def test_unexpected_parent_on_first_flagged(self):
        r = GovernanceReceipt(receipt_id="r1", timestamp=1.0, parent_receipt_hash="surprise")
        errors = verify_receipt_chain([r])
        assert any("First receipt" in e for e in errors)

    def test_valid_signed_chain(self, signing_key):
        assert verify_receipt_chain(_make_chain("r1", "r2", "r3", sign_with=signing_key)) == []

    def test_single_signed_receipt_valid(self, signing_key):
        assert verify_receipt_chain(_make_chain("r1", sign_with=signing_key)) == []

    def test_broken_chain_detected(self):
        r1 = GovernanceReceipt(receipt_id="r1", timestamp=1.0)
        r2 = GovernanceReceipt(receipt_id="r2", timestamp=2.0, parent_receipt_hash="wrong")
        errors = verify_receipt_chain([r1, r2])
        assert any("Hash chain broken" in e for e in errors)

    def test_deleted_receipt_detected(self):
        r1, r2, r3 = _make_chain("r1", "r2", "r3")
        errors = verify_receipt_chain([r1, r3])
        assert any("Hash chain broken" in e for e in errors)

    def test_inserted_receipt_detected(self, signing_key):
        r1, r2, r3 = _make_chain("r1", "r2", "r3", sign_with=signing_key)
        evil = GovernanceReceipt(receipt_id="evil", timestamp=1.5)
        sign_receipt(evil, signing_key)
        errors = verify_receipt_chain([r1, evil, r2, r3])
        assert any("Hash chain broken" in e for e in errors)

    def test_tampered_signed_receipt_detected(self, signing_key):
        r1, r2 = _make_chain("r1", "r2", sign_with=signing_key)
        r2.tool_name = "TAMPERED"
        assert any("invalid" in e.lower() or "signature" in e.lower() for e in verify_receipt_chain([r1, r2]))

    def test_trusted_key_accepted(self, ed25519_key):
        seed, pub = ed25519_key
        r = _make_chain("r1", sign_with=seed)[0]
        assert verify_receipt_chain([r], trusted_keys=[pub]) == []

    def test_untrusted_key_rejected(self, signing_key):
        r = _make_chain("r1", sign_with=signing_key)[0]
        errors = verify_receipt_chain([r], trusted_keys=["deadbeef" * 4])
        assert any("rejected" in e for e in errors)

    def test_duplicate_receipt_id_flagged(self, signing_key):
        r1 = GovernanceReceipt(receipt_id="same", timestamp=1.0)
        sign_receipt(r1, signing_key)
        r2 = GovernanceReceipt(receipt_id="same", timestamp=2.0, parent_receipt_hash=r1.payload_hash())
        sign_receipt(r2, signing_key)
        errors = verify_receipt_chain([r1, r2])
        assert any("replay" in e.lower() for e in errors)

    def test_all_defaults_unsigned_flagged(self):
        assert any("Unsigned" in e for e in verify_receipt_chain([GovernanceReceipt()]))


# ── Receipt Store ──


class TestReceiptStore:
    def _populated_store(self):
        store = ReceiptStore()
        store.add(GovernanceReceipt(receipt_id="r1", agent_did="a1", tool_name="read", cedar_decision="allow"))
        store.add(GovernanceReceipt(receipt_id="r2", agent_did="a1", tool_name="write", cedar_decision="allow"))
        store.add(GovernanceReceipt(receipt_id="r3", agent_did="a2", tool_name="delete", cedar_decision="deny"))
        return store

    def test_add_count_clear(self):
        store = ReceiptStore()
        assert store.count == 0
        store.add(GovernanceReceipt(receipt_id="r1"))
        assert store.count == 1
        store.clear()
        assert store.count == 0

    def test_query_filters(self):
        store = self._populated_store()
        assert len(store.query(agent_did="a1")) == 2
        assert len(store.query(tool_name="read")) == 1
        assert len(store.query(cedar_decision="deny")) == 1
        assert len(store.query(agent_did="a1", cedar_decision="allow")) == 2

    def test_export_includes_payload_hash(self):
        store = ReceiptStore()
        store.add(GovernanceReceipt(receipt_id="r1", tool_name="T"))
        exported = store.export()
        assert exported[0]["receipt_id"] == "r1"
        assert "payload_hash" in exported[0]

    def test_get_stats(self):
        stats = self._populated_store().get_stats()
        assert stats == {"total": 3, "allowed": 2, "denied": 1, "unique_agents": 2, "unique_tools": 3}
