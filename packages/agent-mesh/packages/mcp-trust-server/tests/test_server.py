# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the MCP Trust Server tool functions."""

from __future__ import annotations

from mcp_trust_server.server import (
    _identity,
    _store,
    check_trust,
    establish_handshake,
    get_identity,
    get_trust_score,
    record_interaction,
    verify_delegation,
    TrustStore,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
AGENT_DID = "did:mesh:aaaa1111bbbb2222cccc3333dddd4444"
PEER_DID = "did:mesh:5555666677778888aaaa9999bbbbcccc"
DELEGATOR_DID = "did:mesh:ddddeeee11112222333344445555ffff"


def _reset_store() -> None:
    """Reset the global store between tests."""
    _store.scores.clear()
    _store.interactions.clear()
    _store.handshakes.clear()


# ---------------------------------------------------------------------------
# check_trust
# ---------------------------------------------------------------------------
class TestCheckTrust:
    def setup_method(self) -> None:
        _reset_store()

    def test_returns_expected_keys(self) -> None:
        result = check_trust(AGENT_DID)
        assert "trusted" in result
        assert "overall_score" in result
        assert "trust_level" in result
        assert "dimensions" in result
        assert "min_trust_threshold" in result

    def test_default_agent_is_trusted(self) -> None:
        result = check_trust(AGENT_DID)
        assert result["trusted"] is True
        assert result["overall_score"] == 500

    def test_dimensions_present(self) -> None:
        result = check_trust(AGENT_DID)
        dims = result["dimensions"]
        for dim in ["competence", "integrity", "availability", "predictability", "transparency"]:
            assert dim in dims
            assert dims[dim] == 500


# ---------------------------------------------------------------------------
# get_trust_score
# ---------------------------------------------------------------------------
class TestGetTrustScore:
    def setup_method(self) -> None:
        _reset_store()

    def test_returns_expected_keys(self) -> None:
        result = get_trust_score(AGENT_DID)
        assert "overall_score" in result
        assert "trust_level" in result
        assert "dimensions" in result
        assert "interaction_count" in result
        assert "last_updated" in result

    def test_all_five_dimensions(self) -> None:
        result = get_trust_score(AGENT_DID)
        assert len(result["dimensions"]) == 5


# ---------------------------------------------------------------------------
# establish_handshake
# ---------------------------------------------------------------------------
class TestEstablishHandshake:
    def setup_method(self) -> None:
        _reset_store()

    def test_creates_handshake(self) -> None:
        result = establish_handshake(PEER_DID, ["read:data"])
        assert result["status"] == "pending"
        assert result["peer_did"] == PEER_DID
        assert "handshake_id" in result
        assert "signature" in result

    def test_handshake_stored(self) -> None:
        result = establish_handshake(PEER_DID, ["read:data", "write:reports"])
        assert result["handshake_id"] in _store.handshakes

    def test_requested_capabilities(self) -> None:
        caps = ["trust:read", "handshake:initiate"]
        result = establish_handshake(PEER_DID, caps)
        assert result["requested_capabilities"] == caps


# ---------------------------------------------------------------------------
# verify_delegation
# ---------------------------------------------------------------------------
class TestVerifyDelegation:
    def setup_method(self) -> None:
        _reset_store()

    def test_valid_delegation(self) -> None:
        result = verify_delegation(AGENT_DID, DELEGATOR_DID, "read:data")
        assert result["valid"] is True
        assert result["delegator_trusted"] is True
        assert result["agent_trusted"] is True

    def test_invalid_when_delegator_untrusted(self) -> None:
        _store.scores[DELEGATOR_DID] = {
            "agent_did": DELEGATOR_DID,
            "overall_score": 100,
            "dimensions": {d: 100 for d in ["competence", "integrity", "availability", "predictability", "transparency"]},
            "trust_level": "untrusted",
            "interaction_count": 0,
            "last_updated": "2025-01-01T00:00:00",
        }
        result = verify_delegation(AGENT_DID, DELEGATOR_DID, "read:data")
        assert result["valid"] is False
        assert result["delegator_trusted"] is False

    def test_returns_expected_keys(self) -> None:
        result = verify_delegation(AGENT_DID, DELEGATOR_DID, "read:data")
        for key in [
            "valid",
            "agent_did",
            "delegator_did",
            "capability",
            "delegator_trust_score",
            "agent_trust_score",
            "checked_at",
        ]:
            assert key in result


# ---------------------------------------------------------------------------
# record_interaction
# ---------------------------------------------------------------------------
class TestRecordInteraction:
    def setup_method(self) -> None:
        _reset_store()

    def test_success_increases_score(self) -> None:
        before = _store.get_score(PEER_DID)["overall_score"]
        result = record_interaction(PEER_DID, "success", "completed task")
        assert result["updated_score"] > before

    def test_failure_decreases_score(self) -> None:
        before = _store.get_score(PEER_DID)["overall_score"]
        result = record_interaction(PEER_DID, "failure", "agent crashed")
        assert result["updated_score"] < before

    def test_invalid_outcome(self) -> None:
        result = record_interaction(PEER_DID, "unknown", "bad outcome")
        assert "error" in result

    def test_interaction_count_increments(self) -> None:
        record_interaction(PEER_DID, "success", "first")
        result = record_interaction(PEER_DID, "success", "second")
        assert result["interaction_count"] == 2


# ---------------------------------------------------------------------------
# get_identity
# ---------------------------------------------------------------------------
class TestGetIdentity:
    def test_returns_did_and_public_key(self) -> None:
        result = get_identity()
        assert result["did"].startswith("did:mesh:")
        assert len(result["public_key"]) > 0

    def test_returns_name(self) -> None:
        result = get_identity()
        assert result["name"] == _identity.name

    def test_returns_capabilities(self) -> None:
        result = get_identity()
        assert isinstance(result["capabilities"], list)
        assert len(result["capabilities"]) > 0
