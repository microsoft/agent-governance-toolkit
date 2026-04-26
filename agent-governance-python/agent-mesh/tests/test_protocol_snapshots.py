# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Snapshot tests for protocol wire format.

Captures and verifies the wire format of identity, handshake, delegation,
trust score, and JWK protocol messages to prevent accidental protocol
breaking changes.
"""

import json
import os
from pathlib import Path
from typing import Any

import pytest

from agentmesh.identity import AgentIdentity, ScopeChain, DelegationLink
from agentmesh.reward.scoring import (
    DimensionType,
    RewardDimension,
    TrustScore,
)
from agentmesh.trust.handshake import (
    HandshakeChallenge,
    HandshakeResponse,
    HandshakeResult,
)

SNAPSHOTS_DIR = Path(__file__).parent / "snapshots"


def assert_snapshot(name: str, data: Any) -> None:
    """Compare *data* against a stored snapshot, creating it on first run.

    On the first run the snapshot file is written so tests pass and produce a
    baseline.  On subsequent runs the stored snapshot is loaded and the set of
    top-level keys (and nested key structures) is compared — values that are
    inherently non-deterministic (timestamps, cryptographic keys) are ignored
    so tests remain stable.
    """
    snapshot_path = SNAPSHOTS_DIR / f"{name}.json"

    if not snapshot_path.exists():
        SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)
        snapshot_path.write_text(json.dumps(data, indent=2, default=str))
        return

    stored = json.loads(snapshot_path.read_text())
    _assert_structure_matches(stored, data, path=name)


def _assert_structure_matches(expected: Any, actual: Any, path: str) -> None:
    """Recursively verify that *actual* has the same key structure as *expected*."""
    if isinstance(expected, dict) and isinstance(actual, dict):
        missing = set(expected.keys()) - set(actual.keys())
        extra = set(actual.keys()) - set(expected.keys())
        assert not missing, f"[{path}] Missing keys: {missing}"
        assert not extra, f"[{path}] Extra keys: {extra}"
        for key in expected:
            _assert_structure_matches(expected[key], actual[key], path=f"{path}.{key}")
    elif isinstance(expected, list) and isinstance(actual, list):
        # For non-empty reference lists, verify the first element structure
        if expected and actual:
            _assert_structure_matches(expected[0], actual[0], path=f"{path}[0]")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def identity() -> AgentIdentity:
    return AgentIdentity.create(
        name="snapshot-agent",
        sponsor="snapshot@example.com",
        capabilities=["read", "write"],
        organization="snapshot-org",
        description="Agent for snapshot testing",
    )


# ---------------------------------------------------------------------------
# 1. AgentIdentity serialization
# ---------------------------------------------------------------------------

class TestAgentIdentitySnapshot:
    def test_identity_serialization(self, identity: AgentIdentity) -> None:
        data = json.loads(identity.model_dump_json())
        assert_snapshot("agent_identity", data)

        # Key fields must always be present
        for field in (
            "did",
            "name",
            "public_key",
            "sponsor_email",
            "status",
            "capabilities",
            "created_at",
            "delegation_depth",
        ):
            assert field in data, f"Missing required field: {field}"


# ---------------------------------------------------------------------------
# 2. Trust handshake initiation message (challenge)
# ---------------------------------------------------------------------------

class TestHandshakeInitiationSnapshot:
    def test_handshake_challenge(self) -> None:
        challenge = HandshakeChallenge.generate()
        data = json.loads(challenge.model_dump_json())
        assert_snapshot("handshake_challenge", data)

        for field in ("challenge_id", "nonce", "timestamp", "expires_in_seconds"):
            assert field in data, f"Missing required field: {field}"


# ---------------------------------------------------------------------------
# 3. Trust handshake response message
# ---------------------------------------------------------------------------

class TestHandshakeResponseSnapshot:
    def test_handshake_response(self, identity: AgentIdentity) -> None:
        response = HandshakeResponse(
            challenge_id="challenge_test123",
            response_nonce="abc123",
            agent_did=str(identity.did),
            capabilities=["read", "write"],
            trust_score=750,
            signature=identity.sign(b"challenge_test123:nonce:abc123"),
            public_key=identity.public_key,
        )
        data = json.loads(response.model_dump_json())
        assert_snapshot("handshake_response", data)

        for field in (
            "challenge_id",
            "response_nonce",
            "agent_did",
            "capabilities",
            "trust_score",
            "signature",
            "public_key",
            "timestamp",
        ):
            assert field in data, f"Missing required field: {field}"


# ---------------------------------------------------------------------------
# 4. Delegation token (serialized delegation link)
# ---------------------------------------------------------------------------

class TestDelegationTokenSnapshot:
    def test_delegation_link(self) -> None:
        link = DelegationLink(
            link_id="link_snap000001",
            depth=1,
            parent_did="did:mesh:parent111",
            child_did="did:mesh:child222",
            parent_capabilities=["read", "write", "admin"],
            delegated_capabilities=["read", "write"],
            parent_signature="sig_placeholder",
            link_hash="",
            previous_link_hash="prev_hash_placeholder",
        )
        link.link_hash = link.compute_hash()
        data = json.loads(link.model_dump_json())
        assert_snapshot("delegation_token", data)

        for field in (
            "link_id",
            "depth",
            "parent_did",
            "child_did",
            "parent_capabilities",
            "delegated_capabilities",
            "parent_signature",
            "link_hash",
            "previous_link_hash",
            "created_at",
        ):
            assert field in data, f"Missing required field: {field}"


# ---------------------------------------------------------------------------
# 5. Trust score report (all 5 dimensions)
# ---------------------------------------------------------------------------

class TestTrustScoreSnapshot:
    def test_trust_score_report(self) -> None:
        dimensions = {}
        for dim in DimensionType:
            dimensions[dim.value] = RewardDimension(
                name=dim.value,
                score=75.0,
                signal_count=10,
                positive_signals=8,
                negative_signals=2,
            )

        score = TrustScore(
            agent_did="did:mesh:scored_agent",
            total_score=750,
            dimensions=dimensions,
        )
        data = score.to_dict()
        assert_snapshot("trust_score_report", data)

        assert "agent_did" in data
        assert "total_score" in data
        assert "tier" in data
        assert "dimensions" in data

        # All 5 dimensions must be present
        for dim in DimensionType:
            assert dim.value in data["dimensions"], f"Missing dimension: {dim.value}"


# ---------------------------------------------------------------------------
# 6. JWK export
# ---------------------------------------------------------------------------

class TestJwkExportSnapshot:
    def test_jwk_public_export(self, identity: AgentIdentity) -> None:
        jwk = identity.to_jwk(include_private=False)
        assert_snapshot("jwk_export", jwk)

        for field in ("kty", "crv", "x", "kid", "use"):
            assert field in jwk, f"Missing required JWK field: {field}"
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert jwk["use"] == "sig"
        assert "d" not in jwk, "Public JWK must not contain private key"
