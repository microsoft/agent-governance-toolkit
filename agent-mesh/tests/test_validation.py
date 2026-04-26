# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for input validation on public constructors."""

import pytest
from pydantic import ValidationError

from agentmesh.identity import AgentIdentity, AgentDID, ScopeChain, DelegationLink
from agentmesh.trust import TrustHandshake
from agentmesh.reward.scoring import TrustScore
from agentmesh.exceptions import (
    IdentityError,
    TrustError,
    DelegationError,
    HandshakeError,
)


# ---------------------------------------------------------------------------
# AgentIdentity validation
# ---------------------------------------------------------------------------

class TestAgentIdentityValidation:
    """Validation tests for AgentIdentity constructor and factory."""

    def test_create_valid(self):
        """Valid inputs produce a working identity."""
        identity = AgentIdentity.create(
            name="test-agent",
            sponsor="sponsor@example.com",
        )
        assert identity.name == "test-agent"
        assert identity.is_active()

    def test_create_empty_name_raises(self):
        with pytest.raises(IdentityError, match="name must not be empty"):
            AgentIdentity.create(name="", sponsor="s@e.com")

    def test_create_whitespace_name_raises(self):
        with pytest.raises(IdentityError, match="name must not be empty"):
            AgentIdentity.create(name="   ", sponsor="s@e.com")

    def test_create_empty_sponsor_raises(self):
        with pytest.raises(IdentityError, match="Sponsor email must not be empty"):
            AgentIdentity.create(name="agent", sponsor="")

    def test_create_invalid_sponsor_email_raises(self):
        with pytest.raises(IdentityError, match="Invalid sponsor email"):
            AgentIdentity.create(name="agent", sponsor="not-an-email")

    def test_constructor_empty_name_raises(self):
        did = AgentDID.generate("x")
        with pytest.raises(IdentityError, match="name must not be empty"):
            AgentIdentity(
                did=did,
                name="",
                public_key="abc",
                verification_key_id="key-1",
                sponsor_email="s@e.com",
            )

    def test_constructor_empty_public_key_raises(self):
        did = AgentDID.generate("x")
        with pytest.raises(IdentityError, match="Public key must not be empty"):
            AgentIdentity(
                did=did,
                name="agent",
                public_key="",
                verification_key_id="key-1",
                sponsor_email="s@e.com",
            )

    def test_constructor_invalid_sponsor_email_raises(self):
        did = AgentDID.generate("x")
        with pytest.raises(IdentityError, match="Invalid sponsor email"):
            AgentIdentity(
                did=did,
                name="agent",
                public_key="abc",
                verification_key_id="key-1",
                sponsor_email="bad-email",
            )

    def test_constructor_invalid_parent_did_raises(self):
        did = AgentDID.generate("x")
        with pytest.raises(IdentityError, match="did:mesh:"):
            AgentIdentity(
                did=did,
                name="agent",
                public_key="abc",
                verification_key_id="key-1",
                sponsor_email="s@e.com",
                parent_did="invalid:did:format",
            )

    def test_constructor_valid_parent_did_accepted(self):
        did = AgentDID.generate("x")
        identity = AgentIdentity(
            did=did,
            name="agent",
            public_key="abc",
            verification_key_id="key-1",
            sponsor_email="s@e.com",
            parent_did="did:mesh:parent123",
        )
        assert identity.parent_did == "did:mesh:parent123"

    def test_constructor_none_parent_did_accepted(self):
        did = AgentDID.generate("x")
        identity = AgentIdentity(
            did=did,
            name="agent",
            public_key="abc",
            verification_key_id="key-1",
            sponsor_email="s@e.com",
            parent_did=None,
        )
        assert identity.parent_did is None

    def test_negative_delegation_depth_raises(self):
        did = AgentDID.generate("x")
        with pytest.raises(ValidationError):
            AgentIdentity(
                did=did,
                name="agent",
                public_key="abc",
                verification_key_id="key-1",
                sponsor_email="s@e.com",
                delegation_depth=-1,
            )


# ---------------------------------------------------------------------------
# TrustHandshake validation
# ---------------------------------------------------------------------------

class TestTrustHandshakeValidation:
    """Validation tests for TrustHandshake constructor."""

    def test_valid_construction(self):
        hs = TrustHandshake(agent_did="did:mesh:agent-a")
        assert hs.agent_did == "did:mesh:agent-a"

    def test_empty_agent_did_raises(self):
        with pytest.raises(HandshakeError, match="must not be empty"):
            TrustHandshake(agent_did="")

    def test_whitespace_agent_did_raises(self):
        with pytest.raises(HandshakeError, match="must not be empty"):
            TrustHandshake(agent_did="   ")

    def test_invalid_did_format_raises(self):
        with pytest.raises(HandshakeError, match="did:mesh:"):
            TrustHandshake(agent_did="bad:format:123")

    def test_negative_cache_ttl_raises(self):
        with pytest.raises(HandshakeError, match="non-negative"):
            TrustHandshake(agent_did="did:mesh:agent", cache_ttl_seconds=-10)

    def test_zero_cache_ttl_accepted(self):
        hs = TrustHandshake(agent_did="did:mesh:agent", cache_ttl_seconds=0)
        assert hs.agent_did == "did:mesh:agent"


# ---------------------------------------------------------------------------
# ScopeChain validation
# ---------------------------------------------------------------------------

class TestScopeChainValidation:
    """Validation tests for ScopeChain constructor."""

    def test_valid_construction(self):
        chain, _ = ScopeChain.create_root(
            sponsor_email="sponsor@example.com",
            root_agent_did="did:mesh:root",
            capabilities=["read"],
        )
        assert chain.root_sponsor_email == "sponsor@example.com"

    def test_empty_chain_id_raises(self):
        with pytest.raises(DelegationError, match="chain_id must not be empty"):
            ScopeChain(
                chain_id="",
                root_sponsor_email="s@e.com",
                root_capabilities=["read"],
                leaf_did="did:mesh:leaf",
                leaf_capabilities=["read"],
            )

    def test_empty_root_sponsor_email_raises(self):
        with pytest.raises(DelegationError, match="root_sponsor_email must not be empty"):
            ScopeChain(
                chain_id="chain_1",
                root_sponsor_email="",
                root_capabilities=["read"],
                leaf_did="did:mesh:leaf",
                leaf_capabilities=["read"],
            )

    def test_invalid_root_sponsor_email_raises(self):
        with pytest.raises(DelegationError, match="Invalid root_sponsor_email"):
            ScopeChain(
                chain_id="chain_1",
                root_sponsor_email="not-an-email",
                root_capabilities=["read"],
                leaf_did="did:mesh:leaf",
                leaf_capabilities=["read"],
            )

    def test_empty_root_capabilities_raises(self):
        with pytest.raises(DelegationError, match="root_capabilities must not be empty"):
            ScopeChain(
                chain_id="chain_1",
                root_sponsor_email="s@e.com",
                root_capabilities=[],
                leaf_did="did:mesh:leaf",
                leaf_capabilities=["read"],
            )

    def test_empty_leaf_did_raises(self):
        with pytest.raises(DelegationError, match="leaf_did must not be empty"):
            ScopeChain(
                chain_id="chain_1",
                root_sponsor_email="s@e.com",
                root_capabilities=["read"],
                leaf_did="",
                leaf_capabilities=["read"],
            )

    def test_invalid_leaf_did_raises(self):
        with pytest.raises(DelegationError, match="did:mesh:"):
            ScopeChain(
                chain_id="chain_1",
                root_sponsor_email="s@e.com",
                root_capabilities=["read"],
                leaf_did="bad:format",
                leaf_capabilities=["read"],
            )


# ---------------------------------------------------------------------------
# TrustScore validation
# ---------------------------------------------------------------------------

class TestTrustScoreValidation:
    """Validation tests for TrustScore constructor."""

    def test_valid_construction(self):
        ts = TrustScore(agent_did="did:mesh:agent-a")
        assert ts.total_score == 500
        assert ts.tier == "standard"

    def test_empty_agent_did_raises(self):
        with pytest.raises(TrustError, match="agent_did must not be empty"):
            TrustScore(agent_did="")

    def test_invalid_did_format_raises(self):
        with pytest.raises(TrustError, match="did:mesh:"):
            TrustScore(agent_did="invalid:did")

    def test_score_above_max_raises(self):
        with pytest.raises(ValidationError):
            TrustScore(agent_did="did:mesh:a", total_score=1001)

    def test_score_below_min_raises(self):
        with pytest.raises(ValidationError):
            TrustScore(agent_did="did:mesh:a", total_score=-1)

    def test_boundary_score_zero(self):
        ts = TrustScore(agent_did="did:mesh:a", total_score=0)
        assert ts.total_score == 0
        assert ts.tier == "untrusted"

    def test_boundary_score_max(self):
        ts = TrustScore(agent_did="did:mesh:a", total_score=1000)
        assert ts.total_score == 1000
        assert ts.tier == "verified_partner"

    def test_boundary_score_trusted(self):
        ts = TrustScore(agent_did="did:mesh:a", total_score=700)
        assert ts.tier == "trusted"

    def test_boundary_score_probationary(self):
        ts = TrustScore(agent_did="did:mesh:a", total_score=300)
        assert ts.tier == "probationary"
