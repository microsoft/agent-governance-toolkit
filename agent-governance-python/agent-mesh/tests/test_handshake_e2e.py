# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""End-to-end integration test for the full handshake lifecycle.

Covers: identity creation → mutual handshake → trust establishment →
capability delegation → chain verification.

Closes #115.
"""

import uuid

import pytest

from agentmesh.identity import AgentIdentity, ScopeChain, DelegationLink
from agentmesh.trust import TrustHandshake, HandshakeResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_identity(name: str) -> AgentIdentity:
    """Create an agent identity with a unique name."""
    return AgentIdentity.create(
        name=name,
        sponsor=f"{name}@test.example.com",
        capabilities=["read", "write", "execute"],
    )


def _make_registry(*identities: AgentIdentity):
    """Create a registry pre-populated with identities."""
    from agentmesh.identity.agent_id import IdentityRegistry
    registry = IdentityRegistry()
    for identity in identities:
        registry.register(identity)
    return registry


async def _mutual_handshake(
    a: AgentIdentity,
    b: AgentIdentity,
    required_score: int = 500,
) -> tuple[HandshakeResult, HandshakeResult]:
    """Perform a mutual trust handshake between two agents.

    Returns (result_a_sees_b, result_b_sees_a).
    """
    registry = _make_registry(a, b)

    hs_a = TrustHandshake(agent_did=str(a.did), identity=a, registry=registry)
    hs_b = TrustHandshake(agent_did=str(b.did), identity=b, registry=registry)

    result_ab = await hs_a.initiate(
        peer_did=str(b.did),
        required_trust_score=required_score,
    )
    result_ba = await hs_b.initiate(
        peer_did=str(a.did),
        required_trust_score=required_score,
    )
    return result_ab, result_ba


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestHandshakeE2E:
    """Full handshake lifecycle integration tests."""

    @pytest.mark.asyncio
    async def test_mutual_trust_established(self):
        """Two agents handshake and both end up with trust scores for each other."""
        agent_a = _make_identity("agent-a")
        agent_b = _make_identity("agent-b")

        result_ab, result_ba = await _mutual_handshake(agent_a, agent_b)

        assert result_ab.verified, f"A→B failed: {result_ab.rejection_reason}"
        assert result_ba.verified, f"B→A failed: {result_ba.rejection_reason}"

        assert result_ab.trust_score > 0
        assert result_ba.trust_score > 0
        assert result_ab.peer_did == str(agent_b.did)
        assert result_ba.peer_did == str(agent_a.did)

    @pytest.mark.asyncio
    async def test_handshake_result_has_capabilities(self):
        """Handshake results include capability information."""
        agent_a = _make_identity("cap-a")
        agent_b = _make_identity("cap-b")

        result_ab, _ = await _mutual_handshake(agent_a, agent_b)

        assert isinstance(result_ab.capabilities, list)
        assert len(result_ab.capabilities) > 0

    @pytest.mark.asyncio
    async def test_handshake_result_latency(self):
        """Handshake results include timing information."""
        agent_a = _make_identity("lat-a")
        agent_b = _make_identity("lat-b")

        result_ab, _ = await _mutual_handshake(agent_a, agent_b)

        assert result_ab.handshake_completed is not None
        assert result_ab.latency_ms is not None and result_ab.latency_ms >= 0

    @pytest.mark.asyncio
    async def test_scope_chain_after_handshake(self):
        """After A↔B handshake, B delegates to C, and the chain A→B→C validates."""
        agent_a = _make_identity("root-a")
        agent_b = _make_identity("mid-b")

        # Step 1 — mutual handshake between A and B
        result_ab, result_ba = await _mutual_handshake(agent_a, agent_b)
        assert result_ab.verified
        assert result_ba.verified

        # Step 2 — create agent C
        agent_c = _make_identity("leaf-c")

        # Step 3 — B delegates a narrowed capability set to C
        chain, root_link = ScopeChain.create_root(
            sponsor_email="root-a@test.example.com",
            root_agent_did=str(agent_b.did),
            capabilities=["read", "write"],
        )
        chain.add_link(root_link)

        child_link = DelegationLink(
            link_id=f"link_{uuid.uuid4().hex[:12]}",
            depth=1,
            parent_did=str(agent_b.did),
            child_did=str(agent_c.did),
            parent_capabilities=["read", "write"],
            delegated_capabilities=["read"],
            parent_signature="test_signature",
            link_hash="",
            previous_link_hash=root_link.link_hash,
        )
        child_link.link_hash = child_link.compute_hash()
        chain.add_link(child_link)

        # Step 4 — verify scope chain is valid
        is_valid, error = chain.verify()
        assert is_valid, f"Chain verification failed: {error}"

        # Step 5 — verify chain properties
        assert chain.leaf_did == str(agent_c.did)
        assert chain.leaf_capabilities == ["read"]
        assert len(chain.links) == 2

    @pytest.mark.asyncio
    async def test_scope_chain_capability_narrowing(self):
        """Scope chain enforces capability narrowing at every hop."""
        agent_b = _make_identity("del-b")
        agent_c = _make_identity("del-c")

        chain, root_link = ScopeChain.create_root(
            sponsor_email="admin@test.example.com",
            root_agent_did=str(agent_b.did),
            capabilities=["read"],
        )
        chain.add_link(root_link)

        # Attempt to widen capabilities should fail
        bad_link = DelegationLink(
            link_id=f"link_{uuid.uuid4().hex[:12]}",
            depth=1,
            parent_did=str(agent_b.did),
            child_did=str(agent_c.did),
            parent_capabilities=["read"],
            delegated_capabilities=["read", "write"],  # wider than parent
            parent_signature="sig",
            link_hash="",
            previous_link_hash=root_link.link_hash,
        )
        bad_link.link_hash = bad_link.compute_hash()

        with pytest.raises(ValueError):
            chain.add_link(bad_link)

    @pytest.mark.asyncio
    async def test_scope_chain_trace(self):
        """Trace a capability through the full scope chain."""
        agent_b = _make_identity("trace-b")
        agent_c = _make_identity("trace-c")

        chain, root_link = ScopeChain.create_root(
            sponsor_email="sponsor@test.example.com",
            root_agent_did=str(agent_b.did),
            capabilities=["read", "write", "execute"],
        )
        chain.add_link(root_link)

        child_link = DelegationLink(
            link_id=f"link_{uuid.uuid4().hex[:12]}",
            depth=1,
            parent_did=str(agent_b.did),
            child_did=str(agent_c.did),
            parent_capabilities=["read", "write", "execute"],
            delegated_capabilities=["read"],
            parent_signature="sig",
            link_hash="",
            previous_link_hash=root_link.link_hash,
        )
        child_link.link_hash = child_link.compute_hash()
        chain.add_link(child_link)

        trace = chain.trace_capability("read")
        assert len(trace) >= 2  # root grant + at least one link

    @pytest.mark.asyncio
    async def test_full_lifecycle(self):
        """Full lifecycle: create → handshake → trust → delegate → verify chain."""
        # 1. Create identities
        agent_a = _make_identity("life-a")
        agent_b = _make_identity("life-b")
        agent_c = _make_identity("life-c")

        # 2. Mutual handshake A ↔ B
        result_ab, result_ba = await _mutual_handshake(agent_a, agent_b)
        assert result_ab.verified
        assert result_ba.verified

        # 3. Trust is established (both have non-zero scores)
        assert result_ab.trust_score > 0
        assert result_ba.trust_score > 0

        # 4. B delegates to C with narrowed capabilities
        chain, root_link = ScopeChain.create_root(
            sponsor_email="life-a@test.example.com",
            root_agent_did=str(agent_b.did),
            capabilities=["read", "write"],
        )
        chain.add_link(root_link)

        delegation_link = DelegationLink(
            link_id=f"link_{uuid.uuid4().hex[:12]}",
            depth=1,
            parent_did=str(agent_b.did),
            child_did=str(agent_c.did),
            parent_capabilities=["read", "write"],
            delegated_capabilities=["read"],
            parent_signature="sig",
            link_hash="",
            previous_link_hash=root_link.link_hash,
        )
        delegation_link.link_hash = delegation_link.compute_hash()
        chain.add_link(delegation_link)

        # 5. Verify chain
        is_valid, error = chain.verify()
        assert is_valid, f"Chain invalid: {error}"
        assert chain.leaf_did == str(agent_c.did)
        assert chain.get_effective_capabilities() == ["read"]
