# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for scope chain depth limit enforcement."""

import uuid

import pytest

from agentmesh.constants import DEFAULT_DELEGATION_MAX_DEPTH
from agentmesh.exceptions import DelegationDepthError
from agentmesh.identity.delegation import ScopeChain, DelegationLink


def _make_link(depth: int, parent_did: str, child_did: str, previous_hash: str | None = None):
    """Helper to create a valid DelegationLink."""
    caps = ["read:data"]
    link = DelegationLink(
        link_id=f"link_{uuid.uuid4().hex[:12]}",
        depth=depth,
        parent_did=parent_did,
        child_did=child_did,
        parent_capabilities=caps,
        delegated_capabilities=caps,
        parent_signature="",
        link_hash="",
        previous_link_hash=previous_hash,
    )
    link.link_hash = link.compute_hash()
    return link


def _make_chain(max_depth: int = DEFAULT_DELEGATION_MAX_DEPTH) -> ScopeChain:
    """Helper to create a minimal ScopeChain."""
    return ScopeChain(
        chain_id=f"chain_{uuid.uuid4().hex[:16]}",
        root_sponsor_email="sponsor@example.com",
        root_capabilities=["read:data"],
        leaf_did="did:mesh:root",
        leaf_capabilities=["read:data"],
        max_depth=max_depth,
    )


class TestDelegationDepthDefault:
    def test_default_depth_is_five(self):
        assert DEFAULT_DELEGATION_MAX_DEPTH == 5

    def test_chain_default_max_depth(self):
        chain = _make_chain()
        assert chain.max_depth == 5

    def test_class_constant_matches(self):
        assert ScopeChain.DEFAULT_MAX_DEPTH == 5


class TestDelegationDepthWithinLimit:
    def test_single_link_succeeds(self):
        chain = _make_chain()
        link = _make_link(0, "did:mesh:root", "did:mesh:child0")
        chain.add_link(link)
        assert chain.get_depth() == 1

    def test_chain_at_exact_limit_succeeds(self):
        chain = _make_chain(max_depth=3)
        prev_hash = None
        parent = "did:mesh:root"
        for i in range(3):
            child = f"did:mesh:agent{i}"
            link = _make_link(i, parent, child, prev_hash)
            chain.add_link(link)
            prev_hash = link.link_hash
            parent = child
        assert chain.get_depth() == 3


class TestDelegationDepthExceeded:
    def test_exceeding_limit_raises_error(self):
        chain = _make_chain(max_depth=2)
        prev_hash = None
        parent = "did:mesh:root"
        for i in range(2):
            child = f"did:mesh:agent{i}"
            link = _make_link(i, parent, child, prev_hash)
            chain.add_link(link)
            prev_hash = link.link_hash
            parent = child

        extra_link = _make_link(2, parent, "did:mesh:overflow", prev_hash)
        with pytest.raises(DelegationDepthError):
            chain.add_link(extra_link)

    def test_error_message_includes_depth_info(self):
        chain = _make_chain(max_depth=1)
        link0 = _make_link(0, "did:mesh:root", "did:mesh:a")
        chain.add_link(link0)

        link1 = _make_link(1, "did:mesh:a", "did:mesh:b", link0.link_hash)
        with pytest.raises(DelegationDepthError, match=r"depth 2.*maximum.*1"):
            chain.add_link(link1)


class TestCustomMaxDepth:
    def test_custom_max_depth_is_respected(self):
        chain = _make_chain(max_depth=10)
        assert chain.max_depth == 10

        prev_hash = None
        parent = "did:mesh:root"
        for i in range(10):
            child = f"did:mesh:agent{i}"
            link = _make_link(i, parent, child, prev_hash)
            chain.add_link(link)
            prev_hash = link.link_hash
            parent = child

        assert chain.get_depth() == 10

        overflow = _make_link(10, parent, "did:mesh:overflow", prev_hash)
        with pytest.raises(DelegationDepthError):
            chain.add_link(overflow)

    def test_max_depth_one(self):
        chain = _make_chain(max_depth=1)
        link = _make_link(0, "did:mesh:root", "did:mesh:a")
        chain.add_link(link)

        link2 = _make_link(1, "did:mesh:a", "did:mesh:b", link.link_hash)
        with pytest.raises(DelegationDepthError):
            chain.add_link(link2)


class TestGetDepth:
    def test_empty_chain_depth_is_zero(self):
        chain = _make_chain()
        assert chain.get_depth() == 0

    def test_depth_increments_with_links(self):
        chain = _make_chain()
        prev_hash = None
        parent = "did:mesh:root"
        for i in range(3):
            child = f"did:mesh:agent{i}"
            link = _make_link(i, parent, child, prev_hash)
            chain.add_link(link)
            assert chain.get_depth() == i + 1
            prev_hash = link.link_hash
            parent = child


class TestDelegationDepthErrorHierarchy:
    def test_is_delegation_error(self):
        from agentmesh.exceptions import DelegationError

        assert issubclass(DelegationDepthError, DelegationError)

    def test_is_agentmesh_error(self):
        from agentmesh.exceptions import AgentMeshError

        assert issubclass(DelegationDepthError, AgentMeshError)
