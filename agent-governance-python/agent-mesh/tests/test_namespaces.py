# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for agent namespace support."""

import pytest

from agentmesh.identity import AgentNamespace, NamespaceRule, NamespaceManager


class TestAgentNamespace:
    """Tests for the AgentNamespace model."""

    def test_create_namespace(self):
        """Test basic namespace creation."""
        ns = AgentNamespace(name="finance", description="Finance team agents")
        assert ns.name == "finance"
        assert ns.members == set()
        assert ns.parent is None

    def test_create_nested_namespace(self):
        """Test namespace with parent."""
        ns = AgentNamespace(
            name="finance.trading",
            description="Trading desk agents",
            parent="finance",
        )
        assert ns.parent == "finance"


class TestNamespaceRule:
    """Tests for NamespaceRule model."""

    def test_create_rule(self):
        """Test creating a cross-namespace rule."""
        rule = NamespaceRule(
            source_namespace="finance",
            target_namespace="compliance",
            allowed=True,
            min_trust_score=700,
        )
        assert rule.allowed is True
        assert rule.min_trust_score == 700
        assert rule.require_approval is False


class TestNamespaceManager:
    """Tests for NamespaceManager."""

    @pytest.fixture()
    def manager(self) -> NamespaceManager:
        return NamespaceManager()

    # ── CRUD & membership ───────────────────────────────────────────

    def test_create_and_get_namespace(self, manager: NamespaceManager):
        """Create a namespace then retrieve it."""
        ns = manager.create_namespace("finance", "Finance agents")
        assert ns.name == "finance"
        assert manager.get_namespace("finance") is ns

    def test_create_duplicate_raises(self, manager: NamespaceManager):
        """Duplicate namespace names are rejected."""
        manager.create_namespace("finance", "Finance agents")
        with pytest.raises(ValueError, match="already exists"):
            manager.create_namespace("finance", "Duplicate")

    def test_get_missing_namespace_raises(self, manager: NamespaceManager):
        """Accessing a non-existent namespace raises KeyError."""
        with pytest.raises(KeyError, match="not found"):
            manager.get_namespace("nonexistent")

    def test_add_remove_member(self, manager: NamespaceManager):
        """Add and remove an agent from a namespace."""
        manager.create_namespace("finance", "Finance agents")
        manager.add_member("finance", "did:mesh:agent1")
        assert "did:mesh:agent1" in manager.get_namespace("finance").members

        manager.remove_member("finance", "did:mesh:agent1")
        assert "did:mesh:agent1" not in manager.get_namespace("finance").members

    def test_remove_nonexistent_member_is_silent(self, manager: NamespaceManager):
        """Removing an agent that isn't a member does not raise."""
        manager.create_namespace("finance", "Finance agents")
        manager.remove_member("finance", "did:mesh:ghost")  # no error

    def test_get_agent_namespace(self, manager: NamespaceManager):
        """Look up which namespace an agent belongs to."""
        manager.create_namespace("finance", "Finance agents")
        manager.add_member("finance", "did:mesh:agent1")
        assert manager.get_agent_namespace("did:mesh:agent1") == "finance"

    def test_get_agent_namespace_returns_none(self, manager: NamespaceManager):
        """An unregistered agent returns None."""
        assert manager.get_agent_namespace("did:mesh:unknown") is None

    def test_list_namespaces(self, manager: NamespaceManager):
        """list_namespaces returns all registered namespaces."""
        manager.create_namespace("a", "A")
        manager.create_namespace("b", "B")
        names = {ns.name for ns in manager.list_namespaces()}
        assert names == {"a", "b"}

    # ── Same-namespace communication ────────────────────────────────

    def test_same_namespace_communication_allowed(self, manager: NamespaceManager):
        """Agents in the same namespace can always communicate."""
        manager.create_namespace("finance", "Finance agents")
        manager.add_member("finance", "did:mesh:a")
        manager.add_member("finance", "did:mesh:b")
        assert manager.can_communicate("did:mesh:a", "did:mesh:b") is True

    # ── Cross-namespace denied by default ───────────────────────────

    def test_cross_namespace_denied_by_default(self, manager: NamespaceManager):
        """Cross-namespace communication is denied without an explicit rule."""
        manager.create_namespace("finance", "Finance")
        manager.create_namespace("hr", "HR")
        manager.add_member("finance", "did:mesh:a")
        manager.add_member("hr", "did:mesh:b")
        assert manager.can_communicate("did:mesh:a", "did:mesh:b") is False

    # ── Cross-namespace allowed via rule ────────────────────────────

    def test_cross_namespace_allowed_with_rule(self, manager: NamespaceManager):
        """An explicit allow rule enables cross-namespace communication."""
        manager.create_namespace("finance", "Finance")
        manager.create_namespace("compliance", "Compliance")
        manager.add_member("finance", "did:mesh:a")
        manager.add_member("compliance", "did:mesh:b")

        manager.add_rule(
            NamespaceRule(
                source_namespace="finance",
                target_namespace="compliance",
                allowed=True,
            )
        )
        assert manager.can_communicate("did:mesh:a", "did:mesh:b") is True

    def test_cross_namespace_rule_denied(self, manager: NamespaceManager):
        """A deny rule explicitly blocks cross-namespace communication."""
        manager.create_namespace("finance", "Finance")
        manager.create_namespace("compliance", "Compliance")
        manager.add_member("finance", "did:mesh:a")
        manager.add_member("compliance", "did:mesh:b")

        manager.add_rule(
            NamespaceRule(
                source_namespace="finance",
                target_namespace="compliance",
                allowed=False,
            )
        )
        assert manager.can_communicate("did:mesh:a", "did:mesh:b") is False

    # ── Delegation scoping ──────────────────────────────────────────

    def test_delegation_same_namespace(self, manager: NamespaceManager):
        """Delegation is allowed within the same namespace."""
        manager.create_namespace("finance", "Finance")
        manager.add_member("finance", "did:mesh:a")
        manager.add_member("finance", "did:mesh:b")
        assert manager.can_delegate("did:mesh:a", "did:mesh:b") is True

    def test_delegation_cross_namespace_denied(self, manager: NamespaceManager):
        """Delegation across namespaces is denied by default."""
        manager.create_namespace("finance", "Finance")
        manager.create_namespace("hr", "HR")
        manager.add_member("finance", "did:mesh:a")
        manager.add_member("hr", "did:mesh:b")
        assert manager.can_delegate("did:mesh:a", "did:mesh:b") is False

    # ── Nested namespaces ───────────────────────────────────────────

    def test_nested_namespace_creation(self, manager: NamespaceManager):
        """Child namespace records its parent."""
        manager.create_namespace("finance", "Finance")
        child = manager.create_namespace("finance.trading", "Trading", parent="finance")
        assert child.parent == "finance"

    def test_nested_namespace_invalid_parent_raises(self, manager: NamespaceManager):
        """Creating a child with a non-existent parent raises."""
        with pytest.raises(ValueError, match="does not exist"):
            manager.create_namespace("finance.trading", "Trading", parent="finance")

    def test_nested_namespace_communication(self, manager: NamespaceManager):
        """Parent and child namespace agents can communicate."""
        manager.create_namespace("finance", "Finance")
        manager.create_namespace("finance.trading", "Trading", parent="finance")
        manager.add_member("finance", "did:mesh:parent-agent")
        manager.add_member("finance.trading", "did:mesh:child-agent")
        assert manager.can_communicate("did:mesh:parent-agent", "did:mesh:child-agent") is True
        assert manager.can_communicate("did:mesh:child-agent", "did:mesh:parent-agent") is True

    # ── Edge cases ──────────────────────────────────────────────────

    def test_agent_in_no_namespace_cannot_communicate(self, manager: NamespaceManager):
        """An agent not in any namespace is denied communication."""
        manager.create_namespace("finance", "Finance")
        manager.add_member("finance", "did:mesh:a")
        assert manager.can_communicate("did:mesh:a", "did:mesh:orphan") is False
        assert manager.can_communicate("did:mesh:orphan", "did:mesh:a") is False

    def test_agent_in_no_namespace_cannot_delegate(self, manager: NamespaceManager):
        """An agent not in any namespace cannot delegate."""
        manager.create_namespace("finance", "Finance")
        manager.add_member("finance", "did:mesh:a")
        assert manager.can_delegate("did:mesh:a", "did:mesh:orphan") is False

    def test_empty_namespace(self, manager: NamespaceManager):
        """An empty namespace has no members."""
        ns = manager.create_namespace("empty", "Empty namespace")
        assert len(ns.members) == 0
