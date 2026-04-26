# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for delegation chain support in AgentIdentity (Issue #607)."""

import pytest

from agentmesh.identity.agent_id import AgentIdentity, IdentityRegistry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_identity(
    name: str = "agent",
    capabilities: list[str] | None = None,
    sponsor: str = "sponsor@example.com",
    org: str = "acme",
) -> AgentIdentity:
    return AgentIdentity.create(
        name=name,
        sponsor=sponsor,
        capabilities=capabilities or ["read", "write", "execute"],
        organization=org,
    )


# ---------------------------------------------------------------------------
# delegate() — already exists; validate existing behaviour
# ---------------------------------------------------------------------------

class TestDelegate:
    """Verify the existing delegate() method."""

    def test_delegate_creates_child(self):
        parent = _create_identity()
        child = parent.delegate("child", ["read"])
        assert child.parent_did == str(parent.did)
        assert child.delegation_depth == 1
        assert child.capabilities == ["read"]

    def test_delegate_narrows_capabilities(self):
        parent = _create_identity(capabilities=["read", "write"])
        child = parent.delegate("child", ["read"])
        assert "write" not in child.capabilities

    def test_delegate_rejects_superset(self):
        parent = _create_identity(capabilities=["read"])
        with pytest.raises(ValueError, match="not in parent"):
            parent.delegate("child", ["read", "admin"])

    def test_delegate_rejects_wildcard(self):
        parent = _create_identity(capabilities=["read", "*"])
        with pytest.raises(ValueError, match="wildcard"):
            parent.delegate("child", ["*"])

    def test_delegate_depth_increments(self):
        root = _create_identity()
        d1 = root.delegate("d1", ["read", "write"])
        d2 = d1.delegate("d2", ["read"])
        assert d2.delegation_depth == 2

    def test_delegate_max_depth_enforced(self):
        current = _create_identity(capabilities=["read"])
        for i in range(AgentIdentity.MAX_DELEGATION_DEPTH):
            current = current.delegate(f"child-{i}", ["read"])
        with pytest.raises(ValueError, match="depth"):
            current.delegate("one-too-many", ["read"])


# ---------------------------------------------------------------------------
# verify_delegation_chain()
# ---------------------------------------------------------------------------

class TestVerifyDelegationChain:
    """Tests for the new verify_delegation_chain() static method."""

    def test_root_identity_valid(self):
        root = _create_identity()
        assert AgentIdentity.verify_delegation_chain(root) is True

    def test_root_identity_valid_with_registry(self):
        registry = IdentityRegistry()
        root = _create_identity()
        registry.register(root)
        assert AgentIdentity.verify_delegation_chain(root, registry) is True

    def test_single_delegation_valid(self):
        registry = IdentityRegistry()
        parent = _create_identity(capabilities=["read", "write"])
        registry.register(parent)
        child = parent.delegate("child", ["read"])
        registry.register(child)
        assert AgentIdentity.verify_delegation_chain(child, registry) is True

    def test_multi_level_chain_valid(self):
        registry = IdentityRegistry()
        root = _create_identity(capabilities=["read", "write", "execute"])
        registry.register(root)
        mid = root.delegate("mid", ["read", "write"])
        registry.register(mid)
        leaf = mid.delegate("leaf", ["read"])
        registry.register(leaf)
        assert AgentIdentity.verify_delegation_chain(leaf, registry) is True

    def test_missing_parent_fails(self):
        registry = IdentityRegistry()
        parent = _create_identity()
        child = parent.delegate("child", ["read"])
        # Parent not registered
        registry.register(child)
        assert AgentIdentity.verify_delegation_chain(child, registry) is False

    def test_revoked_parent_fails(self):
        registry = IdentityRegistry()
        parent = _create_identity()
        registry.register(parent)
        child = parent.delegate("child", ["read"])
        registry.register(child)
        parent.revoke("test")
        assert AgentIdentity.verify_delegation_chain(child, registry) is False

    def test_depth_mismatch_fails(self):
        registry = IdentityRegistry()
        parent = _create_identity()
        registry.register(parent)
        child = parent.delegate("child", ["read"])
        child.delegation_depth = 5  # force incorrect depth
        registry.register(child)
        assert AgentIdentity.verify_delegation_chain(child, registry) is False

    def test_non_delegated_with_nonzero_depth_fails(self):
        root = _create_identity()
        root.delegation_depth = 1  # inconsistent
        root.parent_did = None
        assert AgentIdentity.verify_delegation_chain(root) is False

    def test_delegated_with_zero_depth_fails(self):
        registry = IdentityRegistry()
        parent = _create_identity()
        registry.register(parent)
        child = parent.delegate("child", ["read"])
        child.delegation_depth = 0  # force bad depth
        registry.register(child)
        assert AgentIdentity.verify_delegation_chain(child, registry) is False

    def test_without_registry_structural_only(self):
        parent = _create_identity()
        child = parent.delegate("child", ["read"])
        # Without registry we only check structural consistency
        assert AgentIdentity.verify_delegation_chain(child) is True

    def test_without_registry_root_valid(self):
        root = _create_identity()
        assert AgentIdentity.verify_delegation_chain(root) is True


# ---------------------------------------------------------------------------
# get_effective_capabilities()
# ---------------------------------------------------------------------------

class TestGetEffectiveCapabilities:
    """Tests for get_effective_capabilities()."""

    def test_root_returns_own_capabilities(self):
        root = _create_identity(capabilities=["read", "write"])
        caps = root.get_effective_capabilities()
        assert set(caps) == {"read", "write"}

    def test_single_delegation_intersection(self):
        registry = IdentityRegistry()
        parent = _create_identity(capabilities=["read", "write", "admin"])
        registry.register(parent)
        child = parent.delegate("child", ["read", "write"])
        registry.register(child)
        caps = child.get_effective_capabilities(registry)
        assert set(caps) == {"read", "write"}

    def test_multi_level_intersection(self):
        registry = IdentityRegistry()
        root = _create_identity(capabilities=["read", "write", "execute"])
        registry.register(root)
        mid = root.delegate("mid", ["read", "write"])
        registry.register(mid)
        leaf = mid.delegate("leaf", ["read"])
        registry.register(leaf)
        caps = leaf.get_effective_capabilities(registry)
        assert caps == ["read"]

    def test_no_registry_returns_own(self):
        parent = _create_identity(capabilities=["read", "write"])
        child = parent.delegate("child", ["read"])
        caps = child.get_effective_capabilities()
        assert caps == ["read"]

    def test_missing_parent_returns_own(self):
        registry = IdentityRegistry()
        parent = _create_identity(capabilities=["read", "write"])
        child = parent.delegate("child", ["read"])
        registry.register(child)
        # parent not in registry
        caps = child.get_effective_capabilities(registry)
        assert caps == ["read"]

    def test_effective_caps_sorted(self):
        root = _create_identity(capabilities=["write", "read", "admin"])
        caps = root.get_effective_capabilities()
        assert caps == sorted(caps)
