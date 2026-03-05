# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for policy composition, inheritance, and override utilities."""

import pytest

from agent_os.integrations.base import GovernancePolicy
from agent_os.integrations.policy_compose import (
    compose_policies,
    override_policy,
    PolicyHierarchy,
)


# ---------------------------------------------------------------------------
# override_policy
# ---------------------------------------------------------------------------

class TestOverridePolicy:
    def test_basic_override(self):
        base = GovernancePolicy(name="base", max_tokens=4096)
        result = override_policy(base, max_tokens=2048)
        assert result.max_tokens == 2048
        assert result.name == "base"

    def test_override_does_not_mutate_original(self):
        base = GovernancePolicy(name="base", max_tokens=4096)
        _ = override_policy(base, max_tokens=2048)
        assert base.max_tokens == 4096

    def test_override_name(self):
        base = GovernancePolicy(name="base")
        result = override_policy(base, name="child")
        assert result.name == "child"

    def test_override_multiple_fields(self):
        base = GovernancePolicy()
        result = override_policy(base, max_tokens=1000, max_tool_calls=5, require_human_approval=True)
        assert result.max_tokens == 1000
        assert result.max_tool_calls == 5
        assert result.require_human_approval is True


# ---------------------------------------------------------------------------
# compose_policies
# ---------------------------------------------------------------------------

class TestComposePolicies:
    def test_single_policy_returns_copy(self):
        p = GovernancePolicy(name="only", max_tokens=1024)
        result = compose_policies(p)
        assert result.max_tokens == 1024
        assert result.name == "only"
        assert result is not p

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            compose_policies()

    def test_min_max_tokens(self):
        a = GovernancePolicy(name="a", max_tokens=4096)
        b = GovernancePolicy(name="b", max_tokens=2048)
        result = compose_policies(a, b)
        assert result.max_tokens == 2048

    def test_min_max_tool_calls(self):
        a = GovernancePolicy(name="a", max_tool_calls=10)
        b = GovernancePolicy(name="b", max_tool_calls=3)
        result = compose_policies(a, b)
        assert result.max_tool_calls == 3

    def test_union_blocked_patterns(self):
        a = GovernancePolicy(name="a", blocked_patterns=["secret"])
        b = GovernancePolicy(name="b", blocked_patterns=["password"])
        result = compose_policies(a, b)
        assert "secret" in result.blocked_patterns
        assert "password" in result.blocked_patterns

    def test_union_blocked_patterns_no_duplicates(self):
        a = GovernancePolicy(name="a", blocked_patterns=["secret"])
        b = GovernancePolicy(name="b", blocked_patterns=["secret", "key"])
        result = compose_policies(a, b)
        assert result.blocked_patterns.count("secret") == 1

    def test_intersect_allowed_tools_both_specified(self):
        a = GovernancePolicy(name="a", allowed_tools=["search", "calc", "read"])
        b = GovernancePolicy(name="b", allowed_tools=["calc", "read", "write"])
        result = compose_policies(a, b)
        assert set(result.allowed_tools) == {"calc", "read"}

    def test_allowed_tools_one_empty(self):
        a = GovernancePolicy(name="a", allowed_tools=["search"])
        b = GovernancePolicy(name="b", allowed_tools=[])
        result = compose_policies(a, b)
        assert result.allowed_tools == ["search"]

    def test_highest_version(self):
        a = GovernancePolicy(name="a", version="1.0.0")
        b = GovernancePolicy(name="b", version="2.1.0")
        result = compose_policies(a, b)
        assert result.version == "2.1.0"

    def test_combined_names(self):
        a = GovernancePolicy(name="security")
        b = GovernancePolicy(name="budget")
        result = compose_policies(a, b)
        assert result.name == "security + budget"

    def test_human_approval_true_if_any(self):
        a = GovernancePolicy(name="a", require_human_approval=False)
        b = GovernancePolicy(name="b", require_human_approval=True)
        result = compose_policies(a, b)
        assert result.require_human_approval is True

    def test_three_policies(self):
        a = GovernancePolicy(name="a", max_tokens=4096, blocked_patterns=["x"])
        b = GovernancePolicy(name="b", max_tokens=2048, blocked_patterns=["y"])
        c = GovernancePolicy(name="c", max_tokens=1024, blocked_patterns=["z"])
        result = compose_policies(a, b, c)
        assert result.max_tokens == 1024
        assert result.name == "a + b + c"
        assert set(result.blocked_patterns) == {"x", "y", "z"}


# ---------------------------------------------------------------------------
# PolicyHierarchy
# ---------------------------------------------------------------------------

class TestPolicyHierarchy:
    def test_extend_returns_new_policy(self):
        base = GovernancePolicy(name="parent", max_tokens=4096)
        h = PolicyHierarchy(base)
        child = h.extend(max_tokens=2048)
        assert child.max_tokens == 2048
        assert child.name == "parent"
        assert base.max_tokens == 4096

    def test_policy_property(self):
        base = GovernancePolicy(name="root")
        h = PolicyHierarchy(base)
        assert h.policy is base

    def test_child_creates_hierarchy(self):
        base = GovernancePolicy(name="org", max_tokens=8192, max_tool_calls=20)
        h = PolicyHierarchy(base)
        team = h.child("team", max_tokens=4096)
        assert isinstance(team, PolicyHierarchy)
        assert team.policy.name == "team"
        assert team.policy.max_tokens == 4096
        assert team.policy.max_tool_calls == 20  # inherited

    def test_nested_child(self):
        root = PolicyHierarchy(GovernancePolicy(name="org", max_tokens=8192))
        team = root.child("team", max_tokens=4096)
        project = team.child("project", max_tokens=2048)
        assert project.policy.max_tokens == 2048
        assert project.policy.name == "project"

    def test_chain_last_wins_scalar(self):
        base = GovernancePolicy(name="base", max_tokens=4096, timeout_seconds=300)
        override = GovernancePolicy(name="override", max_tokens=2048, timeout_seconds=60)
        h = PolicyHierarchy(base)
        result = h.chain(override)
        assert result.max_tokens == 2048
        assert result.timeout_seconds == 60

    def test_chain_unions_blocked_patterns(self):
        base = GovernancePolicy(name="base", blocked_patterns=["secret"])
        extra = GovernancePolicy(name="extra", blocked_patterns=["password"])
        h = PolicyHierarchy(base)
        result = h.chain(extra)
        assert "secret" in result.blocked_patterns
        assert "password" in result.blocked_patterns

    def test_chain_name_combined(self):
        base = GovernancePolicy(name="base")
        a = GovernancePolicy(name="layer1")
        b = GovernancePolicy(name="layer2")
        h = PolicyHierarchy(base)
        result = h.chain(a, b)
        assert result.name == "base + layer1 + layer2"

    def test_chain_no_policies(self):
        base = GovernancePolicy(name="base", max_tokens=4096)
        h = PolicyHierarchy(base)
        result = h.chain()
        assert result.max_tokens == 4096
        assert result is not base

    def test_chain_intersects_allowed_tools(self):
        base = GovernancePolicy(name="base", allowed_tools=["a", "b", "c"])
        layer = GovernancePolicy(name="layer", allowed_tools=["b", "c", "d"])
        h = PolicyHierarchy(base)
        result = h.chain(layer)
        assert set(result.allowed_tools) == {"b", "c"}


# ---------------------------------------------------------------------------
# Import from __init__
# ---------------------------------------------------------------------------

class TestExports:
    def test_importable_from_integrations(self):
        from agent_os.integrations import compose_policies, PolicyHierarchy, override_policy
        assert callable(compose_policies)
        assert callable(override_policy)
        assert PolicyHierarchy is not None
