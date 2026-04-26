# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for session policy pinning and tool alias registry."""

import copy
import pytest

from agent_os.integrations.base import (
    BaseIntegration,
    ExecutionContext,
    GovernancePolicy,
    PolicyInterceptor,
    ToolCallRequest,
)
from agent_os.integrations.tool_aliases import ToolAliasRegistry, DEFAULT_ALIASES


class _StubIntegration(BaseIntegration):
    """Minimal concrete BaseIntegration for testing."""

    def wrap(self, agent):
        return agent

    def unwrap(self, governed):
        return governed


# ── Session Policy Pinning Tests ────────────────────────────


class TestSessionPolicyPinning:
    def test_context_gets_policy_copy_not_reference(self):
        """Mutating the integration's policy should NOT affect existing contexts."""
        policy = GovernancePolicy(name="original", max_tool_calls=10)
        integration = _StubIntegration(policy=policy)
        ctx = integration.create_context("agent-1")

        # Mutate the live policy
        integration.policy.max_tool_calls = 0

        # Context should still see the original
        assert ctx.policy.max_tool_calls == 10

    def test_context_policy_is_independent(self):
        """Two contexts created at different times get independent snapshots."""
        policy = GovernancePolicy(name="v1", max_tokens=4096)
        integration = _StubIntegration(policy=policy)

        ctx1 = integration.create_context("agent-1")
        integration.policy.max_tokens = 1024
        ctx2 = integration.create_context("agent-2")

        assert ctx1.policy.max_tokens == 4096
        assert ctx2.policy.max_tokens == 1024

    def test_context_policy_mutation_doesnt_affect_integration(self):
        """Mutating the context's policy shouldn't affect the integration."""
        policy = GovernancePolicy(name="base", require_human_approval=False)
        integration = _StubIntegration(policy=policy)
        ctx = integration.create_context("agent-1")

        ctx.policy.require_human_approval = True
        assert integration.policy.require_human_approval is False

    def test_pre_execute_uses_integration_policy_not_context(self):
        """pre_execute currently reads self.policy — this documents the behavior.

        The session pinning fix ensures create_context() snapshots policy,
        but pre_execute still reads the live integration policy. A follow-up
        should refactor pre_execute to use ctx.policy for full isolation.
        """
        policy = GovernancePolicy(name="permissive", max_tool_calls=100)
        integration = _StubIntegration(policy=policy)
        ctx = integration.create_context("agent-1")

        # Tighten the live policy AFTER context creation
        integration.policy.max_tool_calls = 0

        # pre_execute reads self.policy (the live one), so this should BLOCK
        allowed, reason = integration.pre_execute(ctx, "test input")
        assert allowed is False
        # But the context's pinned policy still has the original value
        assert ctx.policy.max_tool_calls == 100


# ── Tool Alias Registry Tests ───────────────────────────────


class TestToolAliasRegistry:
    def test_default_aliases_loaded(self):
        registry = ToolAliasRegistry()
        assert len(registry) > 0
        assert registry.canonicalize("bing_search") == "web_search"

    def test_no_defaults(self):
        registry = ToolAliasRegistry(use_defaults=False)
        assert len(registry) == 0

    def test_register_alias(self):
        registry = ToolAliasRegistry(use_defaults=False)
        registry.register_alias("my_tool", "canonical_tool")
        assert registry.canonicalize("my_tool") == "canonical_tool"

    def test_case_insensitive(self):
        registry = ToolAliasRegistry(use_defaults=False)
        registry.register_alias("MyTool", "canonical")
        assert registry.canonicalize("MYTOOL") == "canonical"
        assert registry.canonicalize("mytool") == "canonical"

    def test_unknown_returns_lowered_original(self):
        registry = ToolAliasRegistry(use_defaults=False)
        assert registry.canonicalize("UnknownTool") == "unknowntool"

    def test_pattern_matching(self):
        registry = ToolAliasRegistry(use_defaults=False)
        registry.register_pattern(r".*search.*", "web_search")
        assert registry.canonicalize("my_custom_search_tool") == "web_search"
        assert registry.canonicalize("websearch") == "web_search"

    def test_exact_match_before_pattern(self):
        registry = ToolAliasRegistry(use_defaults=False)
        registry.register_alias("search_internal", "internal_search")
        registry.register_pattern(r".*search.*", "web_search")
        assert registry.canonicalize("search_internal") == "internal_search"

    def test_is_allowed(self):
        registry = ToolAliasRegistry()
        # bing_search canonicalizes to web_search
        assert registry.is_allowed("bing_search", ["web_search"]) is True
        assert registry.is_allowed("bing_search", ["file_read"]) is False

    def test_is_allowed_empty_list(self):
        registry = ToolAliasRegistry()
        assert registry.is_allowed("any_tool", []) is True

    def test_is_blocked(self):
        registry = ToolAliasRegistry()
        assert registry.is_blocked("run_command", ["shell_execute"]) is True
        assert registry.is_blocked("run_command", ["web_search"]) is False

    def test_is_blocked_empty_list(self):
        registry = ToolAliasRegistry()
        assert registry.is_blocked("any_tool", []) is False

    def test_get_aliases(self):
        registry = ToolAliasRegistry()
        aliases = registry.get_aliases("web_search")
        assert "bing_search" in aliases
        assert "google_search" in aliases

    def test_list_canonical_tools(self):
        registry = ToolAliasRegistry()
        canonical = registry.list_canonical_tools()
        assert "web_search" in canonical
        assert "shell_execute" in canonical

    def test_contains(self):
        registry = ToolAliasRegistry()
        assert "bing_search" in registry
        assert "completely_unknown_xyz" not in registry

    def test_bypass_prevention(self):
        """The core security test: renamed tools cannot bypass policy."""
        registry = ToolAliasRegistry()
        blocked = ["web_search", "shell_execute"]

        # All of these should be blocked despite different names
        assert registry.is_blocked("bing_search", blocked) is True
        assert registry.is_blocked("google_search", blocked) is True
        assert registry.is_blocked("search_web", blocked) is True
        assert registry.is_blocked("run_command", blocked) is True
        assert registry.is_blocked("bash", blocked) is True
        assert registry.is_blocked("exec_command", blocked) is True

    def test_default_aliases_cover_common_families(self):
        """Verify all documented tool families have aliases."""
        registry = ToolAliasRegistry()
        families = ["web_search", "file_read", "file_write",
                     "shell_execute", "code_execute", "database_query",
                     "http_request"]
        for family in families:
            aliases = registry.get_aliases(family)
            assert len(aliases) >= 2, f"{family} should have at least 2 aliases"
