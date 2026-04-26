# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for PolicyTemplates factory methods."""

import pytest

from agent_os.integrations.base import GovernancePolicy
from agent_os.integrations.templates import PolicyTemplates


class TestStrictPolicy:
    def test_returns_governance_policy(self):
        policy = PolicyTemplates.strict()
        assert isinstance(policy, GovernancePolicy)

    def test_low_token_limit(self):
        policy = PolicyTemplates.strict()
        assert policy.max_tokens == 1000

    def test_low_tool_call_limit(self):
        policy = PolicyTemplates.strict()
        assert policy.max_tool_calls == 3

    def test_has_allowed_tools_whitelist(self):
        policy = PolicyTemplates.strict()
        assert len(policy.allowed_tools) > 0

    def test_blocks_dangerous_patterns(self):
        policy = PolicyTemplates.strict()
        dangerous = {"eval", "exec", "rm -rf", "DROP TABLE"}
        blocked_set = set(policy.blocked_patterns)
        assert dangerous.issubset(blocked_set)

    def test_requires_human_approval(self):
        policy = PolicyTemplates.strict()
        assert policy.require_human_approval is True

    def test_short_timeout(self):
        policy = PolicyTemplates.strict()
        assert policy.timeout_seconds <= 60

    def test_high_confidence_threshold(self):
        policy = PolicyTemplates.strict()
        assert policy.confidence_threshold >= 0.9

    def test_logging_enabled(self):
        policy = PolicyTemplates.strict()
        assert policy.log_all_calls is True


class TestPermissivePolicy:
    def test_returns_governance_policy(self):
        policy = PolicyTemplates.permissive()
        assert isinstance(policy, GovernancePolicy)

    def test_high_token_limit(self):
        policy = PolicyTemplates.permissive()
        assert policy.max_tokens == 100000

    def test_high_tool_call_limit(self):
        policy = PolicyTemplates.permissive()
        assert policy.max_tool_calls == 100

    def test_no_blocked_patterns(self):
        policy = PolicyTemplates.permissive()
        assert policy.blocked_patterns == []

    def test_all_tools_allowed(self):
        policy = PolicyTemplates.permissive()
        assert policy.allowed_tools == []

    def test_no_human_approval(self):
        policy = PolicyTemplates.permissive()
        assert policy.require_human_approval is False

    def test_logging_disabled(self):
        policy = PolicyTemplates.permissive()
        assert policy.log_all_calls is False


class TestEnterprisePolicy:
    def test_returns_governance_policy(self):
        policy = PolicyTemplates.enterprise()
        assert isinstance(policy, GovernancePolicy)

    def test_moderate_token_limit(self):
        policy = PolicyTemplates.enterprise()
        assert policy.max_tokens == 10000

    def test_moderate_tool_call_limit(self):
        policy = PolicyTemplates.enterprise()
        assert policy.max_tool_calls == 20

    def test_blocks_sql_injection_patterns(self):
        policy = PolicyTemplates.enterprise()
        blocked = policy.blocked_patterns
        assert "DROP TABLE" in blocked
        assert "DELETE FROM" in blocked

    def test_blocks_shell_patterns(self):
        policy = PolicyTemplates.enterprise()
        blocked = policy.blocked_patterns
        assert "rm -rf" in blocked

    def test_audit_logging_enabled(self):
        policy = PolicyTemplates.enterprise()
        assert policy.log_all_calls is True


class TestResearchPolicy:
    def test_returns_governance_policy(self):
        policy = PolicyTemplates.research()
        assert isinstance(policy, GovernancePolicy)

    def test_generous_token_limit(self):
        policy = PolicyTemplates.research()
        assert policy.max_tokens == 50000

    def test_generous_tool_call_limit(self):
        policy = PolicyTemplates.research()
        assert policy.max_tool_calls == 50

    def test_blocks_destructive_operations(self):
        policy = PolicyTemplates.research()
        blocked = policy.blocked_patterns
        assert "rm -rf" in blocked
        assert "DROP TABLE" in blocked

    def test_no_human_approval(self):
        policy = PolicyTemplates.research()
        assert policy.require_human_approval is False

    def test_logging_enabled(self):
        policy = PolicyTemplates.research()
        assert policy.log_all_calls is True


class TestMinimalPolicy:
    def test_returns_governance_policy(self):
        policy = PolicyTemplates.minimal()
        assert isinstance(policy, GovernancePolicy)

    def test_default_token_cap(self):
        policy = PolicyTemplates.minimal()
        assert policy.max_tokens == 4096

    def test_no_blocked_patterns(self):
        policy = PolicyTemplates.minimal()
        assert policy.blocked_patterns == []

    def test_no_human_approval(self):
        policy = PolicyTemplates.minimal()
        assert policy.require_human_approval is False

    def test_logging_disabled(self):
        policy = PolicyTemplates.minimal()
        assert policy.log_all_calls is False


class TestCustomPolicy:
    def test_returns_governance_policy(self):
        policy = PolicyTemplates.custom()
        assert isinstance(policy, GovernancePolicy)

    def test_defaults_match_base(self):
        policy = PolicyTemplates.custom()
        default = GovernancePolicy()
        assert policy.max_tokens == default.max_tokens
        assert policy.max_tool_calls == default.max_tool_calls

    def test_override_single_field(self):
        policy = PolicyTemplates.custom(max_tokens=5000)
        assert policy.max_tokens == 5000

    def test_override_multiple_fields(self):
        policy = PolicyTemplates.custom(
            max_tokens=8000,
            require_human_approval=True,
            blocked_patterns=["eval"],
        )
        assert policy.max_tokens == 8000
        assert policy.require_human_approval is True
        assert policy.blocked_patterns == ["eval"]

    def test_invalid_field_raises(self):
        with pytest.raises(TypeError):
            PolicyTemplates.custom(nonexistent_field=True)


class TestTemplateDifferences:
    """Verify that templates produce distinct configurations."""

    def test_strict_more_restrictive_than_permissive(self):
        strict = PolicyTemplates.strict()
        permissive = PolicyTemplates.permissive()
        assert strict.max_tokens < permissive.max_tokens
        assert strict.max_tool_calls < permissive.max_tool_calls

    def test_enterprise_between_strict_and_permissive(self):
        strict = PolicyTemplates.strict()
        enterprise = PolicyTemplates.enterprise()
        permissive = PolicyTemplates.permissive()
        assert strict.max_tokens < enterprise.max_tokens < permissive.max_tokens

    def test_all_templates_return_unique_policies(self):
        policies = [
            PolicyTemplates.strict(),
            PolicyTemplates.permissive(),
            PolicyTemplates.enterprise(),
            PolicyTemplates.research(),
            PolicyTemplates.minimal(),
        ]
        token_values = [p.max_tokens for p in policies]
        assert len(set(token_values)) == len(token_values)
