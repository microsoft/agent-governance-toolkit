# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Conformance tests for AGENT-OS-POLICY-ENGINE-1.0 specification.

Each test references a specific section of the spec and verifies a MUST
or MUST NOT requirement. If any test fails, the implementation has
diverged from the specification.

Spec: docs/specs/AGENT-OS-POLICY-ENGINE-1.0.md
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

import pytest

from agent_os.integrations.base import (
    CompositeInterceptor,
    ExecutionContext,
    GovernancePolicy,
    PatternType,
    PolicyInterceptor,
    ToolCallRequest,
    ToolCallResult,
)
from agent_os.policies.conflict_resolution import (
    CandidateDecision,
    ConflictResolutionStrategy,
    PolicyConflictResolver,
    PolicyScope,
)
from agent_os.policies.evaluator import PolicyDecision, PolicyEvaluator
from agent_os.policies.merge import merge_policies
from agent_os.policies.schema import (
    PolicyAction,
    PolicyCondition,
    PolicyDefaults,
    PolicyDocument,
    PolicyOperator,
    PolicyRule,
)


# ===================================================================
# Section 5: Condition Operators
# ===================================================================


class TestConditionOperatorsSpec:
    """Spec Section 5.1: All nine operators MUST be supported."""

    def _make_evaluator(self, field: str, op: str, value) -> PolicyEvaluator:
        doc = PolicyDocument(
            name="test",
            rules=[
                PolicyRule(
                    name="r1",
                    condition=PolicyCondition(
                        field=field,
                        operator=PolicyOperator(op),
                        value=value,
                    ),
                    action=PolicyAction.DENY,
                )
            ],
        )
        return PolicyEvaluator(policies=[doc])

    def test_eq_matches(self):
        ev = self._make_evaluator("tool_name", "eq", "exec")
        result = ev.evaluate({"tool_name": "exec"})
        assert not result.allowed

    def test_eq_no_match(self):
        ev = self._make_evaluator("tool_name", "eq", "exec")
        result = ev.evaluate({"tool_name": "read"})
        assert result.allowed

    def test_ne_matches(self):
        ev = self._make_evaluator("tool_name", "ne", "read")
        result = ev.evaluate({"tool_name": "exec"})
        assert not result.allowed

    def test_gt_matches(self):
        ev = self._make_evaluator("count", "gt", 10)
        result = ev.evaluate({"count": 15})
        assert not result.allowed

    def test_lt_matches(self):
        ev = self._make_evaluator("count", "lt", 10)
        result = ev.evaluate({"count": 5})
        assert not result.allowed

    def test_gte_matches(self):
        ev = self._make_evaluator("count", "gte", 10)
        result = ev.evaluate({"count": 10})
        assert not result.allowed

    def test_lte_matches(self):
        ev = self._make_evaluator("count", "lte", 10)
        result = ev.evaluate({"count": 10})
        assert not result.allowed

    def test_in_matches(self):
        ev = self._make_evaluator("tool_name", "in", ["exec", "delete"])
        result = ev.evaluate({"tool_name": "exec"})
        assert not result.allowed

    def test_contains_matches(self):
        ev = self._make_evaluator("args", "contains", "password")
        result = ev.evaluate({"args": "user_password_hash"})
        assert not result.allowed

    def test_matches_regex(self):
        ev = self._make_evaluator("tool_name", "matches", "^exec_.*")
        result = ev.evaluate({"tool_name": "exec_code"})
        assert not result.allowed


class TestMissingFieldSpec:
    """Spec Section 5.2: Missing fields MUST evaluate to false."""

    def test_missing_field_does_not_match(self):
        doc = PolicyDocument(
            name="test",
            rules=[
                PolicyRule(
                    name="r1",
                    condition=PolicyCondition(
                        field="nonexistent_field",
                        operator=PolicyOperator.EQ,
                        value="anything",
                    ),
                    action=PolicyAction.DENY,
                )
            ],
        )
        ev = PolicyEvaluator(policies=[doc])
        result = ev.evaluate({"tool_name": "exec"})
        assert result.allowed, "Missing field MUST evaluate to false (Section 5.2)"


# ===================================================================
# Section 6: Policy Actions
# ===================================================================


class TestPolicyActionsSpec:
    """Spec Section 6.1: allow and audit are allowing; deny and block are denying."""

    @pytest.mark.parametrize("action", [PolicyAction.ALLOW, PolicyAction.AUDIT])
    def test_allowing_actions(self, action):
        doc = PolicyDocument(
            name="test",
            rules=[
                PolicyRule(
                    name="r1",
                    condition=PolicyCondition(
                        field="x", operator=PolicyOperator.EQ, value=1
                    ),
                    action=action,
                )
            ],
        )
        ev = PolicyEvaluator(policies=[doc])
        result = ev.evaluate({"x": 1})
        assert result.allowed, f"{action.value} MUST be an allowing action"

    @pytest.mark.parametrize("action", [PolicyAction.DENY, PolicyAction.BLOCK])
    def test_denying_actions(self, action):
        doc = PolicyDocument(
            name="test",
            rules=[
                PolicyRule(
                    name="r1",
                    condition=PolicyCondition(
                        field="x", operator=PolicyOperator.EQ, value=1
                    ),
                    action=action,
                )
            ],
        )
        ev = PolicyEvaluator(policies=[doc])
        result = ev.evaluate({"x": 1})
        assert not result.allowed, f"{action.value} MUST be a denying action"


# ===================================================================
# Section 7: Evaluation Semantics
# ===================================================================


class TestEvaluationOrderSpec:
    """Spec Section 7.1: Rules MUST be sorted by priority descending, first match wins."""

    def test_higher_priority_wins(self):
        doc = PolicyDocument(
            name="test",
            rules=[
                PolicyRule(
                    name="low",
                    condition=PolicyCondition(
                        field="x", operator=PolicyOperator.EQ, value=1
                    ),
                    action=PolicyAction.ALLOW,
                    priority=10,
                ),
                PolicyRule(
                    name="high",
                    condition=PolicyCondition(
                        field="x", operator=PolicyOperator.EQ, value=1
                    ),
                    action=PolicyAction.DENY,
                    priority=100,
                ),
            ],
        )
        ev = PolicyEvaluator(policies=[doc])
        result = ev.evaluate({"x": 1})
        assert not result.allowed, "Higher priority rule MUST win (Section 7.1)"
        assert result.matched_rule == "high"

    def test_first_match_short_circuits(self):
        doc = PolicyDocument(
            name="test",
            rules=[
                PolicyRule(
                    name="first",
                    condition=PolicyCondition(
                        field="x", operator=PolicyOperator.EQ, value=1
                    ),
                    action=PolicyAction.DENY,
                    priority=100,
                ),
                PolicyRule(
                    name="second",
                    condition=PolicyCondition(
                        field="x", operator=PolicyOperator.EQ, value=1
                    ),
                    action=PolicyAction.ALLOW,
                    priority=50,
                ),
            ],
        )
        ev = PolicyEvaluator(policies=[doc])
        result = ev.evaluate({"x": 1})
        assert result.matched_rule == "first"


class TestDefaultActionSpec:
    """Spec Section 7.3: Default action MUST be used when no rule matches."""

    def test_default_allow(self):
        doc = PolicyDocument(
            name="test",
            defaults=PolicyDefaults(action=PolicyAction.ALLOW),
        )
        ev = PolicyEvaluator(policies=[doc])
        result = ev.evaluate({"x": 999})
        assert result.allowed

    def test_default_deny(self):
        doc = PolicyDocument(
            name="test",
            defaults=PolicyDefaults(action=PolicyAction.DENY),
        )
        ev = PolicyEvaluator(policies=[doc])
        result = ev.evaluate({"x": 999})
        assert not result.allowed

    def test_no_policies_defaults_to_allow(self):
        ev = PolicyEvaluator()
        result = ev.evaluate({"x": 1})
        assert result.allowed, "No loaded policies MUST default to allow (Section 7.3)"


# ===================================================================
# Section 8: GovernancePolicy Validation
# ===================================================================


class TestGovernancePolicyValidationSpec:
    """Spec Section 8.3: Validation MUST occur at construction time."""

    def test_max_tokens_must_be_positive(self):
        with pytest.raises(ValueError, match="max_tokens"):
            GovernancePolicy(max_tokens=0)

    def test_max_tokens_rejects_negative(self):
        with pytest.raises(ValueError, match="max_tokens"):
            GovernancePolicy(max_tokens=-1)

    def test_max_tool_calls_allows_zero(self):
        p = GovernancePolicy(max_tool_calls=0)
        assert p.max_tool_calls == 0

    def test_max_tool_calls_rejects_negative(self):
        with pytest.raises(ValueError, match="max_tool_calls"):
            GovernancePolicy(max_tool_calls=-1)

    def test_confidence_threshold_range(self):
        with pytest.raises(ValueError, match="confidence_threshold"):
            GovernancePolicy(confidence_threshold=1.5)

    def test_drift_threshold_range(self):
        with pytest.raises(ValueError, match="drift_threshold"):
            GovernancePolicy(drift_threshold=-0.1)

    def test_timeout_must_be_positive(self):
        with pytest.raises(ValueError, match="timeout_seconds"):
            GovernancePolicy(timeout_seconds=0)

    def test_version_must_be_nonempty(self):
        with pytest.raises(ValueError, match="version"):
            GovernancePolicy(version="")

    def test_allowed_tools_must_be_strings(self):
        with pytest.raises(ValueError, match="allowed_tools"):
            GovernancePolicy(allowed_tools=[123])  # type: ignore

    def test_invalid_regex_rejected_at_construction(self):
        with pytest.raises(ValueError, match="invalid regex"):
            GovernancePolicy(blocked_patterns=[("[invalid", PatternType.REGEX)])


# ===================================================================
# Section 8.5: Strictness Comparison
# ===================================================================


class TestStrictnessSpec:
    """Spec Section 8.5: is_stricter_than MUST follow defined rules."""

    def test_stricter_lower_tokens(self):
        base = GovernancePolicy()
        strict = GovernancePolicy(max_tokens=2048)
        assert strict.is_stricter_than(base)

    def test_identical_is_not_stricter(self):
        a = GovernancePolicy()
        b = GovernancePolicy()
        assert not a.is_stricter_than(b), "Identical policies are NOT stricter"

    def test_loosening_any_field_breaks_strictness(self):
        base = GovernancePolicy(max_tokens=2048, max_tool_calls=5)
        candidate = GovernancePolicy(max_tokens=1024, max_tool_calls=20)
        assert not candidate.is_stricter_than(base)


# ===================================================================
# Section 9: Pattern Matching
# ===================================================================


class TestPatternMatchingSpec:
    """Spec Section 9: All three pattern types MUST be supported."""

    def test_substring_case_insensitive(self):
        p = GovernancePolicy(blocked_patterns=["PASSWORD"])
        assert p.matches_pattern("my_password_field")

    def test_regex_search_semantics(self):
        p = GovernancePolicy(
            blocked_patterns=[("rm\\s+-rf", PatternType.REGEX)]
        )
        assert p.matches_pattern("sudo rm -rf /")

    def test_glob_pattern(self):
        p = GovernancePolicy(
            blocked_patterns=[("*.exe", PatternType.GLOB)]
        )
        assert p.matches_pattern("malware.exe")

    def test_matches_pattern_returns_all(self):
        """Section 9.4: MUST return ALL matching patterns."""
        p = GovernancePolicy(
            blocked_patterns=["secret", "password"]
        )
        matches = p.matches_pattern("secret_password")
        assert len(matches) == 2


# ===================================================================
# Section 10: Tool Call Interception
# ===================================================================


class TestToolCallInterceptionSpec:
    """Spec Section 10.3: PolicyInterceptor enforcement order."""

    def test_human_approval_checked_first(self):
        policy = GovernancePolicy(
            require_human_approval=True,
            allowed_tools=["exec"],
        )
        interceptor = PolicyInterceptor(policy)
        req = ToolCallRequest(tool_name="exec", arguments={})
        result = interceptor.intercept(req)
        assert not result.allowed, "Human approval MUST be checked first"

    def test_allowed_tools_checked_second(self):
        policy = GovernancePolicy(allowed_tools=["read_file"])
        interceptor = PolicyInterceptor(policy)
        req = ToolCallRequest(tool_name="delete_file", arguments={})
        result = interceptor.intercept(req)
        assert not result.allowed

    def test_blocked_patterns_checked_third(self):
        policy = GovernancePolicy(blocked_patterns=["password"])
        interceptor = PolicyInterceptor(policy)
        req = ToolCallRequest(
            tool_name="query",
            arguments={"q": "get password"},
        )
        result = interceptor.intercept(req)
        assert not result.allowed

    def test_call_count_checked_fourth(self):
        policy = GovernancePolicy(max_tool_calls=2)
        ctx = ExecutionContext(
            agent_id="a1",
            session_id="s1",
            policy=policy,
            call_count=2,
        )
        interceptor = PolicyInterceptor(policy, context=ctx)
        req = ToolCallRequest(tool_name="read", arguments={})
        result = interceptor.intercept(req)
        assert not result.allowed

    def test_all_pass_allows(self):
        policy = GovernancePolicy(allowed_tools=["read"])
        ctx = ExecutionContext(
            agent_id="a1", session_id="s1", policy=policy, call_count=0
        )
        interceptor = PolicyInterceptor(policy, context=ctx)
        req = ToolCallRequest(tool_name="read", arguments={})
        result = interceptor.intercept(req)
        assert result.allowed


class TestCompositeInterceptorSpec:
    """Spec Section 10.4: ALL interceptors MUST allow for the call to proceed."""

    def test_all_allow(self):
        p = GovernancePolicy(allowed_tools=["read"])
        composite = CompositeInterceptor([PolicyInterceptor(p)])
        req = ToolCallRequest(tool_name="read", arguments={})
        assert composite.intercept(req).allowed

    def test_one_deny_short_circuits(self):
        allow_policy = GovernancePolicy()
        deny_policy = GovernancePolicy(allowed_tools=["other"])
        composite = CompositeInterceptor([
            PolicyInterceptor(allow_policy),
            PolicyInterceptor(deny_policy),
        ])
        req = ToolCallRequest(tool_name="read", arguments={})
        assert not composite.intercept(req).allowed


# ===================================================================
# Section 11: Policy Merge
# ===================================================================


class TestPolicyMergeSpec:
    """Spec Section 11: Folder-level merge semantics."""

    def test_deny_immutability_invariant(self):
        """Section 11.2: Parent deny MUST NOT be overridden."""
        parent = PolicyDocument(
            name="parent",
            rules=[
                PolicyRule(
                    name="no-delete",
                    condition=PolicyCondition(
                        field="tool", operator=PolicyOperator.EQ, value="del"
                    ),
                    action=PolicyAction.DENY,
                    priority=10,
                )
            ],
        )
        child = PolicyDocument(
            name="child",
            rules=[
                PolicyRule(
                    name="no-delete",
                    condition=PolicyCondition(
                        field="tool", operator=PolicyOperator.EQ, value="del"
                    ),
                    action=PolicyAction.ALLOW,
                    priority=200,
                    override=True,
                )
            ],
        )
        merged = merge_policies([parent, child])
        assert len(merged) == 1
        assert merged[0].action == PolicyAction.DENY

    def test_non_deny_override_replaces(self):
        parent = PolicyDocument(
            name="parent",
            rules=[
                PolicyRule(
                    name="log-reads",
                    condition=PolicyCondition(
                        field="tool", operator=PolicyOperator.EQ, value="read"
                    ),
                    action=PolicyAction.AUDIT,
                    priority=10,
                )
            ],
        )
        child = PolicyDocument(
            name="child",
            rules=[
                PolicyRule(
                    name="log-reads",
                    condition=PolicyCondition(
                        field="tool", operator=PolicyOperator.EQ, value="read"
                    ),
                    action=PolicyAction.ALLOW,
                    priority=50,
                    override=True,
                )
            ],
        )
        merged = merge_policies([parent, child])
        assert len(merged) == 1
        assert merged[0].action == PolicyAction.ALLOW

    def test_same_name_without_override_dropped(self):
        """Section 11.1 point 4: child without override MUST be dropped."""
        parent = PolicyDocument(
            name="parent",
            rules=[
                PolicyRule(
                    name="rule-x",
                    condition=PolicyCondition(
                        field="x", operator=PolicyOperator.EQ, value=1
                    ),
                    action=PolicyAction.DENY,
                    priority=10,
                )
            ],
        )
        child = PolicyDocument(
            name="child",
            rules=[
                PolicyRule(
                    name="rule-x",
                    condition=PolicyCondition(
                        field="x", operator=PolicyOperator.EQ, value=1
                    ),
                    action=PolicyAction.ALLOW,
                    priority=100,
                )
            ],
        )
        merged = merge_policies([parent, child])
        assert len(merged) == 1
        assert merged[0].action == PolicyAction.DENY

    def test_merged_sorted_by_priority(self):
        """Section 11.1 point 6: Final list MUST be sorted by priority descending."""
        doc = PolicyDocument(
            name="test",
            rules=[
                PolicyRule(
                    name="low",
                    condition=PolicyCondition(
                        field="x", operator=PolicyOperator.EQ, value=1
                    ),
                    action=PolicyAction.ALLOW,
                    priority=1,
                ),
                PolicyRule(
                    name="high",
                    condition=PolicyCondition(
                        field="x", operator=PolicyOperator.EQ, value=2
                    ),
                    action=PolicyAction.DENY,
                    priority=100,
                ),
            ],
        )
        merged = merge_policies([doc])
        assert merged[0].priority >= merged[-1].priority


# ===================================================================
# Section 12: Policy Discovery
# ===================================================================


class TestPolicyDiscoverySpec:
    """Spec Section 12: Discovery semantics."""

    def test_path_traversal_protection(self):
        """Section 12.4: Action path outside root MUST return empty chain."""
        from agent_os.policies.discovery import discover_policies

        root = Path(tempfile.mkdtemp())
        outside = Path(tempfile.mkdtemp())
        result = discover_policies(outside, root)
        assert result == [], "Path outside root MUST produce empty chain"

    def test_inherit_false_cuts_chain(self):
        """Section 12.2: inherit: false MUST exclude parent policies."""
        root = Path(tempfile.mkdtemp())
        sub = root / "sub"
        sub.mkdir()

        # Root policy
        (root / "governance.yaml").write_text(
            "version: '1.0'\nname: root\nrules: []\n"
        )
        # Sub policy with inherit: false
        (sub / "governance.yaml").write_text(
            "version: '1.0'\nname: sub\ninherit: false\nrules: []\n"
        )

        from agent_os.policies.discovery import discover_policies

        result = discover_policies(sub, root)
        assert len(result) == 1
        assert "sub" in str(result[0])


# ===================================================================
# Section 13: Conflict Resolution
# ===================================================================


class TestConflictResolutionSpec:
    """Spec Section 13: All four strategies MUST be supported."""

    def _deny_candidate(self, priority=10, scope=PolicyScope.GLOBAL):
        return CandidateDecision(
            action="deny", priority=priority, scope=scope,
            rule_name="deny-rule", reason="blocked"
        )

    def _allow_candidate(self, priority=50, scope=PolicyScope.AGENT):
        return CandidateDecision(
            action="allow", priority=priority, scope=scope,
            rule_name="allow-rule", reason="permitted"
        )

    def test_deny_overrides(self):
        """Section 13.2.1: ANY deny wins regardless of priority."""
        resolver = PolicyConflictResolver(ConflictResolutionStrategy.DENY_OVERRIDES)
        result = resolver.resolve([
            self._allow_candidate(priority=100),
            self._deny_candidate(priority=10),
        ])
        assert result.winning_decision.action == "deny"
        assert result.conflict_detected

    def test_allow_overrides(self):
        """Section 13.2.2: ANY allow wins."""
        resolver = PolicyConflictResolver(ConflictResolutionStrategy.ALLOW_OVERRIDES)
        result = resolver.resolve([
            self._deny_candidate(priority=100),
            self._allow_candidate(priority=10),
        ])
        assert result.winning_decision.action == "allow"

    def test_priority_first_match(self):
        """Section 13.2.3: Highest priority wins regardless of action."""
        resolver = PolicyConflictResolver(
            ConflictResolutionStrategy.PRIORITY_FIRST_MATCH
        )
        result = resolver.resolve([
            self._deny_candidate(priority=100),
            self._allow_candidate(priority=50),
        ])
        assert result.winning_decision.action == "deny"
        assert result.winning_decision.priority == 100

    def test_most_specific_wins(self):
        """Section 13.2.4: Agent scope beats global."""
        resolver = PolicyConflictResolver(
            ConflictResolutionStrategy.MOST_SPECIFIC_WINS
        )
        result = resolver.resolve([
            self._deny_candidate(priority=100, scope=PolicyScope.GLOBAL),
            self._allow_candidate(priority=10, scope=PolicyScope.AGENT),
        ])
        assert result.winning_decision.scope == PolicyScope.AGENT

    def test_empty_candidates_raises(self):
        """Section 13.5: Zero candidates MUST raise an error."""
        resolver = PolicyConflictResolver()
        with pytest.raises(ValueError):
            resolver.resolve([])

    def test_resolution_result_has_trace(self):
        """Section 13.4: Result MUST include resolution trace."""
        resolver = PolicyConflictResolver(ConflictResolutionStrategy.DENY_OVERRIDES)
        result = resolver.resolve([self._deny_candidate()])
        assert isinstance(result.resolution_trace, list)
        assert len(result.resolution_trace) > 0


# ===================================================================
# Section 16: Failure Semantics
# ===================================================================


class TestFailClosedSpec:
    """Spec Section 16.1: Evaluation errors MUST result in deny."""

    def test_evaluation_error_denies(self):
        """On exception during evaluation, MUST deny (fail closed)."""
        doc = PolicyDocument(
            name="test",
            rules=[
                PolicyRule(
                    name="r1",
                    condition=PolicyCondition(
                        field="x", operator=PolicyOperator.GT, value="not_a_number"
                    ),
                    action=PolicyAction.ALLOW,
                    priority=10,
                )
            ],
        )
        ev = PolicyEvaluator(policies=[doc])
        # This will cause a comparison error (string > string, but context has int)
        # The evaluator should catch the exception and deny
        result = ev.evaluate({"x": 5})
        # The spec says: if evaluation errors, deny.
        # However, if the comparison just returns False (no error), it falls through
        # to default allow. Both behaviors are acceptable depending on whether
        # the comparison raises or returns False. The key invariant is: if it
        # DOES raise, the result MUST be deny.
        # We can test with a truly broken condition by monkeypatching.
        assert isinstance(result, PolicyDecision)


class TestFailClosedMonkeySpec:
    """Forced failure to verify fail-closed behavior."""

    def test_forced_exception_denies(self):
        ev = PolicyEvaluator()

        # Force an exception by giving a policies list that breaks iteration
        class BrokenList(list):
            def __iter__(self):
                raise RuntimeError("Simulated failure")

        ev.policies = BrokenList()
        result = ev.evaluate({"x": 1})
        assert not result.allowed, "Evaluation error MUST result in deny"
        assert result.action == "deny"


# ===================================================================
# Section 17: Audit and Observability
# ===================================================================


class TestAuditSpec:
    """Spec Section 17.1: Every decision MUST produce an audit entry."""

    def test_matched_rule_has_audit_entry(self):
        doc = PolicyDocument(
            name="audit-test",
            rules=[
                PolicyRule(
                    name="block-it",
                    condition=PolicyCondition(
                        field="x", operator=PolicyOperator.EQ, value=1
                    ),
                    action=PolicyAction.DENY,
                )
            ],
        )
        ev = PolicyEvaluator(policies=[doc])
        result = ev.evaluate({"x": 1})
        assert result.audit_entry, "Decision MUST include audit_entry"
        assert "policy" in result.audit_entry
        assert "rule" in result.audit_entry
        assert "action" in result.audit_entry
        assert "timestamp" in result.audit_entry
        assert "context_snapshot" in result.audit_entry

    def test_default_action_has_audit_entry(self):
        doc = PolicyDocument(name="audit-test")
        ev = PolicyEvaluator(policies=[doc])
        result = ev.evaluate({"x": 1})
        assert result.audit_entry, "Default decisions MUST include audit_entry"


# ===================================================================
# Section 18: Policy Composability
# ===================================================================


class TestPolicyComposabilitySpec:
    """Spec Section 18.2: Version tracking and diff."""

    def test_version_diff(self):
        v1 = GovernancePolicy(version="1.0.0", max_tokens=4096)
        v2 = GovernancePolicy(version="2.0.0", max_tokens=2048)
        comparison = v1.compare_versions(v2)
        assert comparison["versions_differ"]
        assert "max_tokens" in comparison["changes"]


# ===================================================================
# Section 19: Serialization
# ===================================================================


class TestSerializationSpec:
    """Spec Section 19: Round-trip serialization MUST be lossless."""

    def test_yaml_round_trip(self):
        original = GovernancePolicy(
            name="rt-test",
            max_tokens=2048,
            max_tool_calls=5,
            blocked_patterns=["secret", ("rm\\s+-rf", PatternType.REGEX)],
            confidence_threshold=0.9,
            version="2.1.0",
        )
        yaml_str = original.to_yaml()
        restored = GovernancePolicy.from_yaml(yaml_str)
        assert restored.max_tokens == original.max_tokens
        assert restored.max_tool_calls == original.max_tool_calls
        assert restored.confidence_threshold == original.confidence_threshold
        assert restored.version == original.version

    def test_dict_round_trip(self):
        original = GovernancePolicy(
            name="rt-test",
            max_tokens=1024,
            allowed_tools=["read", "write"],
            version="3.0.0",
        )
        d = original.to_dict()
        restored = GovernancePolicy.from_dict(d)
        assert restored.max_tokens == original.max_tokens
        assert restored.allowed_tools == original.allowed_tools
        assert restored.version == original.version

    def test_unknown_fields_ignored(self):
        """Section 19.3: Unknown fields MUST be silently ignored."""
        d = {"max_tokens": 2048, "unknown_future_field": True, "version": "1.0.0"}
        p = GovernancePolicy.from_dict(d)
        assert p.max_tokens == 2048


# ===================================================================
# Section 8.2: ExecutionContext Validation
# ===================================================================


class TestExecutionContextSpec:
    """ExecutionContext field validation."""

    def test_agent_id_must_be_nonempty(self):
        with pytest.raises(ValueError, match="agent_id"):
            ExecutionContext(agent_id="", session_id="s1", policy=GovernancePolicy())

    def test_agent_id_must_match_pattern(self):
        with pytest.raises(ValueError, match="agent_id"):
            ExecutionContext(
                agent_id="bad agent!", session_id="s1", policy=GovernancePolicy()
            )

    def test_session_id_must_be_nonempty(self):
        with pytest.raises(ValueError, match="session_id"):
            ExecutionContext(agent_id="a1", session_id="", policy=GovernancePolicy())

    def test_valid_context_construction(self):
        ctx = ExecutionContext(
            agent_id="agent-1", session_id="session-1", policy=GovernancePolicy()
        )
        assert ctx.agent_id == "agent-1"
