# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for policy conflict resolution strategies."""

import pytest

from agentmesh.governance.conflict_resolution import (
    CandidateDecision,
    ConflictResolutionStrategy,
    PolicyConflictResolver,
    PolicyScope,
    ResolutionResult,
)
from agentmesh.governance.policy import Policy, PolicyEngine, PolicyRule


# ── Resolver unit tests ─────────────────────────────────────


class TestConflictResolutionStrategy:
    def test_enum_values(self):
        assert ConflictResolutionStrategy.DENY_OVERRIDES == "deny_overrides"
        assert ConflictResolutionStrategy.ALLOW_OVERRIDES == "allow_overrides"
        assert ConflictResolutionStrategy.PRIORITY_FIRST_MATCH == "priority_first_match"
        assert ConflictResolutionStrategy.MOST_SPECIFIC_WINS == "most_specific_wins"


class TestPolicyScope:
    def test_specificity_ordering(self):
        agent = CandidateDecision(action="deny", scope=PolicyScope.AGENT, rule_name="a")
        tenant = CandidateDecision(action="deny", scope=PolicyScope.TENANT, rule_name="t")
        global_ = CandidateDecision(action="deny", scope=PolicyScope.GLOBAL, rule_name="g")

        assert agent.specificity > tenant.specificity > global_.specificity


class TestDenyOverrides:
    def setup_method(self):
        self.resolver = PolicyConflictResolver(ConflictResolutionStrategy.DENY_OVERRIDES)

    def test_deny_wins_over_allow(self):
        candidates = [
            CandidateDecision(action="allow", priority=100, rule_name="permissive"),
            CandidateDecision(action="deny", priority=1, rule_name="strict"),
        ]
        result = self.resolver.resolve(candidates)
        assert result.winning_decision.action == "deny"
        assert result.winning_decision.rule_name == "strict"
        assert result.conflict_detected is True

    def test_highest_priority_deny_wins(self):
        candidates = [
            CandidateDecision(action="deny", priority=10, rule_name="low-deny"),
            CandidateDecision(action="deny", priority=50, rule_name="high-deny"),
        ]
        result = self.resolver.resolve(candidates)
        assert result.winning_decision.rule_name == "high-deny"

    def test_no_denies_falls_to_highest_allow(self):
        candidates = [
            CandidateDecision(action="allow", priority=5, rule_name="low"),
            CandidateDecision(action="allow", priority=20, rule_name="high"),
        ]
        result = self.resolver.resolve(candidates)
        assert result.winning_decision.rule_name == "high"
        assert result.conflict_detected is False


class TestAllowOverrides:
    def setup_method(self):
        self.resolver = PolicyConflictResolver(ConflictResolutionStrategy.ALLOW_OVERRIDES)

    def test_allow_wins_over_deny(self):
        candidates = [
            CandidateDecision(action="deny", priority=100, rule_name="strict"),
            CandidateDecision(action="allow", priority=1, rule_name="exception"),
        ]
        result = self.resolver.resolve(candidates)
        assert result.winning_decision.action == "allow"
        assert result.winning_decision.rule_name == "exception"
        assert result.conflict_detected is True

    def test_highest_priority_allow_wins(self):
        candidates = [
            CandidateDecision(action="allow", priority=5, rule_name="low-allow"),
            CandidateDecision(action="allow", priority=50, rule_name="high-allow"),
        ]
        result = self.resolver.resolve(candidates)
        assert result.winning_decision.rule_name == "high-allow"

    def test_no_allows_falls_to_highest_deny(self):
        candidates = [
            CandidateDecision(action="deny", priority=5, rule_name="low"),
            CandidateDecision(action="deny", priority=20, rule_name="high"),
        ]
        result = self.resolver.resolve(candidates)
        assert result.winning_decision.rule_name == "high"


class TestPriorityFirstMatch:
    def setup_method(self):
        self.resolver = PolicyConflictResolver(ConflictResolutionStrategy.PRIORITY_FIRST_MATCH)

    def test_highest_priority_wins(self):
        candidates = [
            CandidateDecision(action="allow", priority=5, rule_name="low"),
            CandidateDecision(action="deny", priority=50, rule_name="high"),
        ]
        result = self.resolver.resolve(candidates)
        assert result.winning_decision.rule_name == "high"
        assert result.winning_decision.action == "deny"

    def test_preserves_v1_behavior(self):
        """Priority-first-match is the same as the old sort-by-priority logic."""
        candidates = [
            CandidateDecision(action="deny", priority=10, rule_name="r1"),
            CandidateDecision(action="allow", priority=5, rule_name="r2"),
            CandidateDecision(action="deny", priority=1, rule_name="r3"),
        ]
        result = self.resolver.resolve(candidates)
        assert result.winning_decision.rule_name == "r1"


class TestMostSpecificWins:
    def setup_method(self):
        self.resolver = PolicyConflictResolver(ConflictResolutionStrategy.MOST_SPECIFIC_WINS)

    def test_agent_scope_overrides_global(self):
        candidates = [
            CandidateDecision(
                action="deny", priority=100, scope=PolicyScope.GLOBAL, rule_name="global-deny"
            ),
            CandidateDecision(
                action="allow", priority=1, scope=PolicyScope.AGENT, rule_name="agent-allow"
            ),
        ]
        result = self.resolver.resolve(candidates)
        assert result.winning_decision.rule_name == "agent-allow"
        assert result.winning_decision.action == "allow"

    def test_tenant_overrides_global(self):
        candidates = [
            CandidateDecision(
                action="deny", priority=50, scope=PolicyScope.GLOBAL, rule_name="global"
            ),
            CandidateDecision(
                action="allow", priority=10, scope=PolicyScope.TENANT, rule_name="tenant"
            ),
        ]
        result = self.resolver.resolve(candidates)
        assert result.winning_decision.rule_name == "tenant"

    def test_priority_breaks_same_scope_tie(self):
        candidates = [
            CandidateDecision(
                action="deny", priority=5, scope=PolicyScope.TENANT, rule_name="low-tenant"
            ),
            CandidateDecision(
                action="allow", priority=50, scope=PolicyScope.TENANT, rule_name="high-tenant"
            ),
        ]
        result = self.resolver.resolve(candidates)
        assert result.winning_decision.rule_name == "high-tenant"

    def test_full_hierarchy(self):
        """Agent > tenant > global, with priority as tiebreaker."""
        candidates = [
            CandidateDecision(action="deny", priority=100, scope=PolicyScope.GLOBAL, rule_name="g"),
            CandidateDecision(action="deny", priority=50, scope=PolicyScope.TENANT, rule_name="t"),
            CandidateDecision(action="allow", priority=1, scope=PolicyScope.AGENT, rule_name="a"),
        ]
        result = self.resolver.resolve(candidates)
        assert result.winning_decision.rule_name == "a"
        assert result.winning_decision.action == "allow"


class TestResolverEdgeCases:
    def test_single_candidate(self):
        resolver = PolicyConflictResolver(ConflictResolutionStrategy.DENY_OVERRIDES)
        result = resolver.resolve([
            CandidateDecision(action="allow", rule_name="only")
        ])
        assert result.winning_decision.rule_name == "only"
        assert result.conflict_detected is False
        assert result.candidates_evaluated == 1

    def test_empty_candidates_raises(self):
        resolver = PolicyConflictResolver()
        with pytest.raises(ValueError, match="zero candidates"):
            resolver.resolve([])

    def test_resolution_trace_populated(self):
        resolver = PolicyConflictResolver(ConflictResolutionStrategy.DENY_OVERRIDES)
        result = resolver.resolve([
            CandidateDecision(action="allow", priority=10, rule_name="a"),
            CandidateDecision(action="deny", priority=5, rule_name="b"),
        ])
        assert len(result.resolution_trace) > 0
        assert "DENY_OVERRIDES" in result.resolution_trace[0]


# ── PolicyEngine integration tests ──────────────────────────


class TestPolicyEngineConflictResolution:
    """Test that PolicyEngine correctly delegates to the resolver."""

    def _make_policy(self, name, rules, scope="global", agents=None):
        return Policy(
            name=name,
            scope=scope,
            agents=agents or ["*"],
            rules=[PolicyRule(**r) for r in rules],
            default_action="deny",
        )

    def test_default_strategy_is_priority_first_match(self):
        engine = PolicyEngine()
        assert engine._conflict_strategy == ConflictResolutionStrategy.PRIORITY_FIRST_MATCH

    def test_deny_overrides_strategy(self):
        engine = PolicyEngine(conflict_strategy="deny_overrides")
        # Global policy allows with high priority
        engine.load_policy(self._make_policy("permissive", [
            {"name": "allow-all", "condition": "action.type == 'read'", "action": "allow", "priority": 100},
        ], scope="global"))
        # Agent policy denies with low priority
        engine.load_policy(self._make_policy("restrictive", [
            {"name": "deny-reads", "condition": "action.type == 'read'", "action": "deny", "priority": 1},
        ], scope="agent"))

        result = engine.evaluate("agent-1", {"action": {"type": "read"}})
        assert result.allowed is False
        assert result.matched_rule == "deny-reads"

    def test_allow_overrides_strategy(self):
        engine = PolicyEngine(conflict_strategy="allow_overrides")
        engine.load_policy(self._make_policy("restrictive", [
            {"name": "deny-all", "condition": "action.type == 'write'", "action": "deny", "priority": 100},
        ]))
        engine.load_policy(self._make_policy("exception", [
            {"name": "allow-write", "condition": "action.type == 'write'", "action": "allow", "priority": 1},
        ]))

        result = engine.evaluate("agent-1", {"action": {"type": "write"}})
        assert result.allowed is True
        assert result.matched_rule == "allow-write"

    def test_most_specific_wins_strategy(self):
        engine = PolicyEngine(conflict_strategy="most_specific_wins")
        engine.load_policy(self._make_policy("global-deny", [
            {"name": "block-shell", "condition": "tool == 'shell'", "action": "deny", "priority": 100},
        ], scope="global"))
        engine.load_policy(self._make_policy("agent-allow", [
            {"name": "permit-shell", "condition": "tool == 'shell'", "action": "allow", "priority": 1},
        ], scope="agent"))

        result = engine.evaluate("agent-1", {"tool": "shell"})
        assert result.allowed is True
        assert result.matched_rule == "permit-shell"

    def test_backward_compat_priority_first_match(self):
        """Default strategy matches v1.0 behavior: highest priority wins."""
        engine = PolicyEngine()
        engine.load_policy(self._make_policy("p1", [
            {"name": "high-deny", "condition": "action.type == 'export'", "action": "deny", "priority": 50},
        ]))
        engine.load_policy(self._make_policy("p2", [
            {"name": "low-allow", "condition": "action.type == 'export'", "action": "allow", "priority": 10},
        ]))

        result = engine.evaluate("agent-1", {"action": {"type": "export"}})
        assert result.allowed is False
        assert result.matched_rule == "high-deny"

    def test_no_matching_rules_uses_default(self):
        engine = PolicyEngine(conflict_strategy="deny_overrides")
        engine.load_policy(self._make_policy("strict", [
            {"name": "r1", "condition": "never_matches", "action": "deny"},
        ]))

        result = engine.evaluate("agent-1", {"action": {"type": "read"}})
        assert result.reason == "No matching rules, using default"

    def test_policy_scope_in_yaml(self):
        """Scope field survives YAML round-trip."""
        yaml_content = """
apiVersion: governance.toolkit/v1
name: tenant-policy
scope: tenant
agents: ["*"]
rules:
  - name: tenant-rule
    condition: "data.contains_pii"
    action: deny
    priority: 10
"""
        engine = PolicyEngine()
        policy = engine.load_yaml(yaml_content)
        assert policy.scope == "tenant"

    def test_scope_defaults_to_global(self):
        policy = Policy(name="test")
        assert policy.scope == "global"
