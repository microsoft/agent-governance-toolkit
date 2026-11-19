# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for trust policy DSL — models, YAML I/O, and evaluation."""

import tempfile
from pathlib import Path

import pytest

from agentmesh.governance.trust_policy import (
    ConditionEvaluationError,
    ConditionOperator,
    TrustCondition,
    TrustDefaults,
    TrustPolicy,
    TrustRule,
    load_policies,
)
from agentmesh.governance.policy_evaluator import PolicyEvaluator, TrustPolicyDecision


# ── Helpers ────────────────────────────────────────────────────

EXAMPLES_DIR = Path(__file__).resolve().parents[1] / "examples" / "policies"


def _make_policy(
    rules: list[TrustRule] | None = None,
    defaults: TrustDefaults | None = None,
) -> TrustPolicy:
    return TrustPolicy(
        name="test-policy",
        version="1.0",
        description="Unit-test policy",
        rules=rules or [],
        defaults=defaults or TrustDefaults(),
    )


def _rule(
    name: str,
    field: str,
    operator: str,
    value,
    action: str = "deny",
    priority: int = 100,
) -> TrustRule:
    return TrustRule(
        name=name,
        condition=TrustCondition(field=field, operator=operator, value=value),
        action=action,
        priority=priority,
    )


# ── YAML roundtrip ────────────────────────────────────────────


class TestYamlRoundtrip:
    def test_save_load_roundtrip(self, tmp_path: Path):
        """Load → save → load produces identical policy."""
        policy = _make_policy(
            rules=[
                _rule("r1", "trust_score", "gt", 500, action="allow", priority=10),
                _rule("r2", "delegation_depth", "lte", 3, action="allow", priority=20),
            ],
            defaults=TrustDefaults(
                min_trust_score=400,
                max_delegation_depth=4,
                allowed_namespaces=["core", "dev"],
                require_handshake=False,
            ),
        )
        yaml_path = tmp_path / "policy.yaml"
        policy.to_yaml(yaml_path)
        loaded = TrustPolicy.from_yaml(yaml_path)

        assert loaded.name == policy.name
        assert loaded.version == policy.version
        assert len(loaded.rules) == 2
        assert loaded.rules[0].name == "r1"
        assert loaded.rules[1].condition.operator == ConditionOperator.lte
        assert loaded.defaults.min_trust_score == 400
        assert loaded.defaults.allowed_namespaces == ["core", "dev"]
        assert loaded.defaults.require_handshake is False

    def test_load_policies_directory(self, tmp_path: Path):
        """load_policies loads all YAML files from a directory."""
        for name in ("a.yaml", "b.yaml", "c.yml"):
            p = _make_policy()
            p.name = name
            p.to_yaml(tmp_path / name)

        policies = load_policies(tmp_path)
        assert len(policies) == 3


# ── Condition operators ───────────────────────────────────────


class TestConditionOperators:
    @pytest.mark.parametrize(
        "op, value, ctx_value, expected",
        [
            ("eq", 500, 500, True),
            ("eq", 500, 499, False),
            ("ne", 500, 499, True),
            ("ne", 500, 500, False),
            ("gt", 500, 501, True),
            ("gt", 500, 500, False),
            ("gte", 500, 500, True),
            ("gte", 500, 499, False),
            ("lt", 500, 499, True),
            ("lt", 500, 500, False),
            ("lte", 500, 500, True),
            ("lte", 500, 501, False),
            ("in", ["a", "b", "c"], "b", True),
            ("in", ["a", "b", "c"], "d", False),
            ("not_in", ["a", "b"], "c", True),
            ("not_in", ["a", "b"], "a", False),
            ("matches", r"^agent-\d+$", "agent-42", True),
            ("matches", r"^agent-\d+$", "service-x", False),
        ],
    )
    def test_operator(self, op, value, ctx_value, expected):
        cond = TrustCondition(field="x", operator=op, value=value)
        assert cond.evaluate({"x": ctx_value}) is expected

    def test_nested_field(self):
        cond = TrustCondition(field="agent.namespace", operator="eq", value="core")
        assert cond.evaluate({"agent": {"namespace": "core"}}) is True
        assert cond.evaluate({"agent": {"namespace": "other"}}) is False

    def test_missing_field_returns_false(self):
        cond = TrustCondition(field="missing.path", operator="eq", value="x")
        assert cond.evaluate({}) is False


# ── Priority ordering ────────────────────────────────────────


class TestPriorityOrdering:
    def test_lower_priority_wins(self):
        """Lower priority number should be evaluated first and win."""
        policy = _make_policy(
            rules=[
                _rule("low-prio-deny", "trust_score", "gt", 0, action="deny", priority=50),
                _rule("high-prio-allow", "trust_score", "gt", 0, action="allow", priority=10),
            ]
        )
        evaluator = PolicyEvaluator([policy])
        decision = evaluator.evaluate({"trust_score": 600})

        assert decision.allowed is True
        assert decision.rule_name == "high-prio-allow"
        assert decision.action == "allow"

    def test_same_priority_stable_order(self):
        """Rules with equal priority keep insertion order (first wins)."""
        policy = _make_policy(
            rules=[
                _rule("first", "trust_score", "gt", 0, action="deny", priority=10),
                _rule("second", "trust_score", "gt", 0, action="allow", priority=10),
            ]
        )
        evaluator = PolicyEvaluator([policy])
        decision = evaluator.evaluate({"trust_score": 600})
        assert decision.rule_name == "first"


# ── Default fallback ─────────────────────────────────────────


class TestDefaultFallback:
    def test_no_rules_uses_defaults_trust_score(self):
        policy = _make_policy(defaults=TrustDefaults(min_trust_score=500))
        evaluator = PolicyEvaluator([policy])

        ok = evaluator.evaluate({"trust_score": 600})
        assert ok.allowed is True

        denied = evaluator.evaluate({"trust_score": 300})
        assert denied.allowed is False
        assert "below minimum" in denied.reason

    def test_no_rules_uses_defaults_delegation_depth(self):
        policy = _make_policy(defaults=TrustDefaults(max_delegation_depth=3))
        evaluator = PolicyEvaluator([policy])

        denied = evaluator.evaluate({"delegation_depth": 5})
        assert denied.allowed is False
        assert "exceeds maximum" in denied.reason

    def test_no_rules_uses_defaults_namespace(self):
        policy = _make_policy(
            defaults=TrustDefaults(allowed_namespaces=["core", "internal"])
        )
        evaluator = PolicyEvaluator([policy])

        denied = evaluator.evaluate({"agent": {"namespace": "external"}})
        assert denied.allowed is False
        assert "not in allowed" in denied.reason

    def test_wildcard_namespace_allows_all(self):
        policy = _make_policy(defaults=TrustDefaults(allowed_namespaces=["*"]))
        evaluator = PolicyEvaluator([policy])

        ok = evaluator.evaluate({"agent": {"namespace": "anything"}})
        assert ok.allowed is True

    def test_no_policies_default_allow(self):
        evaluator = PolicyEvaluator([])
        decision = evaluator.evaluate({"trust_score": 100})
        assert decision.allowed is True
        assert decision.action == "allow"


# ── Example policies ──────────────────────────────────────────


class TestExamplePolicies:
    @pytest.mark.skipif(
        not EXAMPLES_DIR.exists(), reason="examples/policies/ not found"
    )
    def test_all_example_policies_load(self):
        """All example YAML policies load and validate."""
        policies = load_policies(EXAMPLES_DIR)
        assert len(policies) >= 3
        names = {p.name for p in policies}
        assert "default-trust-policy" in names
        assert "strict-trust-policy" in names
        assert "permissive-trust-policy" in names

    @pytest.mark.skipif(
        not EXAMPLES_DIR.exists(), reason="examples/policies/ not found"
    )
    def test_strict_policy_denies_low_trust(self):
        policies = load_policies(EXAMPLES_DIR)
        strict = next(p for p in policies if p.name == "strict-trust-policy")
        evaluator = PolicyEvaluator([strict])
        decision = evaluator.evaluate({"trust_score": 400, "agent": {"namespace": "core"}})
        assert decision.allowed is False

    @pytest.mark.skipif(
        not EXAMPLES_DIR.exists(), reason="examples/policies/ not found"
    )
    def test_permissive_policy_allows_high_trust(self):
        policies = load_policies(EXAMPLES_DIR)
        permissive = next(p for p in policies if p.name == "permissive-trust-policy")
        evaluator = PolicyEvaluator([permissive])
        decision = evaluator.evaluate({"trust_score": 900})
        assert decision.allowed is True


# ── Edge cases ────────────────────────────────────────────────


class TestEdgeCases:
    def test_empty_rules_list(self):
        """Policy with no rules should fall back to defaults."""
        policy = _make_policy(rules=[])
        evaluator = PolicyEvaluator([policy])
        decision = evaluator.evaluate({"trust_score": 600})
        assert decision.allowed is True

    def test_conflicting_rules_priority_wins(self):
        """When rules conflict, the higher-priority (lower number) wins."""
        policy = _make_policy(
            rules=[
                _rule("allow-all", "trust_score", "gte", 0, action="allow", priority=50),
                _rule("deny-all", "trust_score", "gte", 0, action="deny", priority=1),
            ]
        )
        evaluator = PolicyEvaluator([policy])
        decision = evaluator.evaluate({"trust_score": 999})
        assert decision.allowed is False
        assert decision.rule_name == "deny-all"

    def test_decision_model_fields(self):
        """TrustPolicyDecision has expected fields."""
        d = TrustPolicyDecision(
            allowed=True, rule_name="r1", action="allow", reason="ok"
        )
        assert d.allowed is True
        assert d.rule_name == "r1"
        assert d.action == "allow"
        assert d.reason == "ok"

    def test_multiple_policies_merged(self):
        """Rules from multiple policies are merged and sorted."""
        p1 = _make_policy(
            rules=[_rule("p1-deny", "trust_score", "lt", 100, action="deny", priority=20)]
        )
        p1.name = "policy-1"
        p2 = TrustPolicy(
            name="policy-2",
            rules=[_rule("p2-allow", "trust_score", "gte", 0, action="allow", priority=10)],
        )
        evaluator = PolicyEvaluator([p1, p2])
        decision = evaluator.evaluate({"trust_score": 50})
        # p2-allow has priority 10 (higher priority) so it wins
        assert decision.allowed is True
        assert decision.rule_name == "p2-allow"


def test_matches_allows_bounded_quantifier_regex():
    """A quantifier over an unambiguous body is ReDoS-safe and must be allowed.

    Blocking '{' made a `matches` rule like '^svc-[0-9]{4}$' silently return
    False (fail-open: a deny/require_approval rule using it never fires).
    """
    cond = TrustCondition(field="agent.id", operator="matches", value=r"^svc-[0-9]{4}$")
    assert cond.evaluate({"agent": {"id": "svc-1234"}}) is True
    assert cond.evaluate({"agent": {"id": "svc-12"}}) is False


@pytest.mark.parametrize(
    ("pattern", "matching_subject"),
    [
        (r"^svc-[0-9]{4}$", "svc-1234"),
        (r"a{3}", "aaa"),
        (r"^(ab){2,3}$", "abab"),
        (r"^[a-z]+-[0-9]{1,3}$", "svc-12"),
        (r"alpha|beta", "alpha"),  # top-level alternation, not under a quantifier
        # Four variable-width quantifiers (an IPv4 matcher) sit well under the
        # variable-quantifier ceiling.
        (r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", "10.0.0.1"),
    ],
)
def test_matches_structural_guard_allows_safe_patterns(pattern, matching_subject):
    """Quantifiers over unambiguous bodies construct and evaluate normally."""
    cond = TrustCondition(field="agent.id", operator="matches", value=pattern)
    # Assert True on a matching subject: a guard rejection would raise, and a
    # bool-typed assertion alone would pass even if the guard wrongly blocked
    # the pattern from ever matching.
    assert cond.evaluate({"agent": {"id": matching_subject}}) is True


def test_matches_rejects_stacked_variable_quantifiers_at_load():
    """Non-nested exponential shapes are rejected by the quantifier ceiling.

    ^a?a?...a?aaa...a$ (25 of each) is 2^n against a short subject and
    contains no nested quantifier, so the nesting guard alone cannot see it.
    """
    pattern = "^" + "a?" * 25 + "a" * 25 + "$"
    with pytest.raises(ValueError, match="variable-width quantifiers"):
        TrustCondition(field="agent.id", operator="matches", value=pattern)


@pytest.mark.parametrize(
    "pattern",
    [
        r"(a{1,5}){1,5}$",  # nested bounded quantifiers
        r"(x{2,}){2,}$",  # nested open-ended quantifiers
        r"(a+)+$",  # the classic
        r"(.*)*",  # star over star
        r"(\d{1,3}\.?){1,40}$",  # quantified group with an inner quantifier
        r"(a|aa){1,40}$",  # alternation under a quantifier
        r"(a?a?){1,30}$",  # optional (?) repeats nest too: {0,1} is variable-width
    ],
)
def test_matches_rejects_catastrophic_patterns_at_load(pattern):
    """A pattern that can backtrack catastrophically fails at load time.

    Before, such a pattern was either rejected by a substring blocklist or
    accepted outright; either way `matches` silently returned False or hung.
    Now TrustCondition refuses to construct, so a bad policy is a loud load
    error rather than a deny rule that never fires.
    """
    with pytest.raises(ValueError, match="catastrophically"):
        TrustCondition(field="agent.id", operator="matches", value=pattern)


def test_matches_invalid_regex_rejected_at_load():
    """An uncompilable pattern is a load error, not a silent eval False."""
    with pytest.raises(ValueError, match="not a valid regex"):
        TrustCondition(field="agent.id", operator="matches", value=r"[unterminated")


def test_matches_overlong_pattern_rejected_at_load():
    with pytest.raises(ValueError, match="limit is 200"):
        TrustCondition(field="agent.id", operator="matches", value="a" * 201)


def test_matches_overlong_subject_fails_closed():
    """A subject past the cap must not evaluate as "no match" — that would
    let an attacker disarm a deny rule by padding the field. The condition
    raises, and the evaluator converts that into a deny."""
    cond = TrustCondition(field="agent.id", operator="matches", value=r"^[a-z]+$")
    assert cond.evaluate({"agent": {"id": "a" * 1024}}) is True
    with pytest.raises(ConditionEvaluationError):
        cond.evaluate({"agent": {"id": "a" * 1025}})

    policy = _make_policy(
        rules=[
            TrustRule(
                name="deny-bad-ids",
                condition=TrustCondition(field="agent.id", operator="matches", value=r"^evil-"),
                action="deny",
                priority=10,
            )
        ]
    )
    evaluator = PolicyEvaluator([policy])
    decision = evaluator.evaluate({"agent": {"id": "x" * 5000}})
    assert decision.allowed is False
    assert decision.action == "deny"
    assert "could not be evaluated safely" in decision.reason
