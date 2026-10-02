# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for OrgPolicyRule condition-expression parity.

``OrgPolicyRule.evaluate`` (federation.py) delegates to a standalone
``_eval_expression`` whose docstring claims parity with
``PolicyRule._eval_expression`` (policy.py), but it previously only
supported ``==`` and bare-boolean conditions — not even ``!=``, ``in``,
or numeric comparisons, let alone ``contains``/``startswith``/
``endswith``. A federation/org trust-agreement rule using any of these
operators would hit the same silent no-match fallthrough that
test_policy_rule_string_operators.py covers for the core PolicyRule.
"""

from unittest.mock import patch

from agentmesh.governance import federation
from agentmesh.governance.federation import OrgPolicyRule


def _rule(condition: str) -> OrgPolicyRule:
    return OrgPolicyRule(name="test-rule", condition=condition, action="deny")


def test_contains_matches_substring():
    rule = _rule("action.path contains '..'")
    assert rule.evaluate({"action": {"path": "../../etc/passwd"}}) is True
    assert rule.evaluate({"action": {"path": "/etc/passwd"}}) is False


def test_startswith_matches_prefix():
    rule = _rule("action.tool startswith 'delete_'")
    assert rule.evaluate({"action": {"tool": "delete_user"}}) is True
    assert rule.evaluate({"action": {"tool": "read_user"}}) is False


def test_endswith_matches_suffix():
    rule = _rule("resource.name endswith '.pem'")
    assert rule.evaluate({"resource": {"name": "server.pem"}}) is True
    assert rule.evaluate({"resource": {"name": "server.pem.bak"}}) is False


def test_inequality():
    rule = _rule("action.type != 'export'")
    assert rule.evaluate({"action": {"type": "import"}}) is True
    assert rule.evaluate({"action": {"type": "export"}}) is False


def test_membership():
    rule = _rule("user.role in ['admin', 'operator']")
    assert rule.evaluate({"user": {"role": "admin"}}) is True
    assert rule.evaluate({"user": {"role": "guest"}}) is False


def test_numeric_comparison():
    rule = _rule("action.cost > 100")
    assert rule.evaluate({"action": {"cost": 150}}) is True
    assert rule.evaluate({"action": {"cost": 50}}) is False


def test_string_operators_are_type_safe_against_non_string_values():
    """A non-string field must not raise, and must fail closed for a deny rule."""
    rule = _rule("action.path contains '..'")
    assert rule.evaluate({"action": {"path": 123}}) is True
    assert rule.evaluate({"action": {}}) is True


def test_string_operators_fail_open_for_allow_rules_on_non_string_values():
    rule = OrgPolicyRule(
        name="allow-safe-path", condition="action.path contains 'safe'", action="allow"
    )
    assert rule.evaluate({"action": {"path": 123}}) is False


def test_empty_operand_is_treated_as_a_malformed_condition(caplog):
    """An empty literal (`contains ''`) no longer parses as a real 'contains'
    check (which would match every string) -- it falls through to the
    unrecognized-syntax fallback, which fails closed for deny and open for
    allow.
    """
    deny_rule = _rule("action.path contains ''")
    with caplog.at_level("WARNING"):
        assert deny_rule.evaluate({"action": {"path": "anything"}}) is True
    assert "unrecognized condition syntax" in caplog.text

    allow_rule = OrgPolicyRule(
        name="allow-empty-path", condition="action.path contains ''", action="allow"
    )
    assert allow_rule.evaluate({"action": {"path": "anything"}}) is False


def test_inequality_absent_field_does_not_match_allow_rule():
    """A missing field is not evidence of inequality -- `!=` must not grant
    access on an allow rule just because the field was never set."""
    deny_rule = _rule("user.role != 'blocked'")
    assert deny_rule.evaluate({}) is True

    allow_rule = OrgPolicyRule(
        name="allow-not-blocked", condition="user.role != 'blocked'", action="allow"
    )
    assert allow_rule.evaluate({}) is False


def test_numeric_comparison_absent_field_does_not_match_allow_rule():
    """A missing numeric field must not be coerced to 0 -- `action.cost < 10`
    must not match an allow rule with no cost recorded."""
    deny_rule = _rule("action.cost < 10")
    assert deny_rule.evaluate({}) is True

    allow_rule = OrgPolicyRule(name="allow-cheap", condition="action.cost < 10", action="allow")
    assert allow_rule.evaluate({}) is False


def test_numeric_comparison_malformed_value_does_not_match_allow_rule():
    deny_rule = _rule("action.cost < 10")
    assert deny_rule.evaluate({"action": {"cost": "not-a-number"}}) is True

    allow_rule = OrgPolicyRule(name="allow-cheap", condition="action.cost < 10", action="allow")
    assert allow_rule.evaluate({"action": {"cost": "not-a-number"}}) is False


def test_string_operators_reject_trailing_garbage():
    """Malformed policy text must not be accepted as a valid operator prefix."""
    rule = OrgPolicyRule(
        name="allow-safe-path",
        condition="action.path contains 'safe' THIS_IS_NOT_VALID",
        action="allow",
    )
    assert rule.evaluate({"action": {"path": "safe/file"}}) is False


def test_trailing_whitespace_does_not_trigger_unrecognized_syntax():
    deny_rule = _rule("action.cost > 100 ")
    assert deny_rule.evaluate({"action": {"cost": 50}}) is False

    allow_rule = OrgPolicyRule(name="allow-cheap", condition="action.cost > 100\t", action="allow")
    assert allow_rule.evaluate({"action": {"cost": 150}}) is True


def test_equality_inequality_and_membership_reject_trailing_garbage():
    allow_eq = OrgPolicyRule(
        name="allow-eq", condition="action.path == 'safe/file' JUNK", action="allow"
    )
    assert allow_eq.evaluate({"action": {"path": "safe/file"}}) is False

    allow_neq = OrgPolicyRule(name="allow-neq", condition="action.path != 'x' JUNK", action="allow")
    assert allow_neq.evaluate({"action": {"path": "safe/file"}}) is False

    allow_in = OrgPolicyRule(
        name="allow-in", condition="action.path in ['safe/file'] JUNK", action="allow"
    )
    assert allow_in.evaluate({"action": {"path": "safe/file"}}) is False


def test_numeric_comparison_rejects_non_finite_values():
    deny_rule = _rule("action.cost > 100")
    assert deny_rule.evaluate({"action": {"cost": "NaN"}}) is True
    assert deny_rule.evaluate({"action": {"cost": "inf"}}) is True

    allow_rule = OrgPolicyRule(name="allow-cheap", condition="action.cost > 100", action="allow")
    assert allow_rule.evaluate({"action": {"cost": "NaN"}}) is False


def test_inequality_rejects_non_string_values():
    deny_rule = _rule("user.role != 'blocked'")
    assert deny_rule.evaluate({"user": {"role": []}}) is True

    allow_rule = OrgPolicyRule(
        name="allow-not-blocked", condition="user.role != 'blocked'", action="allow"
    )
    assert allow_rule.evaluate({"user": {"role": []}}) is False


def test_string_operators_require_matching_quote_delimiters():
    allow_contains = OrgPolicyRule(
        name="allow-safe-path", condition="action.path contains 'safe\"", action="allow"
    )
    assert allow_contains.evaluate({"action": {"path": "safe/file"}}) is False

    allow_startswith = OrgPolicyRule(
        name="allow-safe-path", condition="action.path startswith 'safe\"", action="allow"
    )
    assert allow_startswith.evaluate({"action": {"path": "safe/file"}}) is False

    allow_endswith = OrgPolicyRule(
        name="allow-safe-path", condition="action.path endswith 'file\"", action="allow"
    )
    assert allow_endswith.evaluate({"action": {"path": "safe/file"}}) is False

    allow_eq = OrgPolicyRule(
        name="allow-eq", condition="action.path == 'safe/file\"", action="allow"
    )
    assert allow_eq.evaluate({"action": {"path": "safe/file"}}) is False

    allow_neq = OrgPolicyRule(name="allow-neq", condition="action.path != 'zzz\"", action="allow")
    assert allow_neq.evaluate({"action": {"path": "safe/file"}}) is False


def test_string_operators_compose_with_and_or():
    rule = _rule("action.type == 'export' and resource.name endswith '.pem'")
    assert rule.evaluate({"action": {"type": "export"}, "resource": {"name": "id.pem"}}) is True
    assert rule.evaluate({"action": {"type": "export"}, "resource": {"name": "id.txt"}}) is False


def test_evaluation_error_fails_closed():
    """An exception mid-evaluation must MATCH (True), not silently pass through.

    Mirrors PolicyRule.evaluate's V27 fail-closed pattern: without this, an
    exception in a higher-priority deny/require_approval rule would let
    evaluation quietly fall through to a lower-priority rule or an allow
    default_action -- the same "rule never fires" failure mode this
    condition DSL exists to avoid, just triggered by an exception instead
    of an unrecognized operator.
    """
    rule = _rule("action.type == 'export'")
    with patch.object(federation, "_eval_expression", side_effect=RuntimeError("boom")):
        assert rule.evaluate({"action": {"type": "export"}}) is True


def test_evaluation_error_fails_open_for_allow_rules():
    """An exception in an allow rule must not grant access."""
    rule = OrgPolicyRule(name="allow-export", condition="action.type == 'export'", action="allow")
    with patch.object(federation, "_eval_expression", side_effect=RuntimeError("boom")):
        assert rule.evaluate({"action": {"type": "export"}}) is False


def test_excessive_depth_fails_closed_instead_of_recursing_unbounded():
    # A single `expr.split(" and ")` consumes every occurrence of the
    # delimiter at once, so a flat and-chain of any length only ever
    # recurses one level deep -- it can't organically reach the depth cap.
    # This exercises the guard itself directly instead.
    assert (
        federation._eval_expression(
            "action.type == 'export'",
            {"action": {"type": "export"}},
            _depth=federation._MAX_EXPRESSION_DEPTH + 1,
            action="deny",
        )
        is True
    )
    assert (
        federation._eval_expression(
            "action.type == 'export'",
            {"action": {"type": "export"}},
            _depth=federation._MAX_EXPRESSION_DEPTH + 1,
            action="allow",
        )
        is False
    )


def test_oversized_expression_is_rejected(caplog):
    condition = "action.type == '" + ("a" * 3000) + "'"
    rule = _rule(condition)
    with caplog.at_level("WARNING"):
        assert rule.evaluate({"action": {"type": "a" * 3000}}) is True
    assert "exceeds 2000-char limit" in caplog.text

    allow_rule = OrgPolicyRule(name="allow-oversized", condition=condition, action="allow")
    assert allow_rule.evaluate({"action": {"type": "a" * 3000}}) is False
