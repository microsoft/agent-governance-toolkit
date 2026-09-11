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
    rule = OrgPolicyRule(name="allow-safe-path", condition="action.path contains 'safe'", action="allow")
    assert rule.evaluate({"action": {"path": 123}}) is False


def test_empty_operand_does_not_match_every_string():
    rule = _rule("action.path contains ''")
    assert rule.evaluate({"action": {"path": "anything"}}) is False


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
