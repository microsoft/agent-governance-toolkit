# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for PolicyRule string-matching condition operators.

Before this fix, ``PolicyRule._eval_expression`` only recognized ``==``,
``!=``, ``in [...]``, numeric comparisons, and bare boolean-attribute
conditions. A condition written with ``contains``/``startswith``/
``endswith`` fell through every branch and silently returned ``False`` —
a no-match, not an evaluation error — so a ``deny`` rule using one of
these operators would never fire and no warning was raised anywhere.
"""

from agentmesh.governance.policy import PolicyRule


def test_contains_matches_substring():
    rule = PolicyRule(
        name="deny-path-traversal", condition="action.path contains '..'", action="deny"
    )
    assert rule.evaluate({"action": {"path": "../../etc/passwd"}}) is True


def test_contains_no_match_when_substring_absent():
    rule = PolicyRule(
        name="deny-path-traversal", condition="action.path contains '..'", action="deny"
    )
    assert rule.evaluate({"action": {"path": "/etc/passwd"}}) is False


def test_startswith_matches_prefix():
    rule = PolicyRule(
        name="deny-delete-tools", condition="action.tool startswith 'delete_'", action="deny"
    )
    assert rule.evaluate({"action": {"tool": "delete_user"}}) is True
    assert rule.evaluate({"action": {"tool": "read_user"}}) is False


def test_endswith_matches_suffix():
    rule = PolicyRule(
        name="deny-key-files", condition="resource.name endswith '.pem'", action="deny"
    )
    assert rule.evaluate({"resource": {"name": "server.pem"}}) is True
    assert rule.evaluate({"resource": {"name": "server.pem.bak"}}) is False


def test_string_operators_are_type_safe_against_non_string_values():
    """A non-string field must not raise, and must fail closed for a deny rule."""
    rule = PolicyRule(
        name="deny-path-traversal", condition="action.path contains '..'", action="deny"
    )
    assert rule.evaluate({"action": {"path": 123}}) is True
    assert rule.evaluate({"action": {}}) is True


def test_string_operators_fail_open_for_allow_rules_on_non_string_values():
    """An allow rule must not match on a non-string value — matching would grant access."""
    rule = PolicyRule(
        name="allow-safe-path", condition="action.path contains 'safe'", action="allow"
    )
    assert rule.evaluate({"action": {"path": 123}}) is False


def test_empty_operand_is_treated_as_a_malformed_condition(caplog):
    """An empty literal (`contains ''`) no longer parses as a real 'contains'
    check (which would match every string) -- it falls through to the
    unrecognized-syntax fallback, which fails closed for deny and open for
    allow.
    """
    deny_rule = PolicyRule(
        name="deny-empty-path", condition="action.path contains ''", action="deny"
    )
    with caplog.at_level("WARNING"):
        assert deny_rule.evaluate({"action": {"path": "anything"}}) is True
    assert "unrecognized condition syntax" in caplog.text

    allow_rule = PolicyRule(
        name="allow-empty-path", condition="action.path contains ''", action="allow"
    )
    assert allow_rule.evaluate({"action": {"path": "anything"}}) is False


def test_inequality_absent_field_does_not_match_allow_rule():
    """A missing field is not evidence of inequality -- `!=` must not grant
    access on an allow rule just because the field was never set."""
    deny_rule = PolicyRule(name="deny-blocked", condition="user.role != 'blocked'", action="deny")
    assert deny_rule.evaluate({}) is True

    allow_rule = PolicyRule(
        name="allow-not-blocked", condition="user.role != 'blocked'", action="allow"
    )
    assert allow_rule.evaluate({}) is False


def test_numeric_comparison_absent_field_does_not_match_allow_rule():
    """A missing numeric field must not be coerced to 0 -- `action.cost < 10`
    must not match an allow rule with no cost recorded."""
    deny_rule = PolicyRule(name="deny-cheap", condition="action.cost < 10", action="deny")
    assert deny_rule.evaluate({}) is True

    allow_rule = PolicyRule(name="allow-cheap", condition="action.cost < 10", action="allow")
    assert allow_rule.evaluate({}) is False


def test_numeric_comparison_malformed_value_does_not_match_allow_rule():
    deny_rule = PolicyRule(name="deny-cheap", condition="action.cost < 10", action="deny")
    assert deny_rule.evaluate({"action": {"cost": "not-a-number"}}) is True

    allow_rule = PolicyRule(name="allow-cheap", condition="action.cost < 10", action="allow")
    assert allow_rule.evaluate({"action": {"cost": "not-a-number"}}) is False


def test_string_operators_reject_trailing_garbage():
    """Malformed policy text must not be accepted as a valid operator prefix."""
    rule = PolicyRule(
        name="allow-safe-path",
        condition="action.path contains 'safe' THIS_IS_NOT_VALID",
        action="allow",
    )
    assert rule.evaluate({"action": {"path": "safe/file"}}) is False


def test_oversized_expression_fails_closed_for_deny_and_open_for_allow(caplog):
    condition = "action.type == '" + ("a" * 3000) + "'"
    rule = PolicyRule(name="deny-oversized", condition=condition, action="deny")
    with caplog.at_level("WARNING"):
        assert rule.evaluate({"action": {"type": "a" * 3000}}) is True
    assert "exceeds 2000-char limit" in caplog.text

    allow_rule = PolicyRule(name="allow-oversized", condition=condition, action="allow")
    assert allow_rule.evaluate({"action": {"type": "a" * 3000}}) is False


def test_trailing_whitespace_does_not_trigger_unrecognized_syntax():
    """Trailing whitespace must not push an otherwise-valid condition into
    the anchored regexes' unrecognized-syntax fallback."""
    deny_rule = PolicyRule(name="deny-cheap", condition="action.cost > 100 ", action="deny")
    assert deny_rule.evaluate({"action": {"cost": 50}}) is False

    allow_rule = PolicyRule(name="allow-cheap", condition="action.cost > 100\t", action="allow")
    assert allow_rule.evaluate({"action": {"cost": 150}}) is True


def test_equality_inequality_and_membership_reject_trailing_garbage():
    allow_eq = PolicyRule(
        name="allow-eq", condition="action.path == 'safe/file' JUNK", action="allow"
    )
    assert allow_eq.evaluate({"action": {"path": "safe/file"}}) is False

    allow_neq = PolicyRule(name="allow-neq", condition="action.path != 'x' JUNK", action="allow")
    assert allow_neq.evaluate({"action": {"path": "safe/file"}}) is False

    allow_in = PolicyRule(
        name="allow-in", condition="action.path in ['safe/file'] JUNK", action="allow"
    )
    assert allow_in.evaluate({"action": {"path": "safe/file"}}) is False


def test_numeric_comparison_rejects_non_finite_values():
    """NaN/inf parse as floats but every ordered comparison against them is
    False -- that must not silently fail open a deny rule."""
    deny_rule = PolicyRule(name="deny-cheap", condition="action.cost > 100", action="deny")
    assert deny_rule.evaluate({"action": {"cost": "NaN"}}) is True
    assert deny_rule.evaluate({"action": {"cost": "inf"}}) is True

    allow_rule = PolicyRule(name="allow-cheap", condition="action.cost > 100", action="allow")
    assert allow_rule.evaluate({"action": {"cost": "NaN"}}) is False


def test_inequality_rejects_non_string_values():
    """A non-string value always compares unequal to a string literal, which
    must not be treated as evidence of inequality."""
    deny_rule = PolicyRule(name="deny-blocked", condition="user.role != 'blocked'", action="deny")
    assert deny_rule.evaluate({"user": {"role": []}}) is True

    allow_rule = PolicyRule(
        name="allow-not-blocked", condition="user.role != 'blocked'", action="allow"
    )
    assert allow_rule.evaluate({"user": {"role": []}}) is False


def test_string_operators_require_matching_quote_delimiters():
    """A mismatched quote pair (opening `'`, closing `"`) is a malformed
    literal, not a valid operand."""
    allow_contains = PolicyRule(
        name="allow-safe-path", condition="action.path contains 'safe\"", action="allow"
    )
    assert allow_contains.evaluate({"action": {"path": "safe/file"}}) is False

    allow_startswith = PolicyRule(
        name="allow-safe-path", condition="action.path startswith 'safe\"", action="allow"
    )
    assert allow_startswith.evaluate({"action": {"path": "safe/file"}}) is False

    allow_endswith = PolicyRule(
        name="allow-safe-path", condition="action.path endswith 'file\"", action="allow"
    )
    assert allow_endswith.evaluate({"action": {"path": "safe/file"}}) is False

    allow_eq = PolicyRule(name="allow-eq", condition="action.path == 'safe/file\"", action="allow")
    assert allow_eq.evaluate({"action": {"path": "safe/file"}}) is False

    allow_neq = PolicyRule(name="allow-neq", condition="action.path != 'zzz\"", action="allow")
    assert allow_neq.evaluate({"action": {"path": "safe/file"}}) is False


def test_string_operators_compose_with_and_or():
    rule = PolicyRule(
        name="deny-sensitive-export",
        condition="action.type == 'export' and resource.name endswith '.pem'",
        action="deny",
    )
    assert rule.evaluate({"action": {"type": "export"}, "resource": {"name": "id.pem"}}) is True
    assert rule.evaluate({"action": {"type": "export"}, "resource": {"name": "id.txt"}}) is False
