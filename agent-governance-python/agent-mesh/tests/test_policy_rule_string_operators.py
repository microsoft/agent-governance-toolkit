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
    rule = PolicyRule(name="deny-path-traversal", condition="action.path contains '..'", action="deny")
    assert rule.evaluate({"action": {"path": "../../etc/passwd"}}) is True


def test_contains_no_match_when_substring_absent():
    rule = PolicyRule(name="deny-path-traversal", condition="action.path contains '..'", action="deny")
    assert rule.evaluate({"action": {"path": "/etc/passwd"}}) is False


def test_startswith_matches_prefix():
    rule = PolicyRule(name="deny-delete-tools", condition="action.tool startswith 'delete_'", action="deny")
    assert rule.evaluate({"action": {"tool": "delete_user"}}) is True
    assert rule.evaluate({"action": {"tool": "read_user"}}) is False


def test_endswith_matches_suffix():
    rule = PolicyRule(name="deny-key-files", condition="resource.name endswith '.pem'", action="deny")
    assert rule.evaluate({"resource": {"name": "server.pem"}}) is True
    assert rule.evaluate({"resource": {"name": "server.pem.bak"}}) is False


def test_string_operators_are_type_safe_against_non_string_values():
    """A non-string field must not raise, and must fail closed for a deny rule."""
    rule = PolicyRule(name="deny-path-traversal", condition="action.path contains '..'", action="deny")
    assert rule.evaluate({"action": {"path": 123}}) is True
    assert rule.evaluate({"action": {}}) is True


def test_string_operators_fail_open_for_allow_rules_on_non_string_values():
    """An allow rule must not match on a non-string value — matching would grant access."""
    rule = PolicyRule(name="allow-safe-path", condition="action.path contains 'safe'", action="allow")
    assert rule.evaluate({"action": {"path": 123}}) is False


def test_empty_operand_does_not_match_every_string():
    """An empty literal (`contains ''`) must not match unconditionally."""
    rule = PolicyRule(name="deny-empty-path", condition="action.path contains ''", action="deny")
    assert rule.evaluate({"action": {"path": "anything"}}) is False


def test_oversized_expression_fails_closed_for_deny_and_open_for_allow(caplog):
    condition = "action.type == '" + ("a" * 3000) + "'"
    rule = PolicyRule(name="deny-oversized", condition=condition, action="deny")
    with caplog.at_level("WARNING"):
        assert rule.evaluate({"action": {"type": "a" * 3000}}) is True
    assert "exceeds 2000-char limit" in caplog.text

    allow_rule = PolicyRule(name="allow-oversized", condition=condition, action="allow")
    assert allow_rule.evaluate({"action": {"type": "a" * 3000}}) is False


def test_string_operators_compose_with_and_or():
    rule = PolicyRule(
        name="deny-sensitive-export",
        condition="action.type == 'export' and resource.name endswith '.pem'",
        action="deny",
    )
    assert rule.evaluate({"action": {"type": "export"}, "resource": {"name": "id.pem"}}) is True
    assert rule.evaluate({"action": {"type": "export"}, "resource": {"name": "id.txt"}}) is False
