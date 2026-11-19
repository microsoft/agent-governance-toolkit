# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests: ``and``/``or`` inside a quoted literal are not operators.

``PolicyRule._eval_expression`` used to split a condition on every `` or ``
and `` and `` substring, including ones inside a quoted string literal, so
``tool.name == 'search and replace'`` was evaluated as two malformed halves.
``OrgPolicyRule`` (federation.py) had the same split. The .NET
``PolicyRule.SplitCompound`` and the TypeScript ``evaluateExpression``
(#2107) only split outside quotes.
"""

from agentmesh.governance.federation import OrgPolicyRule
from agentmesh.governance.policy import PolicyRule


def test_deny_rule_with_and_in_literal_only_matches_that_value():
    rule = PolicyRule(
        name="deny-search-replace", condition="tool.name == 'search and replace'", action="deny"
    )
    assert rule.evaluate({"tool": {"name": "search and replace"}}) is True
    assert rule.evaluate({"tool": {"name": "read_file"}}) is False


def test_allow_rule_with_or_in_literal_matches_that_value():
    rule = PolicyRule(
        name="allow-read-or-list", condition="tool.name == 'read or list'", action="allow"
    )
    assert rule.evaluate({"tool": {"name": "read or list"}}) is True


def test_compound_condition_with_and_in_literal():
    rule = PolicyRule(
        name="deny-file-and-process",
        condition="tool.name == 'file and process' and action.type != 'delete'",
        action="deny",
    )
    assert rule.evaluate({"tool": {"name": "file and process"}, "action": {"type": "read"}}) is True
    assert rule.evaluate({"tool": {"name": "other"}, "action": {"type": "read"}}) is False


def test_org_policy_rule_with_and_in_literal():
    rule = OrgPolicyRule(
        name="deny-search-replace", condition="tool.name == 'search and replace'", action="deny"
    )
    assert rule.evaluate({"tool": {"name": "search and replace"}}) is True
    assert rule.evaluate({"tool": {"name": "read_file"}}) is False


def test_or_outside_quotes_still_splits():
    rule = PolicyRule(
        name="deny-either",
        condition="tool.name == \"a or b\" or tool.name == 'c'",
        action="deny",
    )
    assert rule.evaluate({"tool": {"name": "a or b"}}) is True
    assert rule.evaluate({"tool": {"name": "c"}}) is True
    assert rule.evaluate({"tool": {"name": "a"}}) is False


def test_unbalanced_quote_fails_closed():
    condition = "tool.name == 'x or tool.name == 'read_file'"
    deny = PolicyRule(name="deny-unbalanced", condition=condition, action="deny")
    allow = PolicyRule(name="allow-unbalanced", condition=condition, action="allow")
    assert deny.evaluate({"tool": {"name": "read_file"}}) is True
    assert allow.evaluate({"tool": {"name": "read_file"}}) is False
