# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Folder-level governance policy merge.

Merges a chain of PolicyDocuments (root-first order) into a single
flat rule list, respecting override semantics and the security
invariant that parent deny rules cannot be overridden.
"""

from __future__ import annotations

import logging

from agent_os.policies.schema import PolicyAction, PolicyDocument, PolicyRule

logger = logging.getLogger(__name__)


def merge_policies(policy_chain: list[PolicyDocument]) -> list[PolicyRule]:
    """Merge a chain of PolicyDocuments into a flat, priority-sorted rule list.

    Rules from all levels are collected. A child rule with
    ``override=True`` and the same ``name`` as a parent rule replaces
    the parent rule — **unless** the parent rule is a ``deny``, which
    is immutable (security invariant matching Azure Policy semantics).

    Args:
        policy_chain: PolicyDocuments in root-first order
            (root at index 0, most specific last).

    Returns:
        Flat list of PolicyRules sorted by priority descending.
    """
    if not policy_chain:
        return []

    # Single policy — fast path
    if len(policy_chain) == 1:
        rules = list(policy_chain[0].rules)
        rules.sort(key=lambda r: r.priority, reverse=True)
        return rules

    # Track rules by name for override detection
    rules_by_name: dict[str, tuple[PolicyRule, int]] = {}
    merged: list[PolicyRule] = []

    for level, doc in enumerate(policy_chain):
        for rule in doc.rules:
            existing = rules_by_name.get(rule.name)

            if existing is not None and rule.override:
                parent_rule, _parent_level = existing

                if parent_rule.action == PolicyAction.DENY:
                    # Security invariant: parent deny cannot be overridden
                    logger.warning(
                        "Rule '%s' at level %d tried to override parent deny — ignored",
                        rule.name,
                        level,
                    )
                    merged.append(rule)
                else:
                    # Replace parent rule
                    merged = [r for r in merged if r.name != rule.name]
                    merged.append(rule)
                    rules_by_name[rule.name] = (rule, level)
                    logger.debug(
                        "Rule '%s' at level %d overrides parent rule",
                        rule.name,
                        level,
                    )
            else:
                merged.append(rule)
                if rule.name not in rules_by_name:
                    rules_by_name[rule.name] = (rule, level)

    merged.sort(key=lambda r: r.priority, reverse=True)
    return merged


def get_effective_defaults(policy_chain: list[PolicyDocument]) -> PolicyDocument:
    """Get the effective defaults from the most specific policy in the chain.

    The most specific (last) policy's defaults take precedence. If it
    doesn't define custom defaults, the parent's defaults are used.

    Args:
        policy_chain: PolicyDocuments in root-first order.

    Returns:
        The PolicyDocument whose defaults should be used.
    """
    if not policy_chain:
        return PolicyDocument()
    return policy_chain[-1]
