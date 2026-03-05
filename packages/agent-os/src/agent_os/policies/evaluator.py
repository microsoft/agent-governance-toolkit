# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Standalone policy evaluator for Agent-OS governance.

Evaluates declarative PolicyDocuments against an execution context dict,
returning a PolicyDecision with matched rule, action, and audit information.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .schema import PolicyAction, PolicyDocument, PolicyOperator, PolicyRule

logger = logging.getLogger(__name__)


class PolicyDecision(BaseModel):
    """Result of evaluating policies against an execution context."""

    allowed: bool = True
    matched_rule: str | None = None
    action: str = "allow"
    reason: str = "No rules matched; default action applied"
    audit_entry: dict[str, Any] = Field(default_factory=dict)


class PolicyEvaluator:
    """Evaluates a set of PolicyDocuments against execution contexts."""

    def __init__(self, policies: list[PolicyDocument] | None = None) -> None:
        self.policies: list[PolicyDocument] = policies or []

    def load_policies(self, directory: str | Path) -> None:
        """Load all YAML policy files from a directory."""
        directory = Path(directory)
        for path in sorted(directory.glob("*.yaml")):
            self.policies.append(PolicyDocument.from_yaml(path))
        for path in sorted(directory.glob("*.yml")):
            self.policies.append(PolicyDocument.from_yaml(path))

    def evaluate(self, context: dict[str, Any]) -> PolicyDecision:
        """Evaluate all loaded policy rules against the given context.

        Rules are sorted by priority (descending). The first matching rule
        determines the decision. If no rule matches, the default action from
        the first policy (or global allow) is used.
        """
        try:
            all_rules: list[tuple[PolicyRule, PolicyDocument]] = []
            for doc in self.policies:
                for rule in doc.rules:
                    all_rules.append((rule, doc))

            # Sort by priority descending so highest priority is checked first
            all_rules.sort(key=lambda pair: pair[0].priority, reverse=True)

            for rule, doc in all_rules:
                if _match_condition(rule.condition, context):
                    allowed = rule.action in (PolicyAction.ALLOW, PolicyAction.AUDIT)
                    return PolicyDecision(
                        allowed=allowed,
                        matched_rule=rule.name,
                        action=rule.action.value,
                        reason=rule.message or f"Matched rule '{rule.name}'",
                        audit_entry={
                            "policy": doc.name,
                            "rule": rule.name,
                            "action": rule.action.value,
                            "context_snapshot": context,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        },
                    )

            # No rule matched — apply defaults
            default_action = PolicyAction.ALLOW
            if self.policies:
                default_action = self.policies[0].defaults.action
            allowed = default_action in (PolicyAction.ALLOW, PolicyAction.AUDIT)
            return PolicyDecision(
                allowed=allowed,
                action=default_action.value,
                reason="No rules matched; default action applied",
                audit_entry={
                    "policy": self.policies[0].name if self.policies else None,
                    "rule": None,
                    "action": default_action.value,
                    "context_snapshot": context,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            )
        except Exception:
            logger.error(
                "Policy evaluation error — denying access (fail closed)",
                exc_info=True,
            )
            return PolicyDecision(
                allowed=False,
                action="deny",
                reason="Policy evaluation error — access denied (fail closed)",
                audit_entry={
                    "policy": None,
                    "rule": None,
                    "action": "deny",
                    "context_snapshot": context,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "error": True,
                },
            )


def _match_condition(condition: Any, context: dict[str, Any]) -> bool:
    """Check whether a single PolicyCondition matches the context."""
    ctx_value = context.get(condition.field)
    if ctx_value is None:
        return False

    op = condition.operator
    target = condition.value

    if op == PolicyOperator.EQ:
        return ctx_value == target
    if op == PolicyOperator.NE:
        return ctx_value != target
    if op == PolicyOperator.GT:
        return ctx_value > target
    if op == PolicyOperator.LT:
        return ctx_value < target
    if op == PolicyOperator.GTE:
        return ctx_value >= target
    if op == PolicyOperator.LTE:
        return ctx_value <= target
    if op == PolicyOperator.IN:
        return ctx_value in target
    if op == PolicyOperator.CONTAINS:
        return target in ctx_value
    if op == PolicyOperator.MATCHES:
        return bool(re.search(str(target), str(ctx_value)))

    return False
