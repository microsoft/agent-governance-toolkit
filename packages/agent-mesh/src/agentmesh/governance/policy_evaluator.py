# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Trust Policy Evaluator

Evaluates trust policies against a context dictionary.
Rules are evaluated in priority order (lower number = higher priority).
First matching rule wins. Falls back to defaults if no rule matches.
"""

from pydantic import BaseModel, Field
from typing import Optional

from .trust_policy import TrustPolicy


class TrustPolicyDecision(BaseModel):
    """Result of trust policy evaluation.

    Attributes:
        allowed: Whether the action is permitted.
        rule_name: Name of the matched rule, or ``None`` if defaults applied.
        action: Action taken (allow, deny, warn, or require_approval).
        reason: Human-readable explanation of the decision.
    """

    allowed: bool = Field(..., description="Whether the action is allowed")
    rule_name: Optional[str] = Field(None, description="Name of the matched rule, if any")
    action: str = Field(..., description="Action taken (allow/deny/warn/require_approval)")
    reason: str = Field(..., description="Human-readable explanation")


class PolicyEvaluator:
    """
    Evaluates trust policies against a context.

    Rules across all loaded policies are merged and sorted by priority
    (lower number = higher priority). The first matching rule wins.
    If no rule matches, defaults from the first policy are applied
    against the context.
    """

    def __init__(self, policies: list[TrustPolicy]) -> None:
        """Initialise the evaluator with a list of trust policies.

        Args:
            policies: Trust policies whose rules will be merged and
                evaluated in priority order.
        """
        self._policies = list(policies)

    def evaluate(self, context: dict) -> TrustPolicyDecision:
        """Evaluate all trust rules against the context.

        Rules across all loaded policies are sorted by priority
        (lower number = higher priority). The first matching rule
        wins. If no rule matches, default trust parameters are applied.

        Args:
            context: Runtime context dictionary containing fields such
                as ``trust_score``, ``delegation_depth``, and ``agent``.

        Returns:
            A ``TrustPolicyDecision`` indicating the outcome.
        """
        # Collect and sort all rules by priority (lower = higher priority)
        all_rules = []
        for policy in self._policies:
            for rule in policy.rules:
                all_rules.append((policy, rule))
        all_rules.sort(key=lambda pr: pr[1].priority)

        # Evaluate in priority order; first match wins
        for policy, rule in all_rules:
            if rule.condition.evaluate(context):
                allowed = rule.action == "allow"
                return TrustPolicyDecision(
                    allowed=allowed,
                    rule_name=rule.name,
                    action=rule.action,
                    reason=(
                        f"Rule '{rule.name}' matched in policy '{policy.name}': "
                        f"{rule.description or rule.action}"
                    ),
                )

        # No rule matched — apply defaults from first policy (or sensible fallback)
        if self._policies:
            defaults = self._policies[0].defaults
        else:
            return TrustPolicyDecision(
                allowed=True,
                rule_name=None,
                action="allow",
                reason="No policies loaded; default allow",
            )

        return self._apply_defaults(defaults, context)

    @staticmethod
    def _apply_defaults(defaults, context: dict) -> TrustPolicyDecision:
        """Apply default trust parameters against context."""
        trust_score = context.get("trust_score")
        if trust_score is not None and trust_score < defaults.min_trust_score:
            return TrustPolicyDecision(
                allowed=False,
                rule_name=None,
                action="deny",
                reason=(
                    f"Trust score {trust_score} below minimum {defaults.min_trust_score}"
                ),
            )

        delegation_depth = context.get("delegation_depth")
        if delegation_depth is not None and delegation_depth > defaults.max_delegation_depth:
            return TrustPolicyDecision(
                allowed=False,
                rule_name=None,
                action="deny",
                reason=(
                    f"Delegation depth {delegation_depth} exceeds maximum "
                    f"{defaults.max_delegation_depth}"
                ),
            )

        namespace = context.get("agent", {}).get("namespace") if isinstance(
            context.get("agent"), dict
        ) else context.get("agent_namespace")
        if namespace and "*" not in defaults.allowed_namespaces:
            if namespace not in defaults.allowed_namespaces:
                return TrustPolicyDecision(
                    allowed=False,
                    rule_name=None,
                    action="deny",
                    reason=f"Namespace '{namespace}' not in allowed namespaces",
                )

        return TrustPolicyDecision(
            allowed=True,
            rule_name=None,
            action="allow",
            reason="No rules matched; defaults passed",
        )
