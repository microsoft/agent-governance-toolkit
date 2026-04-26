# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Cross-project shared policy language for Agent-OS and Agent-Mesh.

Provides a unified governance schema (SharedPolicySchema) with rules,
conditions, and an evaluator that works across both projects. Includes
YAML serialization and a bridge to the existing PolicyDocument format.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .schema import (
    PolicyAction,
    PolicyCondition,
    PolicyDocument,
    PolicyOperator,
    PolicyRule,
)

# ---------------------------------------------------------------------------
# Enums / literals kept as plain strings for cross-project portability
# ---------------------------------------------------------------------------

VALID_SCOPES = ("agent", "tool", "flow", "mesh")
VALID_ACTIONS = ("allow", "deny", "audit", "escalate", "rate_limit")
VALID_OPERATORS = ("eq", "ne", "in", "not_in", "gt", "lt", "matches")


# ---------------------------------------------------------------------------
# Core dataclasses
# ---------------------------------------------------------------------------


@dataclass
class Condition:
    """A single predicate evaluated against an execution context."""

    field: str
    operator: str
    value: Any

    def __post_init__(self) -> None:
        if self.operator not in VALID_OPERATORS:
            raise ValueError(
                f"Invalid operator '{self.operator}', must be one of {VALID_OPERATORS}"
            )


@dataclass
class SharedPolicyRule:
    """A single governance rule within a shared policy."""

    id: str
    action: str
    conditions: list[Condition] = field(default_factory=list)
    priority: int = 0

    def __post_init__(self) -> None:
        if self.action not in VALID_ACTIONS:
            raise ValueError(
                f"Invalid action '{self.action}', must be one of {VALID_ACTIONS}"
            )


# ---------------------------------------------------------------------------
# Schema model (Pydantic for validation & serialization)
# ---------------------------------------------------------------------------


class SharedPolicySchema(BaseModel):
    """Unified policy schema that works across Agent-OS and Agent-Mesh."""

    version: str = "1.0"
    name: str
    description: str = ""
    scope: str
    rules: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        if self.scope not in VALID_SCOPES:
            raise ValueError(
                f"Invalid scope '{self.scope}', must be one of {VALID_SCOPES}"
            )

    def parsed_rules(self) -> list[SharedPolicyRule]:
        """Deserialize raw rule dicts into SharedPolicyRule objects."""
        result: list[SharedPolicyRule] = []
        for raw in self.rules:
            conditions = [
                Condition(field=c["field"], operator=c["operator"], value=c["value"])
                for c in raw.get("conditions", [])
            ]
            result.append(
                SharedPolicyRule(
                    id=raw["id"],
                    action=raw["action"],
                    conditions=conditions,
                    priority=raw.get("priority", 0),
                )
            )
        return result

    # -- YAML I/O ----------------------------------------------------------

    @classmethod
    def from_yaml(cls, path: str | Path) -> SharedPolicySchema:
        """Load a SharedPolicySchema from a YAML file."""
        try:
            import yaml
        except ImportError as exc:
            raise ImportError("pyyaml is required: pip install pyyaml") from exc

        path = Path(path)
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls.model_validate(data)

    def to_yaml(self, path: str | Path) -> None:
        """Serialize this SharedPolicySchema to a YAML file."""
        try:
            import yaml
        except ImportError as exc:
            raise ImportError("pyyaml is required: pip install pyyaml") from exc

        path = Path(path)
        with open(path, "w") as f:
            yaml.dump(
                self.model_dump(mode="json"),
                f,
                default_flow_style=False,
                sort_keys=False,
            )


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------


@dataclass
class SharedPolicyDecision:
    """Result of evaluating shared policy rules against a context."""

    allowed: bool = True
    action: str = "allow"
    matched_rule_id: str | None = None
    reason: str = "No rules matched; default allow"
    audit: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------


class SharedPolicyEvaluator:
    """Evaluates SharedPolicyRules against an execution context dict."""

    def evaluate(
        self,
        context: dict[str, Any],
        rules: list[SharedPolicyRule],
    ) -> SharedPolicyDecision:
        """Evaluate *rules* against *context*, returning a decision.

        Rules are sorted by priority descending. The first rule whose
        **all** conditions match determines the outcome.
        """
        sorted_rules = sorted(rules, key=lambda r: r.priority, reverse=True)

        for rule in sorted_rules:
            if all(_eval_condition(c, context) for c in rule.conditions):
                allowed = rule.action in ("allow", "audit")
                return SharedPolicyDecision(
                    allowed=allowed,
                    action=rule.action,
                    matched_rule_id=rule.id,
                    reason=f"Matched rule '{rule.id}'",
                    audit={
                        "rule_id": rule.id,
                        "action": rule.action,
                        "context_snapshot": context,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                )

        return SharedPolicyDecision()


def _eval_condition(condition: Condition, context: dict[str, Any]) -> bool:
    """Evaluate a single Condition against the context."""
    ctx_value = context.get(condition.field)
    if ctx_value is None:
        return False

    op = condition.operator
    target = condition.value

    if op == "eq":
        return ctx_value == target  # type: ignore[no-any-return]
    if op == "ne":
        return ctx_value != target  # type: ignore[no-any-return]
    if op == "gt":
        return ctx_value > target  # type: ignore[no-any-return]
    if op == "lt":
        return ctx_value < target  # type: ignore[no-any-return]
    if op == "in":
        return ctx_value in target  # type: ignore[no-any-return]
    if op == "not_in":
        return ctx_value not in target  # type: ignore[no-any-return]
    if op == "matches":
        return bool(re.search(str(target), str(ctx_value)))

    return False


# ---------------------------------------------------------------------------
# Bridge helpers — SharedPolicySchema <-> PolicyDocument
# ---------------------------------------------------------------------------

_ACTION_MAP_TO_POLICY: dict[str, PolicyAction] = {
    "allow": PolicyAction.ALLOW,
    "deny": PolicyAction.DENY,
    "audit": PolicyAction.AUDIT,
    "escalate": PolicyAction.BLOCK,
    "rate_limit": PolicyAction.BLOCK,
}

_OPERATOR_MAP_TO_POLICY: dict[str, PolicyOperator] = {
    "eq": PolicyOperator.EQ,
    "ne": PolicyOperator.NE,
    "gt": PolicyOperator.GT,
    "lt": PolicyOperator.LT,
    "in": PolicyOperator.IN,
    "not_in": PolicyOperator.NE,
    "matches": PolicyOperator.MATCHES,
}

_ACTION_MAP_FROM_POLICY: dict[PolicyAction, str] = {
    PolicyAction.ALLOW: "allow",
    PolicyAction.DENY: "deny",
    PolicyAction.AUDIT: "audit",
    PolicyAction.BLOCK: "deny",
}

_OPERATOR_MAP_FROM_POLICY: dict[PolicyOperator, str] = {
    PolicyOperator.EQ: "eq",
    PolicyOperator.NE: "ne",
    PolicyOperator.GT: "gt",
    PolicyOperator.LT: "lt",
    PolicyOperator.GTE: "gt",
    PolicyOperator.LTE: "lt",
    PolicyOperator.IN: "in",
    PolicyOperator.CONTAINS: "matches",
    PolicyOperator.MATCHES: "matches",
}


def shared_to_policy_document(schema: SharedPolicySchema) -> PolicyDocument:
    """Convert a SharedPolicySchema into the existing PolicyDocument format."""
    doc_rules: list[PolicyRule] = []
    for rule in schema.parsed_rules():
        if not rule.conditions:
            continue
        first_cond = rule.conditions[0]
        doc_rules.append(
            PolicyRule(
                name=rule.id,
                condition=PolicyCondition(
                    field=first_cond.field,
                    operator=_OPERATOR_MAP_TO_POLICY.get(
                        first_cond.operator, PolicyOperator.EQ
                    ),
                    value=first_cond.value,
                ),
                action=_ACTION_MAP_TO_POLICY.get(rule.action, PolicyAction.DENY),
                priority=rule.priority,
                message=f"Converted from shared rule '{rule.id}'",
            )
        )

    return PolicyDocument(
        version=schema.version,
        name=schema.name,
        description=schema.description,
        rules=doc_rules,
    )


def policy_document_to_shared(
    doc: PolicyDocument,
    scope: str = "agent",
) -> SharedPolicySchema:
    """Convert an existing PolicyDocument into a SharedPolicySchema."""
    raw_rules: list[dict[str, Any]] = []
    for rule in doc.rules:
        cond = rule.condition
        raw_rules.append(
            {
                "id": rule.name,
                "action": _ACTION_MAP_FROM_POLICY.get(rule.action, "deny"),
                "priority": rule.priority,
                "conditions": [
                    {
                        "field": cond.field,
                        "operator": _OPERATOR_MAP_FROM_POLICY.get(
                            cond.operator, "eq"
                        ),
                        "value": cond.value,
                    }
                ],
            }
        )

    return SharedPolicySchema(
        version=doc.version,
        name=doc.name,
        description=doc.description,
        scope=scope,
        rules=raw_rules,
    )
