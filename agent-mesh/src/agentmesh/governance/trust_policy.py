# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Trust Policy DSL

Declarative trust policy definitions with rule-based evaluation,
priority ordering, and YAML configuration support.
"""

import re
from enum import Enum
from pathlib import Path
from typing import Any, Literal, Optional

import yaml
from pydantic import BaseModel, Field


class ConditionOperator(str, Enum):
    """Supported condition operators for trust rules."""

    eq = "eq"
    ne = "ne"
    gt = "gt"
    gte = "gte"
    lt = "lt"
    lte = "lte"
    in_ = "in"
    not_in = "not_in"
    matches = "matches"


class TrustCondition(BaseModel):
    """A single condition in a trust rule.

    Attributes:
        field: Dot-notated path to a context value
            (e.g. ``"trust_score"``, ``"agent.namespace"``).
        operator: Comparison operator to apply.
        value: Expected value to compare against.
    """

    field: str = Field(..., description="Dot-notated field path (e.g. 'trust_score', 'agent.namespace')")
    operator: ConditionOperator = Field(..., description="Comparison operator")
    value: Any = Field(..., description="Value to compare against")

    def evaluate(self, context: dict) -> bool:
        """Evaluate this condition against a context dictionary.

        Args:
            context: Runtime context with values accessible via
                dot-notated field paths.

        Returns:
            ``True`` if the condition is satisfied.
        """
        actual = self._resolve_field(context, self.field)
        return self._apply_operator(actual, self.operator, self.value)

    @staticmethod
    def _resolve_field(context: dict, field: str) -> Any:
        """Resolve a dot-notated field path against a context dict."""
        parts = field.split(".")
        current: Any = context
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current

    @staticmethod
    def _apply_operator(actual: Any, operator: ConditionOperator, expected: Any) -> bool:
        """Apply a comparison operator."""
        if actual is None:
            return False

        if operator == ConditionOperator.eq:
            return actual == expected
        elif operator == ConditionOperator.ne:
            return actual != expected
        elif operator == ConditionOperator.gt:
            return actual > expected
        elif operator == ConditionOperator.gte:
            return actual >= expected
        elif operator == ConditionOperator.lt:
            return actual < expected
        elif operator == ConditionOperator.lte:
            return actual <= expected
        elif operator == ConditionOperator.in_:
            return actual in expected
        elif operator == ConditionOperator.not_in:
            return actual not in expected
        elif operator == ConditionOperator.matches:
            pattern = str(expected)
            # V31: Reject overly complex regex patterns to prevent ReDoS
            if len(pattern) > 200 or any(c in pattern for c in ['{', '(+', '(.*)*', '(.+)+']):
                return False
            try:
                return bool(re.search(pattern, str(actual), flags=re.DOTALL))
            except re.error:
                return False
        return False


class TrustRule(BaseModel):
    """A single trust policy rule with condition, action, and priority.

    Attributes:
        name: Unique rule name.
        description: Human-readable description of what the rule does.
        condition: The ``TrustCondition`` to evaluate.
        action: Action to take when the condition matches
            (allow, deny, warn, or require_approval).
        priority: Evaluation priority (lower number = higher priority).
    """

    name: str = Field(..., description="Rule name")
    description: Optional[str] = Field(None, description="Human-readable description")
    condition: TrustCondition = Field(..., description="Condition to evaluate")
    action: Literal["allow", "deny", "warn", "require_approval"] = Field(
        default="deny", description="Action when condition matches"
    )
    priority: int = Field(default=100, description="Priority (lower number = higher priority)")


class TrustDefaults(BaseModel):
    """Default trust policy parameters applied when no rule matches."""

    min_trust_score: int = Field(default=500, description="Minimum trust score required")
    max_delegation_depth: int = Field(default=3, description="Maximum scope chain depth")
    allowed_namespaces: list[str] = Field(
        default_factory=lambda: ["*"], description="Allowed agent namespaces"
    )
    require_handshake: bool = Field(default=True, description="Require trust handshake")


class TrustPolicy(BaseModel):
    """
    A declarative trust policy with rules and defaults.

    Policies can be loaded from and saved to YAML files for easy configuration.
    """

    name: str = Field(..., description="Policy name")
    version: str = Field(default="1.0", description="Policy version")
    description: Optional[str] = Field(None, description="Policy description")
    rules: list[TrustRule] = Field(default_factory=list, description="Ordered list of trust rules")
    defaults: TrustDefaults = Field(
        default_factory=TrustDefaults, description="Default trust parameters"
    )

    @classmethod
    def from_yaml(cls, path: str | Path) -> "TrustPolicy":
        """Load a TrustPolicy from a YAML file.

        Args:
            path: Path to the YAML policy file.

        Returns:
            A fully-constructed ``TrustPolicy`` instance.
        """
        path = Path(path)
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        return cls(**data)

    def to_yaml(self, path: str | Path) -> None:
        """Save this TrustPolicy to a YAML file.

        Args:
            path: Destination file path.
        """
        path = Path(path)
        data = self.model_dump(mode="json")
        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)


def load_policies(directory: str | Path) -> list[TrustPolicy]:
    """Load all YAML trust policies from a directory.

    Scans for ``*.yaml`` and ``*.yml`` files in sorted order.

    Args:
        directory: Path to the directory containing policy files.

    Returns:
        List of ``TrustPolicy`` instances loaded from the directory.
    """
    directory = Path(directory)
    policies: list[TrustPolicy] = []
    for yaml_file in sorted(directory.glob("*.yaml")):
        policies.append(TrustPolicy.from_yaml(yaml_file))
    for yml_file in sorted(directory.glob("*.yml")):
        policies.append(TrustPolicy.from_yaml(yml_file))
    return policies
