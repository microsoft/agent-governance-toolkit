# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Declarative policy schema for Agent-OS governance.

Defines PolicyDocument and related models that represent policies as
pure data (JSON/YAML) rather than coupling structure with evaluation logic.
"""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class PolicyOperator(str, Enum):
    """Comparison operators for policy conditions."""

    EQ = "eq"
    NE = "ne"
    GT = "gt"
    LT = "lt"
    GTE = "gte"
    LTE = "lte"
    IN = "in"
    MATCHES = "matches"
    CONTAINS = "contains"


class PolicyAction(str, Enum):
    """Actions a policy rule can prescribe."""

    ALLOW = "allow"
    DENY = "deny"
    AUDIT = "audit"
    BLOCK = "block"


class PolicyCondition(BaseModel):
    """A single condition evaluated against execution context."""

    field: str = Field(..., description="Context field, e.g. 'tool_name', 'token_count'")
    operator: PolicyOperator = Field(..., description="Comparison operator")
    value: Any = Field(..., description="Value to compare against")


class PolicyRule(BaseModel):
    """A single governance rule within a policy document."""

    name: str
    condition: PolicyCondition
    action: PolicyAction
    priority: int = Field(default=0, description="Higher priority rules are evaluated first")
    message: str = Field(default="", description="Human-readable explanation")


class PolicyDefaults(BaseModel):
    """Default settings applied when no rule matches."""

    action: PolicyAction = PolicyAction.ALLOW
    max_tokens: int = 4096
    max_tool_calls: int = 10
    confidence_threshold: float = 0.8


class PolicyDocument(BaseModel):
    """Top-level declarative policy document."""

    version: str = "1.0"
    name: str = "unnamed"
    description: str = ""
    rules: list[PolicyRule] = Field(default_factory=list)
    defaults: PolicyDefaults = Field(default_factory=PolicyDefaults)

    @classmethod
    def from_yaml(cls, path: str | Path) -> PolicyDocument:
        """Load a PolicyDocument from a YAML file."""
        try:
            import yaml
        except ImportError as exc:
            raise ImportError("pyyaml is required: pip install pyyaml") from exc

        path = Path(path)
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls.model_validate(data)

    def to_yaml(self, path: str | Path) -> None:
        """Serialize this PolicyDocument to a YAML file."""
        try:
            import yaml
        except ImportError as exc:
            raise ImportError("pyyaml is required: pip install pyyaml") from exc

        path = Path(path)
        with open(path, "w") as f:
            yaml.dump(self.model_dump(mode="json"), f, default_flow_style=False, sort_keys=False)

    @classmethod
    def from_json(cls, path: str | Path) -> PolicyDocument:
        """Load a PolicyDocument from a JSON file."""
        path = Path(path)
        with open(path) as f:
            data = json.load(f)
        return cls.model_validate(data)

    def to_json(self, path: str | Path) -> None:
        """Serialize this PolicyDocument to a JSON file."""
        path = Path(path)
        with open(path, "w") as f:
            json.dump(self.model_dump(mode="json"), f, indent=2)
