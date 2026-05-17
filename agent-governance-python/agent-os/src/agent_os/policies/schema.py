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
from typing import Any, Literal

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
    override: bool = Field(
        default=False,
        description="If true, replaces a parent rule with the same name during folder-level merge",
    )


class PolicyDefaults(BaseModel):
    """Default settings applied when no rule matches.

    The first four fields are language/runtime budgets evaluated by the
    rule engine. The remaining fields are **sandbox resource constraints**
    consumed by sandbox providers (Azure, Docker, Hyperlight) and are
    ignored by the rule engine itself.
    """

    action: PolicyAction = PolicyAction.ALLOW
    max_tokens: int = 4096
    max_tool_calls: int = 10
    confidence_threshold: float = 0.8

    # ---- Sandbox resource constraints (provider-consumed) -------------
    max_cpu: float | None = Field(
        default=None,
        description="Sandbox CPU limit in vCPUs (e.g. 0.5, 1.0). None = provider default.",
    )
    max_memory_mb: int | None = Field(
        default=None,
        description="Sandbox memory limit in MiB. None = provider default.",
    )
    timeout_seconds: int | None = Field(
        default=None,
        description="Per-execute_code wall-clock cap. None = provider default.",
    )
    network_default: Literal["allow", "deny"] = Field(
        default="deny",
        description=(
            "Default sandbox egress action when a host is not on "
            "network_allowlist. 'deny' is fail-closed and is the default. "
            "Set to 'allow' only for trusted dev/research workloads."
        ),
    )


class PolicyDocument(BaseModel):
    """Top-level declarative policy document."""

    version: str = "1.0"
    name: str = "unnamed"
    description: str = ""
    rules: list[PolicyRule] = Field(default_factory=list)
    defaults: PolicyDefaults = Field(default_factory=PolicyDefaults)
    inherit: bool = Field(
        default=True,
        description="If false, parent governance.yaml files are not loaded (stops inheritance)",
    )
    scope: str | None = Field(
        default=None,
        description="Glob pattern — policy only applies when action path matches",
    )

    # ---- Sandbox extension fields (provider-consumed) -----------------
    # Read by ACASandboxProvider / DockerSandboxProvider / etc.; the
    # rule engine itself ignores them. Defined natively here so callers
    # do not need SimpleNamespace wrappers.
    network_allowlist: list[str] = Field(
        default_factory=list,
        description=(
            "Host patterns the sandbox may reach (e.g. 'pypi.org', "
            "'*.github.com'). Combined with defaults.network_default to "
            "form the sandbox egress policy."
        ),
    )
    tool_allowlist: list[str] = Field(
        default_factory=list,
        description=(
            "Tool names the agent may invoke. Enforced host-side by the "
            "PolicyEvaluator before any sandbox call."
        ),
    )

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
