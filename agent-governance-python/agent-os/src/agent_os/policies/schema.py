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

from pydantic import BaseModel, Field, model_validator


class PolicyOperator(str, Enum):
    """Comparison operators for policy conditions."""

    EQ = "eq"
    NE = "ne"
    GT = "gt"
    LT = "lt"
    GTE = "gte"
    LTE = "lte"
    IN = "in"
    NOT_IN = "not_in"
    MATCHES = "matches"
    CONTAINS = "contains"


class PolicyAction(str, Enum):
    """Actions a policy rule can prescribe."""

    ALLOW = "allow"
    DENY = "deny"
    AUDIT = "audit"
    BLOCK = "block"


class DynamicConditionType(str, Enum):
    """Supported dynamic condition types for v1."""

    TIME_WINDOW = "time_window"
    DAY_OF_WEEK = "day_of_week"
    TOKEN_COUNT_PER_WINDOW = "token_count_per_window"
    COST_PER_WINDOW = "cost_per_window"


class DynamicCondition(BaseModel):
    """Optional dynamic runtime condition attached to a policy rule.

    This model is additive and does not alter existing field/operator/value
    behavior for static conditions.
    """

    type: DynamicConditionType
    timezone: str | None = Field(
        default=None,
        description="IANA timezone name (for temporal conditions), e.g. 'America/New_York'.",
    )
    start_time: str | None = Field(
        default=None,
        description="Inclusive window start in HH:MM (24-hour) local time.",
    )
    end_time: str | None = Field(
        default=None,
        description="Exclusive window end in HH:MM (24-hour) local time.",
    )
    days_of_week: list[int] | None = Field(
        default=None,
        description="ISO weekday numbers (1=Mon .. 7=Sun).",
    )
    window: str | None = Field(
        default=None,
        description="Budget window duration (e.g. '1h', '1d', '15m').",
    )
    limit: float | int | None = Field(
        default=None,
        description="Per-window budget cap for token/cost conditions.",
    )

    @model_validator(mode="after")
    def _validate_shape(self) -> "DynamicCondition":
        if self.type == DynamicConditionType.TIME_WINDOW:
            if self.start_time is None or self.end_time is None:
                raise ValueError("time_window requires start_time and end_time")
        elif self.type == DynamicConditionType.DAY_OF_WEEK:
            if not self.days_of_week:
                raise ValueError("day_of_week requires days_of_week")
        elif self.type in (
            DynamicConditionType.TOKEN_COUNT_PER_WINDOW,
            DynamicConditionType.COST_PER_WINDOW,
        ):
            if self.window is None or self.limit is None:
                raise ValueError("budget conditions require window and limit")
        return self


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
    dynamic_condition: DynamicCondition | None = Field(
        default=None,
        description="Optional v1 dynamic runtime condition.",
    )
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

    # Fail closed by default so Python matches the TS and .NET SDKs.
    # To opt back into permissive behavior, set defaults.action: allow explicitly.
    action: PolicyAction = PolicyAction.DENY
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


class SandboxMounts(BaseModel):
    """Host directories exposed to a sandbox session.

    Both paths are optional. ``input_dir`` is mounted read-only and
    ``output_dir`` read-write by the sandbox providers. Defined natively
    so policies loaded from YAML/JSON retain the mounts (Pydantic drops
    unknown keys, so a duck-typed block would otherwise be lost).
    """

    input_dir: str | None = Field(
        default=None,
        description="Host path mounted read-only into the sandbox.",
    )
    output_dir: str | None = Field(
        default=None,
        description="Host path mounted read-write into the sandbox.",
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
    sandbox_mounts: SandboxMounts = Field(
        default_factory=SandboxMounts,
        description=(
            "Host directories exposed to the sandbox. ``input_dir`` is "
            "mounted read-only and ``output_dir`` read-write. Consumed by "
            "the sandbox providers (Docker / Hyperlight / MXC); ignored by "
            "the rule engine."
        ),
    )

    @classmethod
    def from_yaml(cls, path: str | Path) -> PolicyDocument:
        """Load a PolicyDocument from a YAML file."""
        try:
            import yaml
        except ImportError as exc:
            raise ImportError(
                "pyyaml is required: pip install pyyaml"
            ) from exc

        path = Path(path)
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls.model_validate(data)

    def to_yaml(self, path: str | Path) -> None:
        """Serialize this PolicyDocument to a YAML file."""
        try:
            import yaml
        except ImportError as exc:
            raise ImportError(
                "pyyaml is required: pip install pyyaml"
            ) from exc

        path = Path(path)
        with open(path, "w") as f:
            yaml.dump(self.model_dump(mode="json"), f, default_flow_style=False, sort_keys=False)

    @classmethod
    def from_json(cls, path: str | Path) -> PolicyDocument:
        """Load a PolicyDocument from a JSON file."""
        path = Path(path)
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return cls.model_validate(data)

    def to_json(self, path: str | Path) -> None:
        """Serialize this PolicyDocument to a JSON file."""
        path = Path(path)
        with open(path, "w") as f:
            json.dump(self.model_dump(mode="json"), f, indent=2)
