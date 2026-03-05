# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic implementation
"""SLO-as-code: version-controlled SLO definitions in YAML."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class ComparisonOp(str, Enum):
    """Comparison operator for SLI thresholds."""

    LTE = "lte"  # less than or equal (e.g., latency <= 5s)
    GTE = "gte"  # greater than or equal (e.g., availability >= 99%)
    LT = "lt"
    GT = "gt"


class SLISpec(BaseModel):
    """Service Level Indicator specification."""

    metric: str = Field(..., description="Metric name (Prometheus naming)")
    threshold: float = Field(..., description="Threshold value for the SLI")
    comparison: ComparisonOp = Field(
        default=ComparisonOp.GTE,
        description="How to compare metric against threshold",
    )


class BurnRateThreshold(BaseModel):
    """A burn rate alert threshold."""

    name: str
    rate: float = Field(..., gt=0, description="Burn rate multiplier")
    severity: str = Field(default="warning")
    window_seconds: int = Field(default=3600, gt=0)


class ErrorBudgetPolicy(BaseModel):
    """Error budget policy with burn rate thresholds."""

    burn_rate_thresholds: list[BurnRateThreshold] = Field(default_factory=list)


class SLOSpec(BaseModel):
    """Version-controlled SLO definition.

    Can be serialized to/from YAML for SLO-as-code workflows.
    """

    name: str = Field(..., description="Unique SLO name")
    description: str = Field(default="", description="Human-readable description")
    service: str = Field(default="", description="Agent/service name")
    sli: SLISpec | None = Field(default=None, description="Service level indicator")
    target: float = Field(default=99.0, description="Target percentage (0-100)")
    window: str = Field(default="30d", description="Rolling window duration")
    error_budget_policy: ErrorBudgetPolicy = Field(default_factory=ErrorBudgetPolicy)
    labels: dict[str, str] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    inherits_from: str | None = Field(
        default=None,
        description="Name of parent SLO spec to inherit from",
    )

    @classmethod
    def from_yaml(cls, path: str | Path) -> SLOSpec:
        """Load an SLO spec from a YAML file."""
        path = Path(path)
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls.model_validate(data)

    def to_yaml(self, path: str | Path) -> None:
        """Save this SLO spec to a YAML file."""
        path = Path(path)
        data = self.model_dump(mode="json", exclude_none=True)
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)


def load_slo_specs(directory: str | Path) -> list[SLOSpec]:
    """Load all SLO specs from YAML files in a directory."""
    directory = Path(directory)
    specs: list[SLOSpec] = []
    for path in sorted(directory.glob("*.yaml")):
        specs.append(SLOSpec.from_yaml(path))
    for path in sorted(directory.glob("*.yml")):
        if path.with_suffix(".yaml") not in directory.glob("*.yaml"):
            specs.append(SLOSpec.from_yaml(path))
    return specs


def resolve_inheritance(specs: list[SLOSpec]) -> list[SLOSpec]:
    """Resolve inheritance chains across SLO specs.

    Child specs override parent fields; unset fields inherit from parent.
    Returns new list with all inheritance resolved.
    """
    by_name: dict[str, SLOSpec] = {s.name: s for s in specs}
    resolved: dict[str, SLOSpec] = {}

    def _resolve(spec: SLOSpec) -> SLOSpec:
        if spec.name in resolved:
            return resolved[spec.name]

        if spec.inherits_from is None:
            resolved[spec.name] = spec
            return spec

        parent_name = spec.inherits_from
        if parent_name not in by_name:
            raise ValueError(
                f"SLO '{spec.name}' inherits from unknown spec '{parent_name}'"
            )

        parent = _resolve(by_name[parent_name])

        # Merge: child overrides parent; use parent for fields the child left default
        parent_data = parent.model_dump(exclude_none=True)
        child_data = spec.model_dump(exclude_none=True)

        # Remove inheritance marker from merged result
        merged = {**parent_data, **child_data}
        merged.pop("inherits_from", None)

        # Merge labels and metadata (additive)
        merged["labels"] = {**parent_data.get("labels", {}), **child_data.get("labels", {})}
        merged["metadata"] = {
            **parent_data.get("metadata", {}),
            **child_data.get("metadata", {}),
        }

        result = SLOSpec.model_validate(merged)
        resolved[spec.name] = result
        return result

    return [_resolve(s) for s in specs]
