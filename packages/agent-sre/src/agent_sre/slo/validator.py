# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic implementation
"""SLO spec validation and diff detection."""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from agent_sre.slo.spec import SLOSpec


class ValidationError(BaseModel):
    """A single validation error on an SLO spec."""

    field: str
    message: str
    severity: str = Field(default="error")  # error, warning


class TargetChange(str, Enum):
    """How the SLO target changed between versions."""

    TIGHTENED = "tightened"
    LOOSENED = "loosened"
    UNCHANGED = "unchanged"


class SLODiff(BaseModel):
    """Diff between two versions of an SLO spec."""

    changed_fields: list[str] = Field(default_factory=list)
    target_change: TargetChange = Field(default=TargetChange.UNCHANGED)
    is_breaking: bool = Field(default=False)
    details: dict[str, Any] = Field(default_factory=dict)


def _parse_window_seconds(window: str) -> int | None:
    """Parse a window string like '30d', '1h', '7d' into seconds."""
    if not window:
        return None
    suffix = window[-1].lower()
    try:
        value = int(window[:-1])
    except ValueError:
        return None
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    multiplier = multipliers.get(suffix)
    if multiplier is None:
        return None
    return value * multiplier


def validate_spec(spec: SLOSpec) -> list[ValidationError]:
    """Validate an SLO spec and return any errors found.

    Checks:
        - Target is between 0-100%
        - Window is a positive duration
        - SLI metric name is non-empty
        - Burn rate thresholds are ordered correctly
    """
    errors: list[ValidationError] = []

    # Target range check
    if spec.target < 0 or spec.target > 100:
        errors.append(ValidationError(
            field="target",
            message=f"Target must be between 0 and 100, got {spec.target}",
        ))

    # Window must be a valid positive duration
    window_secs = _parse_window_seconds(spec.window)
    if window_secs is None:
        errors.append(ValidationError(
            field="window",
            message=f"Invalid window format: '{spec.window}'. Use e.g. '30d', '1h', '7d'.",
        ))
    elif window_secs <= 0:
        errors.append(ValidationError(
            field="window",
            message="Window must be a positive duration.",
        ))

    # SLI metric name check
    if spec.sli is not None and not spec.sli.metric.strip():
        errors.append(ValidationError(
            field="sli.metric",
            message="SLI metric name must be non-empty.",
        ))

    # Burn rate thresholds ordering: rates should be in ascending order
    thresholds = spec.error_budget_policy.burn_rate_thresholds
    if len(thresholds) >= 2:
        rates = [t.rate for t in thresholds]
        if rates != sorted(rates):
            errors.append(ValidationError(
                field="error_budget_policy.burn_rate_thresholds",
                message=(
                    f"Burn rate thresholds must be in ascending order, "
                    f"got rates: {rates}"
                ),
            ))

    return errors


def diff_specs(old: SLOSpec, new: SLOSpec) -> SLODiff:
    """Compute the diff between two versions of an SLO spec.

    Returns an SLODiff showing what changed, whether the target was
    tightened or loosened, and whether the change is breaking.
    """
    old_data = old.model_dump(mode="json", exclude_none=True)
    new_data = new.model_dump(mode="json", exclude_none=True)

    changed_fields: list[str] = []
    details: dict[str, Any] = {}

    all_keys = set(old_data.keys()) | set(new_data.keys())
    for key in sorted(all_keys):
        old_val = old_data.get(key)
        new_val = new_data.get(key)
        if old_val != new_val:
            changed_fields.append(key)
            details[key] = {"old": old_val, "new": new_val}

    # Determine target change direction
    if new.target > old.target:
        target_change = TargetChange.TIGHTENED
    elif new.target < old.target:
        target_change = TargetChange.LOOSENED
    else:
        target_change = TargetChange.UNCHANGED

    # Breaking change: tightened target or changed SLI metric
    is_breaking = target_change == TargetChange.TIGHTENED
    if old.sli and new.sli and old.sli.metric != new.sli.metric:
        is_breaking = True

    return SLODiff(
        changed_fields=changed_fields,
        target_change=target_change,
        is_breaking=is_breaking,
        details=details,
    )
