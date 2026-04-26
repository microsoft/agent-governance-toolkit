# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""EU AI Act Art. 15(1) formal accuracy declaration mechanism.

Provides ``AccuracyDeclaration`` — a Pydantic model that formally
specifies expected accuracy levels per risk category, with factory
methods for recommended thresholds and validation against runtime SLIs.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class RiskTier(str, Enum):
    """EU AI Act risk classification tier."""

    MINIMAL = "minimal"
    LIMITED = "limited"
    HIGH = "high"
    UNACCEPTABLE = "unacceptable"


class AccuracyThreshold(BaseModel):
    """Minimum accuracy threshold for a specific metric."""

    metric_name: str = Field(..., description="SLI metric name (e.g. tool_call_accuracy)")
    minimum_value: float = Field(..., ge=0.0, le=1.0, description="Hard minimum — below this is non-compliant")
    recommended_value: float = Field(..., ge=0.0, le=1.0, description="Recommended target for production")
    unit: str = Field(default="ratio", description="Measurement unit (ratio, percentage, rate)")
    description: str = Field(default="", description="Human-readable explanation")


class AccuracyDeclaration(BaseModel):
    """Formal accuracy declaration per EU AI Act Art. 15(1).

    Declares expected accuracy levels for a system, allowing conformity
    assessors to verify that configured SLI targets meet declared minimums.

    Example::

        decl = AccuracyDeclaration.for_high_risk("MyAgent")
        passed, msg = decl.validate_against_sli("tool_call_accuracy", 0.97)
        assert passed  # 0.97 >= 0.95 minimum
    """

    system_name: str
    risk_tier: RiskTier
    declared_thresholds: list[AccuracyThreshold] = Field(default_factory=list)
    justification: str = Field(
        default="",
        description="Rationale for chosen thresholds relative to use case",
    )

    @classmethod
    def for_high_risk(cls, system_name: str) -> AccuracyDeclaration:
        """Create declaration with recommended HIGH risk thresholds."""
        return cls(
            system_name=system_name,
            risk_tier=RiskTier.HIGH,
            declared_thresholds=[
                AccuracyThreshold(
                    metric_name="tool_call_accuracy",
                    minimum_value=0.95,
                    recommended_value=0.99,
                    description="Tool calls must succeed >= 95%",
                ),
                AccuracyThreshold(
                    metric_name="hallucination_rate",
                    minimum_value=0.05,
                    recommended_value=0.02,
                    unit="rate",
                    description="Hallucination rate must be <= 5%",
                ),
                AccuracyThreshold(
                    metric_name="task_success_rate",
                    minimum_value=0.90,
                    recommended_value=0.95,
                    description="Tasks must complete successfully >= 90%",
                ),
                AccuracyThreshold(
                    metric_name="calibration_delta",
                    minimum_value=0.10,
                    recommended_value=0.05,
                    unit="delta",
                    description="Confidence calibration delta must be <= 10%",
                ),
            ],
            justification="Default HIGH risk thresholds per EU AI Act Art. 15(1) guidance",
        )

    @classmethod
    def for_limited_risk(cls, system_name: str) -> AccuracyDeclaration:
        """Create declaration with relaxed LIMITED risk thresholds."""
        return cls(
            system_name=system_name,
            risk_tier=RiskTier.LIMITED,
            declared_thresholds=[
                AccuracyThreshold(
                    metric_name="tool_call_accuracy",
                    minimum_value=0.85,
                    recommended_value=0.95,
                    description="Tool calls must succeed >= 85%",
                ),
                AccuracyThreshold(
                    metric_name="hallucination_rate",
                    minimum_value=0.10,
                    recommended_value=0.05,
                    unit="rate",
                    description="Hallucination rate must be <= 10%",
                ),
                AccuracyThreshold(
                    metric_name="task_success_rate",
                    minimum_value=0.80,
                    recommended_value=0.90,
                    description="Tasks must complete successfully >= 80%",
                ),
            ],
            justification="Default LIMITED risk thresholds — relaxed requirements",
        )

    def validate_against_sli(
        self, metric_name: str, actual_value: float
    ) -> tuple[bool, str]:
        """Check if an actual SLI value meets the declared minimum.

        For rate metrics (hallucination_rate, calibration_delta), the
        actual value must be **at or below** the minimum. For accuracy
        metrics, the actual value must be **at or above** the minimum.

        Returns:
            ``(True, message)`` if compliant, ``(False, message)`` if not.
        """
        for threshold in self.declared_thresholds:
            if threshold.metric_name == metric_name:
                is_inverse = threshold.unit in ("rate", "delta")

                if is_inverse:
                    passed = actual_value <= threshold.minimum_value
                    direction = "<="
                else:
                    passed = actual_value >= threshold.minimum_value
                    direction = ">="

                if passed:
                    msg = (
                        f"{metric_name}: {actual_value:.4f} {direction} "
                        f"{threshold.minimum_value:.4f} — COMPLIANT"
                    )
                    if is_inverse:
                        below_recommended = actual_value <= threshold.recommended_value
                    else:
                        below_recommended = actual_value < threshold.recommended_value

                    if below_recommended and not is_inverse:
                        logger.warning(
                            "%s meets minimum but below recommended %.4f",
                            metric_name,
                            threshold.recommended_value,
                        )
                        msg += f" (below recommended {threshold.recommended_value:.4f})"
                    return True, msg

                msg = (
                    f"{metric_name}: {actual_value:.4f} does not meet "
                    f"minimum {direction} {threshold.minimum_value:.4f} — "
                    f"NON-COMPLIANT"
                )
                logger.warning("Art. 15(1) violation: %s", msg)
                return False, msg

        return True, f"{metric_name}: no declared threshold (unconstrained)"

    def to_compliance_section(self) -> dict[str, Any]:
        """Export as a section for compliance report / Annex IV."""
        return {
            "article": "Art. 15(1)",
            "title": "Accuracy, Robustness, and Cybersecurity",
            "system_name": self.system_name,
            "risk_tier": self.risk_tier.value,
            "declared_thresholds": [
                {
                    "metric": t.metric_name,
                    "minimum": t.minimum_value,
                    "recommended": t.recommended_value,
                    "unit": t.unit,
                    "description": t.description,
                }
                for t in self.declared_thresholds
            ],
            "justification": self.justification,
        }
