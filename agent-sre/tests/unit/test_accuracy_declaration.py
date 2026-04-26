# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for AccuracyDeclaration (EU AI Act Art. 15(1))."""

from __future__ import annotations

import pytest

from agent_sre.accuracy_declaration import (
    AccuracyDeclaration,
    AccuracyThreshold,
    RiskTier,
)


class TestAccuracyThreshold:
    def test_valid_threshold(self):
        t = AccuracyThreshold(
            metric_name="tool_call_accuracy",
            minimum_value=0.95,
            recommended_value=0.99,
        )
        assert t.metric_name == "tool_call_accuracy"
        assert t.minimum_value == 0.95

    def test_rejects_negative(self):
        with pytest.raises(Exception):
            AccuracyThreshold(
                metric_name="x", minimum_value=-0.1, recommended_value=0.5
            )

    def test_rejects_above_one(self):
        with pytest.raises(Exception):
            AccuracyThreshold(
                metric_name="x", minimum_value=1.5, recommended_value=0.5
            )


class TestAccuracyDeclaration:
    def test_for_high_risk_factory(self):
        decl = AccuracyDeclaration.for_high_risk("MyAgent")
        assert decl.risk_tier == RiskTier.HIGH
        assert decl.system_name == "MyAgent"
        assert len(decl.declared_thresholds) == 4
        names = {t.metric_name for t in decl.declared_thresholds}
        assert "tool_call_accuracy" in names
        assert "hallucination_rate" in names

    def test_for_limited_risk_factory(self):
        decl = AccuracyDeclaration.for_limited_risk("LowRiskBot")
        assert decl.risk_tier == RiskTier.LIMITED
        assert len(decl.declared_thresholds) == 3

    def test_limited_has_relaxed_thresholds(self):
        high = AccuracyDeclaration.for_high_risk("H")
        limited = AccuracyDeclaration.for_limited_risk("L")
        high_acc = next(
            t for t in high.declared_thresholds if t.metric_name == "tool_call_accuracy"
        )
        lim_acc = next(
            t for t in limited.declared_thresholds if t.metric_name == "tool_call_accuracy"
        )
        assert lim_acc.minimum_value < high_acc.minimum_value

    def test_validate_accuracy_above_minimum_passes(self):
        decl = AccuracyDeclaration.for_high_risk("Agent")
        passed, msg = decl.validate_against_sli("tool_call_accuracy", 0.97)
        assert passed is True
        assert "COMPLIANT" in msg

    def test_validate_accuracy_below_minimum_fails(self):
        decl = AccuracyDeclaration.for_high_risk("Agent")
        passed, msg = decl.validate_against_sli("tool_call_accuracy", 0.80)
        assert passed is False
        assert "NON-COMPLIANT" in msg

    def test_validate_rate_metric_inverse_logic(self):
        """Hallucination rate: lower is better, must be <= minimum."""
        decl = AccuracyDeclaration.for_high_risk("Agent")
        # 3% hallucination <= 5% minimum = PASS
        passed, msg = decl.validate_against_sli("hallucination_rate", 0.03)
        assert passed is True

        # 8% hallucination > 5% minimum = FAIL
        passed, msg = decl.validate_against_sli("hallucination_rate", 0.08)
        assert passed is False

    def test_validate_unknown_metric_unconstrained(self):
        decl = AccuracyDeclaration.for_high_risk("Agent")
        passed, msg = decl.validate_against_sli("custom_metric", 0.5)
        assert passed is True
        assert "unconstrained" in msg

    def test_to_compliance_section(self):
        decl = AccuracyDeclaration.for_high_risk("ProductionAgent")
        section = decl.to_compliance_section()
        assert section["article"] == "Art. 15(1)"
        assert section["system_name"] == "ProductionAgent"
        assert section["risk_tier"] == "high"
        assert len(section["declared_thresholds"]) == 4
        assert all("metric" in t for t in section["declared_thresholds"])

    def test_custom_thresholds(self):
        decl = AccuracyDeclaration(
            system_name="Custom",
            risk_tier=RiskTier.HIGH,
            declared_thresholds=[
                AccuracyThreshold(
                    metric_name="custom_accuracy",
                    minimum_value=0.99,
                    recommended_value=0.999,
                    description="Custom high bar",
                ),
            ],
        )
        passed, msg = decl.validate_against_sli("custom_accuracy", 0.995)
        assert passed is True

    def test_json_roundtrip(self):
        decl = AccuracyDeclaration.for_high_risk("RoundtripAgent")
        json_str = decl.model_dump_json()
        restored = AccuracyDeclaration.model_validate_json(json_str)
        assert restored.system_name == "RoundtripAgent"
        assert len(restored.declared_thresholds) == 4
