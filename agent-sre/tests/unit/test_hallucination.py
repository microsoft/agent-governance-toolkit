# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for hallucination rate SLI."""

from agent_sre.slo.indicators import HallucinationRate, SLIRegistry


class TestHallucinationRate:
    def test_initial_rate_is_zero(self):
        sli = HallucinationRate()
        assert sli.name == "hallucination_rate"
        value = sli.collect()
        assert value.value == 0.0

    def test_record_evaluations(self):
        sli = HallucinationRate(target=0.05)
        sli.record_evaluation(hallucinated=False)
        sli.record_evaluation(hallucinated=False)
        sli.record_evaluation(hallucinated=True)
        value = sli.collect()
        assert abs(value.value - 1 / 3) < 0.01

    def test_compliance_lower_is_better(self):
        sli = HallucinationRate(target=0.10)
        # Record values below target
        sli.record_evaluation(hallucinated=False)
        sli.record_evaluation(hallucinated=False)
        sli.record_evaluation(hallucinated=False)
        compliance = sli.compliance()
        assert compliance is not None
        assert compliance == 1.0

    def test_compliance_above_target(self):
        sli = HallucinationRate(target=0.01)
        # 50% hallucination rate - all measurements above target
        for _ in range(5):
            sli.record_evaluation(hallucinated=True)
            sli.record_evaluation(hallucinated=False)
        # All recorded rates > 0.01
        compliance = sli.compliance()
        assert compliance is not None
        assert compliance < 1.0

    def test_confidence_in_metadata(self):
        sli = HallucinationRate()
        val = sli.record_evaluation(hallucinated=True, confidence=0.95)
        assert val.metadata["confidence"] == 0.95

    def test_registered_in_registry(self):
        registry = SLIRegistry()
        assert "HallucinationRate" in registry.list_types()
        cls = registry.get_type("HallucinationRate")
        assert cls is HallucinationRate

    def test_to_dict(self):
        sli = HallucinationRate()
        sli.record_evaluation(hallucinated=False)
        d = sli.to_dict()
        assert d["name"] == "hallucination_rate"
        assert "current_value" in d
