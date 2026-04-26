# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for SLO template loader and pre-built templates.

Verifies:
- All templates load without error
- Template structure is correct (required keys present)
- Indicator configs have valid types and targets
- list_templates returns all expected templates
"""

import pytest

from agent_sre.specs import list_templates, load_slo_template

EXPECTED_TEMPLATES = [
    "coding-agent",
    "customer-support-agent",
    "data-pipeline-agent",
    "research-agent",
]

VALID_INDICATOR_TYPES = {
    "TaskSuccessRate",
    "ToolCallAccuracy",
    "ResponseLatency",
    "CostPerTask",
    "PolicyCompliance",
    "DelegationChainDepth",
    "HallucinationRate",
}


class TestListTemplates:
    def test_returns_all_templates(self):
        templates = list_templates()
        for name in EXPECTED_TEMPLATES:
            assert name in templates, f"Missing template: {name}"

    def test_returns_sorted(self):
        templates = list_templates()
        assert templates == sorted(templates)


class TestLoadTemplate:
    @pytest.mark.parametrize("name", EXPECTED_TEMPLATES)
    def test_loads_without_error(self, name):
        spec = load_slo_template(name)
        assert isinstance(spec, dict)

    @pytest.mark.parametrize("name", EXPECTED_TEMPLATES)
    def test_has_required_keys(self, name):
        spec = load_slo_template(name)
        assert "name" in spec
        assert "description" in spec
        assert "indicators" in spec
        assert isinstance(spec["indicators"], list)
        assert len(spec["indicators"]) >= 2  # At least 2 indicators

    @pytest.mark.parametrize("name", EXPECTED_TEMPLATES)
    def test_name_matches_filename(self, name):
        spec = load_slo_template(name)
        assert spec["name"] == name

    @pytest.mark.parametrize("name", EXPECTED_TEMPLATES)
    def test_has_labels(self, name):
        spec = load_slo_template(name)
        assert "labels" in spec
        labels = spec["labels"]
        assert isinstance(labels, dict)
        assert "domain" in labels

    @pytest.mark.parametrize("name", EXPECTED_TEMPLATES)
    def test_has_error_budget(self, name):
        spec = load_slo_template(name)
        assert "error_budget" in spec
        budget = spec["error_budget"]
        assert isinstance(budget, dict)
        assert "target" in budget

    @pytest.mark.parametrize("name", EXPECTED_TEMPLATES)
    def test_indicator_types_valid(self, name):
        spec = load_slo_template(name)
        for indicator in spec["indicators"]:
            assert "type" in indicator, f"Indicator missing 'type': {indicator}"
            assert indicator["type"] in VALID_INDICATOR_TYPES, (
                f"Unknown indicator type '{indicator['type']}' in {name}"
            )

    def test_not_found(self):
        with pytest.raises(FileNotFoundError, match="not found"):
            load_slo_template("nonexistent-agent")


class TestCustomerSupportTemplate:
    def test_specific_values(self):
        spec = load_slo_template("customer-support-agent")
        indicators = {i["type"]: i for i in spec["indicators"]}

        assert "TaskSuccessRate" in indicators
        assert indicators["TaskSuccessRate"]["target"] == 0.95

        assert "ResponseLatency" in indicators
        assert indicators["ResponseLatency"]["target_ms"] == 10000

        assert "CostPerTask" in indicators
        assert indicators["CostPerTask"]["target_usd"] == 0.25

        assert "HallucinationRate" in indicators


class TestCodingAgentTemplate:
    def test_specific_values(self):
        spec = load_slo_template("coding-agent")
        indicators = {i["type"]: i for i in spec["indicators"]}

        # Coding agents tolerate higher latency
        assert indicators["ResponseLatency"]["target_ms"] == 30000
        # But need high tool accuracy
        assert indicators["ToolCallAccuracy"]["target"] == 0.995
        # Higher cost tolerance
        assert indicators["CostPerTask"]["target_usd"] == 1.0


class TestResearchAgentTemplate:
    def test_specific_values(self):
        spec = load_slo_template("research-agent")
        indicators = {i["type"]: i for i in spec["indicators"]}

        # Research agents need even more latency tolerance
        assert indicators["ResponseLatency"]["target_ms"] == 60000
        # And have delegation depth tracking
        assert "DelegationChainDepth" in indicators


class TestDataPipelineTemplate:
    def test_specific_values(self):
        spec = load_slo_template("data-pipeline-agent")
        indicators = {i["type"]: i for i in spec["indicators"]}

        # Data pipelines need very high success rate
        assert indicators["TaskSuccessRate"]["target"] == 0.99
        # And perfect tool accuracy
        assert indicators["ToolCallAccuracy"]["target"] == 0.999
        # And policy compliance
        assert "PolicyCompliance" in indicators
