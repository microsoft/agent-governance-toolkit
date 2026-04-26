# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the EU AI Act risk classifier (issue #756)."""

import pytest

from agentmesh.governance.eu_ai_act import (
    AgentRiskProfile,
    EUAIActRiskClassifier,
    RiskLevel,
)


@pytest.fixture
def classifier():
    return EUAIActRiskClassifier()


# -----------------------------------------------------------------------
# Article 5 -- Prohibited practices
# -----------------------------------------------------------------------

class TestUnacceptableRisk:
    def test_social_scoring(self, classifier):
        profile = AgentRiskProfile(name="scorer", domain="social_scoring")
        result = classifier.classify(profile)
        assert result.risk_level == RiskLevel.UNACCEPTABLE

    def test_real_time_biometric(self, classifier):
        profile = AgentRiskProfile(
            name="biowatch",
            domain="real_time_biometric_identification",
        )
        result = classifier.classify(profile)
        assert result.risk_level == RiskLevel.UNACCEPTABLE

    def test_subliminal_manipulation(self, classifier):
        profile = AgentRiskProfile(name="manip", domain="subliminal_manipulation")
        result = classifier.classify(profile)
        assert result.risk_level == RiskLevel.UNACCEPTABLE


# -----------------------------------------------------------------------
# Article 6(1) -- Annex I safety components
# -----------------------------------------------------------------------

class TestAnnexISafetyComponent:
    def test_safety_component_medical_device(self, classifier):
        profile = AgentRiskProfile(
            name="med-safety",
            domain="general_monitoring",
            is_safety_component=True,
            harmonisation_legislation="medical_devices",
        )
        result = classifier.classify(profile)
        assert result.risk_level == RiskLevel.HIGH
        assert any("Annex I" in t for t in result.triggers)

    def test_safety_component_unknown_legislation(self, classifier):
        """Safety component under non-Annex-I legislation is not auto-HIGH."""
        profile = AgentRiskProfile(
            name="widget",
            domain="general",
            is_safety_component=True,
            harmonisation_legislation="unknown_directive",
        )
        result = classifier.classify(profile)
        assert result.risk_level == RiskLevel.MINIMAL


# -----------------------------------------------------------------------
# Article 6(2) -- Annex III high-risk domains
# -----------------------------------------------------------------------

class TestAnnexIIIHighRisk:
    @pytest.mark.parametrize("domain", [
        "credit_scoring",
        "medical_diagnosis",
        "employment_recruitment",
        "law_enforcement",
        "critical_infrastructure",
    ])
    def test_annex_iii_domains(self, classifier, domain):
        profile = AgentRiskProfile(name="system", domain=domain)
        result = classifier.classify(profile)
        assert result.risk_level == RiskLevel.HIGH


# -----------------------------------------------------------------------
# Capability-based escalation
# -----------------------------------------------------------------------

class TestCapabilityEscalation:
    def test_autonomous_decision_making(self, classifier):
        profile = AgentRiskProfile(
            name="auto-decider",
            domain="general",
            capabilities=["autonomous_decision_making"],
        )
        result = classifier.classify(profile)
        assert result.risk_level == RiskLevel.HIGH

    def test_multiple_capabilities(self, classifier):
        profile = AgentRiskProfile(
            name="multi",
            domain="general",
            capabilities=["biometric_processing", "financial_decisioning"],
        )
        result = classifier.classify(profile)
        assert result.risk_level == RiskLevel.HIGH


# -----------------------------------------------------------------------
# Article 6(3) -- Exemptions
# -----------------------------------------------------------------------

class TestArticle63Exemptions:
    def test_narrow_procedural_task_exemption(self, classifier):
        """Annex III domain with valid exemption should NOT be HIGH."""
        profile = AgentRiskProfile(
            name="helper",
            domain="credit_scoring",
            exemption_tags=["narrow_procedural_task"],
        )
        result = classifier.classify(profile)
        assert result.risk_level != RiskLevel.HIGH
        assert "narrow_procedural_task" in result.exemptions_applied

    def test_pattern_detection_exemption(self, classifier):
        profile = AgentRiskProfile(
            name="detector",
            domain="law_enforcement",
            exemption_tags=["pattern_detection_no_action"],
        )
        result = classifier.classify(profile)
        assert result.risk_level != RiskLevel.HIGH

    def test_invalid_exemption_ignored(self, classifier):
        """Unrecognized exemption tag should not grant an exemption."""
        profile = AgentRiskProfile(
            name="faker",
            domain="credit_scoring",
            exemption_tags=["made_up_exemption"],
        )
        result = classifier.classify(profile)
        assert result.risk_level == RiskLevel.HIGH


# -----------------------------------------------------------------------
# Profiling override (GDPR Art. 4(4))
# -----------------------------------------------------------------------

class TestProfilingOverride:
    def test_profiling_overrides_exemption(self, classifier):
        """When profiling is involved, Art. 6(3) exemptions do NOT apply."""
        profile = AgentRiskProfile(
            name="profiler",
            domain="credit_scoring",
            exemption_tags=["narrow_procedural_task"],
            involves_profiling=True,
        )
        result = classifier.classify(profile)
        assert result.risk_level == RiskLevel.HIGH
        assert result.profiling_override is True
        assert len(result.exemptions_applied) == 0

    def test_profiling_without_exemption(self, classifier):
        """Profiling in Annex III domain is HIGH regardless."""
        profile = AgentRiskProfile(
            name="profiler2",
            domain="employment_recruitment",
            involves_profiling=True,
        )
        result = classifier.classify(profile)
        assert result.risk_level == RiskLevel.HIGH


# -----------------------------------------------------------------------
# Limited and minimal risk
# -----------------------------------------------------------------------

class TestLimitedAndMinimalRisk:
    def test_chatbot_is_limited(self, classifier):
        profile = AgentRiskProfile(name="bot", domain="chatbot")
        result = classifier.classify(profile)
        assert result.risk_level == RiskLevel.LIMITED

    def test_content_generation_is_limited(self, classifier):
        profile = AgentRiskProfile(name="gen", domain="content_generation")
        result = classifier.classify(profile)
        assert result.risk_level == RiskLevel.LIMITED

    def test_generic_system_is_minimal(self, classifier):
        profile = AgentRiskProfile(name="basic", domain="general_utility")
        result = classifier.classify(profile)
        assert result.risk_level == RiskLevel.MINIMAL

    def test_empty_profile_is_minimal(self, classifier):
        profile = AgentRiskProfile(name="empty")
        result = classifier.classify(profile)
        assert result.risk_level == RiskLevel.MINIMAL


# -----------------------------------------------------------------------
# Issue #756 regression: keyword-only matching misses descriptions
# -----------------------------------------------------------------------

class TestRegressions:
    def test_behavioral_scoring_not_missed(self, classifier):
        """The old assess_risk_category() missed this because no keywords
        matched. The new classifier correctly maps the domain."""
        profile = AgentRiskProfile(
            name="citizen-rater",
            domain="social_scoring",
            description="Rate citizens based on behavior for government rewards",
        )
        result = classifier.classify(profile)
        assert result.risk_level == RiskLevel.UNACCEPTABLE


# -----------------------------------------------------------------------
# Domain normalization
# -----------------------------------------------------------------------

class TestNormalization:
    def test_spaces_and_hyphens_normalized(self, classifier):
        profile = AgentRiskProfile(name="test", domain="Credit Scoring")
        result = classifier.classify(profile)
        assert result.risk_level == RiskLevel.HIGH

    def test_mixed_case(self, classifier):
        profile = AgentRiskProfile(name="test", domain="LAW-ENFORCEMENT")
        result = classifier.classify(profile)
        assert result.risk_level == RiskLevel.HIGH
