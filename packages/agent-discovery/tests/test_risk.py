"""Tests for risk scoring."""

from datetime import datetime, timedelta, timezone

from agent_discovery.models import AgentStatus, DiscoveredAgent, RiskLevel
from agent_discovery.risk import RiskScorer


def _make_agent(**kwargs) -> DiscoveredAgent:
    defaults = {"fingerprint": "test", "name": "Test Agent"}
    defaults.update(kwargs)
    return DiscoveredAgent(**defaults)


class TestRiskScorer:
    def setup_method(self):
        self.scorer = RiskScorer()

    def test_max_risk_no_identity_no_owner_shadow(self):
        agent = _make_agent(status=AgentStatus.SHADOW, confidence=0.8)
        risk = self.scorer.score(agent)
        assert risk.score >= 70.0
        assert risk.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert "No cryptographic identity (DID/SPIFFE)" in risk.factors
        assert "No assigned owner" in risk.factors

    def test_registered_agent_with_identity_low_risk(self):
        agent = _make_agent(
            did="did:agent:abc",
            owner="team@company.com",
            status=AgentStatus.REGISTERED,
            agent_type="agt",
        )
        risk = self.scorer.score(agent)
        assert risk.score <= 25.0
        assert risk.level in (RiskLevel.LOW, RiskLevel.INFO)

    def test_high_risk_agent_type(self):
        agent = _make_agent(agent_type="autogen", status=AgentStatus.SHADOW)
        risk = self.scorer.score(agent)
        assert any("High-risk agent type" in f for f in risk.factors)

    def test_medium_risk_agent_type(self):
        agent = _make_agent(agent_type="mcp-server", status=AgentStatus.SHADOW)
        risk = self.scorer.score(agent)
        assert any("Medium-risk agent type" in f for f in risk.factors)

    def test_long_ungoverned_increases_risk(self):
        agent = _make_agent(
            status=AgentStatus.SHADOW,
            first_seen_at=datetime.now(timezone.utc) - timedelta(days=60),
        )
        risk = self.scorer.score(agent)
        assert any("Ungoverned for" in f for f in risk.factors)

    def test_low_confidence_reduces_risk(self):
        agent = _make_agent(
            status=AgentStatus.SHADOW,
            confidence=0.3,
        )
        risk = self.scorer.score(agent)
        assert any("Low detection confidence" in f for f in risk.factors)

    def test_score_clamped_to_100(self):
        agent = _make_agent(
            status=AgentStatus.SHADOW,
            agent_type="autogen",
            first_seen_at=datetime.now(timezone.utc) - timedelta(days=366),
        )
        risk = self.scorer.score(agent)
        assert risk.score <= 100.0

    def test_score_clamped_to_0(self):
        agent = _make_agent(
            did="did:agent:x",
            owner="owner@test.com",
            status=AgentStatus.REGISTERED,
            confidence=0.3,
        )
        risk = self.scorer.score(agent)
        assert risk.score >= 0.0
