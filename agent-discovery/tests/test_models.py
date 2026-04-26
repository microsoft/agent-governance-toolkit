"""Tests for agent discovery data models."""

import pytest
from datetime import datetime, timezone

from agent_discovery.models import (
    AgentStatus,
    DetectionBasis,
    DiscoveredAgent,
    Evidence,
    RiskAssessment,
    RiskLevel,
    ScanResult,
    ShadowAgent,
)


class TestEvidence:
    def test_create_evidence(self):
        ev = Evidence(
            scanner="process",
            basis=DetectionBasis.PROCESS,
            source="PID 1234",
            detail="LangChain pattern detected",
            confidence=0.85,
        )
        assert ev.scanner == "process"
        assert ev.confidence == 0.85
        assert ev.basis == DetectionBasis.PROCESS
        assert ev.timestamp <= datetime.now(timezone.utc)

    def test_confidence_bounds(self):
        with pytest.raises(Exception):
            Evidence(
                scanner="test",
                basis=DetectionBasis.PROCESS,
                source="test",
                detail="test",
                confidence=1.5,
            )

    def test_confidence_lower_bound(self):
        with pytest.raises(Exception):
            Evidence(
                scanner="test",
                basis=DetectionBasis.PROCESS,
                source="test",
                detail="test",
                confidence=-0.1,
            )


class TestDiscoveredAgent:
    def test_compute_fingerprint_deterministic(self):
        keys = {"repo": "org/myrepo", "config_path": "agentmesh.yaml"}
        fp1 = DiscoveredAgent.compute_fingerprint(keys)
        fp2 = DiscoveredAgent.compute_fingerprint(keys)
        assert fp1 == fp2
        assert len(fp1) == 16

    def test_compute_fingerprint_order_independent(self):
        fp1 = DiscoveredAgent.compute_fingerprint({"a": "1", "b": "2"})
        fp2 = DiscoveredAgent.compute_fingerprint({"b": "2", "a": "1"})
        assert fp1 == fp2

    def test_compute_fingerprint_unique(self):
        fp1 = DiscoveredAgent.compute_fingerprint({"repo": "org/a"})
        fp2 = DiscoveredAgent.compute_fingerprint({"repo": "org/b"})
        assert fp1 != fp2

    def test_add_evidence_updates_confidence(self):
        agent = DiscoveredAgent(
            fingerprint="abc123",
            name="Test Agent",
            confidence=0.5,
        )
        ev = Evidence(
            scanner="github",
            basis=DetectionBasis.GITHUB_REPO,
            source="https://github.com/test",
            detail="Config found",
            confidence=0.9,
        )
        agent.add_evidence(ev)
        assert agent.confidence == 0.9
        assert len(agent.evidence) == 1

    def test_add_evidence_keeps_max_confidence(self):
        agent = DiscoveredAgent(
            fingerprint="abc123",
            name="Test Agent",
            confidence=0.95,
        )
        ev = Evidence(
            scanner="process",
            basis=DetectionBasis.PROCESS,
            source="PID 1",
            detail="Lower confidence",
            confidence=0.5,
        )
        agent.add_evidence(ev)
        assert agent.confidence == 0.95

    def test_default_status_is_unknown(self):
        agent = DiscoveredAgent(fingerprint="x", name="test")
        assert agent.status == AgentStatus.UNKNOWN


class TestScanResult:
    def test_empty_result(self):
        result = ScanResult(scanner_name="test")
        assert result.agent_count == 0
        assert result.errors == []

    def test_agent_count(self):
        result = ScanResult(
            scanner_name="test",
            agents=[
                DiscoveredAgent(fingerprint="a", name="Agent A"),
                DiscoveredAgent(fingerprint="b", name="Agent B"),
            ],
        )
        assert result.agent_count == 2


class TestRiskAssessment:
    def test_create_assessment(self):
        risk = RiskAssessment(
            level=RiskLevel.HIGH,
            score=75.0,
            factors=["No identity", "No owner"],
        )
        assert risk.level == RiskLevel.HIGH
        assert risk.score == 75.0
        assert len(risk.factors) == 2


class TestShadowAgent:
    def test_create_shadow(self):
        agent = DiscoveredAgent(fingerprint="x", name="Shadow")
        shadow = ShadowAgent(
            agent=agent,
            recommended_actions=["Register with AgentMesh"],
        )
        assert shadow.agent.name == "Shadow"
        assert len(shadow.recommended_actions) == 1
