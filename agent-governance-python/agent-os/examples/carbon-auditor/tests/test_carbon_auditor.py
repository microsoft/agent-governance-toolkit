# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for the Carbon Credit Auditor demo.

Verifies CMVK drift detection, agent pipeline, and fraud detection accuracy.
"""

import sys
from pathlib import Path

# Add the example's src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from demo import (
    CMVK,
    AuditorAgent,
    CarbonAuditorSwarm,
    Claim,
    ClaimsAgent,
    GeoAgent,
    Observation,
    VerificationStatus,
)
from datetime import datetime


class TestCMVK:
    def test_verified_claim(self):
        cmvk = CMVK()
        claim = Claim(
            project_id="TEST-001",
            location=(0.0, 0.0),
            claimed_ndvi=0.80,
            claimed_carbon_tonnes=170,
            area_hectares=1000,
            methodology="VM0042",
            year=2024,
        )
        observation = Observation(
            source="Sentinel-2",
            observed_ndvi=0.79,
            observed_carbon_tonnes=168,
            timestamp=datetime.now(),
            confidence=0.95,
        )
        result = cmvk.verify(claim, observation)
        assert result.status == VerificationStatus.VERIFIED
        assert result.drift_score < 0.10

    def test_fraud_detection(self):
        cmvk = CMVK()
        claim = Claim(
            project_id="FRAUD-001",
            location=(0.0, 0.0),
            claimed_ndvi=0.82,
            claimed_carbon_tonnes=180,
            area_hectares=5000,
            methodology="VM0042",
            year=2024,
        )
        observation = Observation(
            source="Sentinel-2",
            observed_ndvi=0.40,  # Deforestation
            observed_carbon_tonnes=50,  # Low carbon
            timestamp=datetime.now(),
            confidence=0.92,
        )
        result = cmvk.verify(claim, observation)
        assert result.status == VerificationStatus.FRAUD
        assert result.drift_score > 0.15

    def test_flagged_claim(self):
        cmvk = CMVK()
        claim = Claim(
            project_id="FLAG-001",
            location=(0.0, 0.0),
            claimed_ndvi=0.80,
            claimed_carbon_tonnes=170,
            area_hectares=1000,
            methodology="VM0042",
            year=2024,
        )
        observation = Observation(
            source="Sentinel-2",
            observed_ndvi=0.70,  # Slight discrepancy
            observed_carbon_tonnes=155,
            timestamp=datetime.now(),
            confidence=0.90,
        )
        result = cmvk.verify(claim, observation)
        assert result.status in (VerificationStatus.FLAGGED, VerificationStatus.FRAUD)

    def test_audit_trail(self):
        cmvk = CMVK()
        claim = Claim("P1", (0, 0), 0.80, 170, 1000, "VM0042", 2024)
        obs = Observation("Sentinel-2", 0.79, 168, datetime.now(), 0.95)
        result = cmvk.verify(claim, obs)
        assert len(result.audit_trail) >= 3
        assert "NDVI drift" in result.audit_trail[0]
        assert "Decision" in result.audit_trail[-1]

    def test_custom_thresholds(self):
        cmvk = CMVK(thresholds={"verified": 0.03, "flagged": 0.05, "fraud": 0.05})
        claim = Claim("P1", (0, 0), 0.80, 170, 1000, "VM0042", 2024)
        obs = Observation("Sentinel-2", 0.74, 160, datetime.now(), 0.90)
        result = cmvk.verify(claim, obs)
        # With tight thresholds (5%), 6.7% drift should be fraud
        assert result.status == VerificationStatus.FRAUD


class TestAgents:
    def test_claims_agent(self):
        agent = ClaimsAgent()
        claim = agent.extract_claim({
            "project_id": "TEST-001",
            "lat": -3.0,
            "lon": -62.0,
            "claimed_ndvi": 0.82,
            "claimed_carbon_tonnes": 180,
            "area_hectares": 5000,
            "methodology": "VM0042",
            "year": 2024,
        })
        assert claim.project_id == "TEST-001"
        assert claim.claimed_ndvi == 0.82

    def test_geo_agent_fraud(self):
        agent = GeoAgent()
        obs = agent.fetch_observation((-3.0, -62.0), is_fraud=True)
        assert obs.observed_ndvi < 0.60  # Low NDVI indicates deforestation
        assert obs.source == "Sentinel-2 Copernicus"

    def test_geo_agent_verified(self):
        agent = GeoAgent()
        obs = agent.fetch_observation((-3.0, -62.0), is_fraud=False)
        assert obs.observed_ndvi >= 0.70  # Healthy forest

    def test_auditor_agent(self):
        agent = AuditorAgent()
        claim = Claim("P1", (0, 0), 0.80, 170, 1000, "VM0042", 2024)
        obs = Observation("Sentinel-2", 0.79, 168, datetime.now(), 0.95)
        result = agent.audit(claim, obs)
        assert result.status == VerificationStatus.VERIFIED


class TestSwarm:
    def test_fraud_pipeline(self):
        swarm = CarbonAuditorSwarm()
        project = {
            "project_id": "VCS-FRAUD-001",
            "lat": -3.4653,
            "lon": -62.2159,
            "claimed_ndvi": 0.82,
            "claimed_carbon_tonnes": 180,
            "area_hectares": 5000,
            "methodology": "VM0042",
            "year": 2024,
        }
        result, elapsed_ms = swarm.run_audit(project, is_fraud_scenario=True)
        assert result.status == VerificationStatus.FRAUD
        assert elapsed_ms < 1000  # Should be fast (no network calls)

    def test_verified_pipeline(self):
        swarm = CarbonAuditorSwarm()
        project = {
            "project_id": "VCS-GOOD-001",
            "lat": 0.4162,
            "lon": 18.4347,
            "claimed_ndvi": 0.78,
            "claimed_carbon_tonnes": 165,
            "area_hectares": 8000,
            "methodology": "VM0042",
            "year": 2024,
        }
        result, elapsed_ms = swarm.run_audit(project, is_fraud_scenario=False)
        assert result.status == VerificationStatus.VERIFIED

    def test_message_bus(self):
        swarm = CarbonAuditorSwarm()
        project = {
            "project_id": "TEST",
            "lat": 0.0, "lon": 0.0,
            "claimed_ndvi": 0.80, "claimed_carbon_tonnes": 170,
            "area_hectares": 1000, "methodology": "VM0042", "year": 2024,
        }
        swarm.run_audit(project, is_fraud_scenario=False)
        assert len(swarm.bus.get_messages("claims")) == 1
        assert len(swarm.bus.get_messages("observations")) == 1
        assert len(swarm.bus.get_messages("verifications")) == 1
