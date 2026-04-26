#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Carbon Credit Auditor Demo - Catch the Phantom Credits

This demo showcases:
- CMVK — Verification Kernel for drift detection
- Agent Message Bus (AMB) for swarm coordination
- Mathematical verification (not LLM inference)

Usage:
    python demo.py --scenario fraud
    python demo.py --scenario verified
    python demo.py --scenario both
"""

import argparse
import json
import math
import random
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional
from uuid import uuid4


class VerificationStatus(Enum):
    """Verification result status"""
    VERIFIED = "VERIFIED"
    FLAGGED = "FLAGGED"  
    FRAUD = "FRAUD"


@dataclass
class Claim:
    """Carbon credit claim from project document"""
    project_id: str
    location: tuple[float, float]  # lat, lon
    claimed_ndvi: float  # Normalized Difference Vegetation Index
    claimed_carbon_tonnes: float
    area_hectares: float
    methodology: str
    year: int


@dataclass
class Observation:
    """Satellite observation data"""
    source: str  # e.g., "Sentinel-2"
    observed_ndvi: float
    observed_carbon_tonnes: float
    timestamp: datetime
    confidence: float


@dataclass
class VerificationResult:
    """Result of CMVK verification"""
    status: VerificationStatus
    drift_score: float
    claim: Claim
    observation: Observation
    explanation: str
    audit_trail: list[str] = field(default_factory=list)


class CMVK:
    """
    CMVK — Verification Kernel
    
    Performs mathematical verification, not LLM inference.
    The decision is auditable, deterministic, and explainable.
    """
    
    def __init__(self, thresholds: dict = None):
        self.thresholds = thresholds or {
            "verified": 0.10,  # <10% drift = verified
            "flagged": 0.15,   # 10-15% drift = flagged
            "fraud": 0.15      # >15% drift = fraud
        }
    
    def verify(self, claim: Claim, observation: Observation) -> VerificationResult:
        """
        Verify claim against observation using mathematical drift detection.
        
        The Math decides, not the AI.
        """
        audit_trail = []
        
        # Calculate NDVI drift
        ndvi_drift = abs(claim.claimed_ndvi - observation.observed_ndvi) / claim.claimed_ndvi
        audit_trail.append(f"NDVI drift: {ndvi_drift:.2%} (claimed: {claim.claimed_ndvi}, observed: {observation.observed_ndvi})")
        
        # Calculate carbon drift  
        carbon_drift = abs(claim.claimed_carbon_tonnes - observation.observed_carbon_tonnes) / claim.claimed_carbon_tonnes
        audit_trail.append(f"Carbon drift: {carbon_drift:.2%} (claimed: {claim.claimed_carbon_tonnes}, observed: {observation.observed_carbon_tonnes})")
        
        # Combined drift score (Euclidean distance in normalized space)
        drift_score = math.sqrt((ndvi_drift ** 2 + carbon_drift ** 2) / 2)
        audit_trail.append(f"Combined drift score: {drift_score:.4f}")
        
        # Determine status based on thresholds
        if drift_score < self.thresholds["verified"]:
            status = VerificationStatus.VERIFIED
            explanation = f"Claims match observations within {self.thresholds['verified']*100:.0f}% tolerance"
        elif drift_score < self.thresholds["fraud"]:
            status = VerificationStatus.FLAGGED
            explanation = f"Minor discrepancy detected ({drift_score*100:.1f}% drift), manual review recommended"
        else:
            status = VerificationStatus.FRAUD
            explanation = f"Significant discrepancy detected ({drift_score*100:.1f}% drift). Claimed NDVI: {claim.claimed_ndvi}, Actual: {observation.observed_ndvi}"
        
        audit_trail.append(f"Decision: {status.value} - {explanation}")
        
        return VerificationResult(
            status=status,
            drift_score=drift_score,
            claim=claim,
            observation=observation,
            explanation=explanation,
            audit_trail=audit_trail
        )


class ClaimsAgent:
    """Agent A: The Reader - Extracts claims from project documents"""
    
    def __init__(self, agent_id: str = "claims-agent"):
        self.agent_id = agent_id
    
    def extract_claim(self, project_data: dict) -> Claim:
        """Extract structured claim from project document"""
        return Claim(
            project_id=project_data["project_id"],
            location=(project_data["lat"], project_data["lon"]),
            claimed_ndvi=project_data["claimed_ndvi"],
            claimed_carbon_tonnes=project_data["claimed_carbon_tonnes"],
            area_hectares=project_data["area_hectares"],
            methodology=project_data["methodology"],
            year=project_data["year"]
        )


class GeoAgent:
    """Agent B: The Eye - Fetches satellite observations"""
    
    def __init__(self, agent_id: str = "geo-agent"):
        self.agent_id = agent_id
    
    def fetch_observation(self, location: tuple[float, float], is_fraud: bool = False) -> Observation:
        """Fetch satellite data for location (simulated)"""
        
        # Simulate satellite data
        if is_fraud:
            # Fraud scenario: significant deforestation
            observed_ndvi = random.uniform(0.35, 0.50)  # Low NDVI = deforestation
            observed_carbon = random.uniform(40, 70)     # Low carbon stock
        else:
            # Verified scenario: healthy forest
            observed_ndvi = random.uniform(0.75, 0.85)
            observed_carbon = random.uniform(160, 180)
        
        return Observation(
            source="Sentinel-2 Copernicus",
            observed_ndvi=observed_ndvi,
            observed_carbon_tonnes=observed_carbon,
            timestamp=datetime.now(),
            confidence=0.92
        )


class AuditorAgent:
    """Agent C: The Judge - Makes verification decisions using CMVK"""
    
    def __init__(self, agent_id: str = "auditor-agent"):
        self.agent_id = agent_id
        self.cmvk = CMVK()
    
    def audit(self, claim: Claim, observation: Observation) -> VerificationResult:
        """Audit claim against observation"""
        return self.cmvk.verify(claim, observation)


class AgentMessageBus:
    """Simplified Agent Message Bus for demo"""
    
    def __init__(self):
        self.messages = []
    
    def publish(self, topic: str, message: dict):
        self.messages.append({"topic": topic, "message": message, "timestamp": datetime.now()})
    
    def get_messages(self, topic: str) -> list:
        return [m["message"] for m in self.messages if m["topic"] == topic]


class CarbonAuditorSwarm:
    """Complete Carbon Auditor Swarm"""
    
    def __init__(self):
        self.bus = AgentMessageBus()
        self.claims_agent = ClaimsAgent()
        self.geo_agent = GeoAgent()
        self.auditor_agent = AuditorAgent()
    
    def run_audit(self, project_data: dict, is_fraud_scenario: bool = True) -> VerificationResult:
        """Run full audit pipeline"""
        start_time = time.time()
        
        # Step 1: Extract claim
        claim = self.claims_agent.extract_claim(project_data)
        self.bus.publish("claims", {"claim": claim.__dict__})
        
        # Step 2: Fetch satellite observation
        observation = self.geo_agent.fetch_observation(claim.location, is_fraud=is_fraud_scenario)
        self.bus.publish("observations", {"observation": observation.__dict__})
        
        # Step 3: Audit with CMVK
        result = self.auditor_agent.audit(claim, observation)
        self.bus.publish("verifications", {"result": result.status.value})
        
        elapsed_ms = (time.time() - start_time) * 1000
        
        return result, elapsed_ms


def run_fraud_scenario():
    """Run fraud detection demo"""
    print("\n" + "="*60)
    print("SCENARIO: FRAUD DETECTION")
    print("="*60)
    
    # Fraudulent project: Claims healthy forest, but deforestation detected
    fraud_project = {
        "project_id": "VCS-FRAUD-001",
        "name": "Amazon Rainforest Protection Initiative",
        "lat": -3.4653,
        "lon": -62.2159,
        "claimed_ndvi": 0.82,  # Claims high vegetation
        "claimed_carbon_tonnes": 180,  # Claims high carbon stock
        "area_hectares": 5000,
        "methodology": "VM0042",
        "year": 2024
    }
    
    print(f"\n[CLAIMS-AGENT] Processing project: {fraud_project['name']}")
    print(f"  Location: {fraud_project['lat']}, {fraud_project['lon']}")
    print(f"  Claimed NDVI: {fraud_project['claimed_ndvi']}")
    print(f"  Claimed Carbon: {fraud_project['claimed_carbon_tonnes']} tonnes/ha")
    
    swarm = CarbonAuditorSwarm()
    result, elapsed_ms = swarm.run_audit(fraud_project, is_fraud_scenario=True)
    
    print(f"\n[GEO-AGENT] Fetching Sentinel-2 imagery...")
    print(f"  Observed NDVI: {result.observation.observed_ndvi:.2f}")
    print(f"  Observed Carbon: {result.observation.observed_carbon_tonnes:.1f} tonnes/ha")
    
    print(f"\n[AUDITOR-AGENT] Running CMVK verification...")
    for step in result.audit_trail:
        print(f"  > {step}")
    
    print(f"\n{'='*60}")
    if result.status == VerificationStatus.FRAUD:
        print(f"[!!!] FRAUD DETECTED [!!!]")
    elif result.status == VerificationStatus.FLAGGED:
        print(f"[!] FLAGGED FOR REVIEW")
    else:
        print(f"[OK] VERIFIED")
    print(f"{'='*60}")
    print(f"Drift Score: {result.drift_score:.4f}")
    print(f"Verification Time: {elapsed_ms:.1f}ms")
    
    return result


def run_verified_scenario():
    """Run verified project demo"""
    print("\n" + "="*60)
    print("SCENARIO: VERIFIED PROJECT")
    print("="*60)
    
    # Legitimate project: Claims match reality
    verified_project = {
        "project_id": "VCS-GOOD-001",
        "name": "Congo Basin Conservation Project",
        "lat": 0.4162,
        "lon": 18.4347,
        "claimed_ndvi": 0.78,
        "claimed_carbon_tonnes": 165,
        "area_hectares": 8000,
        "methodology": "VM0042",
        "year": 2024
    }
    
    print(f"\n[CLAIMS-AGENT] Processing project: {verified_project['name']}")
    print(f"  Location: {verified_project['lat']}, {verified_project['lon']}")
    print(f"  Claimed NDVI: {verified_project['claimed_ndvi']}")
    print(f"  Claimed Carbon: {verified_project['claimed_carbon_tonnes']} tonnes/ha")
    
    swarm = CarbonAuditorSwarm()
    result, elapsed_ms = swarm.run_audit(verified_project, is_fraud_scenario=False)
    
    print(f"\n[GEO-AGENT] Fetching Sentinel-2 imagery...")
    print(f"  Observed NDVI: {result.observation.observed_ndvi:.2f}")
    print(f"  Observed Carbon: {result.observation.observed_carbon_tonnes:.1f} tonnes/ha")
    
    print(f"\n[AUDITOR-AGENT] Running CMVK verification...")
    for step in result.audit_trail:
        print(f"  > {step}")
    
    print(f"\n{'='*60}")
    if result.status == VerificationStatus.FRAUD:
        print(f"[!!!] FRAUD DETECTED [!!!]")
    elif result.status == VerificationStatus.FLAGGED:
        print(f"[!] FLAGGED FOR REVIEW")
    else:
        print(f"[OK] VERIFIED")
    print(f"{'='*60}")
    print(f"Drift Score: {result.drift_score:.4f}")
    print(f"Verification Time: {elapsed_ms:.1f}ms")
    
    return result


def main():
    parser = argparse.ArgumentParser(description="Carbon Credit Auditor Demo")
    parser.add_argument("--scenario", choices=["fraud", "verified", "both"], default="both",
                       help="Which scenario to run")
    parser.add_argument("--verified", action="store_true", help="Run verified scenario (legacy)")
    parser.add_argument("--both", action="store_true", help="Run both scenarios (legacy)")
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("AGENT OS - Carbon Credit Auditor Swarm Demo")
    print("'Catch the Phantom Credits'")
    print("="*60)
    print("\n'The AI didn't decide; the Math decided.'")
    
    # Handle legacy args
    if args.verified:
        args.scenario = "verified"
    if args.both:
        args.scenario = "both"
    
    results = []
    
    if args.scenario in ["fraud", "both"]:
        results.append(("fraud", run_fraud_scenario()))
    
    if args.scenario in ["verified", "both"]:
        results.append(("verified", run_verified_scenario()))
    
    # Summary
    print("\n" + "="*60)
    print("DEMO SUMMARY")
    print("="*60)
    for scenario_name, result in results:
        status_str = "[FRAUD]" if result.status == VerificationStatus.FRAUD else "[OK]"
        print(f"  {scenario_name.upper()}: {status_str} (drift: {result.drift_score:.4f})")
    
    print("\nKey Features Demonstrated:")
    print("  [x] CMVK: Mathematical verification (not LLM inference)")
    print("  [x] AMB: Swarm coordination between agents")
    print("  [x] Drift detection: Claims vs satellite reality")
    print("  [x] Audit trail: Every decision explainable")
    print("="*60)


if __name__ == "__main__":
    main()
