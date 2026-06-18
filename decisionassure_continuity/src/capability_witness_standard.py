"""
Capability Witness Standard – Portable format for capability witnesses.
"""

from typing import Dict, Any, List
from datetime import datetime
import json

class CapabilityWitnessStandard:
    @staticmethod
    def export_witness(
        capability: Dict[str, Any],
        required_actions: List[Dict[str, str]],
        witness_hash: str,
        counterfactual_details: List[Dict[str, Any]],
        severity: str,
        recommendation: str,
        confidence: float = 0.0,
        framework: str = "unknown"
    ) -> Dict[str, Any]:
        return {
            "schema_version": "1.0",
            "witness_type": "capability_witness",
            "timestamp": datetime.now().isoformat(),
            "framework": framework,
            "capability": {
                "name": capability.get("name", "unknown"),
                "id": capability.get("id", "unknown"),
                "severity": severity,
                "confidence": confidence
            },
            "required_actions": required_actions,
            "witness_hash": witness_hash,
            "counterfactual_verified": all(
                cf["capability_still_exists"] is False for cf in counterfactual_details
            ),
            "counterfactual_details": counterfactual_details,
            "governance_recommendation": recommendation,
            "trace_claim": {
                "format": "TRACE v0.1",
                "claim_type": "capability_witness",
                "hash": witness_hash,
                "evidence": required_actions,
                "recommendation": recommendation
            }
        }