# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Auditor Agent (Agent C) - "The Judge"

The decision maker that uses cmvk (Verification Kernel) to detect fraud.
Compares claims against observations using mathematical verification.

Updated for cmvk 0.2.0:
- DistanceMetric.EUCLIDEAN for magnitude-based fraud detection
- threshold_profile="carbon" for domain-specific thresholds
- explain=True for drift explainability
- AuditTrail for immutable verification logs
- dimension_names for readable explanations
"""

from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime, timezone

import numpy as np
import cmvk
from cmvk import (
    verify_embeddings,
    DistanceMetric,
    DriftType,
    AuditTrail,
    configure_audit_trail,
    get_audit_trail,
)

from .base import BaseAgent


@dataclass
class ClaimVector:
    """Vector representation of a carbon credit claim."""
    project_id: str
    ndvi: float
    carbon_stock: float
    year: int
    
    def to_array(self) -> np.ndarray:
        """Convert to numpy array for verification."""
        return np.array([self.ndvi, self.carbon_stock / 1000.0])


@dataclass
class ObservationVector:
    """Vector representation of satellite observations."""
    project_id: str
    ndvi_mean: float
    ndvi_std: float
    cloud_cover: float
    vegetation_coverage: float
    deforestation_indicator: float
    
    @property
    def estimated_carbon_stock(self) -> float:
        """Estimate carbon stock from NDVI (simplified model)."""
        return 250 * (self.ndvi_mean ** 2)
    
    def to_array(self) -> np.ndarray:
        """Convert to numpy array for verification."""
        return np.array([self.ndvi_mean, self.estimated_carbon_stock / 1000.0])
    
    @property
    def confidence(self) -> float:
        """Calculate observation confidence score."""
        cloud_penalty = 1.0 - self.cloud_cover
        variance_penalty = 1.0 - min(self.ndvi_std / 0.3, 1.0)
        return cloud_penalty * variance_penalty


# Dimension names for cmvk explainability (CMVK-010)
DIMENSION_NAMES = ["ndvi", "carbon_stock_normalized"]


class AuditorAgent(BaseAgent):
    """
    The Auditor Agent - "The Judge"
    
    Role: Decision maker that:
        - Subscribes to both Claim and Observation messages
        - Uses cmvk (Verification Kernel) to calculate drift scores
        - Issues verification results: VERIFIED, FLAGGED, or FRAUD
    
    KEY PRINCIPLE: "The AI didn't decide; the Math decided."
    
    The agent doesn't use LLM inference for the verification decision.
    It uses deterministic mathematical calculations via cmvk.
    
    cmvk 0.2.0 Features Used:
        - DistanceMetric.EUCLIDEAN for magnitude-based fraud detection
        - threshold_profile="carbon" for domain-specific thresholds
        - explain=True for drift explainability
        - AuditTrail for immutable verification logs
    
    Subscribes to: CLAIMS, OBSERVATIONS
    Publishes: Verification results and ALERTS
    """

    # Thresholds for verification
    FRAUD_THRESHOLD = 0.15
    FLAG_THRESHOLD = 0.10

    def __init__(
        self,
        agent_id: str,
        threshold: float = 0.15,
        enable_audit_trail: bool = True,
    ):
        """
        Initialize the Auditor Agent.
        
        Args:
            agent_id: Unique identifier
            threshold: Drift score threshold for fraud detection
            enable_audit_trail: Enable cmvk audit trail (CMVK-006)
        """
        super().__init__(agent_id, name="auditor-agent")
        
        self._threshold = threshold
        self._verification_count = 0
        self._results: List[Dict[str, Any]] = []
        
        # NEW: Configure cmvk audit trail (CMVK-006)
        if enable_audit_trail:
            # configure_audit_trail returns an AuditTrail instance
            self._audit_trail = configure_audit_trail(persist_path=None, auto_persist=False)
        else:
            self._audit_trail = None

    @property
    def subscribed_topics(self) -> List[str]:
        """Subscribe to both claims and observations."""
        return ["vcm.claims", "vcm.observations"]

    def verify_project(
        self,
        claim_data: Dict[str, Any],
        observation_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Perform mathematical verification using cmvk.
        
        This is where "the Math decides, not the AI."
        
        Args:
            claim_data: The claim from the claims agent
            observation_data: The observation from the geo agent
            
        Returns:
            Verification result dictionary
        """
        project_id = claim_data.get("project_id", "UNKNOWN")
        
        self._log(f"Performing verification for project: {project_id}")
        self._log("="*60)
        self._metrics.last_activity = datetime.now(timezone.utc)
        
        # Build vectors
        claim_vector = ClaimVector(
            project_id=project_id,
            ndvi=claim_data.get("claimed_ndvi", 0.0),
            carbon_stock=claim_data.get("claimed_carbon_stock", 0.0),
            year=claim_data.get("year", 2024),
        )
        
        observation_vector = ObservationVector(
            project_id=project_id,
            ndvi_mean=observation_data.get("observed_ndvi_mean", 0.0),
            ndvi_std=observation_data.get("observed_ndvi_std", 0.0),
            cloud_cover=observation_data.get("cloud_cover", 0.0),
            vegetation_coverage=observation_data.get("vegetation_coverage", 0.0),
            deforestation_indicator=observation_data.get("deforestation_indicator", 0.0),
        )
        
        self._log(f"Claim Vector: ndvi={claim_vector.ndvi}, carbon={claim_vector.carbon_stock}")
        self._log(f"Observation Vector: ndvi={observation_vector.ndvi_mean:.3f}, "
                  f"est_carbon={observation_vector.estimated_carbon_stock:.1f}")
        
        # Convert to arrays for verification
        claim_arr = claim_vector.to_array()
        obs_arr = observation_vector.to_array()
        
        # =====================================================================
        # cmvk 0.2.0 - Full featured verification
        # =====================================================================
        # NEW: Use Euclidean metric (CMVK-001, CMVK-002)
        # NEW: Use carbon threshold profile (CMVK-005)
        # NEW: Enable explainability (CMVK-010)
        # NEW: Use dimension names for readable explanations
        # NEW: Audit trail configured in __init__ (CMVK-006)
        cmvk_result = verify_embeddings(
            claim_arr,
            obs_arr,
            metric="euclidean",  # CMVK-001: Euclidean distance!
            threshold_profile="carbon",  # CMVK-005: Domain-specific thresholds
            explain=True,  # CMVK-010: Explainability
            dimension_names=DIMENSION_NAMES,  # For readable explanations
            audit_trail=self._audit_trail,  # CMVK-006: Audit trail
        )
        
        # Extract drift score from cmvk result
        drift_score = float(cmvk_result.drift_score)
        
        self._verification_count += 1
        
        # Determine status based on drift
        if drift_score > self._threshold:
            status = "FRAUD"
        elif drift_score > self.FLAG_THRESHOLD:
            status = "FLAGGED"
        else:
            status = "VERIFIED"
        
        # Build detailed result
        details = self._calculate_details(claim_vector, observation_vector, drift_score)
        
        # Extract explanation if available (CMVK-010)
        explanation = None
        if hasattr(cmvk_result, 'explanation') and cmvk_result.explanation:
            expl = cmvk_result.explanation
            # explanation is a dict in cmvk 0.2.0
            explanation = {
                "primary_drift_dimension": expl.get('primary_drift_dimension'),
                "dimension_contributions": expl.get('dimension_contributions'),
                "interpretation": expl.get('interpretation'),
            }
        
        result = {
            "project_id": project_id,
            "status": status,
            "drift_score": drift_score,
            "threshold": self._threshold,
            "confidence": float(observation_vector.confidence),
            "claim_vector": claim_arr.tolist(),
            "observation_vector": obs_arr.tolist(),
            "metric": "euclidean",  # cmvk 0.2.0!
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details,
            "cmvk_drift_type": cmvk_result.drift_type.value,
            "cmvk_confidence": float(cmvk_result.confidence),
            "cmvk_explanation": explanation,  # NEW: Explainability (CMVK-010)
        }
        
        self._log(f"Verification Result: status={status}, drift_score={drift_score:.4f}")
        self._results.append(result)
        
        # Issue alert if fraud detected
        if status == "FRAUD":
            self._issue_alert(result)
        
        return result

    def _calculate_details(
        self,
        claim: ClaimVector,
        observation: ObservationVector,
        drift_score: float,
    ) -> Dict[str, Any]:
        """Calculate detailed breakdown for audit trail."""
        ndvi_diff = claim.ndvi - observation.ndvi_mean
        ndvi_pct_diff = abs(ndvi_diff) / claim.ndvi * 100 if claim.ndvi else 0
        
        carbon_diff = claim.carbon_stock - observation.estimated_carbon_stock
        carbon_pct_diff = abs(carbon_diff) / claim.carbon_stock * 100 if claim.carbon_stock else 0
        
        return {
            "ndvi_claimed": claim.ndvi,
            "ndvi_observed": observation.ndvi_mean,
            "ndvi_difference": round(ndvi_diff, 4),
            "ndvi_percent_difference": round(ndvi_pct_diff, 2),
            "carbon_claimed": claim.carbon_stock,
            "carbon_observed": round(observation.estimated_carbon_stock, 2),
            "carbon_difference": round(carbon_diff, 2),
            "carbon_percent_difference": round(carbon_pct_diff, 2),
            "observation_confidence": round(observation.confidence, 4),
            "deforestation_indicator": observation.deforestation_indicator,
            "vegetation_coverage": observation.vegetation_coverage,
            "audit_note": self._generate_audit_note(drift_score, ndvi_pct_diff, carbon_pct_diff),
        }

    def _generate_audit_note(
        self,
        drift_score: float,
        ndvi_pct_diff: float,
        carbon_pct_diff: float,
    ) -> str:
        """Generate human-readable audit note."""
        if drift_score > self._threshold:
            return (
                f"CRITICAL: Mathematical verification failed. "
                f"NDVI discrepancy: {ndvi_pct_diff:.1f}%, "
                f"Carbon stock discrepancy: {carbon_pct_diff:.1f}%. "
                f"Drift score ({drift_score:.4f}) exceeds threshold ({self._threshold}). "
                f"Recommend investigation for potential fraud."
            )
        elif drift_score > self.FLAG_THRESHOLD:
            return (
                f"WARNING: Minor discrepancies detected. "
                f"NDVI discrepancy: {ndvi_pct_diff:.1f}%, "
                f"Carbon stock discrepancy: {carbon_pct_diff:.1f}%. "
                f"Recommend manual review."
            )
        else:
            return (
                f"VERIFIED: Claim aligns with satellite observations. "
                f"NDVI discrepancy: {ndvi_pct_diff:.1f}%, "
                f"Carbon stock discrepancy: {carbon_pct_diff:.1f}%. "
                f"Within acceptable tolerance."
            )

    def _issue_alert(self, result: Dict[str, Any]) -> None:
        """Issue a CRITICAL alert for detected fraud."""
        self._log("!"*60, level="ALERT")
        self._log(f"FRAUD DETECTED: {result['project_id']}", level="ALERT")
        self._log(f"Drift Score: {result['drift_score']:.4f} (threshold: {result['threshold']})", level="ALERT")
        self._log("!"*60, level="ALERT")

    def get_results(self) -> List[Dict[str, Any]]:
        """Get all verification results."""
        return self._results

    def get_kernel_stats(self) -> Dict[str, Any]:
        """Get verification kernel statistics."""
        stats = {
            "verification_count": self._verification_count,
            "threshold": self._threshold,
            "flag_threshold": self.FLAG_THRESHOLD,
            "cmvk_version": "0.2.0",
            "metric": "euclidean",
            "threshold_profile": "carbon",
        }
        
        # NEW: Include audit trail stats (CMVK-006)
        if self._audit_trail:
            stats["audit_trail_entries"] = len(self._audit_trail.entries)
        
        return stats

    def get_audit_trail(self) -> Optional[List[Dict[str, Any]]]:
        """Get the cmvk audit trail entries (CMVK-006)."""
        if self._audit_trail and self._audit_trail.entries:
            return [entry.to_dict() for entry in self._audit_trail.entries]
        return None
