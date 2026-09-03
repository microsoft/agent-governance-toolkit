"""Runtime governance drift detection."""
import logging
from typing import Dict, Any, List
from datetime import datetime, timezone

from .models.admissibility import GovernanceState

logger = logging.getLogger(__name__)


class DriftDetector:
    """Detects governance drift between snapshot and current state."""

    def __init__(self, drift_threshold_hours: float = 1.0):
        self.drift_threshold_hours = drift_threshold_hours

    def detect_drift(
        self,
        snapshot: GovernanceState,
        current_policy_version: str,
        current_authority: Any,
    ) -> Dict[str, Any]:
        """
        Compare snapshot against current state and detect drift.
        Returns a dict with drift_status, events, and recommendation.
        """
        drift_events = []
        is_drifted = False

        # 1. Policy version drift
        if snapshot.policy_version != current_policy_version:
            drift_events.append({
                "type": "policy_version_drift",
                "snapshot": snapshot.policy_version,
                "current": current_policy_version,
                "severity": "HIGH",
            })
            is_drifted = True

        # 2. Session age drift
        age_hours = (datetime.now(timezone.utc) - snapshot.timestamp).total_seconds() / 3600.0
        if age_hours > self.drift_threshold_hours:
            drift_events.append({
                "type": "session_age_drift",
                "age_hours": age_hours,
                "threshold_hours": self.drift_threshold_hours,
                "severity": "MEDIUM",
            })
            is_drifted = True

        # 3. Authority drift (delegation count changed)
        current_delegations = getattr(current_authority, "delegations", [])
        snapshot_delegations = snapshot.details.get("delegations", [])
        if len(current_delegations) != len(snapshot_delegations):
            drift_events.append({
                "type": "authority_drift",
                "snapshot_count": len(snapshot_delegations),
                "current_count": len(current_delegations),
                "severity": "HIGH",
            })
            is_drifted = True

        # 4. Evidence freshness drift (snapshot was fresh, but now evidence would be stale)
        # We can compute from snapshot's evidence_age_hours and current time
        if snapshot.evidence_age_hours + age_hours > 24:  # hardcoded max
            drift_events.append({
                "type": "evidence_stale_drift",
                "age_hours": snapshot.evidence_age_hours + age_hours,
                "severity": "MEDIUM",
            })
            is_drifted = True

        logger.info(f"Drift detection: {'drifted' if is_drifted else 'stable'} with {len(drift_events)} events.")

        return {
            "is_drifted": is_drifted,
            "drift_events": drift_events,
            "snapshot_age_hours": age_hours,
            "recommendation": "REVIEW" if is_drifted else "OK",
        }

    def should_deny(self, snapshot: GovernanceState, current_policy_version: str, current_authority: Any) -> tuple[bool, str]:
        """
        Check if a request should be denied due to drift.
        Returns (should_deny, reason).
        """
        result = self.detect_drift(snapshot, current_policy_version, current_authority)
        if result["is_drifted"]:
            high_severity = any(e.get("severity") == "HIGH" for e in result["drift_events"])
            if high_severity:
                return True, f"Governance drift detected: {result['drift_events']}"
        return False, ""