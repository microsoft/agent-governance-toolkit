"""Integration hooks for AGT and other agent frameworks."""
import logging
from typing import Dict, Any, Optional

from .engine import ImpactEngine
from .drift import DriftDetector
from .models.trace import TraceBatch
from .models.admissibility import GovernanceState

logger = logging.getLogger(__name__)


def analyze_impact_for_pr(
    current_policy: Dict[str, Any],
    proposed_policy: Dict[str, Any],
    traces_path: str,
    authority: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Analyze the impact of a proposed policy change (e.g., in a PR).
    Returns a dict with the ImpactReport.
    """
    from .cli import load_traces

    traces = load_traces(traces_path)
    engine = ImpactEngine(traces)

    if authority is None:
        authority = {"delegations": [], "global_tool_capabilities": {}}

    report = engine.analyze_impact(current_policy, authority, proposed_policy, authority)
    return report.model_dump(mode="json", exclude_none=True)


def check_runtime_drift(
    snapshot: GovernanceState,
    current_policy_version: str,
    current_authority: Dict[str, Any],
    drift_threshold_hours: float = 1.0,
) -> Dict[str, Any]:
    """
    Check if the current execution context has drifted from its governance snapshot.
    """
    detector = DriftDetector(drift_threshold_hours)
    result = detector.detect_drift(snapshot, current_policy_version, current_authority)
    return result


def create_snapshot_from_context(context: Dict[str, Any]) -> GovernanceState:
    """
    Create a GovernanceState snapshot from an AGT execution context.
    This should be called at session start.
    """
    return GovernanceState(
        policy_version=context.get("policy_version", "unknown"),
        policy_valid=True,
        authority_valid=True,
        authority_chain=context.get("authority_chain", []),
        evidence_fresh=True,
        evidence_age_hours=0.0,
        capability_authorized=True,
        tool_permissions=context.get("tool_permissions", []),
        model_approved=True,
        model_version=context.get("model_version", ""),
        context_valid=True,
        is_admissible=True,
        details=context.get("details", {}),
    )