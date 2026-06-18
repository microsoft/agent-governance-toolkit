"""
Priority Scorer – Computes a balanced priority score for review.
Priority = 0.4*Novelty + 0.3*SeverityWeight + 0.3*NormalizedImpact
"""

from typing import Dict, Any

SEVERITY_WEIGHTS = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.3,
    "unknown": 0.5
}

class PriorityScorer:
    def __init__(self, novelty_scorer, impact_scorer):
        self.novelty_scorer = novelty_scorer
        self.impact_scorer = impact_scorer

    def compute_priority(self, capability: Dict[str, Any]) -> float:
        required_actions = capability.get('required_actions', [])
        novelty = self.novelty_scorer.novelty_score(required_actions)
        severity = capability.get('severity', 'unknown')
        severity_weight = SEVERITY_WEIGHTS.get(severity, 0.5)
        impact = self.impact_scorer.compute_impact(required_actions)
        normalized_impact = min(impact / 100.0, 1.0) if impact > 0 else 0.0

        # Balanced formula: novelty (40%), severity (30%), impact (30%)
        return 0.4 * novelty + 0.3 * severity_weight + 0.3 * normalized_impact