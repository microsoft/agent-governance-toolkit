"""
Novelty Scorer – Computes how novel a capability is relative to known patterns.
"""

from typing import List, Dict, Any, Set
from src.capability_ontology import KNOWN_PATTERNS, HIDDEN_PATTERNS

class NoveltyScorer:
    def __init__(self):
        self.known_action_sets = [
            set(p.required_actions) for p in KNOWN_PATTERNS + HIDDEN_PATTERNS
        ]

    def novelty_score(self, actions: List[Dict[str, str]]) -> float:
        """
        Compute novelty as 1 - maximum Jaccard similarity to known patterns.
        Higher score means more novel.
        """
        action_set = {a["action"] for a in actions}
        if not action_set:
            return 1.0

        max_sim = 0.0
        for known_set in self.known_action_sets:
            if not known_set:
                continue
            intersection = action_set.intersection(known_set)
            union = action_set.union(known_set)
            sim = len(intersection) / len(union) if union else 0.0
            if sim > max_sim:
                max_sim = sim

        # Novelty = 1 - max similarity to known
        return 1.0 - max_sim