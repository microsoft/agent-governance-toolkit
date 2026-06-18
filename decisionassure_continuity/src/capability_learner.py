"""
Capability Learner – Suggests labels, computes novelty, priority, and manages review.
"""

from typing import List, Dict, Any, Optional, Set
import json
import os
from src.capability_review_queue import CapabilityReviewQueue
from src.capability_ontology import KNOWN_PATTERNS, HIDDEN_PATTERNS
from src.novelty_scorer import NoveltyScorer
from src.impact_scorer import ImpactScorer
from src.priority_scorer import PriorityScorer
from src.models import AgentAction

class CapabilityLearner:
    def __init__(self, label_store_path: str = "data/labels.json", data_dir: str = "data",
                 traces: Optional[List[List[AgentAction]]] = None):
        self.label_store_path = label_store_path
        self.review_queue = CapabilityReviewQueue(data_dir=data_dir)
        self.labels = self._load_labels()
        self.novelty_scorer = NoveltyScorer()
        self.impact_scorer = ImpactScorer(traces or [])
        self.priority_scorer = PriorityScorer(self.novelty_scorer, self.impact_scorer)
        self._coverage_cache = None

    def _load_labels(self) -> Dict[str, str]:
        if os.path.exists(self.label_store_path):
            with open(self.label_store_path, 'r') as f:
                return json.load(f)
        return {}

    def _save_labels(self):
        os.makedirs(os.path.dirname(self.label_store_path), exist_ok=True)
        with open(self.label_store_path, 'w') as f:
            json.dump(self.labels, f, indent=2)

    def _action_similarity(self, actions1: Set[str], actions2: Set[str]) -> float:
        if not actions1 or not actions2:
            return 0.0
        intersection = actions1.intersection(actions2)
        union = actions1.union(actions2)
        return len(intersection) / len(union) if union else 0.0

    def suggest_label(self, actions: List[Dict[str, str]]) -> Dict[str, Any]:
        action_set = set(a["action"] for a in actions)
        best_match = None
        best_score = 0.0
        best_pattern = None
        all_patterns = KNOWN_PATTERNS + HIDDEN_PATTERNS
        for pattern in all_patterns:
            pattern_actions = set(pattern.required_actions)
            score = self._action_similarity(action_set, pattern_actions)
            if score > best_score:
                best_score = score
                best_pattern = pattern
                best_match = pattern.name
        if best_score < 0.5:
            for label, actions_json in self.labels.items():
                stored_set = set(json.loads(actions_json))
                score = self._action_similarity(action_set, stored_set)
                if score > best_score:
                    best_score = score
                    best_match = label
                    best_pattern = None
        return {
            "suggested_label": best_match if best_score >= 0.3 else "New Capability",
            "confidence": best_score,
            "matched_pattern": best_pattern,
            "action_set": list(action_set)
        }

    def add_label(self, action_set: List[Dict[str, str]], label: str):
        key = json.dumps(sorted([a["action"] for a in action_set]))
        self.labels[label] = key
        self._save_labels()
        self._coverage_cache = None

    # ===== CORRECTED COVERAGE =====
    def get_coverage(self, discovered: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Compute coverage metrics from discovered capabilities only.
        (Approved capabilities are already reflected in the discovered list if the ontology was updated.)
        """
        known_total = len(KNOWN_PATTERNS)
        discovered_total = len(discovered)
        discovered_classified = len([cap for cap in discovered if cap['classification'] != 'unknown'])
        unknown_total = discovered_total - discovered_classified

        total_possible = known_total + discovered_classified
        classified_coverage = discovered_classified / total_possible if total_possible > 0 else 0.0
        unknown_coverage = unknown_total / discovered_total if discovered_total > 0 else 0.0

        self._coverage_cache = {
            "known_capabilities": known_total,
            "discovered_capabilities": discovered_total,
            "classified_capabilities": discovered_classified,
            "unknown_capabilities": unknown_total,
            "classified_coverage_percent": round(classified_coverage * 100, 1),
            "unknown_coverage_percent": round(unknown_coverage * 100, 1),
            "total_possible": total_possible
        }
        return self._coverage_cache

    def submit_for_review(self, capability_id: str, capability_name: str,
                          required_actions: List[Dict[str, str]],
                          evidence_hash: Optional[str] = None,
                          severity: str = "unknown") -> Dict[str, Any]:
        suggestion = self.suggest_label(required_actions)
        novelty = self.novelty_scorer.novelty_score(required_actions)
        impact = self.impact_scorer.compute_impact(required_actions)
        priority = self.priority_scorer.compute_priority({
            "required_actions": required_actions,
            "severity": severity
        })
        item = self.review_queue.add_for_review(
            capability_id=capability_id,
            capability_name=capability_name,
            required_actions=required_actions,
            evidence_hash=evidence_hash
        )
        return {
            "submitted": True,
            "item": item.__dict__,
            "suggestion": suggestion,
            "novelty": novelty,
            "impact": impact,
            "priority": priority,
            "queue_position": len(self.review_queue.get_pending_reviews())
        }

    def approve_and_add_to_ontology(self, capability_id: str, reviewer: str,
                                    reasoning: str, capability_name: str,
                                    required_actions: List[Dict[str, str]]) -> Dict[str, Any]:
        success = self.review_queue.approve_review(
            capability_id=capability_id,
            reviewer=reviewer,
            reasoning=reasoning,
            capability_name=capability_name,
            required_actions=required_actions
        )
        if success:
            self.add_label(required_actions, capability_name)
            self._coverage_cache = None
        return {"approved": success}

    def get_pending_reviews(self) -> List[Dict[str, Any]]:
        return [item.__dict__ for item in self.review_queue.get_pending_reviews()]

    def get_ledger(self) -> List[Dict[str, Any]]:
        return [change.__dict__ for change in self.review_queue.get_ledger_entries()]