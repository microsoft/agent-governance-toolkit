from typing import List, Dict, Any, Set, Tuple
from collections import defaultdict, Counter
from datetime import datetime
import hashlib
import json
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer
from src.models import AgentAction, CapabilityWitness
from src.capability_ontology import OntologyMatcher

class CapabilityDiscovery:
    def __init__(self, min_samples: int = 3, eps: float = 0.5):
        self.min_samples = min_samples
        self.eps = eps
        self.discovered_capabilities: List[Dict[str, Any]] = []
        self.ontology_matcher = OntologyMatcher()

    def _extract_action_signatures(self, traces: List[List[AgentAction]]) -> List[str]:
        signatures = []
        for trace in traces:
            agent_actions: Dict[str, Set[str]] = defaultdict(set)
            for act in trace:
                agent_actions[act.agent_id].add(act.action_type)
            sig_parts = []
            for agent, actions in sorted(agent_actions.items()):
                sig_parts.append(f"{agent}:" + ",".join(sorted(actions)))
            signatures.append("|".join(sig_parts))
        return signatures

    def _compute_action_matrix(self, traces: List[List[AgentAction]]) -> Tuple[np.ndarray, List[str]]:
        signatures = self._extract_action_signatures(traces)
        vectorizer = TfidfVectorizer()
        X = vectorizer.fit_transform(signatures)
        return X, vectorizer.get_feature_names_out().tolist()

    def _is_noise_cluster(self, required_actions: List[Dict[str, str]]) -> bool:
        """
        Filter out clusters that don't represent meaningful capability composition.
        """
        action_types = [a["action"] for a in required_actions]
        unique_actions = set(action_types)
        if len(unique_actions) <= 1:
            return True
        if len(action_types) == len(set(a["agent"] for a in required_actions)):
            return False
        action_prefixes = [a.split("_")[0] for a in action_types if "_" in a]
        if len(set(action_prefixes)) <= 1:
            return True
        return False

    def discover(self, traces: List[List[AgentAction]]) -> List[Dict[str, Any]]:
        if len(traces) < self.min_samples:
            return []

        X, feature_names = self._compute_action_matrix(traces)
        clustering = DBSCAN(eps=self.eps, min_samples=self.min_samples)
        labels = clustering.fit_predict(X.toarray())

        cluster_counts = Counter(labels)
        discovered = []

        for label, count in cluster_counts.items():
            if label == -1:
                continue

            cluster_indices = [i for i, l in enumerate(labels) if l == label]
            cluster_traces = [traces[i] for i in cluster_indices]

            action_sets: List[Set[Tuple[str, str]]] = []
            for trace in cluster_traces:
                actions = set()
                for act in trace:
                    actions.add((act.agent_id, act.action_type))
                action_sets.append(actions)

            common_actions = set.intersection(*action_sets) if action_sets else set()
            confidence = len(cluster_traces) / len(traces)

            if common_actions:
                required_actions = [{"agent": a, "action": b} for a, b in sorted(common_actions)]

                # Filter noise
                if self._is_noise_cluster(required_actions):
                    continue

                action_types = {b for _, b in common_actions}

                # Try to match to known ontology
                match_result = self.ontology_matcher.match(action_types)
                matched_pattern = match_result.get("pattern")

                capability_id = f"discovered_{hashlib.md5(str(required_actions).encode()).hexdigest()[:12]}"
                capability_name = matched_pattern.name if matched_pattern else f"Unknown Capability ({len(common_actions)} actions)"
                severity = matched_pattern.severity if matched_pattern else "unknown"
                classification = matched_pattern.capability_id if matched_pattern else "unknown"
                confidence_score = match_result["confidence"]

                # ----- CONFIDENCE BOOST LOGIC -----
                # Boost confidence if all agents are distinct (each action performed by a different agent)
                agents_set = set(a["agent"] for a in required_actions)
                if len(agents_set) == len(required_actions):
                    confidence_score = min(confidence_score + 0.15, 1.0)
                # Also ensure confidence_score is at least the base match confidence
                confidence_score = max(confidence_score, match_result["confidence"])
                # ----- END BOOST -----

                # Generate witness
                witness = CapabilityWitness(
                    capability_id=capability_id,
                    capability_name=capability_name,
                    required_actions=required_actions
                )
                witness.witness_hash = witness.compute_witness_hash()

                # Counterfactual proof
                counterfactual_results = []
                for agent in set(a["agent"] for a in required_actions):
                    remaining = [a for a in required_actions if a["agent"] != agent]
                    still_exists = set(a["action"] for a in remaining) == set(a["action"] for a in required_actions)
                    counterfactual_results.append({
                        "removed_agent": agent,
                        "capability_still_exists": still_exists,
                        "remaining_actions": remaining
                    })

                discovered.append({
                    "capability_id": capability_id,
                    "capability_name": capability_name,
                    "required_actions": required_actions,
                    "confidence": confidence,                    # cluster frequency confidence
                    "match_confidence": confidence_score,       # ontology match confidence (boosted)
                    "classification": classification,
                    "severity": severity,
                    "occurrence_count": len(cluster_traces),
                    "trace_indices": cluster_indices,
                    "witness": witness.model_dump(mode='json'),
                    "counterfactual_proof": counterfactual_results,
                    "discovered_at": datetime.now().isoformat()
                })

        self.discovered_capabilities = discovered
        return discovered