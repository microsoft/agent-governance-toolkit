from typing import List, Dict, Any, Tuple
import random
import numpy as np
from collections import Counter
from src.capability_discovery import CapabilityDiscovery
from src.capability_replay import CapabilityReplay
from src.models import AgentAction
from src.capability_ontology import TRAINING_ONTOLOGY, OntologyMatcher, KNOWN_PATTERNS, HIDDEN_PATTERNS

class CapabilityBenchmark:
    def __init__(self, ground_truth: List[Dict[str, Any]],
                 train_ratio: float = 0.7,
                 min_samples: int = 3,
                 eps: float = 0.5,
                 hidden_capabilities: List[str] = None):
        self.ground_truth = ground_truth
        self.train_ratio = train_ratio
        self.min_samples = min_samples
        self.eps = eps
        self.hidden_capabilities = hidden_capabilities or []

        random.seed(42)
        shuffled = self.ground_truth[:]
        random.shuffle(shuffled)
        split_idx = int(len(shuffled) * self.train_ratio)
        self.train_data = shuffled[:split_idx]
        self.test_data = shuffled[split_idx:]
        self.train_labels = [gt.get('expected_capability', None) for gt in self.train_data]

        # Build lookup for root cause analysis
        self.known_action_sets = {p.capability_id: set(p.required_actions) for p in KNOWN_PATTERNS}
        self.hidden_action_sets = {p.capability_id: set(p.required_actions) for p in HIDDEN_PATTERNS}

    def _compute_cluster_purity(self, discovered: List[Dict[str, Any]],
                                train_labels: List[str]) -> float:
        purities = []
        for cap in discovered:
            indices = cap.get('trace_indices', [])
            labels = [train_labels[i] for i in indices if i < len(train_labels)]
            if labels:
                most_common = Counter(labels).most_common(1)[0][1]
                purity = most_common / len(labels)
                purities.append(purity)
        return np.mean(purities) if purities else 0.0

    def _root_cause_analysis(self, missing_hidden: List[str]) -> Dict[str, str]:
        """
        For each missing hidden capability, find overlapping known capability.
        """
        causes = {}
        for hidden_id in missing_hidden:
            hidden_actions = self.hidden_action_sets.get(hidden_id, set())
            if not hidden_actions:
                causes[hidden_id] = "No action set defined"
                continue
            # Check overlap with known capabilities
            overlaps = {}
            for known_id, known_actions in self.known_action_sets.items():
                common = hidden_actions.intersection(known_actions)
                if common:
                    overlaps[known_id] = common
            if overlaps:
                # Find the known capability with the most overlap
                best = max(overlaps.items(), key=lambda x: len(x[1]))
                causes[hidden_id] = f"Overlaps with {best[0]} (shared actions: {', '.join(best[1])})"
            else:
                causes[hidden_id] = "No overlap with known capabilities – likely insufficient frequency in traces"
        return causes

    def run(self) -> Dict[str, Any]:
        train_traces = [gt["trace"] for gt in self.train_data]
        discovery = CapabilityDiscovery(min_samples=self.min_samples, eps=self.eps)
        discovered = discovery.discover(train_traces)

        tp = fp = fn = tn = 0
        predictions = []

        for gt in self.test_data:
            trace = gt["trace"]
            expected_cap = gt.get("expected_capability")
            is_hidden = expected_cap in self.hidden_capabilities if expected_cap else False

            replay = CapabilityReplay()
            replay.ontology_matcher = OntologyMatcher(ontology=TRAINING_ONTOLOGY)
            actions_dict = [{"agent": a.agent_id, "action": a.action_type} for a in trace]
            result = replay.replay(actions_dict, context={"workflow_type": gt.get("workflow", "unknown")})
            match_result = result["match_result"]
            predicted_pattern = match_result.get("pattern")
            predicted_cap = predicted_pattern.capability_id if predicted_pattern else None

            if is_hidden:
                if predicted_cap is None:
                    tn += 1
                    predictions.append({"expected": expected_cap, "predicted": "EMERGENT", "correct_hidden": True})
                else:
                    fp += 1
                    predictions.append({"expected": expected_cap, "predicted": predicted_cap, "correct_hidden": False})
            else:
                if expected_cap and predicted_cap:
                    if predicted_cap == expected_cap:
                        tp += 1
                    else:
                        fp += 1
                        fn += 1
                elif expected_cap and not predicted_cap:
                    fn += 1
                elif not expected_cap and predicted_cap:
                    fp += 1
                else:
                    tn += 1
                predictions.append({"expected": expected_cap, "predicted": predicted_cap})

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        # Deduplicate known clusters by classification
        known_clusters_dict = {}
        for cap in discovered:
            if cap['classification'] != "unknown":
                key = cap['classification']
                if key not in known_clusters_dict:
                    known_clusters_dict[key] = cap
        known_clusters = list(known_clusters_dict.values())

        unknown_clusters = []
        for cap in discovered:
            if cap['classification'] == "unknown":
                unknown_clusters.append(cap)

        # Discovery metrics
        hidden_found = 0
        found_hidden_ids = []
        for cap in unknown_clusters:
            indices = cap.get('trace_indices', [])
            labels = [self.train_labels[i] for i in indices if i < len(self.train_labels)]
            if labels and len(set(labels)) == 1:
                label = labels[0]
                if label in self.hidden_capabilities:
                    hidden_found += 1
                    found_hidden_ids.append(label)

        discovery_rate = hidden_found / len(self.hidden_capabilities) if self.hidden_capabilities else 0.0
        missing_hidden = list(set(self.hidden_capabilities) - set(found_hidden_ids))

        # Root cause analysis for missing hidden capabilities
        root_causes = self._root_cause_analysis(missing_hidden)

        false_discoveries = 0
        for cap in unknown_clusters:
            indices = cap.get('trace_indices', [])
            labels = [self.train_labels[i] for i in indices if i < len(self.train_labels)]
            if not labels or len(set(labels)) > 1:
                false_discoveries += 1
            else:
                label = labels[0]
                if label not in self.hidden_capabilities:
                    false_discoveries += 1
        false_discovery_rate = false_discoveries / len(unknown_clusters) if unknown_clusters else 0.0

        purity = self._compute_cluster_purity(discovered, self.train_labels)

        mapping_accuracy = 0.0
        if unknown_clusters:
            correct_mappings = 0
            for cap in unknown_clusters:
                indices = cap.get('trace_indices', [])
                labels = [self.train_labels[i] for i in indices if i < len(self.train_labels)]
                if labels:
                    most_common = Counter(labels).most_common(1)[0][0]
                    if most_common in self.hidden_capabilities:
                        correct_mappings += 1
            mapping_accuracy = correct_mappings / len(unknown_clusters)

        return {
            "train_size": len(self.train_data),
            "test_size": len(self.test_data),
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "known_clusters": known_clusters,
            "unknown_clusters": unknown_clusters,
            "hidden_capabilities": self.hidden_capabilities,
            "found_hidden": found_hidden_ids,
            "missing_hidden": missing_hidden,
            "root_causes": root_causes,
            "discovered_capabilities": discovered,
            "predictions": predictions,
            "discovery_rate": discovery_rate,
            "false_discovery_rate": false_discovery_rate,
            "cluster_purity": purity,
            "analyst_mapping_accuracy": mapping_accuracy,
        }