"""
Capability Drift Replay – Replay historical traces against an evolved ontology.
"""

import json, os
from typing import List, Dict, Any
from datetime import datetime
from src.capability_replay import CapabilityReplay
from src.capability_ontology import OntologyMatcher, TRAINING_ONTOLOGY
from src.models import AgentAction

class CapabilityDriftReplay:
    def __init__(self, ontology_path: str = "evolved_ontology.json"):
        self.ontology_path = ontology_path
        self._load_ontology()

    def _load_ontology(self):
        if os.path.exists(self.ontology_path):
            with open(self.ontology_path, 'r') as f:
                data = json.load(f)
                from src.models import CapabilityPattern, CapabilityOntology
                patterns = []
                for p in data.get("patterns", []):
                    patterns.append(CapabilityPattern(
                        capability_id=p["capability_id"],
                        name=p["name"],
                        description=p.get("description", ""),
                        severity=p.get("severity", "unknown"),
                        required_actions=p.get("required_actions", []),
                        min_agents=p.get("min_agents", 1),
                        max_agents=p.get("max_agents", 10)
                    ))
                self.ontology = CapabilityOntology(patterns=patterns)
        else:
            self.ontology = TRAINING_ONTOLOGY

    def replay_trace(self, trace: List[AgentAction]) -> Dict[str, Any]:
        replay = CapabilityReplay()
        replay.ontology_matcher = OntologyMatcher(ontology=self.ontology)
        actions_dict = [{"agent": a.agent_id, "action": a.action_type} for a in trace]
        return replay.replay(actions_dict)

    def replay_traces(self, traces: List[List[AgentAction]]) -> Dict[str, Any]:
        results = []
        new_incidents = 0
        for trace in traces:
            result = self.replay_trace(trace)
            match_result = result.get("match_result", {})
            pattern = match_result.get("pattern")
            decision = match_result.get("decision", "MONITOR")
            if pattern and decision in ["DENY", "HUMAN_REVIEW"]:
                new_incidents += 1
            results.append({
                "trace": trace,
                "result": result,
                "would_flag": pattern is not None and decision in ["DENY", "HUMAN_REVIEW"]
            })
        return {
            "total_traces": len(traces),
            "new_incidents": new_incidents,
            "results": results,
            "timestamp": datetime.now().isoformat()
        }

    def compare_with_old(self, traces: List[List[AgentAction]]) -> Dict[str, Any]:
        self._load_ontology()
        if not self.ontology.patterns:
            return {
                "old_incidents": 0,
                "new_incidents": 0,
                "change": 0,
                "reduction_percent": 0.0,
                "note": "No approved ontology entries available. Please review and approve capabilities first.",
                "coverage_increase": 0.0,
                "newly_detected": 0,
                "total_detected": 0,
                "counterfactual": {}
            }
        old_replay = CapabilityReplay()
        old_replay.ontology_matcher = OntologyMatcher(ontology=TRAINING_ONTOLOGY)
        new_replay = CapabilityReplay()
        new_replay.ontology_matcher = OntologyMatcher(ontology=self.ontology)

        old_incidents = 0
        new_incidents = 0
        newly_detected = []
        total_detected = 0

        decision_counts = {"DENY": 0, "HUMAN_REVIEW": 0, "MONITOR": 0, "ADMIT": 0}
        old_decision_counts = {"DENY": 0, "HUMAN_REVIEW": 0, "MONITOR": 0, "ADMIT": 0}

        for i, trace in enumerate(traces):
            actions_dict = [{"agent": a.agent_id, "action": a.action_type} for a in trace]
            old_result = old_replay.replay(actions_dict)
            new_result = new_replay.replay(actions_dict)
            old_match = old_result.get("match_result", {}).get("pattern")
            new_match = new_result.get("match_result", {}).get("pattern")
            old_decision = old_result.get("match_result", {}).get("decision", "MONITOR")
            new_decision = new_result.get("match_result", {}).get("decision", "MONITOR")

            old_flagged = old_match is not None and old_decision in ["DENY", "HUMAN_REVIEW"]
            new_flagged = new_match is not None and new_decision in ["DENY", "HUMAN_REVIEW"]

            if old_flagged:
                old_incidents += 1
                old_decision_counts[old_decision] = old_decision_counts.get(old_decision, 0) + 1
            if new_flagged:
                new_incidents += 1
                decision_counts[new_decision] = decision_counts.get(new_decision, 0) + 1
                total_detected += 1
                if not old_flagged:
                    newly_detected.append(i)

        change = new_incidents - old_incidents
        reduction_percent = 0.0
        if old_incidents > 0:
            reduction_percent = abs(change / old_incidents) * 100

        coverage_increase = len(newly_detected) / len(traces) * 100 if traces else 0.0

        # Build counterfactual analytics – includes by_capability
        counterfactual = {
            "total_traces": len(traces),
            "total_detected": total_detected,
            "newly_detected": len(newly_detected),
            "decisions": decision_counts,
            "old_decisions": old_decision_counts,
            "by_capability": {}
        }

        # For each pattern in the evolved ontology, count how many traces match
        for pattern in self.ontology.patterns:
            cap_name = pattern.name
            cap_actions = set(pattern.required_actions)
            count = 0
            for trace in traces:
                trace_set = {(act.agent_id, act.action_type) for act in trace}
                # Check if all actions are present (ignoring agent names for simplicity)
                if cap_actions.issubset({a[1] for a in trace_set}):
                    count += 1
            if count > 0:
                counterfactual["by_capability"][cap_name] = count

        return {
            "old_incidents": old_incidents,
            "new_incidents": new_incidents,
            "change": change,
            "reduction_percent": reduction_percent,
            "newly_detected": len(newly_detected),
            "total_detected": total_detected,
            "coverage_increase": coverage_increase,
            "counterfactual": counterfactual,
            "timestamp": datetime.now().isoformat()
        }