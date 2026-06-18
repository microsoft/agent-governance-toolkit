"""
Capability Witness Engine – Produces verifiable capability witnesses with confidence,
minimal action sets, counterfactual proof, and governance recommendations.
Supports a governance learning loop: unknown witnesses can be labelled and added to the ontology.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from src.models import AgentAction
from src.capability_discovery import CapabilityDiscovery
from src.capability_replay import CapabilityReplay
from src.capability_learner import CapabilityLearner
from src.capability_ontology import load_ontology_from_file, OntologyMatcher

class CapabilityWitnessEngine:
    def __init__(self, min_samples: int = 3, eps: float = 0.5,
                 confidence_threshold: float = 0.5, learner: Optional[CapabilityLearner] = None):
        self.min_samples = min_samples
        self.eps = eps
        self.confidence_threshold = confidence_threshold
        self.learner = learner or CapabilityLearner()
        self.ontology = load_ontology_from_file("evolved_ontology.json")
        self.discovery = CapabilityDiscovery(min_samples=min_samples, eps=eps)
        # Ensure discovery uses the loaded ontology
        self.discovery.ontology_matcher = OntologyMatcher(ontology=self.ontology)

    def _refresh_ontology(self):
        """
        Reload the ontology from the evolved file and update the discovery matcher.
        """
        self.ontology = load_ontology_from_file("evolved_ontology.json")
        self.discovery.ontology_matcher = OntologyMatcher(ontology=self.ontology)

    def process_traces(self, traces: List[List[AgentAction]]) -> List[Dict[str, Any]]:
        # Refresh ontology before processing
        self._refresh_ontology()

        discovered = self.discovery.discover(traces)
        witnesses = []

        for cap in discovered:
            actions = [AgentAction(agent_id=a["agent"], action_type=a["action"]) for a in cap['required_actions']]
            # Use the refreshed ontology in replay
            replay = CapabilityReplay()
            replay.ontology_matcher = OntologyMatcher(ontology=self.ontology)
            actions_dict = [{"agent": a.agent_id, "action": a.action_type} for a in actions]
            result = replay.replay(actions_dict)

            confidence = cap.get('match_confidence', 0.5)
            if result.get('verification', 'unknown') == 'verified':
                confidence = min(confidence + 0.1, 1.0)

            minimal_witness = True
            for cf in result.get('counterfactual', []):
                if cf.get('capability_still_exists', True):
                    minimal_witness = False
                    break

            severity = cap.get('severity', 'unknown')
            classification = cap.get('classification', 'unknown')

            # Determine if this is a false witness claim
            is_false = False
            false_reason = None
            if confidence < self.confidence_threshold:
                is_false = True
                false_reason = f"Confidence {confidence:.2%} below threshold {self.confidence_threshold:.2%}"
            elif severity == 'unknown' and classification == 'unknown':
                is_false = True
                false_reason = "Classification unresolved – insufficient evidence to map to known capability"
            elif not result.get('verification', 'unknown') == 'verified':
                is_false = True
                false_reason = "Counterfactual verification failed – removal of actions may not break the capability"

            # Governance recommendation
            if is_false:
                recommendation = "REJECT"
                reason = f"False witness claim: {false_reason}"
            elif severity == 'critical' and classification == 'unknown':
                recommendation = "DENY"
                reason = "Emergent critical capability without prior authorisation"
            elif severity in ['critical', 'high']:
                recommendation = "HUMAN_REVIEW"
                reason = f"High-severity emergent capability: {cap['capability_name']}"
            elif classification == 'unknown':
                recommendation = "MONITOR"
                reason = "Unknown capability – requires observation (suggest adding to ontology)"
            else:
                recommendation = "ADMIT"
                reason = "Known capability – matches training ontology"

            witness = {
                "capability": cap['capability_name'],
                "capability_id": cap['capability_id'],
                "confidence": round(confidence, 4),
                "required_actions": cap['required_actions'],
                "minimal_witness": minimal_witness,
                "counterfactual_verified": result.get('verification', 'unknown') == 'verified',
                "counterfactual_details": result.get('counterfactual', []),
                "severity": severity,
                "classification": classification,
                "witness_hash": cap['witness']['witness_hash'],
                "occurrence_count": cap['occurrence_count'],
                "governance_recommendation": recommendation,
                "governance_reason": reason,
                "is_false_witness": is_false,
                "false_witness_reason": false_reason,
                "suggested_ontology_label": None,
                "timestamp": datetime.now().isoformat(),
                "trace_claim": {
                    "format": "TRACE v0.1",
                    "claim_type": "capability_witness",
                    "hash": cap['witness']['witness_hash'],
                    "evidence": cap['required_actions'],
                    "recommendation": recommendation
                }
            }

            # If unknown, suggest a label using the learner and submit to review queue
            if classification == 'unknown' and not is_false:
                suggested = self.learner.suggest_label(cap['required_actions'])
                witness['suggested_ontology_label'] = suggested
                # Submit to review queue
                result = self.learner.submit_for_review(
                    capability_id=cap['capability_id'],
                    capability_name=cap['capability_name'],
                    required_actions=cap['required_actions'],
                    evidence_hash=cap['witness']['witness_hash']
                )
                witness['review_submitted'] = True

            witnesses.append(witness)

        return witnesses

    def process_single_trace(self, trace: List[AgentAction]) -> Dict[str, Any]:
        traces = [trace]
        results = self.process_traces(traces)
        return results[0] if results else {
            "capability": None,
            "confidence": 0.0,
            "governance_recommendation": "ADMIT",
            "governance_reason": "No emergent capability detected",
            "trace_claim": None
        }