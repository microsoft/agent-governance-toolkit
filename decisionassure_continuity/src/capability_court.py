"""
Capability Court – End‑to‑end pipeline: Trace → Discovery → Witness → Counterfactual → Verdict → TRACE Claim.
"""

from typing import List, Dict, Any, Optional
from src.models import AgentAction
from src.capability_discovery import CapabilityDiscovery
from src.capability_replay import CapabilityReplay

class CapabilityCourt:
    def __init__(self):
        self.discovery = CapabilityDiscovery(min_samples=3, eps=0.5)

    def process_traces(self, traces: List[List[AgentAction]]) -> List[Dict[str, Any]]:
        discovered = self.discovery.discover(traces)
        verdicts = []
        for cap in discovered:
            actions = [AgentAction(agent_id=a["agent"], action_type=a["action"]) for a in cap['required_actions']]
            replay = CapabilityReplay()
            actions_dict = [{"agent": a.agent_id, "action": a.action_type} for a in actions]
            result = replay.replay(actions_dict)
            counterfactual_verified = result['verification'] == "verified"

            severity = cap.get('severity', 'unknown')
            if severity == 'critical' and cap['classification'] == 'unknown':
                verdict = "DENY"
                reason = "Emergent critical capability without prior authorisation"
            elif cap['classification'] == 'unknown':
                verdict = "MONITOR"
                reason = "Unknown capability – requires human review"
            else:
                verdict = "ADMIT"
                reason = "Known capability – matches training ontology"

            # Build TRACE‑compatible witness claim
            claim = {
                "capability": cap['capability_name'],
                "capability_id": cap['capability_id'],
                "classification": cap['classification'],
                "required_actions": cap['required_actions'],
                "witness_hash": cap['witness']['witness_hash'],
                "counterfactual_verified": counterfactual_verified,
                "counterfactual_details": result['counterfactual'],  # includes per-agent removal results
                "verdict": verdict,
                "reason": reason,
                "severity": severity,
                "occurrence_count": cap['occurrence_count'],
                "timestamp": cap['discovered_at'],
                "trace_claim": {
                    "format": "TRACE v0.1",
                    "claim_type": "capability_witness",
                    "hash": cap['witness']['witness_hash'],
                    "evidence": cap['required_actions']
                }
            }
            verdicts.append(claim)
        return verdicts

    def process_single_trace(self, trace: List[AgentAction]) -> Dict[str, Any]:
        traces = [trace]
        results = self.process_traces(traces)
        return results[0] if results else {
            "verdict": "ADMIT",
            "reason": "No emergent capability detected",
            "trace_claim": None
        }