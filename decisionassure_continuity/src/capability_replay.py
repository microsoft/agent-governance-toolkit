from typing import List, Dict, Any
from src.models import AgentAction
from src.capability_witness import CapabilityWitnessEngine
from src.capability_ontology import OntologyMatcher
from src.capability_witness_language import CapabilityWitnessLanguage

class CapabilityReplay:
    def __init__(self):
        self.witness_engine = CapabilityWitnessEngine()
        self.ontology_matcher = OntologyMatcher()
        self.witness_language = CapabilityWitnessLanguage()

    def replay(self, actions: List[Dict[str, str]], context: Dict[str, Any] = None) -> Dict[str, Any]:
        context = context or {}
        workflow = context.get("workflow_type", "unknown")

        agent_actions = []
        for a in actions:
            agent_id = a.get("agent_id") or a.get("agent")
            action_type = a.get("action_type") or a.get("action")
            if agent_id is None or action_type is None:
                raise ValueError(f"Missing agent or action in {a}")
            agent_actions.append(AgentAction(
                agent_id=agent_id,
                action_type=action_type,
                tool=a.get("tool"),
                params=a.get("params", {})
            ))

        action_types = {a.action_type for a in agent_actions}
        match_result = self.ontology_matcher.match(action_types, context)

        witness = self.witness_engine.generate_witness(agent_actions)

        required_actions = [{"agent": a.agent_id, "action": a.action_type} for a in agent_actions]
        counterfactual_results = []
        for agent in set(a.agent_id for a in agent_actions):
            remaining = [r for r in required_actions if r["agent"] != agent]
            still_exists = set(r["action"] for r in remaining) == set(r["action"] for r in required_actions)
            counterfactual_results.append({
                "removed_agent": agent,
                "capability_still_exists": still_exists,
                "remaining_actions": remaining
            })

        intent = match_result.get("intent", "unknown")
        severity = match_result.get("severity", "unknown")
        decision = match_result.get("decision", "MONITOR")
        verification_status = "verified" if witness and match_result["pattern"] else "unknown"

        proof = None
        if witness and match_result["pattern"]:
            pattern = match_result["pattern"]
            proof = self.witness_language.generate_witness_proof(
                capability_id=pattern.capability_id,
                capability_name=pattern.name,
                severity=severity,
                required_actions=required_actions,
                agent_actions=agent_actions,
                counterfactual_results=counterfactual_results,
                verification_status=verification_status,
                intent=intent,
                decision=decision
            )

        return {
            "replay_status": "success",
            "match_result": match_result,
            "witness": witness.model_dump(mode='json') if witness else None,
            "counterfactual": counterfactual_results,
            "verification": verification_status,
            "intent": intent,
            "severity": severity,
            "decision": decision,
            "witness_proof": proof
        }