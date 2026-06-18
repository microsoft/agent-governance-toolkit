from typing import List, Dict, Any
from datetime import datetime
import hashlib
import json
from src.models import AgentAction

class CapabilityWitnessLanguage:
    def generate_witness_proof(
        self,
        capability_id: str,
        capability_name: str,
        severity: str,
        required_actions: List[Dict[str, str]],
        agent_actions: List[AgentAction],
        counterfactual_results: List[Dict[str, Any]],
        verification_status: str,
        intent: str = "unknown",
        decision: str = "MONITOR"
    ) -> Dict[str, Any]:
        minimal_agents = list(set(a.get("agent", a.get("agent_id")) for a in required_actions))
        replay_data = {
            "capability_id": capability_id,
            "required_actions": required_actions,
            "agents": minimal_agents,
            "timestamp": datetime.now().isoformat()
        }
        replay_hash = hashlib.sha256(json.dumps(replay_data, sort_keys=True).encode()).hexdigest()

        return {
            "witness_id": f"witness_{hashlib.md5(capability_id.encode()).hexdigest()[:8]}",
            "capability": {
                "id": capability_id,
                "name": capability_name,
                "severity": severity,
                "intent": intent,
                "decision": decision
            },
            "required_actions": required_actions,
            "minimal_witness": minimal_agents,
            "counterfactual_verified": all(cf["capability_still_exists"] is False for cf in counterfactual_results),
            "counterfactual_details": counterfactual_results,
            "replay_hash": replay_hash,
            "verification_status": verification_status,
            "verified_at": datetime.now().isoformat(),
            "witness_signature": None  # Placeholder for Ed25519 signing
        }