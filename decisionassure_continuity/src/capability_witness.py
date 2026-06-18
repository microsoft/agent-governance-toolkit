from typing import List, Optional
import hashlib
from src.models import AgentAction, CapabilityWitness

class CapabilityWitnessEngine:
    def generate_witness(self, actions: List[AgentAction]) -> Optional[CapabilityWitness]:
        if not actions:
            return None
        required_actions = [{"agent": a.agent_id, "action": a.action_type} for a in actions]
        witness = CapabilityWitness(
            capability_id="witness_" + hashlib.md5(str(required_actions).encode()).hexdigest()[:8],
            capability_name="Witness",
            required_actions=required_actions
        )
        witness.witness_hash = witness.compute_witness_hash()
        return witness