"""
Adapter to integrate DecisionAssure Continuity Kernel into Microsoft AGT.
"""
from typing import Optional, Dict, Any, List
from src.models import (
    ContinuityWitness, CCVResult,
    AgentAction, EmergentCapabilityResult
)
from src.witness_chain import WitnessChain
from src.ccv_engine import CCVEngine
from src.collusion_interceptor import CollusionInterceptor
from src.deception_probe import DeceptionProbe
from src.emergent_detector import EmergentDetector

from typing import Optional, Dict, Any
from src.models import ContinuityWitness, CCVResult
from src.witness_chain import WitnessChain
from src.ccv_engine import CCVEngine
from src.collusion_interceptor import CollusionInterceptor
from src.deception_probe import DeceptionProbe
from src.emergent_detector import EmergentDetector
class AGTAdapter:
    """
    Adapter for Microsoft Agent Governance Toolkit integration.
    """

    def __init__(self):
        self.ccv_engine = CCVEngine()
        self.collusion_interceptor = CollusionInterceptor()
        self.deception_probe = DeceptionProbe()
        self.emergent_detector = EmergentDetector()

    def generate_continuity_witness(
        self,
        agent_id: str,
        session_id: str,
        constitution_hash: str,
        observer_hash: str,
        reference_frame_hash: str,
        action_hash: str,
        previous_witness_hash: Optional[str] = None
    ) -> ContinuityWitness:
        """Generate a witness for the current step."""
        witness = ContinuityWitness(
            index=len(self.ccv_engine.chain.witnesses),
            previous_witness_hash=previous_witness_hash or "0" * 64,
            agent_id=agent_id,
            session_id=session_id,
            constitution_hash=constitution_hash,
            observer_hash=observer_hash,
            reference_frame_hash=reference_frame_hash,
            action_hash=action_hash
        )
        return self.ccv_engine.chain.add_witness(witness)
    def detect_emergent_capability(
        self,
        actions: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Detect emergent capabilities from a list of agent actions.
        """
        agent_actions = [AgentAction(**a) for a in actions]
        results = self.emergent_detector.detect(agent_actions)
        return [r.model_dump(mode='json') for r in results]
    def verify_continuity(
        self,
        witnesses: list,
        baseline: Optional[ContinuityWitness] = None
    ) -> Dict[str, Any]:
        """Verify continuity across the witness chain."""
        result = self.ccv_engine.verify_continuity(witnesses, baseline)
        return {
            "verification_result": result.model_dump(mode='json'),
            "continuity_proof": self.ccv_engine.export_proof(result, witnesses)
        }

    def check_collusion(self, agent_activations: Dict[str, list]) -> Dict[str, Any]:
        """Check for multi-agent collusion."""
        for agent_id, activation in agent_activations.items():
            self.collusion_interceptor.register_agent(agent_id, activation)
        result = self.collusion_interceptor.detect_collusion(list(agent_activations.keys()))
        return result.model_dump(mode='json')

    def scan_jailbreak(self, hidden_state: list, layer: str = "layer_12") -> Dict[str, Any]:
        """Scan for jailbreak attempts."""
        result = self.deception_probe.scan_activation(hidden_state, layer)
        return result.model_dump(mode='json')

    def create_agt_integration_payload(self, agent_id: str, session_id: str) -> Dict[str, Any]:
        """
        Create a payload that can be consumed by AGT's governance middleware.
        """
        return {
            "decisionassure": {
                "version": "1.0",
                "agent_id": agent_id,
                "session_id": session_id,
                "witness_chain": self.ccv_engine.chain.export_chain(),
                "continuity_proof": {
                    "latest_witness": self.ccv_engine.chain.get_latest_witness().model_dump(mode='json') if self.ccv_engine.chain.witnesses else None,
                    "chain_verified": self.ccv_engine.chain.verify_chain()
                }
            }
        }