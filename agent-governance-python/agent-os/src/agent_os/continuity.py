import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

@dataclass
class ContinuityState:
    observer_identity_hash: str
    reference_frame_hash: str
    timestamp: float = field(default_factory=time.time)

@dataclass
class ContinuityTrace:
    sandbox_execution_id: str
    continuity_valid: bool
    decision: str
    observer_identity_hash: str
    reference_frame_hash: str
    reference_frame_diff: Optional[Dict[str, Any]] = None
    recommended_next_action: Optional[str] = None
    control_objective_id: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(self.__dict__, indent=2, default=str)

class ContinuityVerifier:
    def __init__(self, sandbox_id: str):
        self.sandbox_id = sandbox_id
        self.pre_state: Optional[ContinuityState] = None

    def compute_observer_hash(self, agent_id: str, session_id: str, memory_state: Dict[str, Any]) -> str:
        identity_obj = {"agent_id": agent_id, "session_id": session_id, "memory_state": memory_state}
        canonical = json.dumps(identity_obj, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]

    def compute_reference_hash(self, policy_version: str, delegation_chain: list, external_reference_state: Dict[str, Any]) -> str:
        ref_obj = {"policy_version": policy_version, "delegation_chain": delegation_chain, "external_reference_state": external_reference_state}
        canonical = json.dumps(ref_obj, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]

    def capture_pre_state(self, agent_id: str, session_id: str, memory_state: Dict[str, Any],
                          policy_version: str, delegation_chain: list, external_reference_state: Dict[str, Any]) -> None:
        obs_hash = self.compute_observer_hash(agent_id, session_id, memory_state)
        ref_hash = self.compute_reference_hash(policy_version, delegation_chain, external_reference_state)
        self.pre_state = ContinuityState(obs_hash, ref_hash)

    def capture_post_state(self, agent_id: str, session_id: str, memory_state: Dict[str, Any],
                           policy_version: str, delegation_chain: list, external_reference_state: Dict[str, Any]) -> ContinuityTrace:
        if self.pre_state is None:
            raise RuntimeError("pre-state not captured; call capture_pre_state first")
        new_obs_hash = self.compute_observer_hash(agent_id, session_id, memory_state)
        new_ref_hash = self.compute_reference_hash(policy_version, delegation_chain, external_reference_state)
        obs_ok = new_obs_hash == self.pre_state.observer_identity_hash
        ref_ok = new_ref_hash == self.pre_state.reference_frame_hash
        continuity_valid = obs_ok and ref_ok
        diff = None
        recommended = None
        control_obj = None
        if not continuity_valid:
            diff = {}
            if not obs_ok:
                diff["observer_identity_hash"] = {"old": self.pre_state.observer_identity_hash, "new": new_obs_hash}
            if not ref_ok:
                diff["reference_frame_hash"] = {"old": self.pre_state.reference_frame_hash, "new": new_ref_hash}
            recommended = "reauthorize"
            control_obj = "CO-001"
        decision = "ALLOW" if continuity_valid else "DENY"
        return ContinuityTrace(
            sandbox_execution_id=self.sandbox_id,
            continuity_valid=continuity_valid,
            decision=decision,
            observer_identity_hash=new_obs_hash,
            reference_frame_hash=new_ref_hash,
            reference_frame_diff=diff,
            recommended_next_action=recommended,
            control_objective_id=control_obj,
        )
