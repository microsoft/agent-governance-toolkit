from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
import hashlib
import json
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Set
from enum import Enum
from datetime import datetime
import hashlib
import json
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Set
from enum import Enum
from datetime import datetime
import hashlib
import json



# ... (existing ContinuityWitness, CCVResult, etc. remain unchanged) ...


class CounterfactualResult(BaseModel):
    removed_agent: str
    capability_still_exists: bool
    remaining_actions: List[Dict[str, str]]


# ... (other models) ...

# ... (existing ContinuityWitness, CCVResult, etc. remain unchanged) ...
# ... existing imports and models (ContinuityWitness, CCVResult, etc.) ...
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Set
from enum import Enum
from datetime import datetime
import hashlib
import json

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Action(str, Enum):
    MONITOR = "monitor"
    ESCALATE = "escalate"
    QUARANTINE = "quarantine"
    BLOCK = "block"

class DetectionType(str, Enum):
    DELEGATION_ESCALATION = "delegation_escalation"
    TOOL_DRIFT = "tool_drift"
    POLICY_AVOIDANCE = "policy_avoidance"
    IDENTITY_DRIFT = "identity_drift"
    COLLUSION = "collusion"

class ContinuityWitness(BaseModel):
    index: int
    previous_witness_hash: str
    agent_id: str
    session_id: str
    constitution_hash: str
    observer_hash: str
    reference_frame_hash: str
    action_hash: str
    timestamp: datetime = Field(default_factory=datetime.now)
    witness_hash: Optional[str] = None

    def compute_hash(self) -> str:
        data = {
            "index": self.index,
            "previous_witness_hash": self.previous_witness_hash,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "constitution_hash": self.constitution_hash,
            "observer_hash": self.observer_hash,
            "reference_frame_hash": self.reference_frame_hash,
            "action_hash": self.action_hash,
            "timestamp": self.timestamp.isoformat()
        }
        json_str = json.dumps(data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(json_str.encode()).hexdigest()

class CapabilityPattern(BaseModel):
    capability_id: str
    name: str
    description: str
    severity: str
    required_actions: List[str]
    optional_actions: List[str] = []
    min_agents: int = 1
    max_agents: int = 10
    context_hint: Optional[str] = None
    context_rules: Optional[Dict[str, Any]] = None

class CapabilityOntology(BaseModel):
    version: str = "1.0"
    patterns: List[CapabilityPattern]

class CapabilityWitness(BaseModel):
    capability_id: str
    capability_name: str
    required_actions: List[Dict[str, str]]
    witness_hash: Optional[str] = None
    counterfactual: Optional[Dict[str, Any]] = None
    created_at: datetime = Field(default_factory=datetime.now)

    def compute_witness_hash(self) -> str:
        data = {
            "capability_id": self.capability_id,
            "required_actions": sorted(self.required_actions, key=lambda x: (x.get("agent", ""), x.get("action", "")))
        }
        json_str = json.dumps(data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(json_str.encode()).hexdigest()

class AgentAction(BaseModel):
    agent_id: str
    action_type: str
    tool: Optional[str] = None
    target: Optional[str] = None
    params: Dict[str, Any] = {}

class CapabilityContribution(BaseModel):
    agent: str
    contribution_type: str
    action: str
    evidence: Dict[str, Any] = {}

class CapabilityLineage(BaseModel):
    capability_id: str
    capability_name: str
    created_at: datetime = Field(default_factory=datetime.now)
    contributions: List[CapabilityContribution]
    lineage_hash: Optional[str] = None
    witness: Optional[CapabilityWitness] = None

    def compute_lineage_hash(self) -> str:
        data = {
            "capability_id": self.capability_id,
            "contributions": [c.model_dump() for c in self.contributions]
        }
        json_str = json.dumps(data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(json_str.encode()).hexdigest()


# Update EmergentCapabilityResult to include lineage
class EmergentCapabilityResult(BaseModel):
    capability_detected: bool
    capability: Optional[EmergentCapability] = None
    contributing_agents: List[str]
    actions_involved: List[AgentAction]
    confidence: float
    evidence: Dict[str, Any]
    lineage: Optional[CapabilityLineage] = None
    timestamp: datetime = Field(default_factory=datetime.now)



class DelegationEdge(BaseModel):
    from_agent: str
    to_agent: str
    timestamp: datetime


class ToolGraph(BaseModel):
    agent_id: str
    tools: List[str]


class MemoryGraph(BaseModel):
    agent_id: str
    memory_keys: List[str]


class EmergentCapability(BaseModel):
    capability_id: str
    name: str
    description: str
    severity: str  # "low", "medium", "high", "critical"
    required_actions: List[str]   # action types that must be present collectively





class IdentityTransition(BaseModel):
    before_hash: str
    after_hash: str
    preserved: bool


class ConstitutionTransition(BaseModel):
    before_hash: str
    after_hash: str
    preserved: bool


class ObserverTransition(BaseModel):
    before_hash: str
    after_hash: str
    drift: float  # 0.0 - 1.0


class DelegationTransition(BaseModel):
    before: str
    after: str
    drift: float


class CCVResult(BaseModel):
    continuity_score: float
    identity_preserved: bool
    constitution_preserved: bool
    delegation_drift: float
    observer_drift: float
    reference_frame_drift: float
    witness_count: int
    first_break_index: Optional[int] = None
    break_reason: Optional[str] = None
    verification_status: str

    # NEW: detailed evidence
    identity_transition: Optional[IdentityTransition] = None
    constitution_transition: Optional[ConstitutionTransition] = None
    observer_transition: Optional[ObserverTransition] = None
    delegation_transition: Optional[DelegationTransition] = None


class CollusionDetectionResult(BaseModel):
    suspicion_score: float
    threshold: float
    collusion_detected: bool
    agents_involved: List[str]
    alignment_spikes: List[Dict[str, Any]]
    decision: str
    trace_claim_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)


class DeceptionProbeResult(BaseModel):
    harmful_intent_detected: bool
    confidence_score: float
    generation_denied: bool
    probe_layer: str
    activation_pattern: Dict[str, float]
    timestamp: datetime = Field(default_factory=datetime.now)