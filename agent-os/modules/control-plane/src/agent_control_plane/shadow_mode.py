# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Shadow Mode - Simulation and Validation

Shadow Mode provides a "Matrix-like" simulation where agents THINK they are
executing actions, but the Control Plane intercepts everything, logs the intent,
and validates outcomes against constraint graphs without actual execution.

This enables:
- Safe testing of agent behavior before production
- Validation of agent decisions against policies
- Analysis of agent reasoning without side effects
- Telemetry on reasoning chains

Research Foundations:
    - Pre-deployment testing approach from "Practices for Governing Agentic AI Systems"
      (OpenAI, 2023) - simulation before production deployment
    - Risk-free validation patterns for testing agent behavior
    - Statistical analysis of agent patterns for anomaly detection

See docs/RESEARCH_FOUNDATION.md for complete references.
"""

from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from .agent_kernel import ExecutionRequest, ActionType, ExecutionStatus


class SimulationOutcome(Enum):
    """Possible outcomes of simulated execution"""
    WOULD_SUCCEED = "would_succeed"
    WOULD_FAIL = "would_fail"
    POLICY_VIOLATION = "policy_violation"
    RISK_TOO_HIGH = "risk_too_high"
    PERMISSION_DENIED = "permission_denied"


@dataclass
class ReasoningStep:
    """A step in the agent's reasoning chain"""
    step_number: int
    description: str
    action_considered: ActionType
    parameters: Dict[str, Any]
    decision: str  # Why this action was chosen
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class SimulationResult:
    """Result of a shadow mode execution"""
    request_id: str
    agent_id: str
    outcome: SimulationOutcome
    simulated_result: Optional[Any] = None
    actual_impact: Dict[str, Any] = field(default_factory=dict)
    policy_checks: Dict[str, bool] = field(default_factory=dict)
    risk_score: float = 0.0
    reasoning_chain: List[ReasoningStep] = field(default_factory=list)
    would_execute_at: Optional[datetime] = None
    validation_notes: List[str] = field(default_factory=list)


@dataclass
class ShadowModeConfig:
    """Configuration for shadow mode"""
    enabled: bool = True
    log_reasoning: bool = True  # Capture reasoning chain
    simulate_results: bool = True  # Generate simulated results
    validate_constraints: bool = True  # Validate against constraint graphs
    intercept_all: bool = True  # Intercept all actions (true shadow mode)
    allow_safe_actions: bool = False  # Allow safe actions to execute


class ShadowModeExecutor:
    """
    Executes actions in shadow mode - simulating execution without side effects.
    
    This is the "Matrix" for agents - they think they're executing, but
    we're actually just logging their intent and validating decisions.
    """
    
    def __init__(self, config: ShadowModeConfig):
        self.config = config
        self.simulation_log: List[SimulationResult] = []
        self.reasoning_traces: Dict[str, List[ReasoningStep]] = {}
    
    def execute_in_shadow(
        self,
        request: ExecutionRequest,
        reasoning_chain: Optional[List[ReasoningStep]] = None
    ) -> SimulationResult:
        """
        Execute request in shadow mode.
        
        The agent thinks it's executing, but we're just simulating and logging.
        """
        simulation = SimulationResult(
            request_id=request.request_id,
            agent_id=request.agent_context.agent_id,
            outcome=SimulationOutcome.WOULD_SUCCEED,
            risk_score=request.risk_score,
            reasoning_chain=reasoning_chain or []
        )
        
        # Validate request would pass all checks
        outcome, notes = self._validate_request(request)
        simulation.outcome = outcome
        simulation.validation_notes = notes
        
        # Generate simulated result
        if self.config.simulate_results:
            simulation.simulated_result = self._simulate_execution(request)
        
        # Calculate what the actual impact would be
        simulation.actual_impact = self._analyze_impact(request)
        
        # Log the simulation
        self.simulation_log.append(simulation)
        
        # Store reasoning trace
        if reasoning_chain:
            self.reasoning_traces[request.request_id] = reasoning_chain
        
        return simulation
    
    def _validate_request(self, request: ExecutionRequest) -> Tuple[SimulationOutcome, List[str]]:
        """Validate if request would succeed in production"""
        notes = []
        
        # Check permission
        if request.status == ExecutionStatus.DENIED:
            notes.append("Request would be denied due to insufficient permissions")
            return SimulationOutcome.PERMISSION_DENIED, notes
        
        # Check risk
        if request.risk_score > 0.8:
            notes.append(f"Risk score {request.risk_score} exceeds threshold")
            return SimulationOutcome.RISK_TOO_HIGH, notes
        
        # Would succeed
        notes.append("All validation checks would pass")
        return SimulationOutcome.WOULD_SUCCEED, notes
    
    def _simulate_execution(self, request: ExecutionRequest) -> Dict[str, Any]:
        """Generate a simulated execution result"""
        action_simulators = {
            ActionType.FILE_READ: self._simulate_file_read,
            ActionType.FILE_WRITE: self._simulate_file_write,
            ActionType.DATABASE_QUERY: self._simulate_database_query,
            ActionType.CODE_EXECUTION: self._simulate_code_execution,
            ActionType.API_CALL: self._simulate_api_call,
        }
        
        simulator = action_simulators.get(
            request.action_type,
            lambda r: {"status": "simulated", "note": "Generic simulation"}
        )
        
        return simulator(request)
    
    def _simulate_file_read(self, request: ExecutionRequest) -> Dict[str, Any]:
        """Simulate file read operation"""
        return {
            "action": "file_read",
            "path": request.parameters.get('path'),
            "content": f"[SIMULATED CONTENT of {request.parameters.get('path')}]",
            "size": 1024,
            "note": "This is a shadow mode simulation - no actual file was read"
        }
    
    def _simulate_file_write(self, request: ExecutionRequest) -> Dict[str, Any]:
        """Simulate file write operation"""
        return {
            "action": "file_write",
            "path": request.parameters.get('path'),
            "bytes_written": len(str(request.parameters.get('content', ''))),
            "note": "This is a shadow mode simulation - no actual file was written"
        }
    
    def _simulate_database_query(self, request: ExecutionRequest) -> Dict[str, Any]:
        """Simulate database query"""
        return {
            "action": "database_query",
            "query": request.parameters.get('query'),
            "rows": [
                {"id": 1, "name": "[SIMULATED DATA]"},
                {"id": 2, "name": "[SIMULATED DATA]"}
            ],
            "row_count": 2,
            "note": "This is a shadow mode simulation - no actual query was executed"
        }
    
    def _simulate_code_execution(self, request: ExecutionRequest) -> Dict[str, Any]:
        """Simulate code execution"""
        return {
            "action": "code_execution",
            "language": request.parameters.get('language'),
            "output": "[SIMULATED OUTPUT]",
            "exit_code": 0,
            "note": "This is a shadow mode simulation - no actual code was executed"
        }
    
    def _simulate_api_call(self, request: ExecutionRequest) -> Dict[str, Any]:
        """Simulate API call"""
        return {
            "action": "api_call",
            "url": request.parameters.get('url'),
            "status_code": 200,
            "response": {"data": "[SIMULATED API RESPONSE]"},
            "note": "This is a shadow mode simulation - no actual API call was made"
        }
    
    def _analyze_impact(self, request: ExecutionRequest) -> Dict[str, Any]:
        """Analyze what the actual impact would be if executed"""
        impact = {
            "action_type": request.action_type.value,
            "side_effects": []
        }
        
        # Analyze potential side effects
        if request.action_type == ActionType.FILE_WRITE:
            impact["side_effects"].append({
                "type": "file_system_modification",
                "path": request.parameters.get('path'),
                "reversible": True
            })
        
        elif request.action_type == ActionType.DATABASE_WRITE:
            impact["side_effects"].append({
                "type": "data_modification",
                "table": request.parameters.get('table'),
                "reversible": False,  # Conservative assumption; depends on backup/transaction support
                "note": "Reversibility depends on database configuration and backup policies"
            })
        
        elif request.action_type == ActionType.CODE_EXECUTION:
            impact["side_effects"].append({
                "type": "code_execution",
                "danger_level": "high",
                "reversible": False
            })
        
        elif request.action_type == ActionType.WORKFLOW_TRIGGER:
            impact["side_effects"].append({
                "type": "workflow_execution",
                "workflow": request.parameters.get('workflow_id'),
                "reversible": False
            })
        
        return impact
    
    def get_simulation_log(self, agent_id: Optional[str] = None) -> List[SimulationResult]:
        """Get simulation log, optionally filtered by agent"""
        if agent_id:
            return [s for s in self.simulation_log if s.agent_id == agent_id]
        return self.simulation_log.copy()
    
    def get_reasoning_trace(self, request_id: str) -> Optional[List[ReasoningStep]]:
        """Get the reasoning trace for a specific request"""
        return self.reasoning_traces.get(request_id)
    
    def get_policy_violations(self) -> List[SimulationResult]:
        """Get all simulations that would have violated policies"""
        return [
            s for s in self.simulation_log
            if s.outcome in [SimulationOutcome.POLICY_VIOLATION, SimulationOutcome.RISK_TOO_HIGH]
        ]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about shadow mode executions"""
        total = len(self.simulation_log)
        if total == 0:
            return {"total": 0}
        
        outcome_counts = {}
        for sim in self.simulation_log:
            outcome = sim.outcome.value
            outcome_counts[outcome] = outcome_counts.get(outcome, 0) + 1
        
        return {
            "total_simulations": total,
            "outcome_distribution": outcome_counts,
            "success_rate": outcome_counts.get(SimulationOutcome.WOULD_SUCCEED.value, 0) / total,
            "policy_violations": outcome_counts.get(SimulationOutcome.POLICY_VIOLATION.value, 0),
            "risk_denials": outcome_counts.get(SimulationOutcome.RISK_TOO_HIGH.value, 0),
        }


def add_reasoning_step(
    chain: List[ReasoningStep],
    description: str,
    action: ActionType,
    parameters: Dict[str, Any],
    decision: str
) -> List[ReasoningStep]:
    """Helper to add a reasoning step to a chain"""
    step = ReasoningStep(
        step_number=len(chain) + 1,
        description=description,
        action_considered=action,
        parameters=parameters,
        decision=decision
    )
    chain.append(step)
    return chain
