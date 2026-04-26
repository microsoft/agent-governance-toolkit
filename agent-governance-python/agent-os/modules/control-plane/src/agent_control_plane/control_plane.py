# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Agent Control Plane - Main Interface

Layer 3: The Framework - The Governance Layer

The main control plane that integrates all components:
- Agent Kernel (via KernelInterface for dependency injection)
- Policy Engine
- Execution Engine
- Audit System
- Shadow Mode (simulation)
- Validators (via ValidatorInterface - MuteAgent pattern is now optional)
- Constraint Graphs (multi-dimensional)
- Supervisor Agents (via SupervisorInterface)

Allowed Dependencies:
- iatp (for message security)
- cmvk (for verification)
- caas (for context routing)

Forbidden Dependencies:
- scak (should implement KernelInterface instead)
- mute-agent as hard dependency (should use ValidatorInterface)

Pattern: Components are injected at runtime via PluginRegistry.
"""

from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import warnings

from .agent_kernel import (
    AgentKernel, AgentContext, ExecutionRequest, ExecutionResult,
    ActionType, PermissionLevel, PolicyRule, ExecutionStatus
)
from .policy_engine import PolicyEngine, ResourceQuota, RiskPolicy, create_default_policies
from .execution_engine import (
    ExecutionEngine, ExecutionContext, SandboxLevel
)
from .example_executors import (
    file_read_executor, code_execution_executor, api_call_executor
)
from .shadow_mode import ShadowModeExecutor, ShadowModeConfig, ReasoningStep
from .constraint_graphs import (
    DataGraph, PolicyGraph, TemporalGraph, ConstraintGraphValidator
)
from .supervisor_agents import SupervisorAgent, SupervisorNetwork
from .agent_hibernation import HibernationManager, HibernationConfig
from .time_travel_debugger import TimeTravelDebugger, TimeTravelConfig

# Import interfaces for dependency injection
from .interfaces.kernel_interface import KernelInterface, KernelCapability
from .interfaces.plugin_interface import (
    ValidatorInterface,
    ExecutorInterface,
    ContextRouterInterface,
    SupervisorInterface,
    ValidationResult,
)
from .interfaces.protocol_interfaces import (
    MessageSecurityInterface,
    VerificationInterface,
    ContextRoutingInterface,
)

# Import plugin registry for dependency injection
from .plugin_registry import PluginRegistry, PluginType, get_registry

# Import mute_agent for backward compatibility (deprecated pattern)
# New code should use PluginRegistry to register validators
from .mute_agent import MuteAgentValidator, MuteAgentConfig


class AgentControlPlane:
    """
    Agent Control Plane - Main interface for governed agent execution
    
    Layer 3: The Framework - The Governance Layer
    
    This is the primary interface for applications to interact with
    the control plane. It integrates all governance, safety, and
    execution components including:
    - Shadow Mode for simulation
    - Validators (via ValidatorInterface - replaces hard-coded Mute Agent)
    - Constraint Graphs for multi-dimensional context
    - Supervisor Agents (via SupervisorInterface)
    
    Dependency Injection:
        Components can be injected via the PluginRegistry:
        
        ```python
        from agent_control_plane import AgentControlPlane, PluginRegistry
        
        # Get the registry
        registry = PluginRegistry()
        
        # Register custom kernel (e.g., SCAK)
        registry.register_kernel(my_custom_kernel)
        
        # Register validators
        registry.register_validator(my_validator, action_types=["code_execution"])
        
        # Create control plane (will use registered components)
        control_plane = AgentControlPlane(use_plugin_registry=True)
        ```
    
    Allowed Protocol Dependencies:
        - iatp: Inter-Agent Transport Protocol (message security)
        - cmvk: Cryptographic Message Verification Kit
        - caas: Context-as-a-Service (context routing)
    """
    
    def __init__(
        self,
        enable_default_policies: bool = True,
        enable_shadow_mode: bool = False,
        enable_constraint_graphs: bool = False,
        enable_hibernation: bool = False,
        enable_time_travel: bool = False,
        use_plugin_registry: bool = False,
        kernel: Optional[KernelInterface] = None,
        validators: Optional[List[ValidatorInterface]] = None,
        context_router: Optional[Union[ContextRouterInterface, ContextRoutingInterface]] = None,
        message_security: Optional[MessageSecurityInterface] = None,
        verifier: Optional[VerificationInterface] = None,
        hibernation_config: Optional[HibernationConfig] = None,
        time_travel_config: Optional[TimeTravelConfig] = None,
    ):
        """
        Initialize the Agent Control Plane.
        
        Args:
            enable_default_policies: Whether to load default security policies
            enable_shadow_mode: Whether to enable shadow/simulation mode
            enable_constraint_graphs: Whether to enable constraint graph validation
            enable_hibernation: Whether to enable agent hibernation (serverless agents)
            enable_time_travel: Whether to enable time-travel debugging
            use_plugin_registry: If True, use components from PluginRegistry
            kernel: Optional custom kernel implementing KernelInterface
            validators: Optional list of validators implementing ValidatorInterface
            context_router: Optional context router for caas integration
            message_security: Optional message security provider for iatp integration
            verifier: Optional verifier for cmvk integration
            hibernation_config: Optional configuration for hibernation
            time_travel_config: Optional configuration for time-travel debugging
        """
        # Plugin registry integration
        self._use_plugin_registry = use_plugin_registry
        self._registry = get_registry() if use_plugin_registry else None
        
        # Use injected kernel or fall back to default AgentKernel
        if kernel is not None:
            self._custom_kernel = kernel
            # Wrap custom kernel in compatibility layer
            self.kernel = AgentKernel()  # Default for now, custom kernel used via interface
        elif use_plugin_registry and self._registry:
            registered_kernel = self._registry.get_kernel()
            self._custom_kernel = registered_kernel
            self.kernel = AgentKernel()  # Default fallback
        else:
            self._custom_kernel = None
            self.kernel = AgentKernel()
        
        self.policy_engine = PolicyEngine()
        self.execution_engine = ExecutionEngine()
        
        # Wire the policy engine into the kernel so intercept_tool_execution works
        self.kernel.policy_engine = self.policy_engine
        
        # Shadow Mode for simulation
        self.shadow_mode_enabled = enable_shadow_mode
        self.shadow_executor = ShadowModeExecutor(ShadowModeConfig(enabled=enable_shadow_mode))
        
        # Validators (replaces hard-coded mute_validators)
        # Support both legacy MuteAgentValidator and new ValidatorInterface
        self.mute_validators: Dict[str, MuteAgentValidator] = {}  # Legacy support
        self._validators: List[ValidatorInterface] = []  # New interface-based validators
        
        if validators:
            self._validators.extend(validators)
        elif use_plugin_registry and self._registry:
            self._validators.extend(self._registry.get_all_validators())
        
        # Protocol integrations (iatp, cmvk, caas)
        self._context_router = context_router
        self._message_security = message_security
        self._verifier = verifier
        
        if use_plugin_registry and self._registry:
            if not self._context_router:
                self._context_router = self._registry.get_context_router()
            if not self._message_security:
                self._message_security = self._registry.get_message_security()
            if not self._verifier:
                self._verifier = self._registry.get_verifier()
        
        # Constraint Graphs
        self.constraint_graphs_enabled = enable_constraint_graphs
        if enable_constraint_graphs:
            self.data_graph = DataGraph()
            self.policy_graph = PolicyGraph()
            self.temporal_graph = TemporalGraph()
            self.constraint_validator = ConstraintGraphValidator(
                self.data_graph,
                self.policy_graph,
                self.temporal_graph
            )
        else:
            self.data_graph = None
            self.policy_graph = None
            self.temporal_graph = None
            self.constraint_validator = None
        
        # Supervisor Network
        self.supervisor_network = SupervisorNetwork()
        
        # Agent Hibernation (Serverless Agents)
        self.hibernation_enabled = enable_hibernation
        if enable_hibernation:
            self.hibernation_manager = HibernationManager(hibernation_config or HibernationConfig())
        else:
            self.hibernation_manager = None
        
        # Time-Travel Debugging
        self.time_travel_enabled = enable_time_travel
        if enable_time_travel:
            # Pass FlightRecorder if kernel has audit_logger
            flight_recorder = getattr(self.kernel, 'audit_logger', None)
            self.time_travel_debugger = TimeTravelDebugger(
                flight_recorder=flight_recorder,
                config=time_travel_config or TimeTravelConfig()
            )
        else:
            self.time_travel_debugger = None
        
        # Register default executors
        self._register_default_executors()
        
        # Add default policies if requested
        if enable_default_policies:
            self._add_default_policies()
    
    def create_agent(
        self,
        agent_id: str,
        permissions: Optional[Dict[ActionType, PermissionLevel]] = None,
        quota: Optional[ResourceQuota] = None
    ) -> AgentContext:
        """
        Create a new agent with specified permissions and quotas
        
        Args:
            agent_id: Unique identifier for the agent
            permissions: Dictionary of action types to permission levels
            quota: Resource quota for the agent
            
        Returns:
            AgentContext for the created agent session
        """
        # Create agent session in kernel
        context = self.kernel.create_agent_session(agent_id, permissions)
        
        # Set quota if provided
        if quota:
            self.policy_engine.set_quota(agent_id, quota)
        
        return context
    
    def execute_action(
        self,
        agent_context: AgentContext,
        action_type: ActionType,
        parameters: Dict[str, Any],
        execution_context: Optional[ExecutionContext] = None,
        reasoning_chain: Optional[List[ReasoningStep]] = None
    ) -> Dict[str, Any]:
        """
        Execute an action on behalf of an agent
        
        This is the main entry point for agent actions. It goes through
        the complete governance pipeline:
        1. Validator validation (includes legacy Mute Agent support)
        2. Permission check (Kernel)
        3. Constraint Graph validation (if enabled)
        4. Policy validation (Policy Engine)
        5. Risk assessment (Kernel)
        6. Rate limiting (Policy Engine)
        7. Shadow Mode or Real Execution
        8. Audit logging (Kernel)
        
        Args:
            agent_context: Context for the agent making the request
            action_type: Type of action to execute
            parameters: Parameters for the action
            execution_context: Optional execution context (sandboxing, timeouts, etc.)
            reasoning_chain: Optional reasoning steps that led to this action
            
        Returns:
            Dictionary with execution results and metadata
        """
        # Create a temporary request for validation
        temp_request = ExecutionRequest(
            request_id="temp",
            agent_context=agent_context,
            action_type=action_type,
            parameters=parameters,
            timestamp=datetime.now()
        )
        
        # 1a. Validate against registered validators (new pattern)
        for validator in self._validators:
            result = validator.validate_request(temp_request)
            if not result.is_valid:
                return {
                    "success": False,
                    "error": result.reason,
                    "status": "validator_rejected",
                    "details": result.details
                }
        
        # 1b. Validate against legacy Mute Agent capabilities (backward compatibility)
        if agent_context.agent_id in self.mute_validators:
            validator = self.mute_validators[agent_context.agent_id]
            result = validator.validate_request(temp_request)
            if not result.is_valid:
                return {
                    "success": False,
                    "error": result.reason,
                    "status": "capability_mismatch"
                }
        
        # 2. Submit request to kernel for permission check
        request = self.kernel.submit_request(agent_context, action_type, parameters)

        
        if request.status == ExecutionStatus.DENIED:
            return {
                "success": False,
                "error": "Request denied by kernel",
                "request_id": request.request_id,
                "status": request.status.value
            }
        
        # 3. Validate against Constraint Graphs (if enabled)
        if self.constraint_graphs_enabled and self.constraint_validator:
            is_valid, violations = self.constraint_validator.validate_request(request)
            if not is_valid:
                return {
                    "success": False,
                    "error": f"Constraint graph violations: {', '.join(violations)}",
                    "request_id": request.request_id,
                    "status": "constraint_violation",
                    "violations": violations
                }
        
        # 4. Validate with policy engine
        is_valid, reason = self.policy_engine.validate_request(request)
        if not is_valid:
            return {
                "success": False,
                "error": f"Policy validation failed: {reason}",
                "request_id": request.request_id,
                "status": "policy_violation"
            }
        
        # 5. Validate risk level
        if not self.policy_engine.validate_risk(request, request.risk_score):
            return {
                "success": False,
                "error": "Request risk level too high",
                "request_id": request.request_id,
                "risk_score": request.risk_score,
                "status": "risk_denied"
            }
        
        # 6. Execute in Shadow Mode or Real Mode
        if self.shadow_mode_enabled:
            # Shadow mode: simulate without executing
            simulation = self.shadow_executor.execute_in_shadow(request, reasoning_chain)
            return {
                "success": True,
                "result": simulation.simulated_result,
                "request_id": request.request_id,
                "status": "simulated",
                "outcome": simulation.outcome.value,
                "actual_impact": simulation.actual_impact,
                "risk_score": request.risk_score,
                "note": "This was executed in SHADOW MODE - no actual execution occurred"
            }
        else:
            # Real execution
            execution_result = self.execution_engine.execute(request, execution_context)
            
            # Update kernel with execution result
            if execution_result["success"]:
                kernel_result = self.kernel.execute(request)
                return {
                    "success": True,
                    "result": execution_result["result"],
                    "request_id": request.request_id,
                    "metrics": execution_result.get("metrics", {}),
                    "risk_score": request.risk_score
                }
            else:
                return execution_result
    
    def add_policy_rule(self, rule: PolicyRule):
        """Add a custom policy rule"""
        self.kernel.add_policy_rule(rule)
        self.policy_engine.add_custom_rule(rule)
    
    def set_agent_quota(self, agent_id: str, quota: ResourceQuota):
        """Set resource quota for an agent"""
        self.policy_engine.set_quota(agent_id, quota)
    
    def set_risk_policy(self, policy_id: str, policy: RiskPolicy):
        """Set a risk policy"""
        self.policy_engine.set_risk_policy(policy_id, policy)
    
    def get_agent_status(self, agent_id: str) -> Dict[str, Any]:
        """Get comprehensive status for an agent"""
        return {
            "agent_id": agent_id,
            "quota_status": self.policy_engine.get_quota_status(agent_id),
            "active_executions": len([
                ctx for ctx in self.execution_engine.get_active_executions().values()
            ]),
            "execution_history": self.execution_engine.get_execution_history(agent_id, limit=10)
        }
    
    def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get audit log entries"""
        return self.kernel.get_audit_log()[-limit:]
    
    def get_execution_history(
        self,
        agent_id: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get execution history"""
        return self.execution_engine.get_execution_history(agent_id, limit)
    
    def _register_default_executors(self):
        """Register default executors for common action types"""
        self.execution_engine.register_executor(ActionType.FILE_READ, file_read_executor)
        self.execution_engine.register_executor(ActionType.CODE_EXECUTION, code_execution_executor)
        self.execution_engine.register_executor(ActionType.API_CALL, api_call_executor)
    
    def _add_default_policies(self):
        """Add default security policies"""
        for policy in create_default_policies():
            self.add_policy_rule(policy)
    
    # ===== New Methods for Advanced Features =====
    
    def enable_mute_agent(self, agent_id: str, config: MuteAgentConfig):
        """
        Enable Mute Agent mode for an agent.
        
        The agent will only execute actions that match its defined capabilities
        and return NULL for out-of-scope requests.
        """
        self.mute_validators[agent_id] = MuteAgentValidator(config)
    
    def enable_shadow_mode(self, enabled: bool = True):
        """
        Enable or disable shadow mode for all executions.
        
        In shadow mode, actions are simulated but not actually executed.
        """
        self.shadow_mode_enabled = enabled
        self.shadow_executor.config.enabled = enabled
    
    def get_shadow_simulations(self, agent_id: Optional[str] = None) -> List[Any]:
        """Get shadow mode simulation log"""
        return self.shadow_executor.get_simulation_log(agent_id)
    
    def get_shadow_statistics(self) -> Dict[str, Any]:
        """Get statistics about shadow mode executions"""
        return self.shadow_executor.get_statistics()
    
    def add_supervisor(self, supervisor: SupervisorAgent):
        """Add a supervisor agent to monitor worker agents"""
        self.supervisor_network.add_supervisor(supervisor)
    
    def run_supervision(self) -> Dict[str, List[Any]]:
        """
        Run a supervision cycle to check for violations.
        
        Returns violations detected by all supervisors.
        """
        execution_log = self.get_execution_history()
        audit_log = self.get_audit_log()
        return self.supervisor_network.run_supervision_cycle(execution_log, audit_log)
    
    def get_supervisor_summary(self) -> Dict[str, Any]:
        """Get summary of supervisor network activity"""
        return self.supervisor_network.get_network_summary()
    
    # ===== Plugin Registry Integration Methods =====
    
    def register_validator(
        self,
        validator: ValidatorInterface,
        action_types: Optional[List[str]] = None
    ) -> None:
        """
        Register a validator with the control plane.
        
        This is the preferred method for adding validators instead of
        using enable_mute_agent() directly.
        
        Args:
            validator: Validator implementing ValidatorInterface
            action_types: Optional list of action types this validator handles
        """
        self._validators.append(validator)
        
        # Also register with plugin registry if available
        if self._registry:
            self._registry.register_validator(validator, action_types=action_types)
    
    def register_kernel(self, kernel: KernelInterface) -> None:
        """
        Register a custom kernel with the control plane.
        
        This allows injecting custom kernels like SCAK without hard imports.
        
        Args:
            kernel: Kernel implementing KernelInterface
        """
        self._custom_kernel = kernel
        
        # Also register with plugin registry if available
        if self._registry:
            self._registry.register_kernel(kernel)
    
    def register_context_router(
        self,
        router: Union[ContextRouterInterface, ContextRoutingInterface]
    ) -> None:
        """
        Register a context router for caas integration.
        
        Args:
            router: Context router implementing ContextRouterInterface
        """
        self._context_router = router
        
        if self._registry:
            self._registry.register_context_router(router)
    
    def register_message_security(self, security: MessageSecurityInterface) -> None:
        """
        Register a message security provider for iatp integration.
        
        Args:
            security: Security provider implementing MessageSecurityInterface
        """
        self._message_security = security
        
        if self._registry:
            self._registry.register_message_security(security)
    
    def register_verifier(self, verifier: VerificationInterface) -> None:
        """
        Register a verifier for cmvk integration.
        
        Args:
            verifier: Verifier implementing VerificationInterface
        """
        self._verifier = verifier
        
        if self._registry:
            self._registry.register_verifier(verifier)
    
    def get_registered_validators(self) -> List[ValidatorInterface]:
        """Get all registered validators"""
        return self._validators.copy()
    
    def get_plugin_registry(self) -> Optional[PluginRegistry]:
        """Get the plugin registry if enabled"""
        return self._registry
    
    # Constraint Graph methods
    
    def add_data_table(self, table_name: str, schema: Dict[str, Any], metadata: Optional[Dict] = None):
        """Add a database table to the data graph"""
        if self.data_graph:
            self.data_graph.add_database_table(table_name, schema, metadata)
    
    def add_data_path(self, path: str, access_level: str = "read", metadata: Optional[Dict] = None):
        """Add a file path to the data graph"""
        if self.data_graph:
            self.data_graph.add_file_path(path, access_level, metadata)
    
    def add_policy_constraint(self, rule_id: str, name: str, applies_to: List[str], rule_type: str):
        """Add a policy constraint to the policy graph"""
        if self.policy_graph:
            self.policy_graph.add_policy_rule(rule_id, name, applies_to, rule_type)
    
    def add_maintenance_window(self, window_id: str, start_time, end_time, blocked_actions: List[ActionType]):
        """Add a maintenance window to the temporal graph"""
        if self.temporal_graph:
            self.temporal_graph.add_maintenance_window(window_id, start_time, end_time, blocked_actions)
    
    def get_constraint_validation_log(self) -> List[Dict[str, Any]]:
        """Get log of constraint graph validations"""
        if self.constraint_validator:
            return self.constraint_validator.get_validation_log()
        return []
    
    # ===== Agent Hibernation Methods (Serverless Agents) =====
    
    def hibernate_agent(
        self,
        agent_id: str,
        agent_context: AgentContext,
        caas_pointer: Optional[str] = None,
        additional_state: Optional[Dict[str, Any]] = None
    ):
        """
        Hibernate an agent by serializing its state to disk.
        
        This implements the "Serverless Agents" pattern - agents sitting idle
        in memory are hibernated to disk, removing the need for "always-on" servers.
        
        Args:
            agent_id: Agent identifier
            agent_context: Agent context to hibernate
            caas_pointer: Optional pointer to context in caas (Context-as-a-Service)
            additional_state: Optional additional state to serialize
            
        Returns:
            Metadata about the hibernated agent
        """
        if not self.hibernation_enabled or not self.hibernation_manager:
            raise RuntimeError("Hibernation is not enabled")
        
        return self.hibernation_manager.hibernate_agent(
            agent_id, agent_context, caas_pointer, additional_state
        )
    
    def wake_agent(self, agent_id: str) -> Dict[str, Any]:
        """
        Wake up a hibernated agent and restore its state.
        
        Args:
            agent_id: Agent identifier to wake
            
        Returns:
            Restored agent state
        """
        if not self.hibernation_enabled or not self.hibernation_manager:
            raise RuntimeError("Hibernation is not enabled")
        
        return self.hibernation_manager.wake_agent(agent_id)
    
    def is_agent_hibernated(self, agent_id: str) -> bool:
        """Check if an agent is currently hibernated"""
        if not self.hibernation_enabled or not self.hibernation_manager:
            return False
        
        return self.hibernation_manager.is_agent_hibernated(agent_id)
    
    def record_agent_activity(self, agent_id: str):
        """Record activity for an agent (resets idle timer)"""
        if self.hibernation_enabled and self.hibernation_manager:
            self.hibernation_manager.record_agent_activity(agent_id)
    
    def hibernate_idle_agents(self, min_idle_seconds: Optional[int] = None) -> List[str]:
        """
        Automatically hibernate agents that have been idle.
        
        Args:
            min_idle_seconds: Minimum idle time (uses config default if None)
            
        Returns:
            List of agent IDs that were hibernated
        """
        if not self.hibernation_enabled or not self.hibernation_manager:
            return []
        
        idle_agents = self.hibernation_manager.get_idle_agents(min_idle_seconds)
        hibernated = []
        
        for agent_id in idle_agents:
            # Get agent context from active sessions
            if agent_id in self.kernel.active_sessions:
                session_id = None
                for sid, ctx in self.kernel.active_sessions.items():
                    if ctx.agent_id == agent_id:
                        session_id = sid
                        break
                
                if session_id:
                    agent_context = self.kernel.active_sessions[session_id]
                    try:
                        self.hibernate_agent(agent_id, agent_context)
                        hibernated.append(agent_id)
                        # Remove from active sessions
                        del self.kernel.active_sessions[session_id]
                    except Exception as e:
                        self.kernel.logger.error(f"Failed to hibernate idle agent {agent_id}: {e}")
        
        return hibernated
    
    def get_hibernation_statistics(self) -> Dict[str, Any]:
        """Get statistics about agent hibernation"""
        if not self.hibernation_enabled or not self.hibernation_manager:
            return {"enabled": False}
        
        return self.hibernation_manager.get_statistics()
    
    # ===== Time-Travel Debugging Methods =====
    
    def replay_agent_history(
        self,
        agent_id: str,
        minutes: int,
        callback: Optional[callable] = None
    ):
        """
        Replay the last N minutes of an agent's life exactly as it happened.
        
        This implements "Time-Travel Debugging" - re-run agent actions from history
        for debugging and analysis.
        
        Args:
            agent_id: Agent identifier
            minutes: Number of minutes to replay
            callback: Optional callback for each replayed event
            
        Returns:
            ReplaySession for the replay
        """
        if not self.time_travel_enabled or not self.time_travel_debugger:
            raise RuntimeError("Time-travel debugging is not enabled")
        
        session = self.time_travel_debugger.replay_time_window(agent_id, minutes)
        
        if callback:
            self.time_travel_debugger.replay_agent_history(
                agent_id, session.session_id, callback
            )
        
        return session
    
    def capture_agent_state_snapshot(
        self,
        agent_id: str,
        agent_context: AgentContext,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Capture a point-in-time snapshot of agent state for time-travel debugging.
        
        Args:
            agent_id: Agent identifier
            agent_context: Agent context to snapshot
            metadata: Optional metadata
        """
        if not self.time_travel_enabled or not self.time_travel_debugger:
            return
        
        # Convert agent context to serializable state
        state = {
            "session_id": agent_context.session_id,
            "created_at": agent_context.created_at.isoformat(),
            "permissions": {str(k): v.value for k, v in agent_context.permissions.items()},
            "metadata": agent_context.metadata
        }
        
        self.time_travel_debugger.capture_state_snapshot(agent_id, state, metadata)
    
    def get_replay_summary(self, session_id: str) -> Dict[str, Any]:
        """Get summary of a replay session"""
        if not self.time_travel_enabled or not self.time_travel_debugger:
            raise RuntimeError("Time-travel debugging is not enabled")
        
        return self.time_travel_debugger.get_replay_summary(session_id)
    
    def get_time_travel_statistics(self) -> Dict[str, Any]:
        """Get statistics about time-travel debugging"""
        if not self.time_travel_enabled or not self.time_travel_debugger:
            return {"enabled": False}
        
        return self.time_travel_debugger.get_statistics()



# Convenience functions for common operations

def create_read_only_agent(control_plane: AgentControlPlane, agent_id: str) -> AgentContext:
    """Create an agent with read-only permissions"""
    permissions = {
        ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY,
    }
    
    quota = ResourceQuota(
        agent_id=agent_id,
        max_requests_per_minute=30,
        max_requests_per_hour=500,
        allowed_action_types=[ActionType.FILE_READ, ActionType.DATABASE_QUERY]
    )
    
    return control_plane.create_agent(agent_id, permissions, quota)


def create_standard_agent(control_plane: AgentControlPlane, agent_id: str) -> AgentContext:
    """Create an agent with standard permissions"""
    permissions = {
        ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        ActionType.FILE_WRITE: PermissionLevel.READ_WRITE,
        ActionType.API_CALL: PermissionLevel.READ_WRITE,
        ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY,
        ActionType.CODE_EXECUTION: PermissionLevel.READ_WRITE,
    }
    
    quota = ResourceQuota(
        agent_id=agent_id,
        max_requests_per_minute=60,
        max_requests_per_hour=1000,
        allowed_action_types=[
            ActionType.FILE_READ,
            ActionType.FILE_WRITE,
            ActionType.API_CALL,
            ActionType.DATABASE_QUERY,
            ActionType.CODE_EXECUTION,
        ]
    )
    
    return control_plane.create_agent(agent_id, permissions, quota)


def create_admin_agent(control_plane: AgentControlPlane, agent_id: str) -> AgentContext:
    """Create an agent with admin permissions"""
    permissions = {
        action_type: PermissionLevel.ADMIN
        for action_type in ActionType
    }
    
    quota = ResourceQuota(
        agent_id=agent_id,
        max_requests_per_minute=120,
        max_requests_per_hour=5000,
        allowed_action_types=list(ActionType)
    )
    
    return control_plane.create_agent(agent_id, permissions, quota)
