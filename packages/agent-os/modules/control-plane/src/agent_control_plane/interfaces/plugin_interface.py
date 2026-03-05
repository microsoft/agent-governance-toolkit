# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Plugin Interfaces - Abstract Base Classes for Pluggable Components

This module defines the interfaces for pluggable components that can be
injected at runtime without hard dependencies. This enables:
1. Custom validators (instead of hard-coded mute_agent)
2. Custom executors (sandboxing, remote execution, etc.)
3. Custom context routers (for different routing strategies)
4. Custom policy providers (for different policy sources)

Layer 3: The Framework
- Components are injected at runtime via config or dependency injection
- No hard imports of specific implementations
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Callable, Set, TypeVar, Generic
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class PluginCapability(Enum):
    """Capabilities that a plugin may support"""
    
    # Validator capabilities
    REQUEST_VALIDATION = "request_validation"
    CAPABILITY_CHECKING = "capability_checking"
    PARAMETER_VALIDATION = "parameter_validation"
    RISK_ASSESSMENT = "risk_assessment"
    
    # Executor capabilities
    SANDBOXED_EXECUTION = "sandboxed_execution"
    REMOTE_EXECUTION = "remote_execution"
    ASYNC_EXECUTION = "async_execution"
    ROLLBACK_SUPPORT = "rollback_support"
    
    # Context routing capabilities
    STATIC_ROUTING = "static_routing"
    DYNAMIC_ROUTING = "dynamic_routing"
    CONTENT_BASED_ROUTING = "content_based_routing"
    LOAD_BALANCED_ROUTING = "load_balanced_routing"
    
    # Policy provider capabilities
    FILE_BASED_POLICIES = "file_based_policies"
    DATABASE_POLICIES = "database_policies"
    REMOTE_POLICIES = "remote_policies"
    DYNAMIC_POLICIES = "dynamic_policies"


@dataclass
class PluginMetadata:
    """Metadata about a plugin implementation"""
    
    name: str
    version: str
    description: str
    plugin_type: str  # "validator", "executor", "router", "policy_provider"
    capabilities: List[PluginCapability] = field(default_factory=list)
    author: str = ""
    homepage: str = ""
    
    # Dependencies
    requires: List[str] = field(default_factory=list)  # Required plugins
    conflicts: List[str] = field(default_factory=list)  # Conflicting plugins
    
    # Runtime info
    is_loaded: bool = False
    load_timestamp: Optional[datetime] = None
    
    # Configuration schema (JSON Schema format)
    config_schema: Dict[str, Any] = field(default_factory=dict)


# Type variable for generic plugin results
T = TypeVar('T')


class PluginInterface(ABC, Generic[T]):
    """Base interface for all plugins"""
    
    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Return metadata about this plugin"""
        pass
    
    def configure(self, config: Dict[str, Any]) -> None:
        """Configure the plugin with runtime settings"""
        pass
    
    def initialize(self) -> None:
        """Initialize the plugin (called after configuration)"""
        pass
    
    def shutdown(self) -> None:
        """Shutdown the plugin (called before unload)"""
        pass
    
    def health_check(self) -> Dict[str, Any]:
        """Perform a health check"""
        return {
            "status": "healthy",
            "plugin": self.metadata.name,
            "version": self.metadata.version,
            "type": self.metadata.plugin_type
        }


@dataclass
class ValidationResult:
    """Result of a validation operation"""
    is_valid: bool
    reason: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    corrective_actions: List[str] = field(default_factory=list)


class ValidatorInterface(PluginInterface[ValidationResult]):
    """
    Abstract interface for request validators.
    
    Validators check requests before execution and can:
    - Approve or deny requests
    - Provide reasons for denial
    - Suggest corrective actions
    
    This replaces hard-coded validators like MuteAgentValidator.
    
    Example Usage:
        ```python
        from agent_control_plane.interfaces import ValidatorInterface
        
        class CustomValidator(ValidatorInterface):
            def validate_request(self, request, context):
                # Custom validation logic
                ...
        
        # Register with control plane
        control_plane.register_validator(CustomValidator())
        ```
    """
    
    @abstractmethod
    def validate_request(
        self, 
        request: Any, 
        context: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """
        Validate an execution request.
        
        Args:
            request: The execution request to validate
            context: Optional additional context
            
        Returns:
            ValidationResult with approval/denial and details
        """
        pass
    
    def validate_parameters(
        self, 
        action_type: str, 
        parameters: Dict[str, Any]
    ) -> ValidationResult:
        """
        Lightweight parameter validation without full request.
        
        Args:
            action_type: Type of action
            parameters: Parameters to validate
            
        Returns:
            ValidationResult
        """
        return ValidationResult(is_valid=True)
    
    def get_validation_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get log of validation decisions"""
        return []


class CapabilityValidatorInterface(ValidatorInterface):
    """
    Extended interface for capability-based validators (Mute Agent pattern).
    
    These validators implement the "Scale by Subtraction" philosophy:
    - Agents are restricted to defined capabilities
    - Out-of-scope requests return NULL/silence
    - Fail-fast behavior prevents hallucination
    """
    
    @abstractmethod
    def define_capability(
        self, 
        agent_id: str,
        capability_name: str,
        allowed_actions: List[str],
        parameter_schema: Dict[str, Any],
        validator: Optional[Callable[[Any], bool]] = None
    ) -> None:
        """
        Define a capability for an agent.
        
        Args:
            agent_id: ID of the agent
            capability_name: Name of the capability
            allowed_actions: List of allowed action types
            parameter_schema: JSON schema for valid parameters
            validator: Optional custom validation function
        """
        pass
    
    @abstractmethod
    def get_agent_capabilities(self, agent_id: str) -> List[Dict[str, Any]]:
        """Get all capabilities defined for an agent"""
        pass
    
    @abstractmethod
    def get_null_response(self) -> str:
        """Get the NULL response message for out-of-scope requests"""
        pass
    
    @abstractmethod
    def get_rejection_log(self, agent_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get log of rejected (out-of-scope) requests"""
        pass


@dataclass
class ExecutionResult:
    """Result of an execution operation"""
    success: bool
    result: Optional[Any] = None
    error: Optional[str] = None
    execution_time_ms: float = 0.0
    resources_used: Dict[str, Any] = field(default_factory=dict)
    rollback_available: bool = False


class ExecutorInterface(PluginInterface[ExecutionResult]):
    """
    Abstract interface for action executors.
    
    Executors handle the actual execution of approved requests.
    Different executors can provide different execution environments
    (sandboxed, remote, distributed, etc.).
    
    Example Usage:
        ```python
        from agent_control_plane.interfaces import ExecutorInterface
        
        class DockerExecutor(ExecutorInterface):
            def execute(self, request, context):
                # Execute in Docker container
                ...
        
        control_plane.register_executor("code_execution", DockerExecutor())
        ```
    """
    
    @abstractmethod
    def execute(
        self, 
        request: Any, 
        context: Optional[Dict[str, Any]] = None
    ) -> ExecutionResult:
        """
        Execute an approved request.
        
        Args:
            request: The execution request
            context: Optional execution context (timeouts, resources, etc.)
            
        Returns:
            ExecutionResult with output and metadata
        """
        pass
    
    def can_execute(self, action_type: str) -> bool:
        """Check if this executor can handle the given action type"""
        return True
    
    def rollback(self, execution_id: str) -> bool:
        """
        Rollback a previous execution if supported.
        
        Args:
            execution_id: ID of the execution to rollback
            
        Returns:
            True if rollback was successful
        """
        return False
    
    def get_execution_history(
        self, 
        agent_id: Optional[str] = None, 
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get execution history"""
        return []


@dataclass
class RoutingDecision:
    """Result of a routing decision"""
    target: str  # Target agent/handler ID
    priority: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    fallbacks: List[str] = field(default_factory=list)


class ContextRouterInterface(PluginInterface[RoutingDecision]):
    """
    Abstract interface for context routers.
    
    Context routers decide how to route requests based on content,
    agent capabilities, load, or other factors.
    
    This allows integration with caas (Context-as-a-Service).
    
    Example Usage:
        ```python
        from agent_control_plane.interfaces import ContextRouterInterface
        
        class CAASRouter(ContextRouterInterface):
            def route(self, request, available_agents):
                # Route using CAAS
                ...
        
        control_plane.register_router(CAASRouter())
        ```
    """
    
    @abstractmethod
    def route(
        self, 
        request: Any, 
        available_targets: List[str],
        context: Optional[Dict[str, Any]] = None
    ) -> RoutingDecision:
        """
        Route a request to an appropriate target.
        
        Args:
            request: The request to route
            available_targets: List of available target IDs
            context: Optional routing context
            
        Returns:
            RoutingDecision with target and metadata
        """
        pass
    
    def register_target(
        self, 
        target_id: str, 
        capabilities: List[str],
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Register a routing target with its capabilities"""
        pass
    
    def unregister_target(self, target_id: str) -> bool:
        """Unregister a routing target"""
        return False
    
    def get_routing_statistics(self) -> Dict[str, Any]:
        """Get routing statistics"""
        return {}


@dataclass
class PolicyDefinition:
    """Definition of a policy"""
    policy_id: str
    name: str
    description: str
    rules: List[Dict[str, Any]]
    priority: int = 0
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


class PolicyProviderInterface(PluginInterface[PolicyDefinition]):
    """
    Abstract interface for policy providers.
    
    Policy providers supply policy rules from different sources
    (files, databases, remote services, etc.).
    
    Example Usage:
        ```python
        from agent_control_plane.interfaces import PolicyProviderInterface
        
        class DatabasePolicyProvider(PolicyProviderInterface):
            def get_policies(self, agent_id):
                # Fetch policies from database
                ...
        
        control_plane.register_policy_provider(DatabasePolicyProvider())
        ```
    """
    
    @abstractmethod
    def get_policies(
        self, 
        agent_id: Optional[str] = None,
        action_type: Optional[str] = None
    ) -> List[PolicyDefinition]:
        """
        Get applicable policies.
        
        Args:
            agent_id: Optional filter by agent
            action_type: Optional filter by action type
            
        Returns:
            List of applicable policy definitions
        """
        pass
    
    def add_policy(self, policy: PolicyDefinition) -> bool:
        """Add a new policy"""
        return False
    
    def update_policy(self, policy_id: str, updates: Dict[str, Any]) -> bool:
        """Update an existing policy"""
        return False
    
    def delete_policy(self, policy_id: str) -> bool:
        """Delete a policy"""
        return False
    
    def refresh(self) -> None:
        """Refresh policies from source"""
        pass


class SupervisorInterface(PluginInterface[ValidationResult]):
    """
    Abstract interface for supervisor agents.
    
    Supervisors monitor agent behavior and can intervene when
    violations are detected. This enables recursive governance.
    
    Example Usage:
        ```python
        from agent_control_plane.interfaces import SupervisorInterface
        
        class ComplianceSupervisor(SupervisorInterface):
            def supervise(self, execution_log, audit_log):
                # Check for compliance violations
                ...
        
        control_plane.register_supervisor(ComplianceSupervisor())
        ```
    """
    
    @abstractmethod
    def supervise(
        self, 
        execution_log: List[Dict[str, Any]],
        audit_log: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Run supervision cycle and return violations.
        
        Args:
            execution_log: Recent execution history
            audit_log: Recent audit entries
            
        Returns:
            List of detected violations
        """
        pass
    
    @abstractmethod
    def get_monitored_agents(self) -> List[str]:
        """Get list of agent IDs being monitored"""
        pass
    
    def add_monitored_agent(self, agent_id: str) -> None:
        """Add an agent to monitoring"""
        pass
    
    def remove_monitored_agent(self, agent_id: str) -> None:
        """Remove an agent from monitoring"""
        pass
    
    def get_violation_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get history of detected violations"""
        return []
