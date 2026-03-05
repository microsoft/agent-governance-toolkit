# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Kernel Interface - Abstract Base for Agent Kernels

This interface defines the contract that any kernel implementation must follow.
External kernels like SCAK (Self-Correcting Agent Kernel) should inherit from
this interface rather than being hard-imported.

Pattern: Instead of `import scak`, define KernelInterface here.
SCAK and other kernels will later inherit from this interface.

Layer 3: The Framework
- This is the governance layer that defines Agent, Supervisor, Tool, and Policy
- Kernels are injected at runtime via config or dependency injection
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Callable, TYPE_CHECKING
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class KernelCapability(Enum):
    """Capabilities that a kernel implementation may support"""
    
    # Core capabilities
    SESSION_MANAGEMENT = "session_management"
    PERMISSION_CHECKING = "permission_checking"
    POLICY_ENFORCEMENT = "policy_enforcement"
    AUDIT_LOGGING = "audit_logging"
    
    # Advanced capabilities
    SELF_CORRECTION = "self_correction"  # e.g., SCAK
    SHADOW_MODE = "shadow_mode"
    CAPABILITY_RESTRICTION = "capability_restriction"  # e.g., Mute Agent pattern
    CONSTRAINT_GRAPHS = "constraint_graphs"
    
    # Runtime features
    HOT_RELOAD = "hot_reload"
    DISTRIBUTED = "distributed"
    ASYNC_EXECUTION = "async_execution"


@dataclass
class KernelMetadata:
    """Metadata about a kernel implementation"""
    
    name: str
    version: str
    description: str
    capabilities: List[KernelCapability] = field(default_factory=list)
    author: str = ""
    homepage: str = ""
    
    # Runtime info
    is_loaded: bool = False
    load_timestamp: Optional[datetime] = None
    
    # Configuration schema (JSON Schema format)
    config_schema: Dict[str, Any] = field(default_factory=dict)


class KernelInterface(ABC):
    """
    Abstract interface for Agent Kernels.
    
    The Agent Kernel is the central component that mediates all interactions
    between LLMs (raw compute) and the execution environment. It provides
    governance, safety, and observability for autonomous agents.
    
    Any kernel implementation (including SCAK) should inherit from this interface.
    This allows the control plane to work with any kernel without hard dependencies.
    
    Example Usage:
        ```python
        # In your kernel implementation (e.g., scak package)
        from agent_control_plane.interfaces import KernelInterface
        
        class SCAKKernel(KernelInterface):
            def create_session(self, agent_id, permissions=None):
                # SCAK-specific implementation
                ...
        
        # In the control plane
        control_plane = AgentControlPlane()
        control_plane.register_kernel(SCAKKernel())
        ```
    """
    
    @property
    @abstractmethod
    def metadata(self) -> KernelMetadata:
        """Return metadata about this kernel implementation"""
        pass
    
    @abstractmethod
    def create_session(
        self, 
        agent_id: str, 
        permissions: Optional[Dict[str, Any]] = None
    ) -> Any:
        """
        Create a new agent session with specified permissions.
        
        Args:
            agent_id: Unique identifier for the agent
            permissions: Dictionary mapping action types to permission levels
            
        Returns:
            Session context object (implementation-specific)
        """
        pass
    
    @abstractmethod
    def terminate_session(self, session_id: str) -> bool:
        """
        Terminate an agent session.
        
        Args:
            session_id: ID of the session to terminate
            
        Returns:
            True if session was terminated, False if not found
        """
        pass
    
    @abstractmethod
    def check_permission(
        self, 
        session_id: str, 
        action_type: str, 
        parameters: Dict[str, Any]
    ) -> tuple[bool, Optional[str]]:
        """
        Check if an action is permitted for the given session.
        
        Args:
            session_id: ID of the agent session
            action_type: Type of action being requested
            parameters: Parameters for the action
            
        Returns:
            Tuple of (is_permitted, reason_if_denied)
        """
        pass
    
    @abstractmethod
    def submit_request(
        self, 
        session_id: str, 
        action_type: str, 
        parameters: Dict[str, Any]
    ) -> Any:
        """
        Submit an execution request for processing.
        
        Args:
            session_id: ID of the agent session
            action_type: Type of action to execute
            parameters: Parameters for the action
            
        Returns:
            Execution request object (implementation-specific)
        """
        pass
    
    @abstractmethod
    def execute(self, request: Any) -> Any:
        """
        Execute an approved request.
        
        Args:
            request: The execution request to process
            
        Returns:
            Execution result (implementation-specific)
        """
        pass
    
    @abstractmethod
    def add_policy_rule(self, rule: Any) -> None:
        """
        Add a policy rule to the kernel.
        
        Args:
            rule: Policy rule to add (implementation-specific)
        """
        pass
    
    @abstractmethod
    def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get audit log entries.
        
        Args:
            limit: Maximum number of entries to return
            
        Returns:
            List of audit log entries
        """
        pass
    
    # Optional methods with default implementations
    
    def supports_capability(self, capability: KernelCapability) -> bool:
        """Check if this kernel supports a specific capability"""
        return capability in self.metadata.capabilities
    
    def get_active_sessions(self) -> Dict[str, Any]:
        """Get all active sessions (optional)"""
        return {}
    
    def configure(self, config: Dict[str, Any]) -> None:
        """
        Configure the kernel with runtime settings.
        
        Args:
            config: Configuration dictionary
        """
        pass
    
    def health_check(self) -> Dict[str, Any]:
        """
        Perform a health check on the kernel.
        
        Returns:
            Health status dictionary
        """
        return {
            "status": "healthy",
            "kernel": self.metadata.name,
            "version": self.metadata.version,
            "capabilities": [c.value for c in self.metadata.capabilities]
        }


class SelfCorrectingKernelInterface(KernelInterface):
    """
    Extended interface for self-correcting kernels (like SCAK).
    
    This interface adds methods for kernels that can:
    - Learn from execution failures
    - Adapt policies based on observed behavior
    - Self-correct reasoning chains
    """
    
    @abstractmethod
    def record_outcome(
        self, 
        request_id: str, 
        outcome: str, 
        feedback: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Record the outcome of an execution for learning.
        
        Args:
            request_id: ID of the execution request
            outcome: Outcome status (success, failure, partial, etc.)
            feedback: Optional feedback for learning
        """
        pass
    
    @abstractmethod
    def get_correction_suggestions(
        self, 
        request: Any
    ) -> List[Dict[str, Any]]:
        """
        Get suggestions for correcting a request.
        
        Args:
            request: The request to analyze
            
        Returns:
            List of correction suggestions
        """
        pass
    
    @abstractmethod
    def apply_learned_policy(
        self, 
        policy_id: str, 
        confidence_threshold: float = 0.8
    ) -> bool:
        """
        Apply a learned policy if confidence exceeds threshold.
        
        Args:
            policy_id: ID of the learned policy
            confidence_threshold: Minimum confidence required
            
        Returns:
            True if policy was applied
        """
        pass


class CapabilityRestrictedKernelInterface(KernelInterface):
    """
    Extended interface for capability-restricted kernels (Mute Agent pattern).
    
    This interface adds methods for kernels that:
    - Restrict agents to specific capabilities
    - Return NULL/silence for out-of-scope requests
    - Implement "Scale by Subtraction" philosophy
    """
    
    @abstractmethod
    def define_capability(
        self, 
        agent_id: str, 
        capability_name: str, 
        allowed_actions: List[str],
        parameter_schema: Dict[str, Any]
    ) -> None:
        """
        Define a capability for an agent.
        
        Args:
            agent_id: ID of the agent
            capability_name: Name of the capability
            allowed_actions: List of allowed action types
            parameter_schema: JSON schema for valid parameters
        """
        pass
    
    @abstractmethod
    def validate_against_capabilities(
        self, 
        agent_id: str, 
        action_type: str, 
        parameters: Dict[str, Any]
    ) -> tuple[bool, Optional[str]]:
        """
        Validate a request against agent capabilities.
        
        Args:
            agent_id: ID of the agent
            action_type: Type of action requested
            parameters: Action parameters
            
        Returns:
            Tuple of (is_valid, null_response_if_invalid)
        """
        pass
    
    @abstractmethod
    def get_rejection_log(self, agent_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get log of rejected (out-of-scope) requests.
        
        Args:
            agent_id: Optional filter by agent ID
            
        Returns:
            List of rejection log entries
        """
        pass
