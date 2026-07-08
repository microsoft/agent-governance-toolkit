# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
The Mute Agent - Scale by Subtraction

The Mute Agent represents the philosophy of "Scale by Subtraction" - removing
creativity and ensuring agents fail fast with NULL responses when requests
are out of scope, rather than hallucinating or being conversational.

This module provides capabilities for agents to strictly operate within
their defined constraints and return NULL/silence for out-of-scope requests.

Research Foundations:
    - Capability-based security model (principle of least privilege)
    - "If a system can't do something, it can't be tricked into doing it"
    - Fail-safe defaults from secure system design
    - Inspired by NULL semantics in type systems and databases

See docs/RESEARCH_FOUNDATION.md for complete references.

DEPRECATION NOTICE:
    This module is being refactored to use the plugin interface pattern.
    New code should use CapabilityValidatorInterface from 
    agent_control_plane.interfaces instead of directly importing this module.
    
    The MuteAgentValidator class now implements CapabilityValidatorInterface
    and can be registered with the PluginRegistry for dependency injection.
"""

import warnings
import logging
from typing import Any, Dict, Optional, List, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from .agent_kernel import ActionType, ExecutionRequest
from .interfaces.plugin_interface import (
    CapabilityValidatorInterface,
    ValidationResult,
    PluginMetadata,
    PluginCapability,
)


logger = logging.getLogger(__name__)


@dataclass
class AgentCapability:
    """Defines a specific capability an agent has"""
    name: str
    description: str
    action_types: List[ActionType]
    parameter_schema: Dict[str, Any]  # JSON schema for parameters
    validator: Optional[Callable[[ExecutionRequest], bool]] = None


@dataclass
class _NormalizedRequest:
    """Shape-independent view of a request used to drive capability validators.

    Both ``ExecutionRequest`` objects and dict-based requests are normalized to
    this type so that validation strength never depends on the in-memory shape
    of the request. Existing validators only read ``parameters``/``action_type``;
    other ``ExecutionRequest`` fields are passed through when available.
    """
    action_type: Optional[ActionType]
    parameters: Dict[str, Any]
    request_id: str
    timestamp: Any
    agent_context: Any = None
    status: Any = None
    risk_score: float = 0.0


@dataclass
class MuteAgentConfig:
    """Configuration for a Mute Agent"""
    agent_id: str
    capabilities: List[AgentCapability] = field(default_factory=list)
    strict_mode: bool = True  # If True, reject anything outside capabilities
    null_response_message: str = "NULL"  # Response for out-of-scope requests
    enable_explanation: bool = False  # If True, explain why request was rejected


class MuteAgentValidator(CapabilityValidatorInterface):
    """
    Validates requests against agent capabilities.
    
    The Mute Agent knows when to shut up. If a request doesn't map to a
    defined capability, it returns NULL instead of hallucinating or trying
    to be helpful in creative ways.
    
    This class implements CapabilityValidatorInterface for use with the
    PluginRegistry and dependency injection pattern.
    
    DEPRECATION NOTICE:
        Direct instantiation of MuteAgentValidator is deprecated.
        Instead, use the PluginRegistry to register validators:
        
        ```python
        from agent_control_plane import PluginRegistry
        
        registry = PluginRegistry()
        validator = MuteAgentValidator(config)
        registry.register_validator(validator)
        ```
    """
    
    def __init__(self, config: MuteAgentConfig):
        self.config = config
        self.rejection_log: List[Dict[str, Any]] = []
        self._agent_capabilities: Dict[str, List[AgentCapability]] = {
            config.agent_id: config.capabilities
        }
    
    @property
    def metadata(self) -> PluginMetadata:
        """Return metadata about this validator plugin"""
        return PluginMetadata(
            name=f"mute_agent_validator_{self.config.agent_id}",
            version="1.1.0",
            description="Capability-based validator implementing Scale by Subtraction philosophy",
            plugin_type="validator",
            capabilities=[
                PluginCapability.REQUEST_VALIDATION,
                PluginCapability.CAPABILITY_CHECKING,
                PluginCapability.PARAMETER_VALIDATION,
            ]
        )
    
    def validate_request(
        self, 
        request: Any, 
        context: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """
        Validate if request maps to a defined capability.
        
        Implements CapabilityValidatorInterface.validate_request()
        
        Args:
            request: ExecutionRequest to validate
            context: Optional additional context
            
        Returns:
            ValidationResult with approval/denial and details
        """
        # Support both ExecutionRequest and dict-based requests
        # Normalize to a shape-independent view so validation does not depend
        # on whether the request is an ExecutionRequest object or a dict.
        normalized = self._normalize_request(request)
        action_type = normalized.action_type
        request_id = normalized.request_id
        timestamp = normalized.timestamp

        # Fail closed on missing/unrecognized action types, regardless of
        # strict_mode: a malformed request is never silently approved.
        if action_type is None:
            reason = self._format_rejection_reason(
                "unknown",
                "Missing or unrecognized action_type"
            )
            self._log_rejection(request_id, "unknown", reason, timestamp)
            return ValidationResult(
                is_valid=False,
                reason=reason,
                details={"action_type": None}
            )
        
        # Check if action type is within any capability
        matching_capabilities = [
            cap for cap in self.config.capabilities
            if action_type in cap.action_types
        ]
        
        if not matching_capabilities:
            # strict_mode governs out-of-capability actions. When disabled, a
            # well-formed action outside the agent's capabilities is allowed.
            if not self.config.strict_mode:
                return ValidationResult(is_valid=True)
            reason = self._format_rejection_reason(
                action_type,
                "Action type not in agent capabilities"
            )
            self._log_rejection(request_id, action_type, reason, timestamp)
            return ValidationResult(
                is_valid=False,
                reason=reason,
                details={"action_type": str(action_type), "available_capabilities": [c.name for c in self.config.capabilities]}
            )
        
        # Validate parameters against each matching capability's validator,
        # shape-independently. A validator that raises fails closed.
        for capability in matching_capabilities:
            if capability.validator:
                if not self._run_validator(capability.validator, normalized):
                    reason = self._format_rejection_reason(
                        action_type,
                        f"Parameters do not match capability: {capability.name}"
                    )
                    self._log_rejection(request_id, action_type, reason, timestamp)
                    return ValidationResult(
                        is_valid=False,
                        reason=reason,
                        details={"capability": capability.name}
                    )
        
        return ValidationResult(is_valid=True)
    
    # Legacy method for backward compatibility
    def validate_request_legacy(self, request: ExecutionRequest) -> Tuple[bool, Optional[str]]:
        """
        Legacy validation method for backward compatibility.
        
        DEPRECATED: Use validate_request() instead which returns ValidationResult.
        
        Returns:
            (is_valid, reason_if_invalid)
        """
        warnings.warn(
            "validate_request_legacy is deprecated, use validate_request() instead",
            DeprecationWarning,
            stacklevel=2
        )
        result = self.validate_request(request)
        return result.is_valid, result.reason
    
    def validate_action(
        self, 
        action_type: ActionType, 
        parameters: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """
        Lightweight validation without creating an ExecutionRequest.
        
        Returns:
            (is_valid, reason_if_invalid)
        """
        # Coerce/validate the action type; fail closed on malformed input
        # regardless of strict_mode.
        action_type = self._coerce_action_type(action_type)
        if action_type is None:
            return False, self._format_rejection_reason(
                "unknown", "Missing or unrecognized action_type"
            )

        # Check if action type is within any capability
        matching_capabilities = [
            cap for cap in self.config.capabilities
            if action_type in cap.action_types
        ]
        
        if not matching_capabilities:
            # strict_mode governs out-of-capability actions.
            if not self.config.strict_mode:
                return True, None
            reason = self._format_rejection_reason(
                action_type,
                "Action type not in agent capabilities"
            )
            return False, reason
        
        # Run each matching capability's validator against the supplied
        # parameters via a normalized shim. A validator that raises fails closed.
        shim = _NormalizedRequest(
            action_type=action_type,
            parameters=parameters or {},
            request_id="validate_action",
            timestamp=datetime.now(),
        )
        for capability in matching_capabilities:
            if capability.validator:
                if not self._run_validator(capability.validator, shim):
                    return False, self._format_rejection_reason(
                        action_type,
                        f"Parameters do not match capability: {capability.name}"
                    )

        return True, None
    
    @staticmethod
    def _coerce_action_type(value: Any) -> Optional[ActionType]:
        """Coerce a raw action_type (enum or string) to ActionType, or None."""
        if isinstance(value, ActionType):
            return value
        try:
            return ActionType(value)
        except (ValueError, KeyError):
            return None

    def _normalize_request(self, request: Any) -> _NormalizedRequest:
        """Build a shape-independent view from an object or dict request."""
        if hasattr(request, 'action_type'):
            raw_action = request.action_type
            parameters = getattr(request, 'parameters', None) or {}
            request_id = getattr(request, 'request_id', 'unknown')
            timestamp = getattr(request, 'timestamp', datetime.now())
            agent_context = getattr(request, 'agent_context', None)
            status = getattr(request, 'status', None)
            risk_score = getattr(request, 'risk_score', 0.0)
        else:
            raw_action = request.get('action_type')
            parameters = request.get('parameters') or {}
            request_id = request.get('request_id', 'unknown')
            timestamp = request.get('timestamp', datetime.now())
            agent_context = request.get('agent_context')
            status = request.get('status')
            risk_score = request.get('risk_score', 0.0)
        return _NormalizedRequest(
            action_type=self._coerce_action_type(raw_action),
            parameters=parameters,
            request_id=request_id,
            timestamp=timestamp,
            agent_context=agent_context,
            status=status,
            risk_score=risk_score,
        )

    @staticmethod
    def _run_validator(
        validator: Callable[[Any], bool],
        request: _NormalizedRequest,
    ) -> bool:
        """Invoke a capability validator, failing closed on any exception."""
        try:
            return bool(validator(request))
        except Exception as e:  # noqa: BLE001 - fail closed on validator error
            # A validator that raises is a broken validator, not a legitimate
            # rejection. Surface it at warning level with the error string so the
            # fail-closed rejection is visible to operators rather than hidden,
            # mirroring how governance_layer records alignment validator errors
            # (there as a validator_error audit event) instead of swallowing them.
            logger.warning(
                "Capability validator raised (%s); rejecting request (fail closed)", e
            )
            return False

    # =========================================================================
    # CapabilityValidatorInterface implementation
    # =========================================================================
    
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
        
        Implements CapabilityValidatorInterface.define_capability()
        """
        # Convert string action types to ActionType enums
        action_types = []
        for action in allowed_actions:
            try:
                action_types.append(ActionType(action))
            except ValueError:
                # Skip unknown action types
                pass
        
        capability = AgentCapability(
            name=capability_name,
            description=f"Capability {capability_name} for agent {agent_id}",
            action_types=action_types,
            parameter_schema=parameter_schema,
            validator=validator
        )
        
        if agent_id not in self._agent_capabilities:
            self._agent_capabilities[agent_id] = []
        self._agent_capabilities[agent_id].append(capability)
        
        # Also add to config if this is for the configured agent
        if agent_id == self.config.agent_id:
            self.config.capabilities.append(capability)
    
    def get_agent_capabilities(self, agent_id: str) -> List[Dict[str, Any]]:
        """Get all capabilities defined for an agent"""
        capabilities = self._agent_capabilities.get(agent_id, [])
        return [
            {
                "name": cap.name,
                "description": cap.description,
                "action_types": [at.value for at in cap.action_types],
                "parameter_schema": cap.parameter_schema,
                "has_validator": cap.validator is not None
            }
            for cap in capabilities
        ]
    
    def get_null_response(self) -> str:
        """Get the NULL response message for out-of-scope requests"""
        return self.config.null_response_message
    
    def get_rejection_log(self, agent_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get log of rejected (out-of-scope) requests"""
        if agent_id:
            return [r for r in self.rejection_log if r.get("agent_id") == agent_id]
        return self.rejection_log.copy()
    
    # =========================================================================
    # Internal methods
    # =========================================================================
    
    def _format_rejection_reason(self, action_type: ActionType, reason: str) -> str:
        """Format rejection reason based on agent configuration"""
        if self.config.enable_explanation:
            return f"Request rejected: {reason}. Available capabilities: {[c.name for c in self.config.capabilities]}"
        else:
            return self.config.null_response_message
    
    def _log_rejection(self, request_id: str, action_type: ActionType, reason: str, timestamp: datetime):
        """Log rejected requests for analysis"""
        self.rejection_log.append({
            "request_id": request_id,
            "agent_id": self.config.agent_id,
            "action_type": action_type.value if hasattr(action_type, 'value') else str(action_type),
            "reason": reason,
            "timestamp": timestamp.isoformat() if hasattr(timestamp, 'isoformat') else str(timestamp)
        })


def create_sql_agent_capabilities() -> List[AgentCapability]:
    """
    Example: Create capabilities for a SQL-generating agent
    
    This agent can only query databases, not modify them.
    If asked to "build a rocket ship", it returns NULL instead of hallucinating.
    """
    
    def validate_sql_query(request: ExecutionRequest) -> bool:
        """Validate that SQL query is read-only"""
        import re
        query = request.parameters.get('query', '').upper()
        # Only SELECT queries allowed
        if not query.strip().startswith('SELECT'):
            return False
        # No destructive operations (use word boundaries to avoid false matches)
        destructive = ['DROP', 'DELETE', 'INSERT', 'UPDATE', 'ALTER', 'CREATE', 'TRUNCATE']
        for op in destructive:
            # Use word boundary matching to avoid matching "CREATED_AT" with "CREATE"
            if re.search(r'\b' + op + r'\b', query):
                return False
        return True
    
    return [
        AgentCapability(
            name="query_database",
            description="Execute read-only SQL queries",
            action_types=[ActionType.DATABASE_QUERY],
            parameter_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "database": {"type": "string"}
                },
                "required": ["query"]
            },
            validator=validate_sql_query
        )
    ]


def create_data_analyst_capabilities() -> List[AgentCapability]:
    """
    Example: Create capabilities for a data analyst agent
    
    This agent can read files and query databases, but cannot modify anything.
    """
    
    def validate_safe_file_path(request: ExecutionRequest) -> bool:
        """Only allow access to /data directory"""
        path = request.parameters.get('path', '')
        return path.startswith('/data/') or path.startswith('./data/')
    
    return [
        AgentCapability(
            name="read_data_file",
            description="Read data files from /data directory",
            action_types=[ActionType.FILE_READ],
            parameter_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "pattern": "^(/data/|\\./data/).*"}
                },
                "required": ["path"]
            },
            validator=validate_safe_file_path
        ),
        AgentCapability(
            name="query_analytics",
            description="Execute analytics queries",
            action_types=[ActionType.DATABASE_QUERY],
            parameter_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "database": {"type": "string"}
                },
                "required": ["query"]
            }
        )
    ]


def create_mute_sql_agent(agent_id: str) -> MuteAgentConfig:
    """
    Create a Mute SQL Agent configuration
    
    This agent:
    - Only executes SELECT queries
    - Returns NULL for anything outside this capability
    - Does not try to be conversational or creative
    """
    return MuteAgentConfig(
        agent_id=agent_id,
        capabilities=create_sql_agent_capabilities(),
        strict_mode=True,
        null_response_message="NULL",
        enable_explanation=False
    )


def create_mute_data_analyst(agent_id: str, enable_explanation: bool = False) -> MuteAgentConfig:
    """
    Create a Mute Data Analyst configuration
    
    This agent:
    - Can read data files from /data directory
    - Can execute analytics queries
    - Returns NULL for out-of-scope requests
    """
    return MuteAgentConfig(
        agent_id=agent_id,
        capabilities=create_data_analyst_capabilities(),
        strict_mode=True,
        null_response_message="NULL",
        enable_explanation=enable_explanation
    )
