# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic YAML policy enforcement
"""
Mute Agent - Returns empty string on blocked actions.

Keeps AgentCapability and MuteAgentConfig classes with basic
capability checking.  No zero-information-leakage analysis.
"""

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


@dataclass
class AgentCapability:
    """Defines a specific capability an agent has."""
    name: str
    description: str
    action_types: List[ActionType]
    parameter_schema: Dict[str, Any]
    validator: Optional[Callable[[ExecutionRequest], bool]] = None


@dataclass
class MuteAgentConfig:
    """Configuration for a Mute Agent."""
    agent_id: str
    capabilities: List[AgentCapability] = field(default_factory=list)
    strict_mode: bool = True
    null_response_message: str = ""
    enable_explanation: bool = False


class MuteAgentValidator(CapabilityValidatorInterface):
    """Validates requests against agent capabilities.  Returns empty string for blocked actions."""

    def __init__(self, config: MuteAgentConfig):
        self.config = config
        self.rejection_log: List[Dict[str, Any]] = []
        self._agent_capabilities: Dict[str, List[AgentCapability]] = {
            config.agent_id: config.capabilities
        }

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name=f"mute_agent_validator_{self.config.agent_id}",
            version="2.0.0",
            description="Basic capability validator (Community Edition)",
            plugin_type="validator",
            capabilities=[
                PluginCapability.REQUEST_VALIDATION,
                PluginCapability.CAPABILITY_CHECKING,
            ],
        )

    def validate_request(
        self, request: Any, context: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        if hasattr(request, "action_type"):
            action_type = request.action_type
            request_id = getattr(request, "request_id", "unknown")
            timestamp = getattr(request, "timestamp", datetime.now())
        else:
            action_type = request.get("action_type")
            request_id = request.get("request_id", "unknown")
            timestamp = request.get("timestamp", datetime.now())

        matching = [c for c in self.config.capabilities if action_type in c.action_types]
        if not matching:
            reason = self.config.null_response_message or ""
            self._log_rejection(request_id, action_type, reason, timestamp)
            return ValidationResult(
                is_valid=False,
                reason=reason,
                details={
                    "action_type": str(action_type),
                    "available_capabilities": [c.name for c in self.config.capabilities],
                },
            )

        for cap in matching:
            if cap.validator and hasattr(request, "action_type"):
                if not cap.validator(request):
                    reason = self.config.null_response_message or ""
                    self._log_rejection(request_id, action_type, reason, timestamp)
                    return ValidationResult(is_valid=False, reason=reason, details={"capability": cap.name})

        return ValidationResult(is_valid=True)

    def validate_action(
        self, action_type: ActionType, parameters: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        matching = [c for c in self.config.capabilities if action_type in c.action_types]
        if not matching:
            return False, self.config.null_response_message or ""
        return True, None

    def define_capability(
        self,
        agent_id: str,
        capability_name: str,
        allowed_actions: List[str],
        parameter_schema: Dict[str, Any],
        validator: Optional[Callable[[Any], bool]] = None,
    ) -> None:
        action_types = []
        for action in allowed_actions:
            try:
                action_types.append(ActionType(action))
            except ValueError:
                pass
        capability = AgentCapability(
            name=capability_name,
            description=f"Capability {capability_name} for agent {agent_id}",
            action_types=action_types,
            parameter_schema=parameter_schema,
            validator=validator,
        )
        if agent_id not in self._agent_capabilities:
            self._agent_capabilities[agent_id] = []
        self._agent_capabilities[agent_id].append(capability)
        if agent_id == self.config.agent_id:
            self.config.capabilities.append(capability)

    def get_agent_capabilities(self, agent_id: str) -> List[Dict[str, Any]]:
        capabilities = self._agent_capabilities.get(agent_id, [])
        return [
            {
                "name": c.name,
                "description": c.description,
                "action_types": [a.value for a in c.action_types],
                "parameter_schema": c.parameter_schema,
                "has_validator": c.validator is not None,
            }
            for c in capabilities
        ]

    def get_null_response(self) -> str:
        return self.config.null_response_message

    def get_rejection_log(self, agent_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if agent_id:
            return [r for r in self.rejection_log if r.get("agent_id") == agent_id]
        return self.rejection_log.copy()

    def _log_rejection(self, request_id: str, action_type: ActionType, reason: str, timestamp: datetime):
        self.rejection_log.append({
            "request_id": request_id,
            "agent_id": self.config.agent_id,
            "action_type": action_type.value if hasattr(action_type, "value") else str(action_type),
            "reason": reason,
            "timestamp": timestamp.isoformat() if hasattr(timestamp, "isoformat") else str(timestamp),
        })


def create_sql_agent_capabilities() -> List[AgentCapability]:
    """Create capabilities for a SQL-generating agent."""

    def validate_sql_query(request: ExecutionRequest) -> bool:
        import re
        query = request.parameters.get("query", "").upper()
        if not query.strip().startswith("SELECT"):
            return False
        destructive = ["DROP", "DELETE", "INSERT", "UPDATE", "ALTER", "CREATE", "TRUNCATE"]
        for op in destructive:
            if re.search(r"\b" + op + r"\b", query):
                return False
        return True

    return [
        AgentCapability(
            name="query_database",
            description="Execute read-only SQL queries",
            action_types=[ActionType.DATABASE_QUERY],
            parameter_schema={
                "type": "object",
                "properties": {"query": {"type": "string"}, "database": {"type": "string"}},
                "required": ["query"],
            },
            validator=validate_sql_query,
        )
    ]


def create_data_analyst_capabilities() -> List[AgentCapability]:
    """Create capabilities for a data analyst agent."""

    def validate_safe_file_path(request: ExecutionRequest) -> bool:
        path = request.parameters.get("path", "")
        return path.startswith("/data/") or path.startswith("./data/")

    return [
        AgentCapability(
            name="read_data_file",
            description="Read data files from /data directory",
            action_types=[ActionType.FILE_READ],
            parameter_schema={
                "type": "object",
                "properties": {"path": {"type": "string", "pattern": "^(/data/|\\\\./data/).*"}},
                "required": ["path"],
            },
            validator=validate_safe_file_path,
        ),
        AgentCapability(
            name="query_analytics",
            description="Execute analytics queries",
            action_types=[ActionType.DATABASE_QUERY],
            parameter_schema={
                "type": "object",
                "properties": {"query": {"type": "string"}, "database": {"type": "string"}},
                "required": ["query"],
            },
        ),
    ]


def create_mute_sql_agent(agent_id: str) -> MuteAgentConfig:
    return MuteAgentConfig(
        agent_id=agent_id,
        capabilities=create_sql_agent_capabilities(),
        strict_mode=True,
        null_response_message="",
        enable_explanation=False,
    )


def create_mute_data_analyst(agent_id: str, enable_explanation: bool = False) -> MuteAgentConfig:
    return MuteAgentConfig(
        agent_id=agent_id,
        capabilities=create_data_analyst_capabilities(),
        strict_mode=True,
        null_response_message="",
        enable_explanation=enable_explanation,
    )