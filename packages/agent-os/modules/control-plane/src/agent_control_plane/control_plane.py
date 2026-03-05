# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic YAML policy enforcement
"""
Agent Control Plane - Basic sequential policy check pipeline.

Iterates through policies and returns first match.  No dependency injection
via PluginRegistry — direct instantiation only.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime

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
from .mute_agent import MuteAgentValidator, MuteAgentConfig


class AgentControlPlane:
    """
    Agent Control Plane — sequential policy check pipeline.

    Integrates:
    - Agent Kernel (permissions)
    - Policy Engine (quotas, rules)
    - Execution Engine (sandboxed execution)
    - Mute Agent validators (capability filtering)
    """

    def __init__(
        self,
        enable_default_policies: bool = True,
        **kwargs,
    ):
        self.kernel = AgentKernel()
        self.policy_engine = PolicyEngine()
        self.execution_engine = ExecutionEngine()

        # Wire policy engine into kernel
        self.kernel.policy_engine = self.policy_engine

        # Legacy Mute Agent validators
        self.mute_validators: Dict[str, MuteAgentValidator] = {}

        # Register default executors
        self._register_default_executors()

        if enable_default_policies:
            self._add_default_policies()

    # -- agent lifecycle --

    def create_agent(
        self,
        agent_id: str,
        permissions: Optional[Dict[ActionType, PermissionLevel]] = None,
        quota: Optional[ResourceQuota] = None,
    ) -> AgentContext:
        context = self.kernel.create_agent_session(agent_id, permissions)
        if quota:
            self.policy_engine.set_quota(agent_id, quota)
        return context

    # -- main execution pipeline --

    def execute_action(
        self,
        agent_context: AgentContext,
        action_type: ActionType,
        parameters: Dict[str, Any],
        execution_context: Optional[ExecutionContext] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Execute an action through the sequential governance pipeline."""
        temp_request = ExecutionRequest(
            request_id="temp",
            agent_context=agent_context,
            action_type=action_type,
            parameters=parameters,
            timestamp=datetime.now(),
        )

        # 1. Mute Agent validation
        if agent_context.agent_id in self.mute_validators:
            validator = self.mute_validators[agent_context.agent_id]
            result = validator.validate_request(temp_request)
            if not result.is_valid:
                return {
                    "success": False,
                    "error": result.reason,
                    "status": "capability_mismatch",
                }

        # 2. Kernel permission check
        request = self.kernel.submit_request(agent_context, action_type, parameters)
        if request.status == ExecutionStatus.DENIED:
            return {
                "success": False,
                "error": "Request denied by kernel",
                "request_id": request.request_id,
                "status": request.status.value,
            }

        # 3. Policy engine validation
        is_valid, reason = self.policy_engine.validate_request(request)
        if not is_valid:
            return {
                "success": False,
                "error": f"Policy validation failed: {reason}",
                "request_id": request.request_id,
                "status": "policy_violation",
            }

        # 4. Risk validation
        if not self.policy_engine.validate_risk(request, request.risk_score):
            return {
                "success": False,
                "error": "Request risk level too high",
                "request_id": request.request_id,
                "risk_score": request.risk_score,
                "status": "risk_denied",
            }

        # 5. Execute
        execution_result = self.execution_engine.execute(request, execution_context)
        if execution_result["success"]:
            kernel_result = self.kernel.execute(request)
            return {
                "success": True,
                "result": execution_result["result"],
                "request_id": request.request_id,
                "metrics": execution_result.get("metrics", {}),
                "risk_score": request.risk_score,
            }
        return execution_result

    # -- policy helpers --

    def add_policy_rule(self, rule: PolicyRule):
        self.kernel.add_policy_rule(rule)
        self.policy_engine.add_custom_rule(rule)

    def set_agent_quota(self, agent_id: str, quota: ResourceQuota):
        self.policy_engine.set_quota(agent_id, quota)

    def set_risk_policy(self, policy_id: str, policy: RiskPolicy):
        self.policy_engine.set_risk_policy(policy_id, policy)

    def get_agent_status(self, agent_id: str) -> Dict[str, Any]:
        return {
            "agent_id": agent_id,
            "quota_status": self.policy_engine.get_quota_status(agent_id),
            "active_executions": len(
                [c for c in self.execution_engine.get_active_executions().values()]
            ),
            "execution_history": self.execution_engine.get_execution_history(
                agent_id, limit=10
            ),
        }

    def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self.kernel.get_audit_log()[-limit:]

    def get_execution_history(
        self, agent_id: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        return self.execution_engine.get_execution_history(agent_id, limit)

    def enable_mute_agent(self, agent_id: str, config: MuteAgentConfig):
        self.mute_validators[agent_id] = MuteAgentValidator(config)

    # -- internals --

    def _register_default_executors(self):
        self.execution_engine.register_executor(ActionType.FILE_READ, file_read_executor)
        self.execution_engine.register_executor(ActionType.CODE_EXECUTION, code_execution_executor)
        self.execution_engine.register_executor(ActionType.API_CALL, api_call_executor)

    def _add_default_policies(self):
        for policy in create_default_policies():
            self.add_policy_rule(policy)


# Convenience functions

def create_read_only_agent(control_plane: AgentControlPlane, agent_id: str) -> AgentContext:
    permissions = {
        ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY,
    }
    quota = ResourceQuota(
        agent_id=agent_id,
        max_requests_per_minute=30,
        max_requests_per_hour=500,
        allowed_action_types=[ActionType.FILE_READ, ActionType.DATABASE_QUERY],
    )
    return control_plane.create_agent(agent_id, permissions, quota)


def create_standard_agent(control_plane: AgentControlPlane, agent_id: str) -> AgentContext:
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
            ActionType.FILE_READ, ActionType.FILE_WRITE, ActionType.API_CALL,
            ActionType.DATABASE_QUERY, ActionType.CODE_EXECUTION,
        ],
    )
    return control_plane.create_agent(agent_id, permissions, quota)


def create_admin_agent(control_plane: AgentControlPlane, agent_id: str) -> AgentContext:
    permissions = {at: PermissionLevel.ADMIN for at in ActionType}
    quota = ResourceQuota(
        agent_id=agent_id,
        max_requests_per_minute=120,
        max_requests_per_hour=5000,
        allowed_action_types=list(ActionType),
    )
    return control_plane.create_agent(agent_id, permissions, quota)