# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic YAML policy enforcement
"""
Policy Engine - Basic allow/deny policy enforcement.

Provides simple list-based policy evaluation with (action_pattern, resource_pattern,
effect) tuples.  First match wins.
"""

from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from .agent_kernel import ExecutionRequest, ActionType, PolicyRule
import fnmatch
import uuid
import re


@dataclass
class Condition:
    """A simple pattern-match condition for policy evaluation."""

    attribute_path: str  # e.g. "action", "resource"
    operator: str  # "eq", "match" (glob), or "in"
    value: Any

    def evaluate(self, context: Dict[str, Any]) -> bool:
        """Evaluate the condition via simple pattern matching."""
        actual = self._get_nested_value(context, self.attribute_path)
        if actual is None:
            return False
        if self.operator == "eq":
            return actual == self.value
        if self.operator == "match":
            return fnmatch.fnmatch(str(actual), str(self.value))
        if self.operator == "in":
            return actual in self.value
        return False

    def _get_nested_value(self, data: Dict[str, Any], path: str) -> Any:
        keys = path.split(".")
        value = data
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        return value


@dataclass
class ConditionalPermission:
    """A permission that requires conditions to be met."""

    tool_name: str
    conditions: List[Condition]
    require_all: bool = True

    def is_allowed(self, context: Dict[str, Any]) -> bool:
        if self.require_all:
            return all(c.evaluate(context) for c in self.conditions)
        return any(c.evaluate(context) for c in self.conditions)


@dataclass
class ResourceQuota:
    """Resource quota for an agent or tenant."""

    agent_id: str
    max_requests_per_minute: int = 60
    max_requests_per_hour: int = 1000
    max_execution_time_seconds: float = 300.0
    max_concurrent_executions: int = 5
    allowed_action_types: List[ActionType] = field(default_factory=list)

    requests_this_minute: int = 0
    requests_this_hour: int = 0
    current_executions: int = 0
    last_reset_minute: datetime = field(default_factory=datetime.now)
    last_reset_hour: datetime = field(default_factory=datetime.now)


@dataclass
class RiskPolicy:
    """Risk-based policy for agent actions."""

    max_risk_score: float = 0.5
    require_approval_above: float = 0.7
    deny_above: float = 0.9

    high_risk_patterns: List[str] = field(default_factory=list)
    allowed_domains: List[str] = field(default_factory=list)
    blocked_domains: List[str] = field(default_factory=list)


class PolicyEngine:
    """
    Basic Policy Engine — list-based allow/deny evaluation.

    Policies are stored as tuples of (action_pattern, resource_pattern, effect).
    First match wins.  Also supports quotas and custom PolicyRule validators.
    """

    def __init__(self):
        self.quotas: Dict[str, ResourceQuota] = {}
        self.risk_policies: Dict[str, RiskPolicy] = {}
        self.custom_rules: List[PolicyRule] = []
        self.blocked_patterns: List[str] = []

        self.allowed_transitions: set = set()
        self.state_permissions: Dict[str, set] = {}
        self.conditional_permissions: Dict[str, List[ConditionalPermission]] = {}
        self.agent_contexts: Dict[str, Dict[str, Any]] = {}

        self.dangerous_code_patterns: List[re.Pattern] = [
            re.compile(r"\brm\s+-rf\b", re.IGNORECASE),
            re.compile(r"\bdrop\s+table\b", re.IGNORECASE),
            re.compile(r"\bdrop\s+database\b", re.IGNORECASE),
            re.compile(r"\btruncate\s+table\b", re.IGNORECASE),
            re.compile(r"\bdelete\s+from\b", re.IGNORECASE),
        ]

        self.protected_paths: List[str] = [
            "/etc/", "/sys/", "/proc/", "/dev/", "C:\\Windows\\System32",
        ]

    # -- quota / risk / rule setters --

    def set_quota(self, agent_id: str, quota: ResourceQuota):
        self.quotas[agent_id] = quota

    def set_risk_policy(self, policy_id: str, policy: RiskPolicy):
        self.risk_policies[policy_id] = policy

    def add_custom_rule(self, rule: PolicyRule):
        self.custom_rules.append(rule)
        self.custom_rules.sort(key=lambda r: r.priority, reverse=True)

    def add_constraint(self, role: str, allowed_tools: List[str]):
        self.state_permissions[role] = set(allowed_tools)

    def add_conditional_permission(self, agent_role: str, permission: ConditionalPermission):
        if agent_role not in self.conditional_permissions:
            self.conditional_permissions[agent_role] = []
        self.conditional_permissions[agent_role].append(permission)
        if agent_role not in self.state_permissions:
            self.state_permissions[agent_role] = set()
        self.state_permissions[agent_role].add(permission.tool_name)

    def set_agent_context(self, agent_role: str, context: Dict[str, Any]):
        self.agent_contexts[agent_role] = context

    def update_agent_context(self, agent_role: str, updates: Dict[str, Any]):
        if agent_role not in self.agent_contexts:
            self.agent_contexts[agent_role] = {}
        self.agent_contexts[agent_role].update(updates)

    def is_shadow_mode(self, agent_role: str) -> bool:
        return self.agent_contexts.get(agent_role, {}).get("shadow_mode", False)

    # -- core violation check --

    def check_violation(
        self, agent_role: str, tool_name: str, args: Dict[str, Any]
    ) -> Optional[str]:
        """First-match policy check. Returns None (allow) or a violation string."""
        allowed = self.state_permissions.get(agent_role, set())
        if tool_name not in allowed:
            return f"Role {agent_role} cannot use tool {tool_name}"

        if agent_role in self.conditional_permissions:
            for cp in self.conditional_permissions[agent_role]:
                if cp.tool_name == tool_name:
                    ctx = {"args": args, "context": self.agent_contexts.get(agent_role, {})}
                    ctx.update(self.agent_contexts.get(agent_role, {}))
                    if not cp.is_allowed(ctx):
                        return f"Conditional permission denied for {tool_name}: Conditions not met"

        if tool_name in ["execute_code", "run_command"]:
            code_or_cmd = args.get("code", args.get("command", ""))
            for pat in self.dangerous_code_patterns:
                if pat.search(code_or_cmd):
                    return f"Dangerous pattern detected: {pat.pattern}"

        return None

    # -- rate limiting --

    def check_rate_limit(self, request: ExecutionRequest) -> bool:
        agent_id = request.agent_context.agent_id
        if agent_id not in self.quotas:
            return True
        quota = self.quotas[agent_id]
        now = datetime.now()
        if (now - quota.last_reset_minute).total_seconds() >= 60:
            quota.requests_this_minute = 0
            quota.last_reset_minute = now
        if (now - quota.last_reset_hour).total_seconds() >= 3600:
            quota.requests_this_hour = 0
            quota.last_reset_hour = now
        if quota.requests_this_minute >= quota.max_requests_per_minute:
            return False
        if quota.requests_this_hour >= quota.max_requests_per_hour:
            return False
        if quota.current_executions >= quota.max_concurrent_executions:
            return False
        if quota.allowed_action_types and request.action_type not in quota.allowed_action_types:
            return False
        quota.requests_this_minute += 1
        quota.requests_this_hour += 1
        return True

    def validate_risk(self, request: ExecutionRequest, risk_score: float) -> bool:
        for _pid, policy in self.risk_policies.items():
            if risk_score >= policy.deny_above:
                return False
            params_str = str(request.parameters)
            for pattern in policy.high_risk_patterns:
                if pattern.lower() in params_str.lower():
                    return False
        return True

    def validate_request(self, request: ExecutionRequest) -> Tuple[bool, Optional[str]]:
        if not self.check_rate_limit(request):
            return False, "rate_limit_exceeded"
        for rule in self.custom_rules:
            if request.action_type in rule.action_types:
                if not rule.validator(request):
                    return False, f"policy_violation: {rule.name}"
        return True, None

    def get_quota_status(self, agent_id: str) -> Dict[str, Any]:
        if agent_id not in self.quotas:
            return {"error": "No quota set for agent"}
        q = self.quotas[agent_id]
        return {
            "agent_id": agent_id,
            "requests_this_minute": q.requests_this_minute,
            "max_requests_per_minute": q.max_requests_per_minute,
            "requests_this_hour": q.requests_this_hour,
            "max_requests_per_hour": q.max_requests_per_hour,
            "current_executions": q.current_executions,
            "max_concurrent_executions": q.max_concurrent_executions,
        }


def create_default_policies() -> List[PolicyRule]:
    """Create basic default security policies."""

    def no_system_file_access(request: ExecutionRequest) -> bool:
        if request.action_type in [ActionType.FILE_READ, ActionType.FILE_WRITE]:
            path = request.parameters.get("path", "")
            dangerous = ["/etc/", "/sys/", "/proc/", "/dev/", "C:\\Windows\\System32"]
            return not any(dp in path for dp in dangerous)
        return True

    def no_credential_exposure(request: ExecutionRequest) -> bool:
        params_str = str(request.parameters).lower()
        sensitive = ["password", "secret", "api_key", "token", "credential"]
        return not any(kw in params_str for kw in sensitive)

    return [
        PolicyRule(
            rule_id=str(uuid.uuid4()),
            name="no_system_file_access",
            description="Prevent access to system files",
            action_types=[ActionType.FILE_READ, ActionType.FILE_WRITE],
            validator=no_system_file_access,
            priority=10,
        ),
        PolicyRule(
            rule_id=str(uuid.uuid4()),
            name="no_credential_exposure",
            description="Prevent exposure of credentials",
            action_types=[ActionType.CODE_EXECUTION, ActionType.FILE_READ, ActionType.API_CALL],
            validator=no_credential_exposure,
            priority=10,
        ),
    ]
