# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Policy Engine - Governance and compliance rules for agent execution

The Policy Engine enforces rules and constraints on agent behavior,
including resource quotas, access controls, and risk management.

Research Foundations:
    - ABAC model based on NIST SP 800-162 (Attribute-Based Access Control)
    - Risk scoring informed by "A Safety Framework for Real-World Agentic Systems" 
      (arXiv:2511.21990, 2024) - contextual risk management
    - Governance patterns from "Practices for Governing Agentic AI Systems" 
      (OpenAI, 2023) - pre/post-deployment checks
    - Rate limiting patterns from "Fault-Tolerant Multi-Agent Systems" 
      (IEEE Trans. SMC, 2024) - circuit breaker patterns

See docs/RESEARCH_FOUNDATION.md for complete references.
"""

from typing import Dict, List, Optional, Callable, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from types import MappingProxyType  # noqa: F401 — reserved for future immutable dict enforcement
from .agent_kernel import ExecutionRequest, ActionType, PolicyRule
import logging
import uuid
import os
import re
import warnings

logger = logging.getLogger(__name__)


@dataclass
class Condition:
    """
    A condition for ABAC (Attribute-Based Access Control).

    Allows policies like: "Agent can call tool X IF condition Y is true"
    Example: "refund_user" allowed IF user_status == "verified"
    """

    attribute_path: str  # e.g., "user_status", "args.amount", "context.time_of_day"
    operator: str  # eq, ne, gt, lt, gte, lte, in, not_in, contains
    value: Any  # The value to compare against

    def evaluate(self, context: Dict[str, Any]) -> bool:
        """
        Evaluate the condition against a context.

        Args:
            context: Dictionary containing the evaluation context
                    (e.g., {"user_status": "verified", "args": {...}, "context": {...}})

        Returns:
            True if condition is met, False otherwise
        """
        # Extract the value from the context using the attribute path
        actual_value = self._get_nested_value(context, self.attribute_path)

        if actual_value is None:
            return False

        # Evaluate based on operator
        if self.operator == "eq":
            return actual_value == self.value
        elif self.operator == "ne":
            return actual_value != self.value
        elif self.operator == "gt":
            return actual_value > self.value
        elif self.operator == "lt":
            return actual_value < self.value
        elif self.operator == "gte":
            return actual_value >= self.value
        elif self.operator == "lte":
            return actual_value <= self.value
        elif self.operator == "in":
            return actual_value in self.value
        elif self.operator == "not_in":
            return actual_value not in self.value
        elif self.operator == "contains":
            return self.value in actual_value
        else:
            return False

    def _get_nested_value(self, data: Dict[str, Any], path: str) -> Any:
        """
        Get a nested value from a dictionary using dot notation.

        Args:
            data: The dictionary to search
            path: Dot-separated path (e.g., "args.amount")

        Returns:
            The value at the path, or None if not found
        """
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
    """
    A permission that requires conditions to be met.

    Example: "refund_user" allowed IF user_status == "verified" AND amount < 1000
    """

    tool_name: str
    conditions: List[Condition]
    require_all: bool = (
        True  # If True, all conditions must be met (AND). If False, any condition (OR).
    )

    def is_allowed(self, context: Dict[str, Any]) -> bool:
        """
        Check if the permission is allowed given the context.

        Args:
            context: The evaluation context

        Returns:
            True if allowed, False otherwise
        """
        if self.require_all:
            # All conditions must be true (AND)
            return all(cond.evaluate(context) for cond in self.conditions)
        else:
            # Any condition must be true (OR)
            return any(cond.evaluate(context) for cond in self.conditions)


@dataclass
class ResourceQuota:
    """Resource quota for an agent or tenant"""

    agent_id: str
    max_requests_per_minute: int = 60
    max_requests_per_hour: int = 1000
    max_execution_time_seconds: float = 300.0
    max_concurrent_executions: int = 5
    allowed_action_types: List[ActionType] = field(default_factory=list)

    # Usage tracking
    requests_this_minute: int = 0
    requests_this_hour: int = 0
    current_executions: int = 0
    last_reset_minute: datetime = field(default_factory=datetime.now)
    last_reset_hour: datetime = field(default_factory=datetime.now)


@dataclass
class RiskPolicy:
    """Risk-based policy for agent actions"""

    max_risk_score: float = 0.5
    require_approval_above: float = 0.7
    deny_above: float = 0.9

    # Risk factors
    high_risk_patterns: List[str] = field(default_factory=list)
    allowed_domains: List[str] = field(default_factory=list)
    blocked_domains: List[str] = field(default_factory=list)


class PolicyEngine:
    """
    Policy Engine - Enforces governance rules for agent execution

    Provides:
    - Rate limiting and quotas
    - Risk assessment
    - Access control policies
    - Compliance rules
    """

    def __init__(self):
        self.quotas: Dict[str, ResourceQuota] = {}
        self.risk_policies: Dict[str, RiskPolicy] = {}
        self.custom_rules: List[PolicyRule] = []
        self.blocked_patterns: List[str] = []

        # Graph-based allow-list approach (Scale by Subtraction)
        # By default, EVERYTHING is blocked unless explicitly allowed
        self.allowed_transitions: set = set()
        self.state_permissions: Dict[str, set] = {}

        # ABAC: Conditional permissions (Context-Aware Graph)
        # Maps agent_role -> list of conditional permissions
        self.conditional_permissions: Dict[str, List[ConditionalPermission]] = {}
        # Context data for ABAC evaluation (e.g., user_status, time_of_day, etc.)
        self.agent_contexts: Dict[str, Dict[str, Any]] = {}

        # Configurable dangerous patterns for code/command execution
        # Uses regex patterns for better detection
        self.dangerous_code_patterns: List[re.Pattern] = [
            re.compile(r"\brm\s+-rf\b", re.IGNORECASE),
            re.compile(r"\bdel\s+/f\b", re.IGNORECASE),
            re.compile(r"\bformat\s+", re.IGNORECASE),
            re.compile(r"\bdrop\s+table\b", re.IGNORECASE),
            re.compile(r"\bdrop\s+database\b", re.IGNORECASE),
            re.compile(r"\btruncate\s+table\b", re.IGNORECASE),
            re.compile(r"\bdelete\s+from\b", re.IGNORECASE),
        ]

        # Configurable system paths to protect
        self.protected_paths: List[str] = [
            "/etc/",
            "/sys/",
            "/proc/",
            "/dev/",
            "C:\\Windows\\System32",
        ]

        # Immutability controls — call freeze() after initial configuration
        self._frozen: bool = False
        self._mutation_log: List[Dict[str, Any]] = []

    # ── Immutability ────────────────────────────────────────────

    def freeze(self) -> None:
        """Freeze the policy engine, preventing further mutations.

        After calling ``freeze()``, any attempt to call ``add_constraint()``,
        ``set_agent_context()``, ``update_agent_context()``, or
        ``add_conditional_permission()`` will raise ``RuntimeError``.

        In addition to the boolean guard, the underlying data structures
        are replaced with immutable proxies (``MappingProxyType``) so that
        direct attribute access (bypassing the setter methods) will also
        raise ``TypeError``.

        This addresses the self-modification attack vector where an agent
        could call mutation methods to weaken its own policy at runtime.
        """
        self._frozen = True
        # Replace mutable dicts with read-only proxies to harden against
        # direct attribute manipulation (e.g. engine.state_permissions["x"] = ...)
        self.state_permissions = MappingProxyType(
            {k: frozenset(v) for k, v in self.state_permissions.items()}
        )
        self.agent_contexts = MappingProxyType(
            {k: MappingProxyType(v) if isinstance(v, dict) else v
             for k, v in self.agent_contexts.items()}
        )
        self.conditional_permissions = MappingProxyType(
            {k: tuple(v) for k, v in self.conditional_permissions.items()}
        )
        self._log_mutation("freeze", {})
        logger.info("PolicyEngine frozen — data structures converted to immutable proxies")

    @property
    def is_frozen(self) -> bool:
        """Whether the policy engine is currently frozen."""
        return self._frozen

    @property
    def mutation_log(self) -> List[Dict[str, Any]]:
        """Read-only copy of the mutation audit trail."""
        return list(self._mutation_log)

    def _assert_mutable(self, operation: str) -> None:
        """Raise RuntimeError if the engine is frozen."""
        if self._frozen:
            violation = {
                "operation": operation,
                "timestamp": datetime.now().isoformat(),
                "blocked": True,
            }
            self._mutation_log.append(violation)
            logger.warning(
                "Blocked mutation '%s' on frozen PolicyEngine", operation
            )
            raise RuntimeError(
                f"PolicyEngine is frozen — cannot perform '{operation}'. "
                "Call freeze() is irreversible to prevent runtime self-modification."
            )

    def _log_mutation(self, operation: str, details: Dict[str, Any]) -> None:
        """Record a mutation in the audit log."""
        self._mutation_log.append({
            "operation": operation,
            "details": details,
            "timestamp": datetime.now().isoformat(),
            "blocked": False,
        })

    def set_quota(self, agent_id: str, quota: ResourceQuota):
        """Set resource quota for an agent"""
        self.quotas[agent_id] = quota

    def set_risk_policy(self, policy_id: str, policy: RiskPolicy):
        """Set a risk policy"""
        self.risk_policies[policy_id] = policy

    def add_custom_rule(self, rule: PolicyRule):
        """Add a custom policy rule"""
        self.custom_rules.append(rule)
        self.custom_rules.sort(key=lambda r: r.priority, reverse=True)

    def add_constraint(self, role: str, allowed_tools: List[str]):
        """
        Define the 'Physics' of the agent using allow-list approach.

        This implements "Scale by Subtraction" - by defining what IS allowed,
        everything else is implicitly blocked.

        Args:
            role: The agent role/ID
            allowed_tools: List of tool names this role can use

        Raises:
            RuntimeError: If the engine has been frozen.
        """
        self._assert_mutable("add_constraint")
        self.state_permissions[role] = set(allowed_tools)
        self._log_mutation("add_constraint", {"role": role, "tools": allowed_tools})

    def add_conditional_permission(self, agent_role: str, permission: ConditionalPermission):
        """
        Add a conditional permission for ABAC (Attribute-Based Access Control).

        This moves from RBAC to ABAC, allowing context-aware policies like:
        "Agent can call refund_user IF AND ONLY IF user_status == 'verified'"

        Args:
            agent_role: The agent role/ID
            permission: The conditional permission to add

        Raises:
            RuntimeError: If the engine has been frozen.
        """
        self._assert_mutable("add_conditional_permission")

        if agent_role not in self.conditional_permissions:
            self.conditional_permissions[agent_role] = []

        self.conditional_permissions[agent_role].append(permission)

        # Also add the tool to the basic allow-list so it passes the first check
        # The conditional check will happen later
        if agent_role not in self.state_permissions:
            self.state_permissions[agent_role] = set()
        self.state_permissions[agent_role].add(permission.tool_name)
        self._log_mutation(
            "add_conditional_permission",
            {"role": agent_role, "tool": permission.tool_name},
        )

    def set_agent_context(self, agent_role: str, context: Dict[str, Any]):
        """
        Set the context data for an agent for ABAC evaluation.

        Args:
            agent_role: The agent role/ID
            context: Dictionary of context attributes (e.g., {"user_status": "verified", "time_of_day": "business_hours"})

        Raises:
            RuntimeError: If the engine has been frozen.
        """
        self._assert_mutable("set_agent_context")
        self.agent_contexts[agent_role] = context
        self._log_mutation("set_agent_context", {"role": agent_role})

    def update_agent_context(self, agent_role: str, updates: Dict[str, Any]):
        """
        Update specific context attributes for an agent.

        Args:
            agent_role: The agent role/ID
            updates: Dictionary of attributes to update

        Raises:
            RuntimeError: If the engine has been frozen.
        """
        self._assert_mutable("update_agent_context")

        if agent_role not in self.agent_contexts:
            self.agent_contexts[agent_role] = {}

        self.agent_contexts[agent_role].update(updates)
        self._log_mutation(
            "update_agent_context",
            {"role": agent_role, "keys": list(updates.keys())},
        )

    def is_shadow_mode(self, agent_role: str) -> bool:
        """
        Check if an agent is in shadow mode.

        Args:
            agent_role: The agent role/ID

        Returns:
            True if agent is in shadow mode, False otherwise
        """
        context = self.agent_contexts.get(agent_role, {})
        return context.get("shadow_mode", False)

    def check_violation(
        self, agent_role: str, tool_name: str, args: Dict[str, Any]
    ) -> Optional[str]:
        """
        Check if an action violates the constraint graph.

        Uses a three-level check:
        1. Role-Based Check: Is this tool allowed for this role?
        2. Condition-Based Check (ABAC): Are the conditions met?
        3. Argument-Based Check: Are the arguments safe?

        Returns:
            None if no violation, or a string describing the violation
        """
        # 1. Role-Based Check (Allow-list approach)
        allowed = self.state_permissions.get(agent_role, set())
        if tool_name not in allowed:
            return f"Role {agent_role} cannot use tool {tool_name}"

        # 2. Condition-Based Check (ABAC)
        # Check if there are conditional permissions for this agent/tool
        if agent_role in self.conditional_permissions:
            for cond_perm in self.conditional_permissions[agent_role]:
                if cond_perm.tool_name == tool_name:
                    # Build evaluation context
                    eval_context = {
                        "args": args,
                        "context": self.agent_contexts.get(agent_role, {}),
                    }
                    # Merge top-level context attributes
                    eval_context.update(self.agent_contexts.get(agent_role, {}))

                    # Check if conditions are met
                    if not cond_perm.is_allowed(eval_context):
                        return f"Conditional permission denied for {tool_name}: Conditions not met"

        # 3. Argument-Based Check

        # 3a. Path validation with normalization to prevent traversal attacks
        if tool_name in ["write_file", "read_file", "delete_file"] and "path" in args:
            path = args.get("path", "")

            # Reject paths with control characters (newlines, etc.) — prompt injection vector
            if any(c in path for c in ["\n", "\r", "\x00"]):
                return "Path Validation Error: Control characters in path"

            # Check raw path against protected paths (cross-platform)
            for protected in self.protected_paths:
                if path.startswith(protected):
                    return f"Path Violation: Cannot access protected directory {protected}"

            # Normalize path to resolve '..' and symbolic links
            try:
                normalized_path = os.path.normpath(os.path.abspath(path))
            except (ValueError, OSError):
                return "Path Validation Error: Invalid path format"

            # Check normalized path against protected paths
            for protected in self.protected_paths:
                if normalized_path.startswith(os.path.normpath(protected)):
                    return f"Path Violation: Cannot access protected directory {protected}"

        # 3b. Code execution validation using regex patterns
        if tool_name in ["execute_code", "run_command"]:
            code_or_cmd = args.get("code", args.get("command", ""))

            # Check against dangerous patterns using regex
            for pattern in self.dangerous_code_patterns:
                if pattern.search(code_or_cmd):
                    return f"Dangerous pattern detected: {pattern.pattern}"

        # 3c. SQL injection / destructive query validation
        if tool_name in ["database_query", "database_write"]:
            query = args.get("query", "")
            destructive_patterns = [
                r"\bDROP\s+", r"\bDELETE\s+FROM\b", r"\bTRUNCATE\s+",
                r"\bALTER\s+TABLE\b.*\bDROP\b", r"\bUPDATE\s+.*\bSET\b.*\bWHERE\s+1\s*=\s*1",
            ]
            import re as _re
            for pat in destructive_patterns:
                if _re.search(pat, query, _re.IGNORECASE):
                    return f"Destructive SQL blocked: {pat}"

        # 3d. Internal endpoint protection
        if tool_name == "api_call":
            endpoint = args.get("endpoint", "")
            if endpoint.startswith("internal://"):
                return f"Internal endpoint blocked: {endpoint}"

        return None

    def check_rate_limit(self, request: ExecutionRequest) -> bool:
        """Check if request is within rate limits"""
        agent_id = request.agent_context.agent_id

        if agent_id not in self.quotas:
            # No quota set, allow by default (or could deny by default)
            return True

        quota = self.quotas[agent_id]
        now = datetime.now()

        # Reset counters if needed
        if (now - quota.last_reset_minute).total_seconds() >= 60:
            quota.requests_this_minute = 0
            quota.last_reset_minute = now

        if (now - quota.last_reset_hour).total_seconds() >= 3600:
            quota.requests_this_hour = 0
            quota.last_reset_hour = now

        # Check limits
        if quota.requests_this_minute >= quota.max_requests_per_minute:
            return False

        if quota.requests_this_hour >= quota.max_requests_per_hour:
            return False

        if quota.current_executions >= quota.max_concurrent_executions:
            return False

        # Check action type allowed
        if quota.allowed_action_types and request.action_type not in quota.allowed_action_types:
            return False

        # Update counters
        quota.requests_this_minute += 1
        quota.requests_this_hour += 1

        return True

    def validate_risk(self, request: ExecutionRequest, risk_score: float) -> bool:
        """Validate request against risk policies"""
        # Check against all risk policies
        for policy_id, policy in self.risk_policies.items():
            # Check if risk score exceeds limits
            if risk_score >= policy.deny_above:
                return False

            # Check parameters for high-risk patterns
            params_str = str(request.parameters)
            for pattern in policy.high_risk_patterns:
                if pattern.lower() in params_str.lower():
                    return False

            # Check domain restrictions if applicable
            if "url" in request.parameters or "domain" in request.parameters:
                url = request.parameters.get("url", request.parameters.get("domain", ""))

                # Check blocked domains
                for blocked in policy.blocked_domains:
                    if blocked in url:
                        return False

                # Check allowed domains (if list is not empty, only allow listed domains)
                if policy.allowed_domains:
                    allowed = False
                    for allowed_domain in policy.allowed_domains:
                        if allowed_domain in url:
                            allowed = True
                            break
                    if not allowed:
                        return False

        return True

    def validate_request(self, request: ExecutionRequest) -> Tuple[bool, Optional[str]]:
        """
        Comprehensive validation of a request
        Returns (is_valid, reason_if_invalid)
        """
        # Check rate limits
        if not self.check_rate_limit(request):
            return False, "rate_limit_exceeded"

        # Check custom rules
        for rule in self.custom_rules:
            if request.action_type in rule.action_types:
                if not rule.validator(request):
                    return False, f"policy_violation: {rule.name}"

        return True, None

    def get_quota_status(self, agent_id: str) -> Dict[str, Any]:
        """Get current quota usage for an agent"""
        if agent_id not in self.quotas:
            return {"error": "No quota set for agent"}

        quota = self.quotas[agent_id]
        return {
            "agent_id": agent_id,
            "requests_this_minute": quota.requests_this_minute,
            "max_requests_per_minute": quota.max_requests_per_minute,
            "requests_this_hour": quota.requests_this_hour,
            "max_requests_per_hour": quota.max_requests_per_hour,
            "current_executions": quota.current_executions,
            "max_concurrent_executions": quota.max_concurrent_executions,
        }


@dataclass
class SQLPolicyConfig:
    """Configuration for SQL policy rules, loadable from YAML.

    Attributes:
        blocked_statements: SQL statement types to block (e.g., DROP, GRANT).
        require_where_clause: Statements blocked only when missing WHERE.
        blocked_create_types: CREATE subtypes to block (e.g., USER, ROLE).
        blocked_patterns: Regex patterns for vendor-specific blocking.
        disclaimer: Disclaimer text shown in logs.
    """
    blocked_statements: List[str] = field(default_factory=lambda: [
        "DROP", "TRUNCATE", "ALTER", "GRANT", "REVOKE", "MERGE",
    ])
    require_where_clause: List[str] = field(default_factory=lambda: [
        "DELETE", "UPDATE",
    ])
    blocked_create_types: List[str] = field(default_factory=lambda: [
        "USER", "ROLE", "LOGIN",
    ])
    blocked_patterns: List[str] = field(default_factory=lambda: [
        r'\bEXEC(UTE)?\s+XP_CMDSHELL\b',
        r'\bEXEC(UTE)?\s+SP_CONFIGURE\b',
        r'\bEXEC(UTE)?\s+SP_ADDROLEMEMBER\b',
        r'\bLOAD_FILE\s*\(',
        r'\bINTO\s+(OUT|DUMP)FILE\b',
        r'\bLOAD\s+DATA\b',
        r'\bMERGE\s+INTO\b',
    ])
    disclaimer: str = ""


def load_sql_policy_config(path: str) -> SQLPolicyConfig:
    """Load SQL policy configuration from a YAML file.

    Args:
        path: Path to a YAML file with ``sql_policy`` section.

    Returns:
        SQLPolicyConfig populated from the YAML data.

    Raises:
        FileNotFoundError: If the config file does not exist.
        ValueError: If the YAML is missing the ``sql_policy`` section.

    Example::

        config = load_sql_policy_config("examples/policies/sql-safety.yaml")
        rules = create_sql_policy_from_config(config)
    """
    import yaml

    if not os.path.exists(path):
        raise FileNotFoundError(f"SQL policy config not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f.read())

    if not isinstance(data, dict) or "sql_policy" not in data:
        raise ValueError(
            f"YAML file must contain a 'sql_policy' section: {path}"
        )

    sp = data["sql_policy"]
    return SQLPolicyConfig(
        blocked_statements=[s.upper() for s in sp.get("blocked_statements", [])],
        require_where_clause=[s.upper() for s in sp.get("require_where_clause", [])],
        blocked_create_types=[s.upper() for s in sp.get("blocked_create_types", [])],
        blocked_patterns=sp.get("blocked_patterns", []),
        disclaimer=data.get("disclaimer", ""),
    )


def _fallback_sql_check(query: str, config: Optional[SQLPolicyConfig] = None) -> bool:
    """
    Fallback SQL check when sqlglot is not available.

    Uses regex pattern matching. Rules are driven by *config*; when
    *config* is ``None`` a built-in default set is used.
    """
    if config is None:
        config = SQLPolicyConfig()

    query_upper = query.upper()
    # Remove comments to prevent bypass
    query_clean = re.sub(r'/\*.*?\*/', '', query_upper, flags=re.DOTALL)
    query_clean = re.sub(r'--.*$', '', query_clean, flags=re.MULTILINE)

    # Build patterns dynamically from config
    patterns: List[str] = []

    for stmt in config.blocked_statements:
        if stmt == "DROP":
            patterns.append(r'\bDROP\s+(TABLE|DATABASE|INDEX|VIEW|SCHEMA|PROCEDURE|FUNCTION|TRIGGER)\b')
        elif stmt == "TRUNCATE":
            patterns.append(r'\bTRUNCATE\s+(TABLE\s+)?\w+')
        elif stmt == "ALTER":
            patterns.append(r'\bALTER\s+(TABLE|DATABASE|SCHEMA)\b')
        elif stmt == "GRANT":
            patterns.append(r'\bGRANT\b')
        elif stmt == "REVOKE":
            patterns.append(r'\bREVOKE\b')
        elif stmt == "MERGE":
            patterns.append(r'\bMERGE\s+INTO\b')
        elif stmt == "INSERT":
            patterns.append(r'\bINSERT\s+INTO\b')
        elif stmt in ("UPDATE", "DELETE"):
            patterns.append(rf'\b{stmt}\b')

    for stmt in config.require_where_clause:
        if stmt == "DELETE":
            patterns.append(r'\bDELETE\s+FROM\s+\w+\s*(;|$)')
        elif stmt == "UPDATE":
            patterns.append(r'\bUPDATE\s+\w+\s+SET\b(?!.*\bWHERE\b)')

    for ct in config.blocked_create_types:
        patterns.append(rf'\bCREATE\s+{ct}\b')
        patterns.append(rf'\bALTER\s+{ct}\b')
        patterns.append(rf'\bDROP\s+{ct}\b')

    patterns.extend(config.blocked_patterns)

    for pattern in patterns:
        if re.search(pattern, query_clean):
            return False
    return True


def create_policies_from_config(
    sql_config_path: Optional[str] = None,
    sql_config: Optional[SQLPolicyConfig] = None,
) -> List[PolicyRule]:
    """Create security policies with SQL rules driven by external config.

    Load SQL policy rules from a YAML config file or a pre-built
    ``SQLPolicyConfig`` object.  Non-SQL policies (file access, credential
    exposure) use built-in defaults.

    Args:
        sql_config_path: Path to a YAML file with ``sql_policy`` section.
        sql_config: Pre-built config object (takes precedence over path).

    Returns:
        List of PolicyRule instances.

    Example::

        # From YAML file
        rules = create_policies_from_config("examples/policies/sql-safety.yaml")

        # From explicit config
        cfg = SQLPolicyConfig(blocked_statements=["DROP", "GRANT"])
        rules = create_policies_from_config(sql_config=cfg)
    """
    if sql_config is None and sql_config_path is not None:
        sql_config = load_sql_policy_config(sql_config_path)
    if sql_config is None:
        sql_config = SQLPolicyConfig()

    return _build_policy_rules(sql_config)


def create_default_policies() -> List[PolicyRule]:
    """Create a set of default security policies.

    .. deprecated::
        The built-in rules are **samples** and are not guaranteed to be
        exhaustive.  Use :func:`create_policies_from_config` with an
        explicit YAML config file for production deployments.
        See ``examples/policies/`` for sample configurations.
    """
    warnings.warn(
        "create_default_policies() uses built-in sample rules that may not "
        "cover all destructive SQL operations. For production use, load an "
        "explicit policy config with create_policies_from_config(). "
        "See examples/policies/sql-safety.yaml for a sample configuration.",
        stacklevel=2,
    )
    return _build_policy_rules(SQLPolicyConfig())


def _build_policy_rules(sql_config: SQLPolicyConfig) -> List[PolicyRule]:

    def no_system_file_access(request: ExecutionRequest) -> bool:
        """Prevent access to system files"""
        if request.action_type in [ActionType.FILE_READ, ActionType.FILE_WRITE]:
            path = request.parameters.get("path", "")
            dangerous_paths = ["/etc/", "/sys/", "/proc/", "/dev/", "C:\\Windows\\System32"]
            return not any(dp in path for dp in dangerous_paths)
        return True

    def no_credential_exposure(request: ExecutionRequest) -> bool:
        """Prevent exposure of credentials"""
        params_str = str(request.parameters).lower()
        sensitive_keywords = ["password", "secret", "api_key", "token", "credential"]
        # This is a simple check; real implementation would be more sophisticated
        return not any(keyword in params_str for keyword in sensitive_keywords)

    def no_destructive_sql(request: ExecutionRequest) -> bool:
        """
        Prevent destructive SQL operations using AST-level parsing.
        
        Uses sqlglot for proper SQL parsing to detect:
        - DROP TABLE/DATABASE/INDEX/VIEW/USER/ROLE statements
        - TRUNCATE statements
        - DELETE without WHERE clause
        - UPDATE without WHERE clause
        - ALTER TABLE/USER/ROLE statements
        - GRANT / REVOKE privilege statements
        - CREATE USER/ROLE/LOGIN statements
        - EXEC/EXECUTE xp_cmdshell and other dangerous procedures
        - MERGE INTO statements
        - Dangerous file functions (LOAD_FILE, INTO OUTFILE)
        
        This prevents bypass attempts like:
        - Keywords in comments: /* DROP */ SELECT ...
        - Keywords in strings: SELECT 'DROP TABLE'
        - Obfuscated queries
        """
        if request.action_type not in (ActionType.DATABASE_QUERY, ActionType.DATABASE_WRITE):
            return True

        query = request.parameters.get("query", "")
        if not query.strip():
            return True

        try:
            # Try to import sqlglot for AST-level parsing
            import sqlglot
            from sqlglot import exp

            # Parse the SQL query into AST
            try:
                statements = sqlglot.parse(query)
            except sqlglot.errors.ParseError:
                # If parsing fails, fall back to conservative blocking
                return _fallback_sql_check(query, sql_config)

            for statement in statements:
                if statement is None:
                    continue

                # Check for DROP statements (tables, databases, users, roles, etc.)
                if isinstance(statement, exp.Drop):
                    return False

                # Check for TRUNCATE statements
                if isinstance(statement, exp.Command) and statement.this.upper() == "TRUNCATE":
                    return False

                # Check for DELETE without WHERE clause
                if isinstance(statement, exp.Delete):
                    if statement.find(exp.Where) is None:
                        return False

                # Check for UPDATE without WHERE clause
                if isinstance(statement, exp.Update):
                    if statement.find(exp.Where) is None:
                        return False

                # Check for ALTER statements
                if isinstance(statement, exp.AlterTable):
                    return False

                # Check for GRANT / REVOKE statements
                if isinstance(statement, exp.Grant):
                    return False

                # Check for MERGE statements (can do INSERT/UPDATE/DELETE)
                if isinstance(statement, exp.Merge):
                    return False

                # Check for CREATE USER/ROLE and ALTER USER/ROLE
                if isinstance(statement, exp.Create):
                    kind = statement.args.get("kind", "")
                    if isinstance(kind, str) and kind.upper() in ("USER", "ROLE", "LOGIN"):
                        return False

                # Catch GRANT, REVOKE, EXEC, CREATE USER via Command nodes
                # (sqlglot may parse some vendor-specific SQL as Command)
                if isinstance(statement, exp.Command):
                    cmd = statement.this.upper() if statement.this else ""
                    if cmd in ("GRANT", "REVOKE", "EXEC", "EXECUTE", "MERGE"):
                        return False
                    # Block CREATE USER/ROLE/LOGIN parsed as Command
                    if cmd == "CREATE":
                        expr_text = statement.sql().upper()
                        if any(kw in expr_text for kw in ("USER", "ROLE", "LOGIN")):
                            return False

                # Check for dangerous functions in any statement
                for func in statement.find_all(exp.Func):
                    func_name = func.name.upper() if func.name else ""
                    if func_name in ("LOAD_FILE", "INTO OUTFILE", "INTO DUMPFILE"):
                        return False

                # Check for EXEC xp_cmdshell and other dangerous procs
                # in the full SQL text of the statement
                stmt_sql = statement.sql().upper()
                if re.search(r'\bEXEC(UTE)?\s+XP_CMDSHELL\b', stmt_sql):
                    return False
                if re.search(r'\bEXEC(UTE)?\s+SP_CONFIGURE\b', stmt_sql):
                    return False
                if re.search(r'\bEXEC(UTE)?\s+SP_ADDROLEMEMBER\b', stmt_sql):
                    return False

            return True

        except ImportError:
            # sqlglot not installed, fall back to keyword matching
            return _fallback_sql_check(query, sql_config)

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
        PolicyRule(
            rule_id=str(uuid.uuid4()),
            name="no_destructive_sql",
            description="Prevent destructive SQL operations",
            action_types=[ActionType.DATABASE_QUERY, ActionType.DATABASE_WRITE],
            validator=no_destructive_sql,
            priority=9,
        ),
    ]
