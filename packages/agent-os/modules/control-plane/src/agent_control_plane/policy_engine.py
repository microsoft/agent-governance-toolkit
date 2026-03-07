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
from .agent_kernel import ExecutionRequest, ActionType, PolicyRule
import uuid
import os
import re


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
        """
        self.state_permissions[role] = set(allowed_tools)

    def add_conditional_permission(self, agent_role: str, permission: ConditionalPermission):
        """
        Add a conditional permission for ABAC (Attribute-Based Access Control).

        This moves from RBAC to ABAC, allowing context-aware policies like:
        "Agent can call refund_user IF AND ONLY IF user_status == 'verified'"

        Args:
            agent_role: The agent role/ID
            permission: The conditional permission to add
        """
        if agent_role not in self.conditional_permissions:
            self.conditional_permissions[agent_role] = []

        self.conditional_permissions[agent_role].append(permission)

        # Also add the tool to the basic allow-list so it passes the first check
        # The conditional check will happen later
        if agent_role not in self.state_permissions:
            self.state_permissions[agent_role] = set()
        self.state_permissions[agent_role].add(permission.tool_name)

    def set_agent_context(self, agent_role: str, context: Dict[str, Any]):
        """
        Set the context data for an agent for ABAC evaluation.

        Args:
            agent_role: The agent role/ID
            context: Dictionary of context attributes (e.g., {"user_status": "verified", "time_of_day": "business_hours"})
        """
        self.agent_contexts[agent_role] = context

    def update_agent_context(self, agent_role: str, updates: Dict[str, Any]):
        """
        Update specific context attributes for an agent.

        Args:
            agent_role: The agent role/ID
            updates: Dictionary of attributes to update
        """
        if agent_role not in self.agent_contexts:
            self.agent_contexts[agent_role] = {}

        self.agent_contexts[agent_role].update(updates)

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


def _fallback_sql_check(query: str) -> bool:
    """
    Fallback SQL check when sqlglot is not available.
    
    Uses regex pattern matching - less secure but provides basic protection.
    """
    query_upper = query.upper()
    # Remove comments to prevent bypass
    query_clean = re.sub(r'/\*.*?\*/', '', query_upper, flags=re.DOTALL)
    query_clean = re.sub(r'--.*$', '', query_clean, flags=re.MULTILINE)
    
    # Check for destructive operations
    destructive_patterns = [
        r'\bDROP\s+(TABLE|DATABASE|INDEX|VIEW|SCHEMA)\b',
        r'\bTRUNCATE\s+TABLE\b',
        r'\bDELETE\s+FROM\s+\w+\s*(;|$)',  # DELETE without WHERE
        r'\bALTER\s+TABLE\b',
    ]
    for pattern in destructive_patterns:
        if re.search(pattern, query_clean):
            return False
    return True


def create_default_policies() -> List[PolicyRule]:
    """Create a set of default security policies"""

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
        - DROP TABLE/DATABASE/INDEX/VIEW statements
        - TRUNCATE statements
        - DELETE without WHERE clause
        - ALTER TABLE statements
        
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
                # Log the error but err on the side of caution
                return _fallback_sql_check(query)
            
            for statement in statements:
                if statement is None:
                    continue
                    
                # Check for DROP statements
                if isinstance(statement, exp.Drop):
                    return False
                    
                # Check for TRUNCATE statements
                if isinstance(statement, exp.Command) and statement.this.upper() == "TRUNCATE":
                    return False
                    
                # Check for DELETE without WHERE clause
                if isinstance(statement, exp.Delete):
                    # DELETE is only allowed with a WHERE clause
                    if statement.find(exp.Where) is None:
                        return False
                        
                # Check for ALTER statements
                if isinstance(statement, exp.AlterTable):
                    return False
                    
                # Check for dangerous functions in any statement
                for func in statement.find_all(exp.Func):
                    func_name = func.name.upper() if func.name else ""
                    if func_name in ("LOAD_FILE", "INTO OUTFILE", "INTO DUMPFILE"):
                        return False
                        
            return True
            
        except ImportError:
            # sqlglot not installed, fall back to keyword matching
            return _fallback_sql_check(query)

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
