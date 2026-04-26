# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Constraint Engineering - The Logic Firewall

This module implements a deterministic safety layer that intercepts AI-generated
plans before execution. It acts as a firewall between the AI "Brain" and the
execution "Hand".

Architecture:
1. Brain (LLM): Generates plans with high creativity/temperature
2. Firewall (This Module): Deterministic validation layer in Python
3. Hand (Executor): Only executes if firewall approves

Key Principle:
"Never let the AI touch the infrastructure directly. 
The Human builds the walls; the AI plays inside them."
"""

from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import re


class ViolationSeverity(Enum):
    """Severity levels for constraint violations."""
    CRITICAL = "critical"  # Immediate danger (e.g., DROP TABLE)
    HIGH = "high"          # Serious risk (e.g., delete files)
    MEDIUM = "medium"      # Policy violation (e.g., wrong domain)
    LOW = "low"            # Warning (e.g., approaching cost limit)


@dataclass
class ConstraintViolation:
    """Represents a constraint violation detected by the firewall."""
    rule_name: str
    severity: ViolationSeverity
    message: str
    blocked_action: str
    suggested_fix: Optional[str] = None


@dataclass
class ConstraintResult:
    """Result of constraint validation."""
    approved: bool
    violations: List[ConstraintViolation]
    
    def get_blocking_violations(self) -> List[ConstraintViolation]:
        """Get violations that block execution (CRITICAL or HIGH)."""
        return [v for v in self.violations 
                if v.severity in [ViolationSeverity.CRITICAL, ViolationSeverity.HIGH]]
    
    def has_blocking_violations(self) -> bool:
        """Check if there are any blocking violations."""
        return len(self.get_blocking_violations()) > 0


class ConstraintRule:
    """Base class for constraint rules."""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
    
    def validate(self, plan: Dict[str, Any]) -> List[ConstraintViolation]:
        """
        Validate a plan against this constraint rule.
        
        Args:
            plan: Dictionary containing the action plan with keys:
                - action_type: Type of action (e.g., "sql_query", "email", "file_operation")
                - action_data: Data specific to the action
        
        Returns:
            List of constraint violations (empty if valid)
        """
        raise NotImplementedError("Subclasses must implement validate()")


class SQLInjectionRule(ConstraintRule):
    """Detects dangerous SQL operations."""
    
    # Dangerous SQL patterns that should be blocked
    DANGEROUS_PATTERNS = [
        r'\bDROP\s+TABLE\b',
        r'\bDROP\s+DATABASE\b',
        r'\bDELETE\s+FROM\b.*\bWHERE\s+1\s*=\s*1\b',
        r'\bTRUNCATE\s+TABLE\b',
        r'\bALTER\s+TABLE\b.*\bDROP\b',
        r';\s*DROP\b',  # SQL injection pattern - command chaining
        r';\s*DELETE\b',  # SQL injection pattern - command chaining
        r'/\*.*?\*/',    # SQL block comment (non-greedy matching)
    ]
    
    def __init__(self):
        super().__init__(
            name="sql_injection_prevention",
            description="Prevents dangerous SQL operations and injection attempts"
        )
    
    def validate(self, plan: Dict[str, Any]) -> List[ConstraintViolation]:
        violations = []
        
        if plan.get("action_type") != "sql_query":
            return violations
        
        query = plan.get("action_data", {}).get("query", "")
        
        for pattern in self.DANGEROUS_PATTERNS:
            if re.search(pattern, query, re.IGNORECASE):
                violations.append(ConstraintViolation(
                    rule_name=self.name,
                    severity=ViolationSeverity.CRITICAL,
                    message=f"Dangerous SQL operation detected: {pattern}",
                    blocked_action=query,
                    suggested_fix="Use parameterized queries and avoid destructive operations"
                ))
        
        return violations


class FileOperationRule(ConstraintRule):
    """Restricts dangerous file operations."""
    
    # Dangerous file operation patterns
    DANGEROUS_PATTERNS = [
        r'rm\s+-rf\s+/',          # Recursive delete from root
        r'rm\s+-rf\s+\*',         # Delete all files recursively
        r'del\s+/s\s+/q\s+\*',    # Windows equivalent
        r'format\s+[cC]:',         # Format C drive
        r'dd\s+if=.*of=/dev/',     # Overwrite disk
    ]
    
    # Protected paths that should never be modified
    PROTECTED_PATHS = [
        '/etc',
        '/sys',
        '/boot',
        '/bin',
        '/sbin',
        'C:\\Windows',
        'C:\\System32',
    ]
    
    def __init__(self):
        super().__init__(
            name="file_operation_safety",
            description="Prevents dangerous file operations and protects critical paths"
        )
    
    def validate(self, plan: Dict[str, Any]) -> List[ConstraintViolation]:
        violations = []
        
        if plan.get("action_type") != "file_operation":
            return violations
        
        command = plan.get("action_data", {}).get("command", "")
        path = plan.get("action_data", {}).get("path", "")
        
        # Check for dangerous command patterns
        for pattern in self.DANGEROUS_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                violations.append(ConstraintViolation(
                    rule_name=self.name,
                    severity=ViolationSeverity.CRITICAL,
                    message=f"Dangerous file operation detected: {pattern}",
                    blocked_action=command,
                    suggested_fix="Avoid destructive file operations on system directories"
                ))
        
        # Check for protected paths
        for protected in self.PROTECTED_PATHS:
            if path.startswith(protected):
                violations.append(ConstraintViolation(
                    rule_name=self.name,
                    severity=ViolationSeverity.HIGH,
                    message=f"Attempted operation on protected path: {protected}",
                    blocked_action=f"Path: {path}",
                    suggested_fix="Only operate on user data directories"
                ))
        
        return violations


class CostLimitRule(ConstraintRule):
    """Enforces cost limits on operations."""
    
    def __init__(self, max_cost_per_action: float = 0.05):
        super().__init__(
            name="cost_limit_enforcement",
            description=f"Ensures action cost does not exceed ${max_cost_per_action}"
        )
        self.max_cost_per_action = max_cost_per_action
    
    def validate(self, plan: Dict[str, Any]) -> List[ConstraintViolation]:
        violations = []
        
        estimated_cost = plan.get("action_data", {}).get("estimated_cost", 0.0)
        
        if estimated_cost > self.max_cost_per_action:
            violations.append(ConstraintViolation(
                rule_name=self.name,
                severity=ViolationSeverity.HIGH,
                message=f"Action cost ${estimated_cost:.4f} exceeds limit ${self.max_cost_per_action:.4f}",
                blocked_action=f"Action with cost ${estimated_cost:.4f}",
                suggested_fix="Reduce operation scope or request approval for high-cost actions"
            ))
        elif estimated_cost > self.max_cost_per_action * 0.8:
            # Warning when approaching limit
            violations.append(ConstraintViolation(
                rule_name=self.name,
                severity=ViolationSeverity.LOW,
                message=f"Action cost ${estimated_cost:.4f} is approaching limit ${self.max_cost_per_action:.4f}",
                blocked_action=f"Action with cost ${estimated_cost:.4f}",
                suggested_fix="Consider optimizing operation to reduce cost"
            ))
        
        return violations


class EmailDomainRule(ConstraintRule):
    """Restricts email sending to approved domains."""
    
    def __init__(self, allowed_domains: Optional[List[str]] = None):
        super().__init__(
            name="email_domain_restriction",
            description="Restricts email sending to approved domains only"
        )
        self.allowed_domains = allowed_domains or [
            "example.com",
            "company.com",
            "trusted-partner.com"
        ]
    
    def validate(self, plan: Dict[str, Any]) -> List[ConstraintViolation]:
        violations = []
        
        if plan.get("action_type") != "email":
            return violations
        
        recipient = plan.get("action_data", {}).get("recipient", "")
        
        if not recipient:
            return violations
        
        # Extract domain from email
        if "@" in recipient:
            domain = recipient.split("@")[1].lower()
            
            if domain not in self.allowed_domains:
                violations.append(ConstraintViolation(
                    rule_name=self.name,
                    severity=ViolationSeverity.MEDIUM,
                    message=f"Email domain '{domain}' is not in approved list",
                    blocked_action=f"Send email to {recipient}",
                    suggested_fix=f"Only send emails to: {', '.join(self.allowed_domains)}"
                ))
        
        return violations


class RateLimitRule(ConstraintRule):
    """Enforces rate limits on actions."""
    
    def __init__(self, max_actions_per_minute: int = 10):
        super().__init__(
            name="rate_limit_enforcement",
            description=f"Limits actions to {max_actions_per_minute} per minute"
        )
        self.max_actions_per_minute = max_actions_per_minute
    
    def validate(self, plan: Dict[str, Any]) -> List[ConstraintViolation]:
        violations = []
        
        # In a real implementation, this would track actions over time windows
        # For this POC, we demonstrate the concept using rate from plan data
        current_rate = plan.get("action_data", {}).get("current_rate", 0)
        
        if current_rate >= self.max_actions_per_minute:
            violations.append(ConstraintViolation(
                rule_name=self.name,
                severity=ViolationSeverity.MEDIUM,
                message=f"Rate limit exceeded: {current_rate} actions/min >= {self.max_actions_per_minute}",
                blocked_action="Current action",
                suggested_fix="Wait before executing more actions"
            ))
        
        return violations


class ConstraintEngine:
    """
    The Logic Firewall - Deterministic constraint validation layer.
    
    This sits between the AI Brain (LLM) and the Executor (Hand).
    All AI-generated plans must pass through this firewall before execution.
    """
    
    def __init__(self, rules: Optional[List[ConstraintRule]] = None):
        """
        Initialize the constraint engine with validation rules.
        
        Args:
            rules: List of constraint rules to enforce. If None, uses default rules.
        """
        if rules is None:
            # Default rule set for safety
            self.rules = [
                SQLInjectionRule(),
                FileOperationRule(),
                CostLimitRule(),
                EmailDomainRule(),
                RateLimitRule()
            ]
        else:
            self.rules = rules
    
    def add_rule(self, rule: ConstraintRule) -> None:
        """Add a new constraint rule to the engine."""
        self.rules.append(rule)
    
    def remove_rule(self, rule_name: str) -> bool:
        """Remove a constraint rule by name. Returns True if removed."""
        initial_count = len(self.rules)
        self.rules = [r for r in self.rules if r.name != rule_name]
        return len(self.rules) < initial_count
    
    def validate_plan(self, plan: Dict[str, Any], verbose: bool = False) -> ConstraintResult:
        """
        Validate an AI-generated plan against all constraint rules.
        
        Args:
            plan: Dictionary containing the action plan
            verbose: Print validation details
        
        Returns:
            ConstraintResult with approval status and any violations
        """
        all_violations = []
        
        if verbose:
            print("\n" + "="*60)
            print("CONSTRAINT ENGINE: Validating Plan")
            print("="*60)
            print(f"Action Type: {plan.get('action_type', 'unknown')}")
            print(f"Rules Active: {len(self.rules)}")
        
        # Run all rules
        for rule in self.rules:
            violations = rule.validate(plan)
            all_violations.extend(violations)
            
            if verbose and violations:
                for violation in violations:
                    print(f"\n⚠️  VIOLATION DETECTED")
                    print(f"   Rule: {violation.rule_name}")
                    print(f"   Severity: {violation.severity.value.upper()}")
                    print(f"   Message: {violation.message}")
        
        # Determine if plan is approved
        # Block if any CRITICAL or HIGH severity violations
        blocking_violations = [v for v in all_violations 
                              if v.severity in [ViolationSeverity.CRITICAL, ViolationSeverity.HIGH]]
        
        approved = len(blocking_violations) == 0
        
        result = ConstraintResult(
            approved=approved,
            violations=all_violations
        )
        
        if verbose:
            print("\n" + "-"*60)
            if approved:
                print("✅ FIREWALL: Plan APPROVED")
            else:
                print("🚫 FIREWALL: Plan BLOCKED")
                print(f"   Blocking Violations: {len(blocking_violations)}")
            print("="*60)
        
        return result
    
    def intercept_and_validate(self, plan: Dict[str, Any], 
                              execute_fn=None,
                              verbose: bool = False) -> Tuple[bool, Any, ConstraintResult]:
        """
        Intercept a plan, validate it, and optionally execute if approved.
        
        Args:
            plan: The action plan to validate
            execute_fn: Optional function to execute if plan is approved
            verbose: Print validation details
        
        Returns:
            (executed, result, constraint_result) tuple where:
                - executed: Whether the plan was executed
                - result: Result from execute_fn if executed, None otherwise
                - constraint_result: The constraint validation result
        """
        constraint_result = self.validate_plan(plan, verbose=verbose)
        
        if not constraint_result.approved:
            if verbose:
                print("\n🚫 Execution blocked by firewall")
            return False, None, constraint_result
        
        # Execute if approved and function provided
        if execute_fn:
            if verbose:
                print("\n✅ Firewall approved - executing action")
            result = execute_fn(plan)
            return True, result, constraint_result
        
        return True, None, constraint_result


def create_default_engine(max_cost: float = 0.05, 
                         allowed_domains: Optional[List[str]] = None) -> ConstraintEngine:
    """
    Create a constraint engine with sensible defaults.
    
    Args:
        max_cost: Maximum cost per action in dollars
        allowed_domains: List of allowed email domains
    
    Returns:
        Configured ConstraintEngine instance
    """
    rules = [
        SQLInjectionRule(),
        FileOperationRule(),
        CostLimitRule(max_cost_per_action=max_cost),
        EmailDomainRule(allowed_domains=allowed_domains),
        RateLimitRule(max_actions_per_minute=10)
    ]
    
    return ConstraintEngine(rules=rules)
