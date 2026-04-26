# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Policy Engine

Declarative policy engine with YAML/JSON policies.
Policy evaluation latency <5ms with 100% deterministic results.

Supports schema versioning via ``apiVersion`` (e.g.,
``governance.toolkit/v1``). Older versions emit deprecation
warnings; unknown versions raise ``ValueError``.
"""

from datetime import datetime
from typing import Optional, Literal, Any
from pydantic import BaseModel, Field
import logging
import os
import warnings
import yaml
import json
import re

logger = logging.getLogger(__name__)

# Supported schema versions (newest first)
CURRENT_API_VERSION = "governance.toolkit/v1"
SUPPORTED_API_VERSIONS = {
    "governance.toolkit/v1": {"status": "current"},
    "1.0": {"status": "deprecated", "migrate_to": "governance.toolkit/v1"},
}


class PolicyRule(BaseModel):
    """
    A single policy rule.

    Rules define conditions and actions:
    - condition: Expression that evaluates to true/false
    - action: What to do when condition matches (allow, deny, warn, require_approval)
    - stage: When in the agent lifecycle this rule is evaluated
    """

    name: str = Field(..., description="Rule name")
    description: Optional[str] = Field(None)

    # Lifecycle stage
    stage: Literal["pre_input", "pre_tool", "post_tool", "pre_output"] = Field(
        default="pre_tool",
        description="Agent lifecycle stage: pre_input, pre_tool, post_tool, pre_output",
    )

    # Condition
    condition: str = Field(..., description="Condition expression")

    # Action
    action: Literal["allow", "deny", "warn", "require_approval", "log"] = Field(
        default="deny"
    )

    # Rate limiting
    limit: Optional[str] = Field(None, description="Rate limit (e.g., '100/hour')")

    # Approval workflow
    approvers: list[str] = Field(default_factory=list)

    # Priority (higher = evaluated first)
    priority: int = Field(default=0)

    # Enabled
    enabled: bool = Field(default=True)

    def evaluate(self, context: dict) -> bool:
        """Evaluate the rule condition against a context.

        Supports simple expressions like:
        - ``action.type == 'export'``
        - ``data.contains_pii``
        - ``user.role in ['admin', 'operator']``

        Args:
            context: Dictionary of runtime values the condition is
                evaluated against. Keys are accessed via dot notation.

        Returns:
            ``True`` if the rule is enabled and the condition matches,
            ``False`` otherwise (including on evaluation errors).
        """
        if not self.enabled:
            return False

        try:
            # Simple expression evaluation
            # In production, would use a proper expression parser
            return self._eval_expression(self.condition, context)
        except Exception:
            # V27: Fail-closed — treat evaluation errors as a match so
            # the rule's action (typically "deny") takes effect. This
            # prevents attackers from crafting inputs that trigger
            # exceptions to bypass policy rules.
            logger.warning(
                "Policy rule evaluation error for '%s' — treating as MATCH (fail-closed)",
                self.name,
                exc_info=True,
            )
            return True

    # Maximum recursion depth for compound expressions to prevent DoS
    _MAX_EXPRESSION_DEPTH = 20

    def _eval_expression(self, expr: str, context: dict, _depth: int = 0) -> bool:
        """Evaluate a simple expression."""
        if _depth > self._MAX_EXPRESSION_DEPTH:
            return False  # fail-closed on excessive nesting

        if len(expr) > 2000:
            return False  # reject oversized expressions

        # Handle compound conditions first (AND/OR)
        # This must be checked before individual conditions

        # OR conditions
        if " or " in expr:
            parts = expr.split(" or ")
            return any(self._eval_expression(p.strip(), context, _depth + 1) for p in parts)

        # AND conditions
        if " and " in expr:
            parts = expr.split(" and ")
            return all(self._eval_expression(p.strip(), context, _depth + 1) for p in parts)

        # Now handle atomic conditions

        # Equality: action.type == 'export'
        eq_match = re.match(r"(\w+(?:\.\w+)*)\s*==\s*['\"]([^'\"]+)['\"]", expr)
        if eq_match:
            path, value = eq_match.groups()
            actual = self._get_nested(context, path)
            return actual == value

        # Inequality: action.type != 'export'
        neq_match = re.match(r"(\w+(?:\.\w+)*)\s*!=\s*['\"]([^'\"]+)['\"]", expr)
        if neq_match:
            path, value = neq_match.groups()
            actual = self._get_nested(context, path)
            return actual != value

        # Membership: field in ['a', 'b', 'c']
        in_match = re.match(
            r"(\w+(?:\.\w+)*)\s+in\s+\[([^\]]*)\]", expr
        )
        if in_match:
            path, items_str = in_match.groups()
            actual = self._get_nested(context, path)
            items = [s.strip().strip("'\"") for s in items_str.split(",") if s.strip()]
            return actual in items

        # Comparison: field > number
        cmp_match = re.match(r"(\w+(?:\.\w+)*)\s*(>=|<=|>|<)\s*(\d+(?:\.\d+)?)", expr)
        if cmp_match:
            path, op, num_str = cmp_match.groups()
            actual = self._get_nested(context, path)
            try:
                actual_num = float(actual) if actual is not None else 0
                target = float(num_str)
                if op == ">": return actual_num > target
                if op == "<": return actual_num < target
                if op == ">=": return actual_num >= target
                if op == "<=": return actual_num <= target
            except (TypeError, ValueError):
                return False

        # Boolean attribute: data.contains_pii
        bool_match = re.match(r"^(\w+(?:\.\w+)*)$", expr)
        if bool_match:
            path = bool_match.group(1)
            return bool(self._get_nested(context, path))

        return False

    def _get_nested(self, obj: dict, path: str) -> Any:
        """Get nested value from dict using dot notation."""
        parts = path.split(".")
        current = obj
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current


class Policy(BaseModel):
    """
    Complete policy document.

    Policies are defined in YAML/JSON and loaded at runtime.
    Use ``apiVersion: governance.toolkit/v1`` in YAML files for
    schema-versioned policies.

    Supports hierarchical composition via ``extends``. Child policies
    inherit all rules from parent policies and can add new rules but
    cannot weaken or remove parent rules (additive-only semantics).
    """

    apiVersion: str = Field(
        default=CURRENT_API_VERSION,
        description="Schema version (e.g., governance.toolkit/v1)",
    )
    version: str = Field(default="1.0")
    name: str = Field(...)
    description: Optional[str] = Field(None)

    # Composition
    extends: list[str] = Field(
        default_factory=list,
        description="Parent policy file paths to inherit rules from (additive-only)",
    )

    # Target
    agent: Optional[str] = Field(None, description="Agent this policy applies to")
    agents: list[str] = Field(default_factory=list, description="Multiple agents")

    # Scope for conflict resolution
    scope: str = Field(
        default="global",
        description="Policy scope: global, tenant, or agent",
    )

    # Rules
    rules: list[PolicyRule] = Field(default_factory=list)

    # Default action
    default_action: Literal["allow", "deny"] = Field(default="deny")

    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    @classmethod
    def from_yaml(cls, yaml_content: str, base_dir: str = "") -> "Policy":
        """Load a policy from a YAML string.

        Validates the ``apiVersion`` field against supported versions
        and emits deprecation warnings for older schemas. Resolves
        ``extends`` references relative to ``base_dir``.

        Args:
            yaml_content: Raw YAML string containing the policy definition.
            base_dir: Directory for resolving relative ``extends`` paths.

        Returns:
            A fully-constructed ``Policy`` instance with inherited rules.

        Raises:
            ValueError: If the ``apiVersion`` is not recognized or a
                circular ``extends`` reference is detected.
        """
        data = yaml.safe_load(yaml_content)
        _validate_api_version(data)

        # Normalize extends field
        extends_raw = data.pop("extends", None)
        extends_list: list[str] = []
        if isinstance(extends_raw, str):
            extends_list = [extends_raw]
        elif isinstance(extends_raw, list):
            extends_list = extends_raw

        # Parse own rules
        rules = []
        for rule_data in data.get("rules", []):
            rules.append(PolicyRule(**rule_data))
        data["rules"] = rules
        data["extends"] = extends_list

        return cls(**data)

    @classmethod
    def from_yaml_file(
        cls,
        file_path: str,
        _resolve_stack: list[str] | None = None,
    ) -> "Policy":
        """Load a policy from a YAML file, resolving ``extends`` parents.

        Recursively loads parent policies referenced by ``extends``,
        merging rules with additive-only semantics (child can add
        rules but cannot weaken or remove parent deny rules).

        Detects and rejects circular references.

        Args:
            file_path: Path to the YAML policy file.

        Returns:
            A ``Policy`` with all inherited rules merged.

        Raises:
            ValueError: On circular references or missing parent files.
            FileNotFoundError: If a referenced file does not exist.
        """
        abs_path = os.path.abspath(file_path)

        # Cycle detection
        if _resolve_stack is None:
            _resolve_stack = []
        if abs_path in _resolve_stack:
            chain = " -> ".join(_resolve_stack + [abs_path])
            raise ValueError(f"Circular policy extends detected: {chain}")
        _resolve_stack = [*_resolve_stack, abs_path]

        with open(abs_path, "r", encoding="utf-8") as f:
            content = f.read()

        base_dir = os.path.dirname(abs_path)
        policy = cls.from_yaml(content, base_dir=base_dir)

        if not policy.extends:
            return policy

        # Resolve parent policies and merge rules
        parent_rules: list[PolicyRule] = []
        parent_names_seen: set[str] = set()

        for parent_ref in policy.extends:
            parent_path = (
                parent_ref
                if os.path.isabs(parent_ref)
                else os.path.join(base_dir, parent_ref)
            )
            if not os.path.exists(parent_path):
                raise FileNotFoundError(
                    f"Policy extends '{parent_ref}' not found at {parent_path}"
                )

            parent = cls.from_yaml_file(parent_path, _resolve_stack=_resolve_stack)

            # Deduplicate (diamond inheritance) — track by rule name
            for rule in parent.rules:
                if rule.name not in parent_names_seen:
                    parent_names_seen.add(rule.name)
                    parent_rules.append(rule)

        # Merge: parent rules first, then child rules.
        # Child cannot override parent deny rules (additive-only).
        parent_deny_names = {r.name for r in parent_rules if r.action == "deny"}
        child_rules_filtered = []
        for rule in policy.rules:
            if rule.name in parent_deny_names and rule.action in ("allow", "log"):
                logger.warning(
                    "Policy '%s' rule '%s' attempts to weaken parent deny — ignored",
                    policy.name,
                    rule.name,
                )
                continue
            child_rules_filtered.append(rule)

        policy.rules = parent_rules + child_rules_filtered
        return policy

    @classmethod
    def from_json(cls, json_content: str) -> "Policy":
        """Load a policy from a JSON string.

        Validates the ``apiVersion`` field against supported versions
        and emits deprecation warnings for older schemas.

        Args:
            json_content: Raw JSON string containing the policy definition.

        Returns:
            A fully-constructed ``Policy`` instance.

        Raises:
            ValueError: If the ``apiVersion`` is not recognized.
        """
        data = json.loads(json_content)
        _validate_api_version(data)

        rules = []
        for rule_data in data.get("rules", []):
            rules.append(PolicyRule(**rule_data))
        data["rules"] = rules

        return cls(**data)

    def applies_to(self, agent_did: str) -> bool:
        """Check if this policy applies to a given agent.

        A policy applies when the agent DID matches ``self.agent``,
        appears in ``self.agents``, or when ``self.agents`` contains
        the wildcard ``"*"``.

        Args:
            agent_did: Decentralized identifier of the agent.

        Returns:
            ``True`` if the policy targets this agent.
        """
        if self.agent and self.agent == agent_did:
            return True
        if agent_did in self.agents:
            return True
        if "*" in self.agents:
            return True
        return False

    def to_yaml(self) -> str:
        """Export this policy as a YAML string.

        Returns:
            YAML-formatted policy document.
        """
        data = self.model_dump(exclude_none=True)
        # Convert rules to dicts
        data["rules"] = [r.model_dump(exclude_none=True) for r in self.rules]
        return yaml.dump(data, default_flow_style=False)


class PolicyDecision(BaseModel):
    """Result of policy evaluation.

    Attributes:
        allowed: Whether the action is permitted.
        action: The action taken (allow, deny, warn, require_approval, log).
        matched_rule: Name of the rule that triggered the decision.
        policy_name: Name of the policy containing the matched rule.
        reason: Human-readable explanation of the decision.
        approvers: List of required approvers for ``require_approval`` actions.
        rate_limited: Whether the decision was caused by rate limiting.
        rate_limit_reset: When the rate limit resets (if applicable).
        evaluated_at: Timestamp of evaluation.
        evaluation_ms: Evaluation latency in milliseconds.
    """

    allowed: bool
    action: Literal["allow", "deny", "warn", "require_approval", "log"]

    # Which rule matched
    matched_rule: Optional[str] = None
    policy_name: Optional[str] = None

    # Details
    reason: Optional[str] = None

    # For require_approval
    approvers: list[str] = Field(default_factory=list)

    # For rate limiting
    rate_limited: bool = False
    rate_limit_reset: Optional[datetime] = None

    # Timing
    evaluated_at: datetime = Field(default_factory=datetime.utcnow)
    evaluation_ms: Optional[float] = None

    # Extension metadata (e.g., authority resolver details)
    metadata: Optional[dict] = Field(default=None, description="Additional decision context from resolvers")


class PolicyEngine:
    """
    Declarative policy engine.

    Features:
    - YAML/JSON policy definitions
    - <5ms evaluation latency
    - 100% deterministic across runs
    - Rate limiting support
    - Approval workflows
    - Configurable conflict resolution strategy
    """

    MAX_EVAL_MS = 5  # Target: <5ms evaluation

    def __init__(self, conflict_strategy: str = "priority_first_match"):
        """Initialize the policy engine.

        Args:
            conflict_strategy: How to resolve conflicts when multiple
                rules match. One of ``"deny_overrides"``,
                ``"allow_overrides"``, ``"priority_first_match"``
                (default, preserves v1.0 behavior), or
                ``"most_specific_wins"``.
        """
        from agentmesh.governance.conflict_resolution import (
            ConflictResolutionStrategy,
            PolicyConflictResolver,
        )

        self._policies: dict[str, Policy] = {}
        self._rate_limits: dict[str, dict] = {}  # rule_name -> {count, reset_at}
        self._rego_evaluators: list[tuple[str, Any]] = []  # [(package, OPAEvaluator)]
        self._cedar_evaluators: list[Any] = []  # [CedarEvaluator]
        self._authority_resolver: Any = None  # AuthorityResolver protocol
        self._conflict_strategy = ConflictResolutionStrategy(conflict_strategy)
        self._resolver = PolicyConflictResolver(self._conflict_strategy)

    def load_policy(self, policy: Policy) -> None:
        """Load a policy into the engine.

        Args:
            policy: Policy instance to register. Replaces any existing
                policy with the same name.
        """
        self._policies[policy.name] = policy

    def load_yaml(self, yaml_content: str) -> Policy:
        """Parse and register a policy from a YAML string.

        Args:
            yaml_content: Raw YAML policy definition.

        Returns:
            The loaded ``Policy`` instance.
        """
        policy = Policy.from_yaml(yaml_content)
        self.load_policy(policy)
        return policy

    def load_yaml_file(self, file_path: str) -> Policy:
        """Parse and register a policy from a YAML file.

        Resolves ``extends`` references recursively with additive-only
        merge semantics. Parent deny rules cannot be weakened by children.

        Args:
            file_path: Path to the YAML policy file.

        Returns:
            The loaded ``Policy`` with inherited rules merged.
        """
        policy = Policy.from_yaml_file(file_path)
        self.load_policy(policy)
        return policy

    def load_json(self, json_content: str) -> Policy:
        """Parse and register a policy from a JSON string.

        Args:
            json_content: Raw JSON policy definition.

        Returns:
            The loaded ``Policy`` instance.
        """
        policy = Policy.from_json(json_content)
        self.load_policy(policy)
        return policy

    def set_authority_resolver(self, resolver: Any) -> None:
        """Register an ``AuthorityResolver`` for reputation-gated authority.

        The resolver is called during evaluation after YAML/JSON rule
        matching and before OPA/Cedar policies. It can narrow
        capabilities, apply spend limits, or deny the action based on
        trust scoring and delegation chain context.

        Args:
            resolver: An object implementing the ``AuthorityResolver``
                protocol (i.e., has a ``resolve(AuthorityRequest) ->
                AuthorityDecision`` method).
        """
        self._authority_resolver = resolver

    def _apply_rule(self, rule: PolicyRule, policy: Policy, context: Optional[dict] = None) -> PolicyDecision:
        """Apply a matched rule and generate actionable error messages."""
        # Check rate limit if applicable
        if rule.limit:
            if self._is_rate_limited(rule):
                return PolicyDecision(
                    allowed=False,
                    action="deny",
                    matched_rule=rule.name,
                    policy_name=policy.name,
                    reason=f"Rate limit exceeded for rule '{rule.name}': {rule.limit}. Wait for rate limit to reset.",
                    rate_limited=True,
                )
            self._increment_rate_limit(rule)

        # Build actionable error message
        if rule.action == "deny":
            # Build detailed, actionable message
            action_type = context.get("action", {}).get("type", "action") if context else "action"
            suggestion = self._get_suggestion(rule, context)
            reason = (
                f"Policy '{policy.name}' blocked {action_type}. "
                f"Rule: '{rule.name}'. "
                f"Reason: {rule.description or 'Policy condition matched'}. "
                f"{suggestion}"
            )
        elif rule.action == "require_approval":
            approver_list = ", ".join(rule.approvers) if rule.approvers else "designated approvers"
            reason = (
                f"Action requires approval from {approver_list}. "
                f"Policy: '{policy.name}', Rule: '{rule.name}'."
            )
        elif rule.action == "warn":
            reason = (
                f"Warning from policy '{policy.name}': {rule.description or rule.name}. "
                f"Action allowed but logged for review."
            )
        else:
            reason = rule.description or f"Matched rule: {rule.name}"

        return PolicyDecision(
            allowed=(rule.action == "allow"),
            action=rule.action,
            matched_rule=rule.name,
            policy_name=policy.name,
            reason=reason,
            approvers=rule.approvers if rule.action == "require_approval" else [],
        )

    def _get_suggestion(self, rule: PolicyRule, context: Optional[dict] = None) -> str:
        """Generate actionable suggestions based on the rule condition."""
        condition = rule.condition.lower()

        # Pattern-based suggestions
        if "pii" in condition or "contains_pii" in condition:
            return "Suggestion: Remove PII fields or request approval from data privacy team."
        elif "export" in condition:
            return "Suggestion: Use internal data only or request export approval."
        elif "admin" in condition or "role" in condition:
            return "Suggestion: Request elevated permissions or contact your administrator."
        elif "external" in condition or "domain" in condition:
            return "Suggestion: Use approved internal services or request external access."
        elif "budget" in condition or "cost" in condition:
            return "Suggestion: Reduce request scope or request budget increase."
        elif "time" in condition or "hour" in condition:
            return "Suggestion: Retry during allowed hours or request exception."
        else:
            return "Suggestion: Review policy requirements or contact administrator."

    def _is_rate_limited(self, rule: PolicyRule) -> bool:
        """Check if a rule is rate limited."""
        if not rule.limit:
            return False

        limit_key = rule.name
        limit_data = self._rate_limits.get(limit_key)

        if not limit_data:
            return False

        # Check if reset time passed
        if datetime.utcnow() > limit_data["reset_at"]:
            self._rate_limits[limit_key] = None
            return False

        # Parse limit (e.g., "100/hour")
        count, period = self._parse_limit(rule.limit)

        return limit_data["count"] >= count

    def _increment_rate_limit(self, rule: PolicyRule) -> None:
        """Increment rate limit counter."""
        if not rule.limit:
            return

        limit_key = rule.name
        count, period = self._parse_limit(rule.limit)

        if limit_key not in self._rate_limits or self._rate_limits[limit_key] is None:
            from datetime import timedelta
            self._rate_limits[limit_key] = {
                "count": 0,
                "reset_at": datetime.utcnow() + timedelta(seconds=period),
            }

        self._rate_limits[limit_key]["count"] += 1

    def _parse_limit(self, limit: str) -> tuple[int, int]:
        """Parse a limit string like '100/hour'."""
        parts = limit.split("/")
        count = int(parts[0])

        period_map = {
            "second": 1,
            "minute": 60,
            "hour": 3600,
            "day": 86400,
        }

        period = period_map.get(parts[1], 3600)
        return count, period

    def get_policy(self, name: str) -> Optional[Policy]:
        """Get a loaded policy by name.

        Args:
            name: Policy name.

        Returns:
            The ``Policy`` if found, otherwise ``None``.
        """
        return self._policies.get(name)

    def list_policies(self) -> list[str]:
        """List all loaded policy names.

        Returns:
            List of registered policy name strings.
        """
        return list(self._policies.keys())

    def remove_policy(self, name: str) -> bool:
        """Remove a policy from the engine.

        Args:
            name: Name of the policy to remove.

        Returns:
            ``True`` if the policy was found and removed, ``False`` otherwise.
        """
        if name in self._policies:
            del self._policies[name]
            return True
        return False

    # ── OPA/Rego integration ──────────────────────────────────

    def load_rego(self, rego_path: Optional[str] = None, rego_content: Optional[str] = None, package: str = "agentmesh") -> "OPAEvaluator":  # noqa: F821
        """
        Load a .rego file alongside YAML/JSON policies.

        The OPA evaluator runs in parallel: YAML rules are checked first,
        and if no rule matches, the Rego policy is consulted.

        Args:
            rego_path: Path to a .rego file
            rego_content: Inline Rego policy string
            package: Rego package name (used to build query path)

        Returns:
            OPAEvaluator instance for direct use
        """
        from agentmesh.governance.opa import OPAEvaluator
        evaluator = OPAEvaluator(mode="local", rego_path=rego_path, rego_content=rego_content)
        self._rego_evaluators.append((package, evaluator))
        return evaluator

    # ── Cedar integration ─────────────────────────────────────

    def load_cedar(
        self,
        cedar_path: Optional[str] = None,
        cedar_content: Optional[str] = None,
        entities: Optional[list] = None,
        mode: str = "auto",
    ) -> "CedarEvaluator":  # noqa: F821
        """
        Load a .cedar file alongside YAML/JSON and Rego policies.

        Cedar evaluators run after Rego: YAML rules first, then Rego,
        then Cedar, then defaults.

        Args:
            cedar_path: Path to a .cedar policy file
            cedar_content: Inline Cedar policy string
            entities: Cedar entities for authorization context
            mode: Evaluation mode (auto, cedarpy, cli, builtin)

        Returns:
            CedarEvaluator instance for direct use
        """
        from agentmesh.governance.cedar import CedarEvaluator
        evaluator = CedarEvaluator(
            mode=mode,
            policy_path=cedar_path,
            policy_content=cedar_content,
            entities=entities,
        )
        self._cedar_evaluators.append(evaluator)
        return evaluator

    def evaluate(
        self,
        agent_did: str,
        context: dict,
        stage: str = "pre_tool",
    ) -> PolicyDecision:
        """Evaluate all applicable policies for an agent action.

        Collects ALL matching rules across all applicable policies
        for the given lifecycle stage, then resolves conflicts using
        the configured strategy:

        - ``priority_first_match``: Highest-priority matching rule wins
          (v1.0 behavior).
        - ``deny_overrides``: Any deny wins, regardless of priority.
        - ``allow_overrides``: Any allow wins, regardless of priority.
        - ``most_specific_wins``: Agent-scoped > tenant > global;
          priority breaks ties within the same scope.

        Args:
            agent_did: Decentralized identifier of the acting agent.
            context: Runtime context dict describing the action.
            stage: Lifecycle stage to evaluate. One of ``"pre_input"``,
                ``"pre_tool"`` (default), ``"post_tool"``, ``"pre_output"``.
                Only rules matching this stage are evaluated.

        Returns:
            A ``PolicyDecision`` indicating whether the action is allowed
            and which rule (if any) matched.
        """
        from agentmesh.governance.conflict_resolution import (
            CandidateDecision,
            PolicyScope,
        )

        start = datetime.utcnow()

        # 1. Check YAML/JSON policies first
        applicable = [p for p in self._policies.values() if p.applies_to(agent_did)]

        if applicable:
            candidates: list[CandidateDecision] = []
            for policy in applicable:
                # Map policy scope string to enum
                try:
                    scope = PolicyScope(policy.scope)
                except ValueError:
                    scope = PolicyScope.GLOBAL

                for rule in policy.rules:
                    if rule.stage != stage:
                        continue  # skip rules for other stages
                    if rule.enabled and rule.evaluate(context):
                        candidates.append(CandidateDecision(
                            action=rule.action,
                            priority=rule.priority,
                            scope=scope,
                            policy_name=policy.name,
                            rule_name=rule.name,
                            reason=rule.description or f"Rule {rule.name} matched",
                            approvers=rule.approvers,
                        ))

            if candidates:
                result = self._resolver.resolve(candidates)
                winner = result.winning_decision
                elapsed = (datetime.utcnow() - start).total_seconds() * 1000

                # Apply rate limiting for the winning rule
                matched_rule = None
                for policy in applicable:
                    for rule in policy.rules:
                        if rule.name == winner.rule_name:
                            matched_rule = rule
                            break
                    if matched_rule:
                        break

                if matched_rule and matched_rule.limit:
                    if self._is_rate_limited(matched_rule):
                        return PolicyDecision(
                            allowed=False,
                            action="deny",
                            matched_rule=matched_rule.name,
                            policy_name=winner.policy_name,
                            reason=f"Rate limited: {matched_rule.limit}",
                            evaluated_at=start,
                            evaluation_ms=elapsed,
                        )

                return PolicyDecision(
                    allowed=(winner.action == "allow"),
                    action=winner.action,
                    matched_rule=winner.rule_name,
                    policy_name=winner.policy_name,
                    reason=winner.reason,
                    approvers=winner.approvers,
                    evaluated_at=start,
                    evaluation_ms=elapsed,
                )

        # 2. Authority resolution (trust-based narrowing)
        if self._authority_resolver is not None:
            from agentmesh.governance.authority import (
                ActionRequest,
                AuthorityRequest,
                DelegationInfo,
                TrustInfo,
            )
            delegation_info = DelegationInfo(
                agent_did=agent_did,
                delegated_capabilities=context.get("capabilities", []),
            )
            trust_info = TrustInfo(
                score=context.get("trust_score", 500),
                risk_level=context.get("risk_level", "medium"),
            )
            action_info = ActionRequest(
                action_type=context.get("action", {}).get("type", "unknown")
                if isinstance(context.get("action"), dict)
                else context.get("tool_name", "unknown"),
                tool_name=context.get("tool_name"),
                resource=context.get("resource"),
                requested_spend=context.get("requested_spend"),
            )
            authority_req = AuthorityRequest(
                delegation=delegation_info,
                trust=trust_info,
                action=action_info,
                context=context,
            )
            authority_decision = self._authority_resolver.resolve(authority_req)
            if authority_decision.decision == "deny":
                elapsed = (datetime.utcnow() - start).total_seconds() * 1000
                return PolicyDecision(
                    allowed=False,
                    action="deny",
                    reason=f"Authority resolver denied: {authority_decision.narrowing_reason or 'trust check failed'}",
                    evaluated_at=start,
                    evaluation_ms=elapsed,
                )
            if authority_decision.decision == "allow_narrowed":
                elapsed = (datetime.utcnow() - start).total_seconds() * 1000
                return PolicyDecision(
                    allowed=True,
                    action="allow",
                    reason=f"Authority resolver narrowed: {authority_decision.narrowing_reason}",
                    evaluated_at=start,
                    evaluation_ms=elapsed,
                    metadata={
                        "effective_scope": authority_decision.effective_scope,
                        "effective_spend_limit": authority_decision.effective_spend_limit,
                        "trust_tier": authority_decision.trust_tier,
                    },
                )

        # 3. Check Rego policies
        for package, evaluator in self._rego_evaluators:
            query = f"data.{package}.allow"
            opa_result = evaluator.evaluate(query, context)
            if opa_result.error is None:
                elapsed = (datetime.utcnow() - start).total_seconds() * 1000
                return PolicyDecision(
                    allowed=opa_result.allowed,
                    action="allow" if opa_result.allowed else "deny",
                    reason=f"OPA/Rego policy ({package}): {'allowed' if opa_result.allowed else 'denied'}",
                    evaluated_at=start,
                    evaluation_ms=elapsed,
                )

        # 4. Check Cedar policies
        for cedar_eval in self._cedar_evaluators:
            # Map context to Cedar action
            action_name = context.get("action", {}).get("type", context.get("tool_name", "unknown"))
            cedar_action = f'Action::"{action_name}"' if "::" not in action_name else action_name
            cedar_result = cedar_eval.evaluate(cedar_action, context)
            if cedar_result.error is None:
                elapsed = (datetime.utcnow() - start).total_seconds() * 1000
                return PolicyDecision(
                    allowed=cedar_result.allowed,
                    action="allow" if cedar_result.allowed else "deny",
                    reason=f"Cedar policy: {'allowed' if cedar_result.allowed else 'denied'}",
                    evaluated_at=start,
                    evaluation_ms=elapsed,
                )

        # 5. No rules matched - use default
        if applicable:
            default = applicable[0].default_action
        else:
            # V26: Fail-closed — no policies loaded means deny by default.
            # Operators must explicitly load an allow policy.
            default = "deny"

        elapsed = (datetime.utcnow() - start).total_seconds() * 1000
        return PolicyDecision(
            allowed=(default == "allow"),
            action=default,
            reason="No matching rules, using default" if applicable else "No policies loaded (deny by default)",
            evaluated_at=start,
            evaluation_ms=elapsed,
        )


# ── Schema versioning helpers ──────────────────────────────


def _validate_api_version(data: dict) -> None:
    """Validate and warn about the apiVersion field in a policy document.

    Args:
        data: Parsed policy dict (from YAML/JSON).

    Raises:
        ValueError: If the ``apiVersion`` is present but not recognized.
    """
    api_version = data.get("apiVersion")

    if api_version is None:
        # Legacy policy without apiVersion — treat as v1.0, inject current
        legacy_version = data.get("version", "1.0")
        if legacy_version in SUPPORTED_API_VERSIONS:
            info = SUPPORTED_API_VERSIONS[legacy_version]
            if info["status"] == "deprecated":
                warnings.warn(
                    f"Policy schema version '{legacy_version}' is deprecated. "
                    f"Add 'apiVersion: {info['migrate_to']}' to your policy file. "
                    f"See https://github.com/microsoft/agent-governance-toolkit/docs/policy-migration.md",
                    DeprecationWarning,
                    stacklevel=3,
                )
        data["apiVersion"] = CURRENT_API_VERSION
        return

    if api_version not in SUPPORTED_API_VERSIONS:
        raise ValueError(
            f"Unsupported policy apiVersion: '{api_version}'. "
            f"Supported versions: {list(SUPPORTED_API_VERSIONS.keys())}"
        )

    info = SUPPORTED_API_VERSIONS[api_version]
    if info["status"] == "deprecated":
        warnings.warn(
            f"Policy apiVersion '{api_version}' is deprecated. "
            f"Migrate to '{info['migrate_to']}'. "
            f"See https://github.com/microsoft/agent-governance-toolkit/docs/policy-migration.md",
            DeprecationWarning,
            stacklevel=3,
        )


def migrate_policy(yaml_content: str, target_version: str = CURRENT_API_VERSION) -> str:
    """Migrate a policy YAML document to the target schema version.

    Currently supports:
    - ``1.0`` → ``governance.toolkit/v1``: Adds ``apiVersion`` field.

    Args:
        yaml_content: Raw YAML policy string.
        target_version: Target apiVersion to migrate to.

    Returns:
        Updated YAML string with the new apiVersion.

    Raises:
        ValueError: If the target version is not supported.
    """
    if target_version not in SUPPORTED_API_VERSIONS:
        raise ValueError(f"Unknown target version: {target_version}")

    data = yaml.safe_load(yaml_content)
    current = data.get("apiVersion", data.get("version", "1.0"))

    if current == target_version:
        return yaml_content  # Already at target

    # Migration: 1.0 → governance.toolkit/v1
    if current == "1.0" and target_version == CURRENT_API_VERSION:
        data["apiVersion"] = CURRENT_API_VERSION
        if "version" in data:
            del data["version"]
        return yaml.dump(data, default_flow_style=False, sort_keys=False)

    logger.warning(
        "No migration path from '%s' to '%s'", current, target_version
    )
    return yaml_content


def validate_policy_schema(yaml_content: str) -> list[str]:
    """Validate a policy YAML document against its declared schema.

    Checks for required fields, valid values, and structural correctness.

    Args:
        yaml_content: Raw YAML policy string.

    Returns:
        List of validation error strings. Empty list means valid.
    """
    errors: list[str] = []
    try:
        data = yaml.safe_load(yaml_content)
    except yaml.YAMLError as e:
        return [f"YAML parse error: {e}"]

    if not isinstance(data, dict):
        return ["Policy must be a YAML mapping"]

    # Check apiVersion
    api_version = data.get("apiVersion", data.get("version", "1.0"))
    if api_version not in SUPPORTED_API_VERSIONS:
        errors.append(f"Unknown apiVersion: '{api_version}'")

    # Check required fields
    if "name" not in data:
        errors.append("Missing required field: 'name'")

    # Validate rules
    rules = data.get("rules", [])
    if not isinstance(rules, list):
        errors.append("'rules' must be a list")
    else:
        valid_actions = {"allow", "deny", "warn", "require_approval", "log"}
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                errors.append(f"Rule {i}: must be a mapping")
                continue
            if "name" not in rule:
                errors.append(f"Rule {i}: missing required field 'name'")
            if "condition" not in rule:
                errors.append(f"Rule {i}: missing required field 'condition'")
            action = rule.get("action", "deny")
            if action not in valid_actions:
                errors.append(
                    f"Rule {i} ('{rule.get('name', '?')}'): "
                    f"invalid action '{action}', must be one of {valid_actions}"
                )

    # Validate default_action
    default_action = data.get("default_action", "deny")
    if default_action not in ("allow", "deny"):
        errors.append(f"Invalid default_action: '{default_action}', must be 'allow' or 'deny'")

    return errors
