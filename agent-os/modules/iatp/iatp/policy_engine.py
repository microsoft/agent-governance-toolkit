# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
IATP Policy Engine - Protocol Layer Policy Validation.

This module provides policy validation for IATP capability manifests
using a standalone, protocol-native implementation.

Design Note: IATP is Layer 2 (Infrastructure/Protocol). It defines the
message format, handshake protocols, and trust scores. Higher layers
(like agent-control-plane) USE this protocol; this protocol does NOT
depend on them.
"""
from typing import Any, Dict, List, Optional, Protocol, Tuple, runtime_checkable

from iatp.models import CapabilityManifest, ReversibilityLevel


@runtime_checkable
class PolicyEvaluator(Protocol):
    """
    Protocol class for policy evaluation.

    This allows duck typing for any policy evaluator implementation
    without requiring a specific import.
    """

    def evaluate(self, context: Dict[str, Any]) -> str:
        """Evaluate context and return action: 'allow', 'warn', or 'deny'."""
        ...


class PolicyRule:
    """
    A single policy rule for manifest validation.

    Rules are evaluated in order and the first matching rule determines
    the action. Actions can be 'allow', 'warn', or 'deny'.
    """

    def __init__(
        self,
        name: str,
        action: str,
        conditions: Dict[str, List[Any]],
        description: str = ""
    ):
        """
        Initialize a policy rule.

        Args:
            name: Rule identifier
            action: Action to take ('allow', 'warn', 'deny')
            conditions: Dictionary mapping field names to allowed values
            description: Human-readable description
        """
        self.name = name
        self.action = action
        self.conditions = conditions
        self.description = description

    def matches(self, context: Dict[str, Any]) -> bool:
        """
        Check if this rule matches the given context.

        Args:
            context: Policy evaluation context

        Returns:
            True if any condition matches
        """
        for key, values in self.conditions.items():
            if key in context and context[key] in values:
                return True
        return False


class IATPPolicyEngine:
    """
    IATP Policy Engine for capability manifest validation.

    This is a protocol-native policy engine that validates incoming
    agent manifests against configurable policy rules. It uses the
    IATP trust scoring algorithm and provides warn/block decisions.

    The engine is designed to be:
    - Self-contained (no external dependencies beyond IATP models)
    - Extensible (custom rules can be added)
    - Protocol-compliant (follows IATP trust semantics)
    """

    def __init__(self):
        """Initialize the IATP Policy Engine."""
        self.rules: List[PolicyRule] = []
        self._setup_default_policies()

    def _setup_default_policies(self):
        """Setup default security policies for IATP."""
        # Default IATP policy rules
        # These augment (not replace) the SecurityValidator checks
        self.rules = [
            PolicyRule(
                name="WarnUntrustedAgent",
                description="Warn when agents are marked as untrusted",
                action="warn",
                conditions={"trust_level": ["untrusted"]}
            ),
            PolicyRule(
                name="RequireReversibility",
                description="Warn when agents don't support reversibility",
                action="warn",
                conditions={"reversibility": ["none"]}
            ),
            PolicyRule(
                name="AllowEphemeral",
                description="Allow agents with ephemeral data retention",
                action="allow",
                conditions={"retention_policy": ["ephemeral"]}
            ),
        ]

    def add_custom_rule(self, rule: Dict[str, Any]):
        """
        Add a custom policy rule.

        Args:
            rule: Dictionary defining the policy rule with keys:
                - name: Rule name
                - description: Rule description (optional)
                - action: "allow", "warn", or "deny"
                - conditions: Dictionary of conditions to match
        """
        policy_rule = PolicyRule(
            name=rule.get("name", "CustomRule"),
            action=rule.get("action", "warn"),
            conditions=rule.get("conditions", {}),
            description=rule.get("description", "")
        )
        # Insert at beginning so custom rules take precedence
        self.rules.insert(0, policy_rule)

    def validate_manifest(
        self,
        manifest: CapabilityManifest
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Validate a capability manifest against policies.

        This is the main integration point that validates incoming
        agent manifests against the configured policy rules.

        Args:
            manifest: The capability manifest to validate

        Returns:
            Tuple of (is_allowed, error_message, warning_message)
            - is_allowed: True if request should proceed
            - error_message: Blocking error if is_allowed is False
            - warning_message: Warning for user if there are concerns
        """
        # Convert manifest to policy context
        context = self._manifest_to_context(manifest)

        # Evaluate against policy rules
        action = self._evaluate_rules(context)

        # Generate appropriate response
        if action == "deny":
            return False, self._generate_deny_message(manifest, context), None
        elif action == "warn":
            return True, None, self._generate_warn_message(manifest, context)
        else:  # allow
            return True, None, None

    def _evaluate_rules(self, context: Dict[str, Any]) -> str:
        """
        Evaluate policy rules against context.

        Args:
            context: Policy evaluation context

        Returns:
            Action string: "allow", "warn", or "deny"
        """
        for rule in self.rules:
            if rule.matches(context):
                return rule.action

        # Default to allow if no rules match
        return "allow"

    def _manifest_to_context(self, manifest: CapabilityManifest) -> Dict[str, Any]:
        """
        Convert a capability manifest to a policy evaluation context.

        Args:
            manifest: The capability manifest

        Returns:
            Dictionary context for policy evaluation
        """
        return {
            "agent_id": manifest.agent_id,
            "trust_level": manifest.trust_level.value,
            "retention_policy": manifest.privacy_contract.retention.value,
            "reversibility": manifest.capabilities.reversibility.value,
            "idempotency": manifest.capabilities.idempotency,
            "human_review": manifest.privacy_contract.human_review,
            "encryption_at_rest": manifest.privacy_contract.encryption_at_rest,
            "encryption_in_transit": manifest.privacy_contract.encryption_in_transit,
            "scopes": manifest.scopes,
        }

    def _generate_deny_message(
        self,
        manifest: CapabilityManifest,
        context: Dict[str, Any]
    ) -> str:
        """
        Generate a denial message for blocked requests.

        Args:
            manifest: The capability manifest
            context: Policy context

        Returns:
            User-friendly error message
        """
        reasons = []

        if context["retention_policy"] in ["permanent", "forever"]:
            reasons.append(
                f"Agent '{manifest.agent_id}' stores data permanently, "
                "which violates privacy policies"
            )

        if context["trust_level"] == "untrusted":
            reasons.append(
                f"Agent '{manifest.agent_id}' is marked as untrusted"
            )

        if reasons:
            return "Policy Violation: " + "; ".join(reasons)

        return f"Policy Violation: Agent '{manifest.agent_id}' failed policy validation"

    def _generate_warn_message(
        self,
        manifest: CapabilityManifest,
        context: Dict[str, Any]
    ) -> str:
        """
        Generate a warning message for risky requests.

        Args:
            manifest: The capability manifest
            context: Policy context

        Returns:
            User-friendly warning message
        """
        warnings = []

        if context["reversibility"] == "none":
            warnings.append(
                f"Agent '{manifest.agent_id}' does not support transaction reversal"
            )

        if not context["idempotency"]:
            warnings.append(
                f"Agent '{manifest.agent_id}' may not handle duplicate requests safely"
            )

        if context["human_review"]:
            warnings.append(
                f"Agent '{manifest.agent_id}' may have humans review your data"
            )

        if warnings:
            return "⚠️  Policy Warning:\n" + "\n".join(f"  • {w}" for w in warnings)

        return None

    def validate_handshake(
        self,
        manifest: CapabilityManifest,
        required_capabilities: Optional[List[str]] = None,
        required_scopes: Optional[List[str]] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate handshake compatibility between agents.

        This checks if the remote agent's capabilities meet the
        local agent's requirements.

        Args:
            manifest: Remote agent's capability manifest
            required_capabilities: List of required capability keys
            required_scopes: List of required RBAC scopes (e.g., ['repo:write'])

        Returns:
            Tuple of (is_compatible, error_message)
        """
        if not required_capabilities:
            required_capabilities = []
        if not required_scopes:
            required_scopes = []

        # Always validate against base policies first
        is_allowed, error_msg, _ = self.validate_manifest(manifest)
        if not is_allowed:
            return False, error_msg

        # Check specific capability requirements
        missing = []
        for capability in required_capabilities:
            if capability == "reversibility" and \
               manifest.capabilities.reversibility == ReversibilityLevel.NONE:
                missing.append("reversibility support")
            elif capability == "idempotency" and \
                 not manifest.capabilities.idempotency:
                missing.append("idempotency support")

        if missing:
            return False, f"Agent missing required capabilities: {', '.join(missing)}"

        # Check RBAC scope requirements
        missing_scopes = []
        agent_scopes = set(manifest.scopes)
        for scope in required_scopes:
            if scope not in agent_scopes:
                missing_scopes.append(scope)

        if missing_scopes:
            return False, f"Agent missing required scopes: {', '.join(missing_scopes)}"

        return True, None
