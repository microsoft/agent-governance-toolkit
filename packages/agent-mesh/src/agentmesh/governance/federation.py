# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Cross-Organizational Federation Governance.

Enables mutual policy enforcement, org-level trust establishment,
and policy delegation between organizations.

When agents from different organizations interact, the federation
engine evaluates **both** the caller's and callee's org policies,
checks for bilateral trust agreements, and resolves policy
delegations — ensuring the most restrictive decision wins.

Closes: https://github.com/microsoft/agent-governance-toolkit/issues/93
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Literal, Optional, Protocol, runtime_checkable

import yaml
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ── Policy Categories ──────────────────────────────────────────


class PolicyCategory(str, Enum):
    """Extensible taxonomy of governance categories.

    These categories scope what aspects of governance one organization
    may delegate to another.
    """

    PII_HANDLING = "pii_handling"
    DATA_EXPORT = "data_export"
    DATA_RETENTION = "data_retention"
    COST_CONTROL = "cost_control"
    MODEL_SAFETY = "model_safety"
    AUDIT_LOGGING = "audit_logging"
    ACCESS_CONTROL = "access_control"
    COMPLIANCE = "compliance"
    GENERAL = "general"


# ── Org Policy Model ───────────────────────────────────────────


class OrgPolicyRule(BaseModel):
    """A single rule within an organization policy.

    Attributes:
        name: Unique rule identifier.
        description: Human-readable description.
        category: Governance category this rule belongs to.
        condition: Condition expression (same syntax as PolicyRule).
        action: Action when the condition matches.
        priority: Evaluation priority (lower = higher priority).
        enabled: Whether this rule is active.
    """

    name: str = Field(..., description="Rule name")
    description: Optional[str] = Field(None)
    category: PolicyCategory = Field(
        default=PolicyCategory.GENERAL,
        description="Governance category this rule belongs to",
    )
    condition: str = Field(..., description="Condition expression")
    action: Literal["allow", "deny", "warn", "require_approval"] = Field(
        default="deny",
    )
    priority: int = Field(default=100)
    enabled: bool = Field(default=True)

    def evaluate(self, context: dict) -> bool:
        """Evaluate rule condition against context.

        Uses the same simple expression evaluation as the core
        ``PolicyRule``.  Supports ``==``, boolean attributes,
        ``and``/``or`` compound conditions.

        Args:
            context: Runtime context dict.

        Returns:
            ``True`` if enabled and the condition matches.
        """
        if not self.enabled:
            return False
        try:
            return _eval_expression(self.condition, context)
        except Exception:
            logger.debug(
                "OrgPolicyRule evaluation failed for '%s'",
                self.name,
                exc_info=True,
            )
            return False


class DataClassification(str, Enum):
    """Data classification levels for org policy constraints."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class OrgPolicy(BaseModel):
    """Organization-level policy document.

    Extends the governance pattern to organizational boundaries.  Each
    org can define rules that apply to **all** interactions involving
    its agents — both as caller and callee.

    Attributes:
        org_id: Unique organization identifier.
        org_name: Human-readable organization name.
        version: Policy version string.
        description: Optional description.
        rules: Ordered list of org-level policy rules.
        default_action: Fallback action when no rule matches.
        max_data_classification: Highest data classification
            allowed for cross-org transfers.
        required_min_trust_score: Minimum trust score required
            for any agent interacting with this org's agents.
        allowed_partner_orgs: Explicit allowlist of partner org
            IDs.  Empty list means ''trust agreements only''.
        blocked_orgs: Explicit blocklist of org IDs.
        created_at: When this policy was created.
        updated_at: When this policy was last modified.
    """

    org_id: str = Field(..., description="Organization identifier")
    org_name: str = Field(default="", description="Organization name")
    version: str = Field(default="1.0")
    description: Optional[str] = Field(None)

    rules: list[OrgPolicyRule] = Field(default_factory=list)
    default_action: Literal["allow", "deny"] = Field(default="deny")

    # Constraints
    max_data_classification: DataClassification = Field(
        default=DataClassification.INTERNAL,
        description="Highest data classification for cross-org transfers",
    )
    required_min_trust_score: int = Field(
        default=700,
        ge=0,
        le=1000,
        description="Minimum trust score for cross-org interaction",
    )

    # Org allowlist / blocklist
    allowed_partner_orgs: list[str] = Field(
        default_factory=list,
        description="Explicit allowlist of partner org IDs",
    )
    blocked_orgs: list[str] = Field(
        default_factory=list,
        description="Blocked org IDs — always deny",
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )

    def evaluate(self, context: dict) -> OrgPolicyDecision:
        """Evaluate all rules against the given context.

        Rules are sorted by priority (lower first = higher priority).
        The first matching rule wins.

        Args:
            context: Runtime context dict.

        Returns:
            An ``OrgPolicyDecision`` with the matched rule and action.
        """
        sorted_rules = sorted(
            [r for r in self.rules if r.enabled],
            key=lambda r: r.priority,
        )

        for rule in sorted_rules:
            if rule.evaluate(context):
                return OrgPolicyDecision(
                    allowed=(rule.action == "allow"),
                    action=rule.action,
                    matched_rule=rule.name,
                    org_id=self.org_id,
                    reason=rule.description or f"Rule '{rule.name}' matched",
                    category=rule.category,
                )

        return OrgPolicyDecision(
            allowed=(self.default_action == "allow"),
            action=self.default_action,
            matched_rule=None,
            org_id=self.org_id,
            reason="No rules matched, using org default",
            category=PolicyCategory.GENERAL,
        )

    @classmethod
    def from_yaml(cls, yaml_content: str) -> "OrgPolicy":
        """Load an OrgPolicy from a YAML string.

        Args:
            yaml_content: Raw YAML string.

        Returns:
            A fully-constructed ``OrgPolicy``.
        """
        data = yaml.safe_load(yaml_content)
        rules = []
        for rule_data in data.pop("rules", []):
            rules.append(OrgPolicyRule(**rule_data))
        data["rules"] = rules
        return cls(**data)

    def to_yaml(self) -> str:
        """Serialize this OrgPolicy to a YAML string.

        Returns:
            YAML-formatted policy document.
        """
        data = self.model_dump(mode="json", exclude_none=True)
        return yaml.dump(data, default_flow_style=False, sort_keys=False)


class OrgPolicyDecision(BaseModel):
    """Result of evaluating an org-level policy.

    Attributes:
        allowed: Whether the action is permitted.
        action: The action taken.
        matched_rule: Name of the matched rule (if any).
        org_id: Organization that produced this decision.
        reason: Human-readable explanation.
        category: Governance category of the matched rule.
    """

    allowed: bool
    action: str
    matched_rule: Optional[str] = None
    org_id: str = ""
    reason: str = ""
    category: PolicyCategory = PolicyCategory.GENERAL


# ── Org Trust Agreement ────────────────────────────────────────


class OrgTrustAgreement(BaseModel):
    """Bilateral trust agreement between two organizations.

    Establishes that org A and org B trust each other (or one-way)
    for specific governance categories, subject to constraints.

    Attributes:
        agreement_id: Unique identifier for this agreement.
        org_a_id: First organization.
        org_b_id: Second organization.
        trust_categories: Which governance categories this
            agreement covers.
        min_trust_score: Minimum agent trust score required for
            cross-org interaction under this agreement.
        mutual: If ``True``, enforcement is bidirectional.
            If ``False``, only org_a trusts org_b.
        max_data_classification: Highest data classification
            allowed under this agreement.
        created_at: When this agreement was established.
        expires_at: When this agreement expires.  ``None`` means
            no expiration.
        revoked: Whether this agreement has been revoked.
        revocation_reason: Reason for revocation, if applicable.
        verification_method: How this agreement was verified
            (e.g., ``"manual"``, ``"iatp_attestation"``).
    """

    agreement_id: str = Field(
        default_factory=lambda: f"agmt_{uuid.uuid4().hex[:16]}",
    )
    org_a_id: str = Field(..., description="First organization ID")
    org_b_id: str = Field(..., description="Second organization ID")

    trust_categories: list[PolicyCategory] = Field(
        default_factory=lambda: [PolicyCategory.GENERAL],
        description="Governance categories covered",
    )
    min_trust_score: int = Field(
        default=700,
        ge=0,
        le=1000,
        description="Minimum agent trust score",
    )
    mutual: bool = Field(
        default=True,
        description="Bidirectional trust",
    )
    max_data_classification: DataClassification = Field(
        default=DataClassification.INTERNAL,
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    expires_at: Optional[datetime] = Field(None)
    revoked: bool = Field(default=False)
    revocation_reason: Optional[str] = Field(None)

    verification_method: str = Field(
        default="manual",
        description="How this agreement was verified",
    )

    def is_active(self) -> bool:
        """Check if this agreement is active (not expired or revoked)."""
        if self.revoked:
            return False
        if self.expires_at and datetime.now(timezone.utc) > self.expires_at:
            return False
        return True

    def covers_orgs(self, org_a: str, org_b: str) -> bool:
        """Check if this agreement covers the given org pair.

        If ``mutual`` is ``True``, order doesn't matter.
        If ``False``, only org_a trusts org_b (directional).

        Args:
            org_a: Caller org ID.
            org_b: Callee org ID.

        Returns:
            ``True`` if the pair is covered.
        """
        if self.mutual:
            return {self.org_a_id, self.org_b_id} == {org_a, org_b}
        return self.org_a_id == org_a and self.org_b_id == org_b

    def covers_category(self, category: PolicyCategory) -> bool:
        """Check if a governance category is covered.

        Args:
            category: The category to check.

        Returns:
            ``True`` if the category is covered by this agreement.
        """
        if PolicyCategory.GENERAL in self.trust_categories:
            return True
        return category in self.trust_categories

    def revoke(self, reason: str) -> None:
        """Revoke this agreement."""
        self.revoked = True
        self.revocation_reason = reason


# ── Policy Delegation ──────────────────────────────────────────


class PolicyDelegation(BaseModel):
    """Policy delegation: org A accepts org B's governance attestation
    for specific categories.

    This enables one org to say: ''I trust that org B's governance
    is sufficient for PII handling — I don't need to re-evaluate
    PII rules for their agents.''

    Attributes:
        delegation_id: Unique identifier.
        source_org_id: Organization that delegates authority.
        target_org_id: Organization that receives delegation.
        delegated_categories: Governance categories being
            delegated.
        constraints: Additional constraints on the delegation
            (e.g., ``{"region": "EU"}`` restricts PII delegation
            to EU data only).
        created_at: When created.
        expires_at: When this delegation expires.
        active: Whether this delegation is active.
    """

    delegation_id: str = Field(
        default_factory=lambda: f"deleg_{uuid.uuid4().hex[:16]}",
    )
    source_org_id: str = Field(
        ..., description="Org that delegates authority"
    )
    target_org_id: str = Field(
        ..., description="Org that receives delegation"
    )
    delegated_categories: list[PolicyCategory] = Field(
        ..., description="Categories being delegated"
    )
    constraints: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional constraints",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    expires_at: Optional[datetime] = Field(None)
    active: bool = Field(default=True)

    def is_active(self) -> bool:
        """Check if delegation is active and not expired."""
        if not self.active:
            return False
        if self.expires_at and datetime.now(timezone.utc) > self.expires_at:
            return False
        return True

    def covers_category(self, category: PolicyCategory) -> bool:
        """Check if this delegation covers a category.

        Args:
            category: The category to check.

        Returns:
            ``True`` if the category is delegated.
        """
        return category in self.delegated_categories

    def check_constraints(self, context: dict) -> bool:
        """Verify that the context satisfies delegation constraints.

        Each constraint key must be present in the context with a
        matching value.

        Args:
            context: Runtime context dict.

        Returns:
            ``True`` if all constraints are satisfied.
        """
        for key, expected in self.constraints.items():
            actual = context.get(key)
            if actual != expected:
                return False
        return True


# ── Federation Decision ────────────────────────────────────────


class FederationDecision(BaseModel):
    """Result of a cross-organizational federation evaluation.

    Attributes:
        allowed: Whether the cross-org interaction is permitted.
        caller_decision: Decision from the caller org's policy.
        callee_decision: Decision from the callee org's policy.
        trust_agreement_id: ID of the applicable trust agreement.
        delegations_applied: IDs of delegations that were honored.
        reason: Human-readable summary.
        trace: Step-by-step trace of the evaluation logic.
        evaluated_at: Timestamp of evaluation.
    """

    allowed: bool
    caller_decision: Optional[OrgPolicyDecision] = None
    callee_decision: Optional[OrgPolicyDecision] = None
    trust_agreement_id: Optional[str] = None
    delegations_applied: list[str] = Field(default_factory=list)
    reason: str = ""
    trace: list[str] = Field(default_factory=list)
    evaluated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )


# ── Persistence Interface ─────────────────────────────────────


@runtime_checkable
class FederationStore(Protocol):
    """Interface for federation data persistence.

    Implementations may be file-based, SQL-backed, or in-memory.
    """

    def get_org_policy(self, org_id: str) -> Optional[OrgPolicy]: ...
    def get_trust_agreements(
        self, org_a: str, org_b: str
    ) -> list[OrgTrustAgreement]: ...
    def get_delegations(
        self, source_org: str, target_org: str
    ) -> list[PolicyDelegation]: ...


# ── In-Memory Federation Store ────────────────────────────────


class InMemoryFederationStore:
    """Simple in-memory federation store for development and testing.

    For production, implement ``FederationStore`` against a
    database or distributed config store.
    """

    def __init__(self) -> None:
        """Initialize empty in-memory stores for policies, agreements, and delegations."""
        self._org_policies: dict[str, OrgPolicy] = {}
        self._trust_agreements: list[OrgTrustAgreement] = []
        self._delegations: list[PolicyDelegation] = []

    # ── CRUD: Org Policies ─────────────────────────────────

    def add_org_policy(self, policy: OrgPolicy) -> None:
        """Register or update an org policy."""
        self._org_policies[policy.org_id] = policy
        logger.info(
            "Federation: registered org policy for '%s'",
            policy.org_id,
        )

    def remove_org_policy(self, org_id: str) -> bool:
        """Remove an org policy.  Returns True if found."""
        if org_id in self._org_policies:
            del self._org_policies[org_id]
            return True
        return False

    def get_org_policy(self, org_id: str) -> Optional[OrgPolicy]:
        """Retrieve an org policy by org ID."""
        return self._org_policies.get(org_id)

    def list_org_policies(self) -> list[OrgPolicy]:
        """List all registered org policies."""
        return list(self._org_policies.values())

    # ── CRUD: Trust Agreements ─────────────────────────────

    def add_trust_agreement(
        self, agreement: OrgTrustAgreement
    ) -> None:
        """Register a trust agreement."""
        self._trust_agreements.append(agreement)
        logger.info(
            "Federation: registered trust agreement '%s' "
            "between '%s' and '%s'",
            agreement.agreement_id,
            agreement.org_a_id,
            agreement.org_b_id,
        )

    def revoke_trust_agreement(
        self, agreement_id: str, reason: str
    ) -> bool:
        """Revoke a trust agreement by ID."""
        for agmt in self._trust_agreements:
            if agmt.agreement_id == agreement_id:
                agmt.revoke(reason)
                logger.info(
                    "Federation: revoked agreement '%s': %s",
                    agreement_id,
                    reason,
                )
                return True
        return False

    def get_trust_agreements(
        self, org_a: str, org_b: str
    ) -> list[OrgTrustAgreement]:
        """Find active trust agreements covering the given org pair."""
        return [
            a
            for a in self._trust_agreements
            if a.is_active() and a.covers_orgs(org_a, org_b)
        ]

    def list_trust_agreements(self) -> list[OrgTrustAgreement]:
        """List all trust agreements (active and revoked)."""
        return list(self._trust_agreements)

    # ── CRUD: Delegations ──────────────────────────────────

    def add_delegation(self, delegation: PolicyDelegation) -> None:
        """Register a policy delegation."""
        self._delegations.append(delegation)
        logger.info(
            "Federation: registered delegation '%s' "
            "from '%s' to '%s' for %s",
            delegation.delegation_id,
            delegation.source_org_id,
            delegation.target_org_id,
            [c.value for c in delegation.delegated_categories],
        )

    def revoke_delegation(self, delegation_id: str) -> bool:
        """Revoke a delegation by ID."""
        for d in self._delegations:
            if d.delegation_id == delegation_id:
                d.active = False
                return True
        return False

    def get_delegations(
        self, source_org: str, target_org: str
    ) -> list[PolicyDelegation]:
        """Find active delegations from source to target org."""
        return [
            d
            for d in self._delegations
            if d.is_active()
            and d.source_org_id == source_org
            and d.target_org_id == target_org
        ]

    def list_delegations(self) -> list[PolicyDelegation]:
        """List all delegations."""
        return list(self._delegations)


# ── Federation Engine ──────────────────────────────────────────


class FederationEngine:
    """Cross-organizational federation governance engine.

    Provides **mutual enforcement**: when agents from different
    organizations interact, both the caller's and callee's org
    policies are evaluated.  The most restrictive decision wins.

    The engine also handles:
    - Trust agreement lookup and validation
    - Policy delegation (org A accepts org B's governance
      attestation for category X)
    - Graceful fail-closed semantics (missing policy → deny)

    Args:
        store: Federation data store.  Defaults to
            ``InMemoryFederationStore()`` for development.
    """

    def __init__(
        self,
        store: Optional[InMemoryFederationStore] = None,
    ) -> None:
        """Initialize the federation engine with the given store.

        Args:
            store: Federation data store. Defaults to a new
                ``InMemoryFederationStore`` if not provided.
        """
        self.store = store or InMemoryFederationStore()

    # ── Primary evaluation ─────────────────────────────────

    def evaluate(
        self,
        caller_org_id: str,
        callee_org_id: str,
        caller_trust_score: int,
        context: dict,
    ) -> FederationDecision:
        """Evaluate a cross-organizational interaction.

        Steps:
        1. Same-org shortcut — bypass federation if same org.
        2. Check blocklists on both sides.
        3. Look up active trust agreements.
        4. Evaluate caller org policy (caller-side constraints).
        5. Evaluate callee org policy (callee-side constraints).
        6. Apply policy delegations (skip rules for delegated
           categories).
        7. Merge decisions — most restrictive wins.

        Args:
            caller_org_id: Organization ID of the calling agent.
            callee_org_id: Organization ID of the called agent.
            caller_trust_score: Trust score of the calling agent.
            context: Runtime context dict.

        Returns:
            A ``FederationDecision`` with the merged result.
        """
        trace: list[str] = []

        # ── 1. Same-org shortcut ───────────────────────────
        if caller_org_id == callee_org_id:
            trace.append(
                f"Same org ({caller_org_id}): federation bypassed"
            )
            return FederationDecision(
                allowed=True,
                reason="Same organization — federation not required",
                trace=trace,
            )

        trace.append(
            f"Cross-org interaction: {caller_org_id} → {callee_org_id}"
        )

        # ── 2. Load org policies ───────────────────────────
        caller_policy = self.store.get_org_policy(caller_org_id)
        callee_policy = self.store.get_org_policy(callee_org_id)

        # ── 3. Check blocklists ────────────────────────────
        if caller_policy and callee_org_id in caller_policy.blocked_orgs:
            trace.append(
                f"Caller org '{caller_org_id}' blocks '{callee_org_id}'"
            )
            return FederationDecision(
                allowed=False,
                reason=(
                    f"Organization '{callee_org_id}' is blocked by "
                    f"caller org '{caller_org_id}'"
                ),
                trace=trace,
            )

        if callee_policy and caller_org_id in callee_policy.blocked_orgs:
            trace.append(
                f"Callee org '{callee_org_id}' blocks '{caller_org_id}'"
            )
            return FederationDecision(
                allowed=False,
                reason=(
                    f"Organization '{caller_org_id}' is blocked by "
                    f"callee org '{callee_org_id}'"
                ),
                trace=trace,
            )

        # ── 4. Look up trust agreements ────────────────────
        agreements = self.store.get_trust_agreements(
            caller_org_id, callee_org_id
        )

        if not agreements:
            trace.append("No active trust agreement found")
            return FederationDecision(
                allowed=False,
                reason=(
                    f"No trust agreement between '{caller_org_id}' "
                    f"and '{callee_org_id}'"
                ),
                trace=trace,
            )

        agreement = agreements[0]  # Use first active agreement
        trace.append(
            f"Trust agreement found: {agreement.agreement_id}"
        )

        # ── 5. Check trust score ───────────────────────────
        effective_min = max(
            agreement.min_trust_score,
            caller_policy.required_min_trust_score
            if caller_policy
            else 0,
            callee_policy.required_min_trust_score
            if callee_policy
            else 0,
        )

        if caller_trust_score < effective_min:
            trace.append(
                f"Trust score {caller_trust_score} < "
                f"minimum {effective_min}"
            )
            return FederationDecision(
                allowed=False,
                trust_agreement_id=agreement.agreement_id,
                reason=(
                    f"Agent trust score ({caller_trust_score}) below "
                    f"minimum ({effective_min}) for cross-org interaction"
                ),
                trace=trace,
            )

        trace.append(
            f"Trust score {caller_trust_score} ≥ {effective_min}: OK"
        )

        # ── 6. Evaluate org policies (mutual enforcement) ──
        caller_decision = None
        callee_decision = None
        delegations_applied: list[str] = []

        # Caller org policy
        if caller_policy:
            # Check for delegations from caller to callee
            delegations = self.store.get_delegations(
                caller_org_id, callee_org_id
            )
            caller_decision = caller_policy.evaluate(context)
            trace.append(
                f"Caller org policy '{caller_org_id}': "
                f"{caller_decision.action} "
                f"(rule: {caller_decision.matched_rule})"
            )

            # If caller denies but the category is delegated,
            # override to allow
            if (
                not caller_decision.allowed
                and delegations
            ):
                for deleg in delegations:
                    if (
                        deleg.covers_category(caller_decision.category)
                        and deleg.check_constraints(context)
                    ):
                        trace.append(
                            f"Delegation '{deleg.delegation_id}' "
                            f"overrides caller deny for "
                            f"'{caller_decision.category.value}'"
                        )
                        caller_decision = OrgPolicyDecision(
                            allowed=True,
                            action="allow",
                            matched_rule=caller_decision.matched_rule,
                            org_id=caller_org_id,
                            reason=(
                                f"Delegated to '{callee_org_id}' "
                                f"for '{caller_decision.category.value}'"
                            ),
                            category=caller_decision.category,
                        )
                        delegations_applied.append(
                            deleg.delegation_id
                        )
                        break
        else:
            # No caller policy → fail-closed
            trace.append(
                f"No org policy for caller '{caller_org_id}': "
                f"fail-closed (deny)"
            )
            caller_decision = OrgPolicyDecision(
                allowed=False,
                action="deny",
                org_id=caller_org_id,
                reason=(
                    f"No org policy defined for '{caller_org_id}'"
                ),
            )

        # Callee org policy
        if callee_policy:
            callee_decision = callee_policy.evaluate(context)
            trace.append(
                f"Callee org policy '{callee_org_id}': "
                f"{callee_decision.action} "
                f"(rule: {callee_decision.matched_rule})"
            )
        else:
            trace.append(
                f"No org policy for callee '{callee_org_id}': "
                f"fail-closed (deny)"
            )
            callee_decision = OrgPolicyDecision(
                allowed=False,
                action="deny",
                org_id=callee_org_id,
                reason=(
                    f"No org policy defined for '{callee_org_id}'"
                ),
            )

        # ── 7. Merge: most restrictive wins ────────────────
        both_allowed = (
            caller_decision.allowed and callee_decision.allowed
        )

        if both_allowed:
            reason = (
                f"Both orgs allow: "
                f"caller='{caller_org_id}', callee='{callee_org_id}'"
            )
            trace.append("Merged result: ALLOWED (both orgs allow)")
        else:
            deny_reasons = []
            if not caller_decision.allowed:
                deny_reasons.append(
                    f"caller '{caller_org_id}': {caller_decision.reason}"
                )
            if not callee_decision.allowed:
                deny_reasons.append(
                    f"callee '{callee_org_id}': {callee_decision.reason}"
                )
            reason = (
                "Cross-org interaction denied — " + "; ".join(deny_reasons)
            )
            trace.append(
                f"Merged result: DENIED ({'; '.join(deny_reasons)})"
            )

        return FederationDecision(
            allowed=both_allowed,
            caller_decision=caller_decision,
            callee_decision=callee_decision,
            trust_agreement_id=agreement.agreement_id,
            delegations_applied=delegations_applied,
            reason=reason,
            trace=trace,
        )


# ── File-based Federation Store ────────────────────────────────


class FileFederationStore(InMemoryFederationStore):
    """File-based federation store that loads from a directory.

    Expected directory structure::

        federation/
        ├── org_policies/
        │   ├── org_a.yaml
        │   └── org_b.yaml
        ├── trust_agreements.yaml
        └── delegations.yaml

    Falls back to in-memory storage for trust agreements and
    delegations if the YAML files are not present.

    Args:
        directory: Path to the federation config directory.
    """

    def __init__(self, directory: str | Path) -> None:
        """Initialize and load federation data from the given directory.

        Args:
            directory: Path to the federation config directory containing
                ``org_policies/``, ``trust_agreements.yaml``, and
                ``delegations.yaml``.
        """
        super().__init__()
        self._directory = Path(directory)
        self._load()

    def _load(self) -> None:
        """Load federation data from the directory."""
        # Load org policies
        policies_dir = self._directory / "org_policies"
        if policies_dir.is_dir():
            for yaml_file in sorted(policies_dir.glob("*.yaml")):
                with open(yaml_file) as f:
                    policy = OrgPolicy.from_yaml(f.read())
                    self.add_org_policy(policy)
            for yml_file in sorted(policies_dir.glob("*.yml")):
                with open(yml_file) as f:
                    policy = OrgPolicy.from_yaml(f.read())
                    self.add_org_policy(policy)

        # Load trust agreements
        agmt_file = self._directory / "trust_agreements.yaml"
        if agmt_file.is_file():
            with open(agmt_file) as f:
                data = yaml.safe_load(f)
                for agmt_data in data.get("agreements", []):
                    # Convert category strings to enums
                    if "trust_categories" in agmt_data:
                        agmt_data["trust_categories"] = [
                            PolicyCategory(c)
                            for c in agmt_data["trust_categories"]
                        ]
                    if "max_data_classification" in agmt_data:
                        agmt_data["max_data_classification"] = (
                            DataClassification(
                                agmt_data["max_data_classification"]
                            )
                        )
                    self.add_trust_agreement(
                        OrgTrustAgreement(**agmt_data)
                    )

        # Load delegations
        deleg_file = self._directory / "delegations.yaml"
        if deleg_file.is_file():
            with open(deleg_file) as f:
                data = yaml.safe_load(f)
                for deleg_data in data.get("delegations", []):
                    if "delegated_categories" in deleg_data:
                        deleg_data["delegated_categories"] = [
                            PolicyCategory(c)
                            for c in deleg_data["delegated_categories"]
                        ]
                    self.add_delegation(
                        PolicyDelegation(**deleg_data)
                    )


# ── Expression evaluator (reuses PolicyRule patterns) ──────────


def _eval_expression(expr: str, context: dict) -> bool:
    """Evaluate a simple policy expression.

    Supports the same syntax as ``PolicyRule._eval_expression``:
    - ``field == 'value'``
    - ``field`` (boolean truthy)
    - ``expr1 and expr2``
    - ``expr1 or expr2``
    """
    import re

    # OR
    if " or " in expr:
        parts = expr.split(" or ")
        return any(_eval_expression(p.strip(), context) for p in parts)

    # AND
    if " and " in expr:
        parts = expr.split(" and ")
        return all(_eval_expression(p.strip(), context) for p in parts)

    # Equality: field == 'value'
    eq_match = re.match(
        r"(\w+(?:\.\w+)*)\s*==\s*['\"]([^'\"]+)['\"]", expr
    )
    if eq_match:
        path, value = eq_match.groups()
        actual = _get_nested(context, path)
        return actual == value

    # Boolean
    bool_match = re.match(r"^(\w+(?:\.\w+)*)$", expr)
    if bool_match:
        path = bool_match.group(1)
        return bool(_get_nested(context, path))

    return False


def _get_nested(obj: dict, path: str) -> Any:
    """Resolve a dot-notated path against a dict."""
    parts = path.split(".")
    current: Any = obj
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


# ── Public API ─────────────────────────────────────────────────

__all__ = [
    "PolicyCategory",
    "OrgPolicyRule",
    "DataClassification",
    "OrgPolicy",
    "OrgPolicyDecision",
    "OrgTrustAgreement",
    "PolicyDelegation",
    "FederationDecision",
    "FederationStore",
    "InMemoryFederationStore",
    "FileFederationStore",
    "FederationEngine",
]
