# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for cross-organizational federation governance (issue #93).

Covers:
- OrgPolicy model creation and YAML roundtrip
- OrgTrustAgreement lifecycle (creation, expiration, revocation)
- PolicyDelegation (category scoping, constraints)
- FederationEngine mutual enforcement
- Edge cases (same-org, missing policies, blocklists)
- ORGANIZATION scope in conflict resolution
"""

from datetime import datetime, timedelta, timezone

import pytest

from agentmesh.governance.federation import (
    DataClassification,
    FederationDecision,
    FederationEngine,
    InMemoryFederationStore,
    OrgPolicy,
    OrgPolicyDecision,
    OrgPolicyRule,
    OrgTrustAgreement,
    PolicyCategory,
    PolicyDelegation,
)


# ── Helpers ────────────────────────────────────────────────────


def _org_policy(
    org_id: str,
    rules: list[OrgPolicyRule] | None = None,
    default_action: str = "allow",
    blocked_orgs: list[str] | None = None,
    min_trust: int = 500,
) -> OrgPolicy:
    """Create a test OrgPolicy."""
    return OrgPolicy(
        org_id=org_id,
        org_name=f"Org {org_id}",
        rules=rules or [],
        default_action=default_action,
        blocked_orgs=blocked_orgs or [],
        required_min_trust_score=min_trust,
    )


def _pii_deny_rule() -> OrgPolicyRule:
    """Rule that denies PII-containing actions."""
    return OrgPolicyRule(
        name="block-pii-export",
        description="Block cross-org PII export",
        category=PolicyCategory.PII_HANDLING,
        condition="data.contains_pii",
        action="deny",
        priority=10,
    )


def _export_deny_rule() -> OrgPolicyRule:
    """Rule that denies data exports."""
    return OrgPolicyRule(
        name="block-export",
        description="Block data export",
        category=PolicyCategory.DATA_EXPORT,
        condition="action.type == 'export'",
        action="deny",
        priority=20,
    )


def _setup_engine(
    caller_policy: OrgPolicy | None = None,
    callee_policy: OrgPolicy | None = None,
    agreements: list[OrgTrustAgreement] | None = None,
    delegations: list[PolicyDelegation] | None = None,
) -> FederationEngine:
    """Set up a FederationEngine with pre-loaded data."""
    store = InMemoryFederationStore()
    if caller_policy:
        store.add_org_policy(caller_policy)
    if callee_policy:
        store.add_org_policy(callee_policy)
    for agmt in (agreements or []):
        store.add_trust_agreement(agmt)
    for deleg in (delegations or []):
        store.add_delegation(deleg)
    return FederationEngine(store=store)


# ── OrgPolicy Model Tests ─────────────────────────────────────


class TestOrgPolicy:
    """OrgPolicy model creation and evaluation."""

    def test_creation(self):
        policy = _org_policy("org-microsoft", rules=[_pii_deny_rule()])
        assert policy.org_id == "org-microsoft"
        assert policy.org_name == "Org org-microsoft"
        assert len(policy.rules) == 1
        assert policy.rules[0].category == PolicyCategory.PII_HANDLING

    def test_evaluate_deny(self):
        policy = _org_policy("org-a", rules=[_pii_deny_rule()])
        decision = policy.evaluate({"data": {"contains_pii": True}})
        assert decision.allowed is False
        assert decision.action == "deny"
        assert decision.matched_rule == "block-pii-export"
        assert decision.org_id == "org-a"

    def test_evaluate_allow_default(self):
        policy = _org_policy("org-a", rules=[_pii_deny_rule()], default_action="allow")
        decision = policy.evaluate({"data": {"contains_pii": False}})
        assert decision.allowed is True
        assert decision.action == "allow"

    def test_evaluate_deny_default(self):
        policy = _org_policy("org-a", rules=[], default_action="deny")
        decision = policy.evaluate({"some": "context"})
        assert decision.allowed is False

    def test_evaluate_priority_ordering(self):
        """Lower priority number wins."""
        high_prio = OrgPolicyRule(
            name="high-prio-allow",
            condition="data.contains_pii",
            action="allow",
            priority=1,
        )
        low_prio = OrgPolicyRule(
            name="low-prio-deny",
            condition="data.contains_pii",
            action="deny",
            priority=50,
        )
        policy = _org_policy("org-a", rules=[low_prio, high_prio])
        decision = policy.evaluate({"data": {"contains_pii": True}})
        assert decision.allowed is True
        assert decision.matched_rule == "high-prio-allow"

    def test_disabled_rule_skipped(self):
        rule = OrgPolicyRule(
            name="disabled-rule",
            condition="data.contains_pii",
            action="deny",
            enabled=False,
        )
        policy = _org_policy("org-a", rules=[rule], default_action="allow")
        decision = policy.evaluate({"data": {"contains_pii": True}})
        assert decision.allowed is True

    def test_yaml_roundtrip(self):
        policy = _org_policy("org-a", rules=[_pii_deny_rule(), _export_deny_rule()])
        yaml_str = policy.to_yaml()
        loaded = OrgPolicy.from_yaml(yaml_str)
        assert loaded.org_id == "org-a"
        assert len(loaded.rules) == 2
        assert loaded.rules[0].name == "block-pii-export"
        assert loaded.rules[1].name == "block-export"

    def test_data_classification_field(self):
        policy = OrgPolicy(
            org_id="org-a",
            max_data_classification=DataClassification.RESTRICTED,
        )
        assert policy.max_data_classification == DataClassification.RESTRICTED


# ── OrgTrustAgreement Tests ────────────────────────────────────


class TestOrgTrustAgreement:
    """Trust agreement lifecycle."""

    def test_creation_defaults(self):
        agmt = OrgTrustAgreement(org_a_id="org-a", org_b_id="org-b")
        assert agmt.is_active()
        assert agmt.mutual is True
        assert agmt.min_trust_score == 700
        assert agmt.agreement_id.startswith("agmt_")

    def test_covers_orgs_mutual(self):
        agmt = OrgTrustAgreement(org_a_id="org-a", org_b_id="org-b", mutual=True)
        assert agmt.covers_orgs("org-a", "org-b")
        assert agmt.covers_orgs("org-b", "org-a")  # bidirectional

    def test_covers_orgs_directional(self):
        agmt = OrgTrustAgreement(org_a_id="org-a", org_b_id="org-b", mutual=False)
        assert agmt.covers_orgs("org-a", "org-b")
        assert not agmt.covers_orgs("org-b", "org-a")  # one-way

    def test_expiration(self):
        expired = OrgTrustAgreement(
            org_a_id="org-a",
            org_b_id="org-b",
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        assert expired.is_active() is False

    def test_not_yet_expired(self):
        valid = OrgTrustAgreement(
            org_a_id="org-a",
            org_b_id="org-b",
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        assert valid.is_active() is True

    def test_revocation(self):
        agmt = OrgTrustAgreement(org_a_id="org-a", org_b_id="org-b")
        assert agmt.is_active()
        agmt.revoke("Trust breach detected")
        assert agmt.is_active() is False
        assert agmt.revocation_reason == "Trust breach detected"

    def test_covers_category(self):
        agmt = OrgTrustAgreement(
            org_a_id="org-a",
            org_b_id="org-b",
            trust_categories=[PolicyCategory.PII_HANDLING, PolicyCategory.DATA_EXPORT],
        )
        assert agmt.covers_category(PolicyCategory.PII_HANDLING)
        assert agmt.covers_category(PolicyCategory.DATA_EXPORT)
        assert not agmt.covers_category(PolicyCategory.COST_CONTROL)

    def test_general_category_covers_all(self):
        agmt = OrgTrustAgreement(
            org_a_id="org-a",
            org_b_id="org-b",
            trust_categories=[PolicyCategory.GENERAL],
        )
        assert agmt.covers_category(PolicyCategory.PII_HANDLING)
        assert agmt.covers_category(PolicyCategory.COST_CONTROL)


# ── PolicyDelegation Tests ─────────────────────────────────────


class TestPolicyDelegation:
    """Policy delegation model tests."""

    def test_creation(self):
        deleg = PolicyDelegation(
            source_org_id="org-a",
            target_org_id="org-b",
            delegated_categories=[PolicyCategory.PII_HANDLING],
        )
        assert deleg.is_active()
        assert deleg.delegation_id.startswith("deleg_")

    def test_covers_category(self):
        deleg = PolicyDelegation(
            source_org_id="org-a",
            target_org_id="org-b",
            delegated_categories=[PolicyCategory.PII_HANDLING],
        )
        assert deleg.covers_category(PolicyCategory.PII_HANDLING)
        assert not deleg.covers_category(PolicyCategory.DATA_EXPORT)

    def test_expiration(self):
        deleg = PolicyDelegation(
            source_org_id="org-a",
            target_org_id="org-b",
            delegated_categories=[PolicyCategory.GENERAL],
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        assert deleg.is_active() is False

    def test_constraints(self):
        deleg = PolicyDelegation(
            source_org_id="org-a",
            target_org_id="org-b",
            delegated_categories=[PolicyCategory.PII_HANDLING],
            constraints={"region": "EU"},
        )
        assert deleg.check_constraints({"region": "EU"})
        assert not deleg.check_constraints({"region": "US"})
        assert not deleg.check_constraints({})

    def test_revocation(self):
        deleg = PolicyDelegation(
            source_org_id="org-a",
            target_org_id="org-b",
            delegated_categories=[PolicyCategory.GENERAL],
        )
        assert deleg.is_active()
        deleg.active = False
        assert deleg.is_active() is False


# ── InMemoryFederationStore Tests ──────────────────────────────


class TestInMemoryFederationStore:
    """CRUD operations on the in-memory store."""

    def test_org_policy_crud(self):
        store = InMemoryFederationStore()
        policy = _org_policy("org-a")
        store.add_org_policy(policy)
        assert store.get_org_policy("org-a") is policy
        assert len(store.list_org_policies()) == 1
        assert store.remove_org_policy("org-a") is True
        assert store.get_org_policy("org-a") is None
        assert store.remove_org_policy("nonexistent") is False

    def test_trust_agreement_crud(self):
        store = InMemoryFederationStore()
        agmt = OrgTrustAgreement(org_a_id="org-a", org_b_id="org-b")
        store.add_trust_agreement(agmt)
        found = store.get_trust_agreements("org-a", "org-b")
        assert len(found) == 1
        assert found[0].agreement_id == agmt.agreement_id
        assert store.revoke_trust_agreement(agmt.agreement_id, "test")
        assert len(store.get_trust_agreements("org-a", "org-b")) == 0

    def test_delegation_crud(self):
        store = InMemoryFederationStore()
        deleg = PolicyDelegation(
            source_org_id="org-a",
            target_org_id="org-b",
            delegated_categories=[PolicyCategory.PII_HANDLING],
        )
        store.add_delegation(deleg)
        found = store.get_delegations("org-a", "org-b")
        assert len(found) == 1
        assert store.revoke_delegation(deleg.delegation_id)
        assert len(store.get_delegations("org-a", "org-b")) == 0


# ── FederationEngine Tests ─────────────────────────────────────


class TestFederationEngine:
    """Core mutual enforcement engine tests."""

    def test_same_org_bypasses_federation(self):
        engine = _setup_engine()
        result = engine.evaluate("org-a", "org-a", 800, {})
        assert result.allowed is True
        assert "federation bypassed" in result.trace[0].lower() or "same" in result.trace[0].lower()

    def test_no_trust_agreement_denied(self):
        engine = _setup_engine(
            caller_policy=_org_policy("org-a"),
            callee_policy=_org_policy("org-b"),
        )
        result = engine.evaluate("org-a", "org-b", 800, {})
        assert result.allowed is False
        assert "no trust agreement" in result.reason.lower()

    def test_mutual_enforcement_both_allow(self):
        engine = _setup_engine(
            caller_policy=_org_policy("org-a"),
            callee_policy=_org_policy("org-b"),
            agreements=[OrgTrustAgreement(org_a_id="org-a", org_b_id="org-b")],
        )
        result = engine.evaluate("org-a", "org-b", 800, {})
        assert result.allowed is True
        assert result.trust_agreement_id is not None

    def test_mutual_enforcement_caller_denies(self):
        engine = _setup_engine(
            caller_policy=_org_policy("org-a", rules=[_pii_deny_rule()]),
            callee_policy=_org_policy("org-b"),
            agreements=[OrgTrustAgreement(org_a_id="org-a", org_b_id="org-b")],
        )
        result = engine.evaluate("org-a", "org-b", 800, {"data": {"contains_pii": True}})
        assert result.allowed is False
        assert result.caller_decision is not None
        assert result.caller_decision.allowed is False

    def test_mutual_enforcement_callee_denies(self):
        engine = _setup_engine(
            caller_policy=_org_policy("org-a"),
            callee_policy=_org_policy("org-b", rules=[_export_deny_rule()]),
            agreements=[OrgTrustAgreement(org_a_id="org-a", org_b_id="org-b")],
        )
        result = engine.evaluate(
            "org-a", "org-b", 800, {"action": {"type": "export"}}
        )
        assert result.allowed is False
        assert result.callee_decision is not None
        assert result.callee_decision.allowed is False

    def test_mutual_enforcement_both_deny(self):
        engine = _setup_engine(
            caller_policy=_org_policy("org-a", rules=[_pii_deny_rule()]),
            callee_policy=_org_policy("org-b", rules=[_pii_deny_rule()]),
            agreements=[OrgTrustAgreement(org_a_id="org-a", org_b_id="org-b")],
        )
        result = engine.evaluate("org-a", "org-b", 800, {"data": {"contains_pii": True}})
        assert result.allowed is False

    def test_trust_score_below_threshold_denied(self):
        engine = _setup_engine(
            caller_policy=_org_policy("org-a"),
            callee_policy=_org_policy("org-b"),
            agreements=[OrgTrustAgreement(
                org_a_id="org-a", org_b_id="org-b", min_trust_score=800
            )],
        )
        result = engine.evaluate("org-a", "org-b", 600, {})
        assert result.allowed is False
        assert "trust score" in result.reason.lower()

    def test_trust_score_at_threshold_allowed(self):
        engine = _setup_engine(
            caller_policy=_org_policy("org-a", min_trust=700),
            callee_policy=_org_policy("org-b", min_trust=700),
            agreements=[OrgTrustAgreement(
                org_a_id="org-a", org_b_id="org-b", min_trust_score=700
            )],
        )
        result = engine.evaluate("org-a", "org-b", 700, {})
        assert result.allowed is True

    def test_expired_agreement_denied(self):
        engine = _setup_engine(
            caller_policy=_org_policy("org-a"),
            callee_policy=_org_policy("org-b"),
            agreements=[OrgTrustAgreement(
                org_a_id="org-a",
                org_b_id="org-b",
                expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
            )],
        )
        result = engine.evaluate("org-a", "org-b", 800, {})
        assert result.allowed is False
        assert "no trust agreement" in result.reason.lower()

    def test_blocklist_caller_blocks_callee(self):
        engine = _setup_engine(
            caller_policy=_org_policy("org-a", blocked_orgs=["org-b"]),
            callee_policy=_org_policy("org-b"),
            agreements=[OrgTrustAgreement(org_a_id="org-a", org_b_id="org-b")],
        )
        result = engine.evaluate("org-a", "org-b", 800, {})
        assert result.allowed is False
        assert "blocked" in result.reason.lower()

    def test_blocklist_callee_blocks_caller(self):
        engine = _setup_engine(
            caller_policy=_org_policy("org-a"),
            callee_policy=_org_policy("org-b", blocked_orgs=["org-a"]),
            agreements=[OrgTrustAgreement(org_a_id="org-a", org_b_id="org-b")],
        )
        result = engine.evaluate("org-a", "org-b", 800, {})
        assert result.allowed is False
        assert "blocked" in result.reason.lower()

    def test_missing_caller_policy_fail_closed(self):
        engine = _setup_engine(
            callee_policy=_org_policy("org-b"),
            agreements=[OrgTrustAgreement(org_a_id="org-a", org_b_id="org-b")],
        )
        result = engine.evaluate("org-a", "org-b", 800, {})
        assert result.allowed is False
        assert "no org policy" in result.reason.lower()

    def test_missing_callee_policy_fail_closed(self):
        engine = _setup_engine(
            caller_policy=_org_policy("org-a"),
            agreements=[OrgTrustAgreement(org_a_id="org-a", org_b_id="org-b")],
        )
        result = engine.evaluate("org-a", "org-b", 800, {})
        assert result.allowed is False

    def test_federation_decision_has_trace(self):
        engine = _setup_engine(
            caller_policy=_org_policy("org-a"),
            callee_policy=_org_policy("org-b"),
            agreements=[OrgTrustAgreement(org_a_id="org-a", org_b_id="org-b")],
        )
        result = engine.evaluate("org-a", "org-b", 800, {})
        assert len(result.trace) > 0
        assert any("cross-org" in t.lower() for t in result.trace)
        assert result.evaluated_at is not None


# ── Policy Delegation in Engine Tests ──────────────────────────


class TestFederationDelegation:
    """Delegation overrides in the federation engine."""

    def test_delegation_overrides_caller_deny(self):
        """When caller denies PII but has delegated PII to callee, allow."""
        engine = _setup_engine(
            caller_policy=_org_policy("org-a", rules=[_pii_deny_rule()]),
            callee_policy=_org_policy("org-b"),
            agreements=[OrgTrustAgreement(org_a_id="org-a", org_b_id="org-b")],
            delegations=[PolicyDelegation(
                source_org_id="org-a",
                target_org_id="org-b",
                delegated_categories=[PolicyCategory.PII_HANDLING],
            )],
        )
        result = engine.evaluate("org-a", "org-b", 800, {"data": {"contains_pii": True}})
        assert result.allowed is True
        assert len(result.delegations_applied) > 0

    def test_delegation_wrong_category_no_override(self):
        """Delegation for DATA_EXPORT doesn't help when PII is denied."""
        engine = _setup_engine(
            caller_policy=_org_policy("org-a", rules=[_pii_deny_rule()]),
            callee_policy=_org_policy("org-b"),
            agreements=[OrgTrustAgreement(org_a_id="org-a", org_b_id="org-b")],
            delegations=[PolicyDelegation(
                source_org_id="org-a",
                target_org_id="org-b",
                delegated_categories=[PolicyCategory.DATA_EXPORT],
            )],
        )
        result = engine.evaluate("org-a", "org-b", 800, {"data": {"contains_pii": True}})
        assert result.allowed is False
        assert len(result.delegations_applied) == 0

    def test_delegation_with_constraints_met(self):
        engine = _setup_engine(
            caller_policy=_org_policy("org-a", rules=[_pii_deny_rule()]),
            callee_policy=_org_policy("org-b"),
            agreements=[OrgTrustAgreement(org_a_id="org-a", org_b_id="org-b")],
            delegations=[PolicyDelegation(
                source_org_id="org-a",
                target_org_id="org-b",
                delegated_categories=[PolicyCategory.PII_HANDLING],
                constraints={"region": "EU"},
            )],
        )
        result = engine.evaluate(
            "org-a", "org-b", 800,
            {"data": {"contains_pii": True}, "region": "EU"},
        )
        assert result.allowed is True

    def test_delegation_with_constraints_not_met(self):
        engine = _setup_engine(
            caller_policy=_org_policy("org-a", rules=[_pii_deny_rule()]),
            callee_policy=_org_policy("org-b"),
            agreements=[OrgTrustAgreement(org_a_id="org-a", org_b_id="org-b")],
            delegations=[PolicyDelegation(
                source_org_id="org-a",
                target_org_id="org-b",
                delegated_categories=[PolicyCategory.PII_HANDLING],
                constraints={"region": "EU"},
            )],
        )
        result = engine.evaluate(
            "org-a", "org-b", 800,
            {"data": {"contains_pii": True}, "region": "US"},
        )
        assert result.allowed is False

    def test_expired_delegation_not_applied(self):
        engine = _setup_engine(
            caller_policy=_org_policy("org-a", rules=[_pii_deny_rule()]),
            callee_policy=_org_policy("org-b"),
            agreements=[OrgTrustAgreement(org_a_id="org-a", org_b_id="org-b")],
            delegations=[PolicyDelegation(
                source_org_id="org-a",
                target_org_id="org-b",
                delegated_categories=[PolicyCategory.PII_HANDLING],
                expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
            )],
        )
        result = engine.evaluate("org-a", "org-b", 800, {"data": {"contains_pii": True}})
        assert result.allowed is False


# ── ORGANIZATION Scope in Conflict Resolution ──────────────────


class TestOrganizationScope:
    """Verify ORGANIZATION scope ranks correctly in conflict resolution."""

    def test_organization_scope_exists(self):
        from agentmesh.governance.conflict_resolution import PolicyScope
        assert hasattr(PolicyScope, "ORGANIZATION")
        assert PolicyScope.ORGANIZATION.value == "organization"

    def test_organization_scope_specificity(self):
        from agentmesh.governance.conflict_resolution import (
            CandidateDecision,
            PolicyConflictResolver,
            ConflictResolutionStrategy,
            PolicyScope,
        )

        resolver = PolicyConflictResolver(
            ConflictResolutionStrategy.MOST_SPECIFIC_WINS
        )

        candidates = [
            CandidateDecision(
                action="deny",
                priority=10,
                scope=PolicyScope.GLOBAL,
                rule_name="global-deny",
            ),
            CandidateDecision(
                action="allow",
                priority=10,
                scope=PolicyScope.ORGANIZATION,
                rule_name="org-allow",
            ),
        ]

        result = resolver.resolve(candidates)
        assert result.winning_decision.rule_name == "org-allow"
        assert result.winning_decision.action == "allow"

    def test_agent_overrides_organization(self):
        from agentmesh.governance.conflict_resolution import (
            CandidateDecision,
            PolicyConflictResolver,
            ConflictResolutionStrategy,
            PolicyScope,
        )

        resolver = PolicyConflictResolver(
            ConflictResolutionStrategy.MOST_SPECIFIC_WINS
        )

        candidates = [
            CandidateDecision(
                action="allow",
                priority=10,
                scope=PolicyScope.ORGANIZATION,
                rule_name="org-allow",
            ),
            CandidateDecision(
                action="deny",
                priority=10,
                scope=PolicyScope.AGENT,
                rule_name="agent-deny",
            ),
        ]

        result = resolver.resolve(candidates)
        assert result.winning_decision.rule_name == "agent-deny"
        assert result.winning_decision.action == "deny"

    def test_full_specificity_chain(self):
        """AGENT > ORGANIZATION > TENANT > GLOBAL."""
        from agentmesh.governance.conflict_resolution import (
            CandidateDecision,
            PolicyScope,
        )

        scopes = [
            PolicyScope.GLOBAL,
            PolicyScope.TENANT,
            PolicyScope.ORGANIZATION,
            PolicyScope.AGENT,
        ]
        candidates = [
            CandidateDecision(
                action="deny", scope=s, rule_name=s.value, priority=0
            )
            for s in scopes
        ]
        specificities = [c.specificity for c in candidates]
        assert specificities == [0, 1, 2, 3]


# ── PolicyCategory Enum Tests ─────────────────────────────────


class TestPolicyCategory:
    """Verify the extensible category taxonomy."""

    def test_all_categories_exist(self):
        expected = {
            "pii_handling", "data_export", "data_retention",
            "cost_control", "model_safety", "audit_logging",
            "access_control", "compliance", "general",
        }
        actual = {c.value for c in PolicyCategory}
        assert expected == actual

    def test_category_string_roundtrip(self):
        cat = PolicyCategory("pii_handling")
        assert cat == PolicyCategory.PII_HANDLING
        assert cat.value == "pii_handling"


# ── Additional Edge-Case Tests ─────────────────────────────────


class TestMutualEnforcementBothDeny:
    """Verify that when BOTH orgs deny, both denial reasons appear in trace."""

    def test_both_deny_reasons_in_trace(self):
        """Both caller and callee deny — trace must contain both reasons."""
        engine = _setup_engine(
            caller_policy=_org_policy("org-a", rules=[_pii_deny_rule()]),
            callee_policy=_org_policy("org-b", rules=[_pii_deny_rule()]),
            agreements=[
                OrgTrustAgreement(org_a_id="org-a", org_b_id="org-b")
            ],
        )
        result = engine.evaluate(
            "org-a", "org-b", 800, {"data": {"contains_pii": True}}
        )
        assert result.allowed is False
        assert result.caller_decision is not None
        assert result.callee_decision is not None
        assert result.caller_decision.allowed is False
        assert result.callee_decision.allowed is False

        # Both denial reasons must appear in the merged reason/trace
        merged_trace = " ".join(result.trace)
        assert "org-a" in merged_trace
        assert "org-b" in merged_trace
        assert "caller" in result.reason.lower()
        assert "callee" in result.reason.lower()


class TestDelegationWithExpiredTrust:
    """Delegation should not help if the trust agreement is expired."""

    def test_delegation_with_expired_trust_agreement_fails(self):
        """Even with a valid delegation, an expired trust agreement → deny."""
        engine = _setup_engine(
            caller_policy=_org_policy("org-a", rules=[_pii_deny_rule()]),
            callee_policy=_org_policy("org-b"),
            agreements=[
                OrgTrustAgreement(
                    org_a_id="org-a",
                    org_b_id="org-b",
                    expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
                )
            ],
            delegations=[
                PolicyDelegation(
                    source_org_id="org-a",
                    target_org_id="org-b",
                    delegated_categories=[PolicyCategory.PII_HANDLING],
                )
            ],
        )
        result = engine.evaluate(
            "org-a", "org-b", 800, {"data": {"contains_pii": True}}
        )
        assert result.allowed is False
        assert "no trust agreement" in result.reason.lower()
        assert len(result.delegations_applied) == 0


class TestFileFederationStoreYamlYml:
    """FileFederationStore handles both .yaml and .yml without duplicates."""

    def test_yaml_and_yml_same_org_no_duplicate(self, tmp_path):
        """If org_a.yaml and org_a.yml both define 'org-a', store has one entry."""
        from agentmesh.governance.federation import FileFederationStore

        fed_dir = tmp_path / "federation"
        policies_dir = fed_dir / "org_policies"
        policies_dir.mkdir(parents=True)

        yaml_content = (
            "org_id: org-a\n"
            "org_name: Org A YAML\n"
            "default_action: allow\n"
            "rules: []\n"
        )
        yml_content = (
            "org_id: org-a\n"
            "org_name: Org A YML\n"
            "default_action: deny\n"
            "rules: []\n"
        )

        (policies_dir / "org_a.yaml").write_text(yaml_content)
        (policies_dir / "org_a.yml").write_text(yml_content)

        store = FileFederationStore(fed_dir)
        policies = store.list_org_policies()

        # Only one policy for org-a (no duplicates)
        assert len(policies) == 1
        assert policies[0].org_id == "org-a"
        # .yml is loaded second, so it overwrites .yaml
        assert policies[0].org_name == "Org A YML"

    def test_different_orgs_yaml_and_yml(self, tmp_path):
        """Different orgs in .yaml and .yml are both loaded."""
        from agentmesh.governance.federation import FileFederationStore

        fed_dir = tmp_path / "federation"
        policies_dir = fed_dir / "org_policies"
        policies_dir.mkdir(parents=True)

        (policies_dir / "org_a.yaml").write_text(
            "org_id: org-a\norg_name: A\ndefault_action: allow\nrules: []\n"
        )
        (policies_dir / "org_b.yml").write_text(
            "org_id: org-b\norg_name: B\ndefault_action: deny\nrules: []\n"
        )

        store = FileFederationStore(fed_dir)
        policies = store.list_org_policies()
        org_ids = {p.org_id for p in policies}

        assert len(policies) == 2
        assert org_ids == {"org-a", "org-b"}


class TestFederationEngineEmptyStore:
    """FederationEngine with an empty store (no policies, no agreements)."""

    def test_same_org_still_allowed_with_empty_store(self):
        """Same-org bypass works even with empty store."""
        engine = FederationEngine()
        result = engine.evaluate("org-a", "org-a", 800, {})
        assert result.allowed is True

    def test_cross_org_denied_with_empty_store(self):
        """Cross-org with no policies and no agreements → deny."""
        engine = FederationEngine()
        result = engine.evaluate("org-a", "org-b", 800, {})
        assert result.allowed is False
        assert "no trust agreement" in result.reason.lower()

    def test_empty_store_has_no_policies(self):
        """Verify the store is truly empty."""
        engine = FederationEngine()
        assert engine.store.list_org_policies() == []
        assert engine.store.list_trust_agreements() == []
        assert engine.store.list_delegations() == []


class TestOrganizationScopeOrdering:
    """ORGANIZATION scope must rank between AGENT and GLOBAL."""

    def test_organization_between_agent_and_global(self):
        """ORGANIZATION specificity is greater than GLOBAL, less than AGENT."""
        from agentmesh.governance.conflict_resolution import (
            CandidateDecision,
            PolicyScope,
        )

        global_c = CandidateDecision(
            action="deny", scope=PolicyScope.GLOBAL, rule_name="g", priority=0
        )
        org_c = CandidateDecision(
            action="deny", scope=PolicyScope.ORGANIZATION, rule_name="o", priority=0
        )
        agent_c = CandidateDecision(
            action="deny", scope=PolicyScope.AGENT, rule_name="a", priority=0
        )

        assert global_c.specificity < org_c.specificity < agent_c.specificity

    def test_organization_wins_over_global_in_resolver(self):
        """Resolver picks ORGANIZATION over GLOBAL at same priority."""
        from agentmesh.governance.conflict_resolution import (
            CandidateDecision,
            PolicyConflictResolver,
            ConflictResolutionStrategy,
            PolicyScope,
        )

        resolver = PolicyConflictResolver(
            ConflictResolutionStrategy.MOST_SPECIFIC_WINS
        )
        candidates = [
            CandidateDecision(
                action="deny",
                priority=10,
                scope=PolicyScope.GLOBAL,
                rule_name="global-deny",
            ),
            CandidateDecision(
                action="allow",
                priority=10,
                scope=PolicyScope.ORGANIZATION,
                rule_name="org-allow",
            ),
        ]
        result = resolver.resolve(candidates)
        assert result.winning_decision.rule_name == "org-allow"
