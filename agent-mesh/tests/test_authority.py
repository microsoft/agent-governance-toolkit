# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for AuthorityResolver protocol and related types."""

from __future__ import annotations

import pytest

from agentmesh.governance.authority import (
    ActionRequest,
    AuthorityDecision,
    AuthorityRequest,
    AuthorityResolver,
    DefaultAuthorityResolver,
    DelegationInfo,
    TrustInfo,
)
from agentmesh.events.bus import (
    EVENT_TRUST_SCORE_CHANGED,
    EVENT_AUTHORITY_RESOLVED,
    ALL_EVENT_TYPES,
    Event,
    InMemoryEventBus,
)
from agentmesh.identity.agent_id import AgentIdentity


# ── AuthorityDecision Tests ───────────────────────────────────


class TestAuthorityDecision:
    def test_allow_decision(self):
        d = AuthorityDecision(
            decision="allow",
            effective_scope=["read:data", "write:reports"],
            trust_tier="trusted",
        )
        assert d.decision == "allow"
        assert d.effective_scope == ["read:data", "write:reports"]
        assert d.narrowing_reason is None

    def test_allow_narrowed_decision(self):
        d = AuthorityDecision(
            decision="allow_narrowed",
            effective_scope=["read:data"],
            effective_spend_limit=100.0,
            narrowing_reason="Trust tier 'standard' caps spend at $100",
            trust_tier="standard",
        )
        assert d.decision == "allow_narrowed"
        assert d.effective_spend_limit == 100.0
        assert d.narrowing_reason is not None

    def test_deny_decision(self):
        d = AuthorityDecision(
            decision="deny",
            trust_tier="untrusted",
            narrowing_reason="Trust score below minimum for this action",
        )
        assert d.decision == "deny"

    def test_audit_decision(self):
        d = AuthorityDecision(decision="audit", trust_tier="standard")
        assert d.decision == "audit"

    def test_timestamp_auto_set(self):
        d = AuthorityDecision(decision="allow")
        assert d.timestamp is not None

    def test_matched_invariants(self):
        d = AuthorityDecision(
            decision="allow_narrowed",
            matched_invariants=["invariant_1_monotonic_narrowing", "invariant_3_trust_tier_cap"],
        )
        assert len(d.matched_invariants) == 2


# ── AuthorityRequest Tests ────────────────────────────────────


class TestAuthorityRequest:
    def test_build_complete_request(self):
        req = AuthorityRequest(
            delegation=DelegationInfo(
                agent_did="did:mesh:agent-1",
                parent_did="did:mesh:root",
                delegation_depth=1,
                delegated_capabilities=["read:data", "write:reports", "admin:observability"],
                chain_verified=True,
            ),
            trust=TrustInfo(
                score=750,
                risk_level="low",
                identity_score=80,
                behavior_score=70,
            ),
            action=ActionRequest(
                action_type="tool_call",
                tool_name="export_data",
                resource="dataset-A",
                requested_spend=250.0,
            ),
        )
        assert req.delegation.agent_did == "did:mesh:agent-1"
        assert req.trust.score == 750
        assert req.action.requested_spend == 250.0

    def test_delegation_info_defaults(self):
        d = DelegationInfo(agent_did="did:mesh:new-agent")
        assert d.delegation_depth == 0
        assert d.parent_did is None
        assert d.delegated_capabilities == []

    def test_trust_info_defaults(self):
        t = TrustInfo()
        assert t.score == 500
        assert t.risk_level == "medium"


# ── AuthorityResolver Protocol Tests ──────────────────────────


class TestAuthorityResolverProtocol:
    def test_default_resolver_allows_everything(self):
        resolver = DefaultAuthorityResolver()
        req = AuthorityRequest(
            delegation=DelegationInfo(
                agent_did="did:mesh:test",
                delegated_capabilities=["read:data"],
            ),
            trust=TrustInfo(score=500),
            action=ActionRequest(action_type="tool_call"),
        )
        decision = resolver.resolve(req)
        assert decision.decision == "allow"
        assert decision.effective_scope == ["read:data"]

    def test_default_resolver_implements_protocol(self):
        resolver = DefaultAuthorityResolver()
        assert isinstance(resolver, AuthorityResolver)

    def test_custom_resolver_implements_protocol(self):
        """Custom classes that implement resolve() satisfy the protocol."""

        class StrictResolver:
            def resolve(self, request: AuthorityRequest) -> AuthorityDecision:
                if request.trust.score < 700:
                    return AuthorityDecision(
                        decision="deny",
                        trust_tier="restricted",
                        narrowing_reason="Trust score below 700",
                    )
                return AuthorityDecision(
                    decision="allow",
                    effective_scope=request.delegation.delegated_capabilities,
                    trust_tier="trusted",
                )

        resolver = StrictResolver()
        assert isinstance(resolver, AuthorityResolver)

        # Low trust → deny
        low_trust_req = AuthorityRequest(
            delegation=DelegationInfo(agent_did="a", delegated_capabilities=["read:*"]),
            trust=TrustInfo(score=400),
            action=ActionRequest(action_type="tool_call"),
        )
        assert resolver.resolve(low_trust_req).decision == "deny"

        # High trust → allow
        high_trust_req = AuthorityRequest(
            delegation=DelegationInfo(agent_did="a", delegated_capabilities=["read:*"]),
            trust=TrustInfo(score=800),
            action=ActionRequest(action_type="tool_call"),
        )
        assert resolver.resolve(high_trust_req).decision == "allow"

    def test_narrowing_resolver(self):
        """Resolver that narrows capabilities based on trust tier."""

        class NarrowingResolver:
            def resolve(self, request: AuthorityRequest) -> AuthorityDecision:
                caps = request.delegation.delegated_capabilities
                if request.trust.score < 600:
                    # Restrict to read-only
                    narrowed = [c for c in caps if c.startswith("read:")]
                    return AuthorityDecision(
                        decision="allow_narrowed",
                        effective_scope=narrowed,
                        trust_tier="restricted",
                        narrowing_reason="Low trust: read-only access",
                    )
                return AuthorityDecision(
                    decision="allow",
                    effective_scope=caps,
                    trust_tier="trusted",
                )

        resolver = NarrowingResolver()
        req = AuthorityRequest(
            delegation=DelegationInfo(
                agent_did="a",
                delegated_capabilities=["read:data", "write:reports", "admin:config"],
            ),
            trust=TrustInfo(score=450),
            action=ActionRequest(action_type="tool_call"),
        )
        decision = resolver.resolve(req)
        assert decision.decision == "allow_narrowed"
        assert decision.effective_scope == ["read:data"]
        assert "read-only" in decision.narrowing_reason


# ── Event Types Tests ─────────────────────────────────────────


class TestEventTypes:
    def test_trust_score_changed_event_exists(self):
        assert EVENT_TRUST_SCORE_CHANGED == "trust.score_changed"
        assert EVENT_TRUST_SCORE_CHANGED in ALL_EVENT_TYPES

    def test_authority_resolved_event_exists(self):
        assert EVENT_AUTHORITY_RESOLVED == "authority.resolved"
        assert EVENT_AUTHORITY_RESOLVED in ALL_EVENT_TYPES

    def test_trust_score_changed_event_with_direction(self):
        """TrustScoreChanged events carry direction for cache optimization."""
        event = Event(
            event_type=EVENT_TRUST_SCORE_CHANGED,
            source="trust.scorer",
            payload={
                "agent_did": "did:mesh:agent-1",
                "old_score": 750,
                "new_score": 600,
                "direction": "decreased",
            },
        )
        assert event.payload["direction"] == "decreased"
        assert event.payload["new_score"] < event.payload["old_score"]

    def test_event_bus_subscribes_to_trust_events(self):
        bus = InMemoryEventBus()
        received = []
        bus.subscribe("trust.*", lambda e: received.append(e))

        bus.emit(Event(
            event_type=EVENT_TRUST_SCORE_CHANGED,
            source="test",
            payload={"direction": "decreased"},
        ))
        assert len(received) == 1
        assert received[0].payload["direction"] == "decreased"


# ── Lineage-Bound Trust Tests ─────────────────────────────────


class TestLineageBoundTrust:
    def test_delegate_with_trust_bound(self):
        parent = AgentIdentity.create(
            name="parent-agent",
            sponsor="admin@example.com",
            capabilities=["read:data", "write:reports"],
        )
        child = parent.delegate(
            name="child-agent",
            capabilities=["read:data"],
            max_initial_trust_score=650,
        )
        assert child.max_initial_trust_score == 650
        assert child.parent_did == str(parent.did)
        assert child.delegation_depth == 1

    def test_delegate_without_trust_bound(self):
        parent = AgentIdentity.create(
            name="parent-agent",
            sponsor="admin@example.com",
            capabilities=["read:data"],
        )
        child = parent.delegate(name="child", capabilities=["read:data"])
        assert child.max_initial_trust_score is None

    def test_trust_bound_prevents_sybil(self):
        """Low-trust parent cannot spawn high-trust children."""
        parent = AgentIdentity.create(
            name="low-trust-parent",
            sponsor="user@example.com",
            capabilities=["read:data"],
        )
        parent_trust_score = 300
        child = parent.delegate(
            name="child",
            capabilities=["read:data"],
            max_initial_trust_score=parent_trust_score,
        )
        # Child's max trust is capped at parent's score
        assert child.max_initial_trust_score == 300
        # Authority resolver would use min(default_500, max_initial_300) = 300
