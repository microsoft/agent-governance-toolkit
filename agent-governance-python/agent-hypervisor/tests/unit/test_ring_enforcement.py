# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for execution ring enforcement: elevation, resource constraints, session isolation."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

import pytest

from hypervisor.models import ActionDescriptor, ExecutionRing
from hypervisor.rings.elevation import (
    ChildRegistration,
    ElevationDenialReason,
    ELEVATION_TRUST_THRESHOLDS,
    RingElevation,
    RingElevationError,
    RingElevationManager,
)
from hypervisor.rings.enforcer import (
    ResourceConstraints,
    ResourceType,
    RING_CONSTRAINTS,
    RingCheckResult,
    RingEnforcer,
)
from hypervisor.session.isolation import (
    IsolationLevel,
    SessionIsolationManager,
    SessionScope,
)


# ── Elevation Tests ──────────────────────────────────────────────────


class TestElevationGrant:
    """Test that elevation requests are approved when trust is sufficient."""

    def test_ring3_to_ring2_with_sufficient_trust(self):
        mgr = RingElevationManager()
        elev = mgr.request_elevation(
            agent_did="did:mesh:agent1",
            session_id="sess-1",
            current_ring=ExecutionRing.RING_3_SANDBOX,
            target_ring=ExecutionRing.RING_2_STANDARD,
            trust_score=0.6,
        )
        assert elev.is_active
        assert elev.elevated_ring == ExecutionRing.RING_2_STANDARD
        assert elev.original_ring == ExecutionRing.RING_3_SANDBOX

    def test_ring3_to_ring1_with_attestation(self):
        mgr = RingElevationManager()
        elev = mgr.request_elevation(
            agent_did="did:mesh:agent1",
            session_id="sess-1",
            current_ring=ExecutionRing.RING_3_SANDBOX,
            target_ring=ExecutionRing.RING_1_PRIVILEGED,
            trust_score=0.90,
            attestation="sre-witness-token-abc",
        )
        assert elev.elevated_ring == ExecutionRing.RING_1_PRIVILEGED
        assert elev.attestation == "sre-witness-token-abc"

    def test_ring2_to_ring1_with_attestation(self):
        mgr = RingElevationManager()
        elev = mgr.request_elevation(
            agent_did="did:mesh:agent2",
            session_id="sess-2",
            current_ring=ExecutionRing.RING_2_STANDARD,
            target_ring=ExecutionRing.RING_1_PRIVILEGED,
            trust_score=0.9,
            attestation="witness",
        )
        assert elev.is_active

    def test_default_ttl_applied(self):
        mgr = RingElevationManager()
        elev = mgr.request_elevation(
            agent_did="did:mesh:a",
            session_id="s",
            current_ring=ExecutionRing.RING_3_SANDBOX,
            target_ring=ExecutionRing.RING_2_STANDARD,
            trust_score=0.6,
        )
        assert elev.remaining_seconds > 0
        assert elev.remaining_seconds <= RingElevationManager.DEFAULT_TTL

    def test_custom_ttl(self):
        mgr = RingElevationManager()
        elev = mgr.request_elevation(
            agent_did="did:mesh:a",
            session_id="s",
            current_ring=ExecutionRing.RING_3_SANDBOX,
            target_ring=ExecutionRing.RING_2_STANDARD,
            ttl_seconds=60,
            trust_score=0.6,
        )
        assert elev.remaining_seconds <= 60

    def test_ttl_capped_at_max(self):
        mgr = RingElevationManager()
        elev = mgr.request_elevation(
            agent_did="did:mesh:a",
            session_id="s",
            current_ring=ExecutionRing.RING_3_SANDBOX,
            target_ring=ExecutionRing.RING_2_STANDARD,
            ttl_seconds=99999,
            trust_score=0.6,
        )
        assert elev.remaining_seconds <= RingElevationManager.MAX_ELEVATION_TTL


class TestElevationDenial:
    """Test elevation denial scenarios."""

    def test_insufficient_trust_for_ring2(self):
        mgr = RingElevationManager()
        with pytest.raises(RingElevationError) as exc_info:
            mgr.request_elevation(
                agent_did="did:mesh:low",
                session_id="s",
                current_ring=ExecutionRing.RING_3_SANDBOX,
                target_ring=ExecutionRing.RING_2_STANDARD,
                trust_score=0.3,
            )
        assert exc_info.value.denial_reason == ElevationDenialReason.INSUFFICIENT_TRUST

    def test_insufficient_trust_for_ring1(self):
        mgr = RingElevationManager()
        with pytest.raises(RingElevationError) as exc_info:
            mgr.request_elevation(
                agent_did="did:mesh:med",
                session_id="s",
                current_ring=ExecutionRing.RING_3_SANDBOX,
                target_ring=ExecutionRing.RING_1_PRIVILEGED,
                trust_score=0.7,
                attestation="witness",
            )
        assert exc_info.value.denial_reason == ElevationDenialReason.INSUFFICIENT_TRUST

    def test_ring1_without_attestation(self):
        mgr = RingElevationManager()
        with pytest.raises(RingElevationError) as exc_info:
            mgr.request_elevation(
                agent_did="did:mesh:a",
                session_id="s",
                current_ring=ExecutionRing.RING_3_SANDBOX,
                target_ring=ExecutionRing.RING_1_PRIVILEGED,
                trust_score=0.95,
            )
        assert exc_info.value.denial_reason == ElevationDenialReason.NO_SPONSORSHIP

    def test_ring0_always_forbidden(self):
        mgr = RingElevationManager()
        with pytest.raises(RingElevationError) as exc_info:
            mgr.request_elevation(
                agent_did="did:mesh:a",
                session_id="s",
                current_ring=ExecutionRing.RING_1_PRIVILEGED,
                target_ring=ExecutionRing.RING_0_ROOT,
                trust_score=1.0,
                attestation="root-witness",
            )
        assert exc_info.value.denial_reason == ElevationDenialReason.RING_0_FORBIDDEN

    def test_invalid_target_same_ring(self):
        mgr = RingElevationManager()
        with pytest.raises(RingElevationError) as exc_info:
            mgr.request_elevation(
                agent_did="did:mesh:a",
                session_id="s",
                current_ring=ExecutionRing.RING_2_STANDARD,
                target_ring=ExecutionRing.RING_2_STANDARD,
                trust_score=0.8,
            )
        assert exc_info.value.denial_reason == ElevationDenialReason.INVALID_TARGET

    def test_invalid_target_demotion(self):
        mgr = RingElevationManager()
        with pytest.raises(RingElevationError) as exc_info:
            mgr.request_elevation(
                agent_did="did:mesh:a",
                session_id="s",
                current_ring=ExecutionRing.RING_1_PRIVILEGED,
                target_ring=ExecutionRing.RING_2_STANDARD,
                trust_score=0.8,
            )
        assert exc_info.value.denial_reason == ElevationDenialReason.INVALID_TARGET

    def test_duplicate_elevation_rejected(self):
        mgr = RingElevationManager()
        mgr.request_elevation(
            agent_did="did:mesh:a",
            session_id="s",
            current_ring=ExecutionRing.RING_3_SANDBOX,
            target_ring=ExecutionRing.RING_2_STANDARD,
            trust_score=0.6,
        )
        with pytest.raises(RingElevationError) as exc_info:
            mgr.request_elevation(
                agent_did="did:mesh:a",
                session_id="s",
                current_ring=ExecutionRing.RING_3_SANDBOX,
                target_ring=ExecutionRing.RING_2_STANDARD,
                trust_score=0.6,
            )
        assert exc_info.value.denial_reason == ElevationDenialReason.DUPLICATE

    def test_no_trust_score_available(self):
        mgr = RingElevationManager()
        with pytest.raises(RingElevationError) as exc_info:
            mgr.request_elevation(
                agent_did="did:mesh:a",
                session_id="s",
                current_ring=ExecutionRing.RING_3_SANDBOX,
                target_ring=ExecutionRing.RING_2_STANDARD,
            )
        assert exc_info.value.denial_reason == ElevationDenialReason.INSUFFICIENT_TRUST


class TestElevationLifecycle:
    """Test elevation expiration, revocation, and tick()."""

    def test_active_elevations_list(self):
        mgr = RingElevationManager()
        mgr.request_elevation(
            agent_did="did:mesh:a",
            session_id="s",
            current_ring=ExecutionRing.RING_3_SANDBOX,
            target_ring=ExecutionRing.RING_2_STANDARD,
            trust_score=0.6,
        )
        assert len(mgr.active_elevations) == 1

    def test_revoke_elevation(self):
        mgr = RingElevationManager()
        elev = mgr.request_elevation(
            agent_did="did:mesh:a",
            session_id="s",
            current_ring=ExecutionRing.RING_3_SANDBOX,
            target_ring=ExecutionRing.RING_2_STANDARD,
            trust_score=0.6,
        )
        mgr.revoke_elevation(elev.elevation_id)
        assert len(mgr.active_elevations) == 0

    def test_revoke_nonexistent_raises(self):
        mgr = RingElevationManager()
        with pytest.raises(RingElevationError):
            mgr.revoke_elevation("elev:doesnotexist")

    def test_get_effective_ring_with_elevation(self):
        mgr = RingElevationManager()
        mgr.request_elevation(
            agent_did="did:mesh:a",
            session_id="s",
            current_ring=ExecutionRing.RING_3_SANDBOX,
            target_ring=ExecutionRing.RING_2_STANDARD,
            trust_score=0.6,
        )
        effective = mgr.get_effective_ring(
            "did:mesh:a", "s", ExecutionRing.RING_3_SANDBOX
        )
        assert effective == ExecutionRing.RING_2_STANDARD

    def test_get_effective_ring_without_elevation(self):
        mgr = RingElevationManager()
        effective = mgr.get_effective_ring(
            "did:mesh:a", "s", ExecutionRing.RING_3_SANDBOX
        )
        assert effective == ExecutionRing.RING_3_SANDBOX

    def test_tick_expires_past_ttl(self):
        mgr = RingElevationManager()
        elev = mgr.request_elevation(
            agent_did="did:mesh:a",
            session_id="s",
            current_ring=ExecutionRing.RING_3_SANDBOX,
            target_ring=ExecutionRing.RING_2_STANDARD,
            ttl_seconds=1,
            trust_score=0.6,
        )
        # Force expiration by setting expires_at in the past
        elev.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        expired = mgr.tick()
        assert len(expired) == 1
        assert expired[0].elevation_id == elev.elevation_id
        assert not elev.is_active

    def test_tick_does_not_expire_active(self):
        mgr = RingElevationManager()
        mgr.request_elevation(
            agent_did="did:mesh:a",
            session_id="s",
            current_ring=ExecutionRing.RING_3_SANDBOX,
            target_ring=ExecutionRing.RING_2_STANDARD,
            ttl_seconds=3600,
            trust_score=0.6,
        )
        expired = mgr.tick()
        assert len(expired) == 0
        assert len(mgr.active_elevations) == 1

    def test_trust_provider_callback(self):
        mgr = RingElevationManager(
            trust_provider=lambda did: 0.7
        )
        elev = mgr.request_elevation(
            agent_did="did:mesh:a",
            session_id="s",
            current_ring=ExecutionRing.RING_3_SANDBOX,
            target_ring=ExecutionRing.RING_2_STANDARD,
        )
        assert elev.is_active


class TestChildRegistration:
    """Test parent-child ring registration."""

    def test_child_inherits_parent_minus_one(self):
        mgr = RingElevationManager()
        child_ring = mgr.register_child(
            "did:mesh:parent", "did:mesh:child", ExecutionRing.RING_1_PRIVILEGED
        )
        assert child_ring == ExecutionRing.RING_2_STANDARD

    def test_child_of_sandbox_stays_sandbox(self):
        mgr = RingElevationManager()
        child_ring = mgr.register_child(
            "did:mesh:parent", "did:mesh:child", ExecutionRing.RING_3_SANDBOX
        )
        assert child_ring == ExecutionRing.RING_3_SANDBOX

    def test_child_registration_tracked(self):
        mgr = RingElevationManager()
        mgr.register_child(
            "did:mesh:parent", "did:mesh:child", ExecutionRing.RING_2_STANDARD
        )
        reg = mgr.get_child_registration("did:mesh:child")
        assert reg is not None
        assert reg.parent_did == "did:mesh:parent"
        assert reg.child_ring == ExecutionRing.RING_3_SANDBOX

    def test_unknown_child_returns_none(self):
        mgr = RingElevationManager()
        assert mgr.get_child_registration("did:mesh:unknown") is None


# ── Resource Constraint Tests ────────────────────────────────────────


class TestResourceConstraints:
    """Test ring-to-resource constraint mapping."""

    def test_ring3_no_network(self):
        c = RING_CONSTRAINTS[ExecutionRing.RING_3_SANDBOX]
        assert c.network_allowed is False

    def test_ring3_no_filesystem(self):
        c = RING_CONSTRAINTS[ExecutionRing.RING_3_SANDBOX]
        assert c.filesystem_writable is False
        assert c.filesystem_scope == "none"

    def test_ring3_no_subprocess(self):
        c = RING_CONSTRAINTS[ExecutionRing.RING_3_SANDBOX]
        assert c.subprocess_allowed is False

    def test_ring2_has_network(self):
        c = RING_CONSTRAINTS[ExecutionRing.RING_2_STANDARD]
        assert c.network_allowed is True

    def test_ring2_scoped_filesystem(self):
        c = RING_CONSTRAINTS[ExecutionRing.RING_2_STANDARD]
        assert c.filesystem_scope == "scoped"

    def test_ring2_subprocess_allowed(self):
        c = RING_CONSTRAINTS[ExecutionRing.RING_2_STANDARD]
        assert c.subprocess_allowed is True

    def test_ring1_full_access(self):
        c = RING_CONSTRAINTS[ExecutionRing.RING_1_PRIVILEGED]
        assert c.network_allowed is True
        assert c.filesystem_scope == "full"
        assert c.subprocess_allowed is True

    def test_allows_resource_method(self):
        c = RING_CONSTRAINTS[ExecutionRing.RING_3_SANDBOX]
        assert c.allows_resource(ResourceType.NETWORK) is False
        assert c.allows_resource(ResourceType.SUBPROCESS) is False
        assert c.allows_resource(ResourceType.TOOL_EXECUTION) is True


class TestRingEnforcerResources:
    """Test RingEnforcer resource checks."""

    def test_sandbox_network_denied(self):
        enforcer = RingEnforcer()
        result = enforcer.check_resource(
            ExecutionRing.RING_3_SANDBOX, ResourceType.NETWORK
        )
        assert result.allowed is False
        assert ResourceType.NETWORK in result.denied_resources

    def test_standard_network_allowed(self):
        enforcer = RingEnforcer()
        result = enforcer.check_resource(
            ExecutionRing.RING_2_STANDARD, ResourceType.NETWORK
        )
        assert result.allowed is True

    def test_sandbox_subprocess_denied(self):
        enforcer = RingEnforcer()
        result = enforcer.check_resource(
            ExecutionRing.RING_3_SANDBOX, ResourceType.SUBPROCESS
        )
        assert result.allowed is False

    def test_get_constraints(self):
        enforcer = RingEnforcer()
        c = enforcer.get_constraints(ExecutionRing.RING_3_SANDBOX)
        assert c.max_concurrent_tools == 2

    def test_get_constraints_defaults_to_sandbox(self):
        enforcer = RingEnforcer()
        # Ring 0 has its own constraints
        c = enforcer.get_constraints(ExecutionRing.RING_0_ROOT)
        assert c.max_concurrent_tools == 32


# ── Session Isolation Tests ──────────────────────────────────────────


class TestSessionIsolation:
    """Test session isolation enforcement."""

    def test_create_scope(self):
        mgr = SessionIsolationManager()
        scope = mgr.create_scope("sess-1", "did:mesh:agent1")
        assert scope.session_id == "sess-1"
        assert "sess-1" in scope.working_directory

    def test_path_allowed_within_session(self):
        mgr = SessionIsolationManager()
        scope = mgr.create_scope("sess-1", "did:mesh:agent1")
        assert scope.is_path_allowed(scope.working_directory + "/data.json")

    def test_path_denied_outside_session(self):
        mgr = SessionIsolationManager()
        scope = mgr.create_scope(
            "sess-1", "did:mesh:agent1", IsolationLevel.SERIALIZABLE
        )
        assert scope.is_path_allowed("/var/agt/sessions/sess-2/data.json") is False

    def test_cross_session_with_grant(self):
        mgr = SessionIsolationManager()
        scope = mgr.create_scope(
            "sess-1", "did:mesh:agent1", IsolationLevel.READ_COMMITTED
        )
        scope.grant_access("sess-2")
        assert scope.is_path_allowed("/var/agt/sessions/sess-2/data.json") is True

    def test_cross_session_without_grant(self):
        mgr = SessionIsolationManager()
        scope = mgr.create_scope(
            "sess-1", "did:mesh:agent1", IsolationLevel.READ_COMMITTED
        )
        assert scope.is_path_allowed("/var/agt/sessions/sess-2/data.json") is False

    def test_grant_only_works_for_read_committed(self):
        mgr = SessionIsolationManager()
        scope = mgr.create_scope(
            "sess-1", "did:mesh:agent1", IsolationLevel.SNAPSHOT
        )
        scope.grant_access("sess-2")
        # Snapshot ignores grants
        assert scope.is_path_allowed("/var/agt/sessions/sess-2/data.json") is False

    def test_manager_check_access(self):
        mgr = SessionIsolationManager()
        mgr.create_scope("sess-1", "did:mesh:agent1")
        assert mgr.check_access("sess-1", "/var/agt/sessions/sess-1/out.txt") is True
        assert mgr.check_access("sess-1", "/var/agt/sessions/sess-2/out.txt") is False

    def test_manager_no_scope_is_permissive(self):
        mgr = SessionIsolationManager()
        # No scope created = permissive (backward compat)
        assert mgr.check_access("unknown-sess", "/anything") is True

    def test_manager_grant_cross_session(self):
        mgr = SessionIsolationManager()
        mgr.create_scope("sess-1", "did:mesh:a", IsolationLevel.READ_COMMITTED)
        mgr.create_scope("sess-2", "did:mesh:b", IsolationLevel.READ_COMMITTED)
        assert mgr.grant_cross_session_access("sess-1", "sess-2") is True
        assert mgr.check_access("sess-1", "/var/agt/sessions/sess-2/data.json") is True

    def test_manager_grant_fails_for_snapshot(self):
        mgr = SessionIsolationManager()
        mgr.create_scope("sess-1", "did:mesh:a", IsolationLevel.SNAPSHOT)
        assert mgr.grant_cross_session_access("sess-1", "sess-2") is False

    def test_remove_scope(self):
        mgr = SessionIsolationManager()
        mgr.create_scope("sess-1", "did:mesh:a")
        mgr.remove_scope("sess-1")
        assert mgr.active_sessions == 0

    def test_active_sessions_count(self):
        mgr = SessionIsolationManager()
        mgr.create_scope("sess-1", "did:mesh:a")
        mgr.create_scope("sess-2", "did:mesh:b")
        assert mgr.active_sessions == 2

    def test_isolation_level_properties(self):
        assert IsolationLevel.SERIALIZABLE.requires_vector_clocks is True
        assert IsolationLevel.SNAPSHOT.requires_vector_clocks is False
        assert IsolationLevel.SERIALIZABLE.allows_concurrent_writes is False
        assert IsolationLevel.SNAPSHOT.allows_concurrent_writes is True
        assert IsolationLevel.SERIALIZABLE.coordination_cost == "high"
        assert IsolationLevel.SNAPSHOT.coordination_cost == "low"

    def test_revoke_access(self):
        scope = SessionScope(
            session_id="sess-1",
            agent_did="did:mesh:a",
            isolation_level=IsolationLevel.READ_COMMITTED,
        )
        scope.grant_access("sess-2")
        assert scope.is_path_allowed("/var/agt/sessions/sess-2/file") is True
        scope.revoke_access("sess-2")
        assert scope.is_path_allowed("/var/agt/sessions/sess-2/file") is False
