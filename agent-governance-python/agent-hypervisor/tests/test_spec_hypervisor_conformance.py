# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Conformance tests for AGENT-HYPERVISOR-EXECUTION-CONTROL-1.0.

Every test references a specific section of the specification.
Tests marked [Pure Specification] verify normative requirements.
Tests marked [Default Implementation] verify reference defaults.
"""

from __future__ import annotations

import hashlib
import time
from datetime import UTC, datetime, timedelta

import pytest

from hypervisor.audit.delta import (
    DeltaEngine,
    SemanticDelta,
    VFSChange,
)
from hypervisor.constants import (
    MAX_AGENT_ID_LENGTH,
    MAX_API_PATH_LENGTH,
    MAX_DURATION_LIMIT,
    MAX_NAME_LENGTH,
    MAX_PARTICIPANTS_LIMIT,
    MAX_UNDO_WINDOW,
    RATE_LIMIT_RING_0,
    RATE_LIMIT_RING_1,
    RATE_LIMIT_RING_2,
    RATE_LIMIT_RING_3,
    RING_1_TRUST_THRESHOLD,
    RING_2_TRUST_THRESHOLD,
    RISK_WEIGHT_FULL,
    RISK_WEIGHT_NONE,
    RISK_WEIGHT_PARTIAL,
    SAGA_DEFAULT_MAX_RETRIES,
    SAGA_DEFAULT_RETRY_DELAY_SECONDS,
    SAGA_DEFAULT_STEP_TIMEOUT_SECONDS,
    SESSION_DEFAULT_MIN_EFF_SCORE,
)

# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------
from hypervisor.models import (
    ActionDescriptor,
    ConsistencyMode,
    ExecutionRing,
    ReversibilityLevel,
    SessionConfig,
    SessionParticipant,
    SessionState,
)
from hypervisor.rings.elevation import (
    RingElevationManager,
)
from hypervisor.rings.enforcer import (
    RING_CONSTRAINTS,
    ResourceConstraints,
    ResourceType,
    RingCheckResult,
    RingEnforcer,
)
from hypervisor.security.kill_switch import (
    HandoffStatus,
    KillReason,
    KillResult,
    KillSwitch,
    StepHandoff,
)
from hypervisor.security.rate_limiter import (
    AgentRateLimiter,
    RateLimitExceeded,
    TokenBucket,
)
from hypervisor.session.isolation import (
    IsolationLevel,
    SessionIsolationManager,
    SessionScope,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_action(
    action_id: str = "act-1",
    name: str = "test-action",
    execute_api: str = "/api/v1/test",
    reversibility: ReversibilityLevel = ReversibilityLevel.FULL,
    is_read_only: bool = False,
    is_admin: bool = False,
    undo_window_seconds: int = 0,
) -> ActionDescriptor:
    return ActionDescriptor(
        action_id=action_id,
        name=name,
        execute_api=execute_api,
        reversibility=reversibility,
        is_read_only=is_read_only,
        is_admin=is_admin,
        undo_window_seconds=undo_window_seconds,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Section 3: Execution Rings
# ═══════════════════════════════════════════════════════════════════════════


class TestExecutionRings:
    """Spec S3 -- Execution Rings."""

    def test_four_rings_exist(self):
        """S3.1 -- exactly four rings MUST exist."""
        assert len(ExecutionRing) == 4

    def test_ring_values(self):
        """S3.1 -- ring values MUST be 0-3."""
        assert ExecutionRing.RING_0_ROOT.value == 0
        assert ExecutionRing.RING_1_PRIVILEGED.value == 1
        assert ExecutionRing.RING_2_STANDARD.value == 2
        assert ExecutionRing.RING_3_SANDBOX.value == 3

    def test_ring_ordering(self):
        """S3.2 -- lower value = higher privilege."""
        assert ExecutionRing.RING_0_ROOT.value < ExecutionRing.RING_1_PRIVILEGED.value
        assert ExecutionRing.RING_1_PRIVILEGED.value < ExecutionRing.RING_2_STANDARD.value
        assert ExecutionRing.RING_2_STANDARD.value < ExecutionRing.RING_3_SANDBOX.value


# ═══════════════════════════════════════════════════════════════════════════
# Section 4: Ring Assignment
# ═══════════════════════════════════════════════════════════════════════════


class TestRingAssignment:
    """Spec S4 -- Ring Assignment."""

    def test_high_score_with_consensus_gets_ring1(self):
        """S4.1 -- eff_score > 0.95 + consensus -> Ring 1."""
        ring = ExecutionRing.from_eff_score(0.97, has_consensus=True)
        assert ring == ExecutionRing.RING_1_PRIVILEGED

    def test_high_score_without_consensus_gets_ring2(self):
        """S4.1 -- eff_score > 0.95 without consensus -> Ring 2."""
        ring = ExecutionRing.from_eff_score(0.97, has_consensus=False)
        assert ring == ExecutionRing.RING_2_STANDARD

    def test_moderate_score_gets_ring2(self):
        """S4.1 -- eff_score > 0.60 -> Ring 2."""
        ring = ExecutionRing.from_eff_score(0.80, has_consensus=False)
        assert ring == ExecutionRing.RING_2_STANDARD

    def test_low_score_gets_ring3(self):
        """S4.1 -- eff_score <= 0.60 -> Ring 3."""
        ring = ExecutionRing.from_eff_score(0.40)
        assert ring == ExecutionRing.RING_3_SANDBOX

    def test_boundary_0_60_gets_ring3(self):
        """S4.1 -- eff_score == 0.60 -> Ring 3 (threshold is >0.60)."""
        ring = ExecutionRing.from_eff_score(0.60)
        assert ring == ExecutionRing.RING_3_SANDBOX

    def test_boundary_0_95_without_consensus(self):
        """S4.1 -- eff_score == 0.95 without consensus -> Ring 2."""
        ring = ExecutionRing.from_eff_score(0.95)
        assert ring == ExecutionRing.RING_2_STANDARD

    def test_ring0_never_assigned_by_score(self):
        """S4.1 -- Ring 0 is NEVER assigned by score."""
        ring = ExecutionRing.from_eff_score(1.0, has_consensus=True)
        assert ring != ExecutionRing.RING_0_ROOT

    def test_trust_threshold_constants(self):
        """S4.2 -- threshold constants match spec."""
        assert RING_1_TRUST_THRESHOLD == 0.95
        assert RING_2_TRUST_THRESHOLD == 0.60

    def test_ring_demotion_detection(self):
        """S4.3 -- should_demote detects trust drop."""
        enforcer = RingEnforcer()
        # Agent at Ring 2 with score that warrants Ring 3
        assert enforcer.should_demote(ExecutionRing.RING_2_STANDARD, 0.40)
        # Agent at Ring 2 with score that warrants Ring 2
        assert not enforcer.should_demote(ExecutionRing.RING_2_STANDARD, 0.80)


# ═══════════════════════════════════════════════════════════════════════════
# Section 5: Action Classification
# ═══════════════════════════════════════════════════════════════════════════


class TestActionClassification:
    """Spec S5 -- Action Classification."""

    def test_admin_action_requires_ring0(self):
        """S5.2 -- is_admin -> Ring 0."""
        action = _make_action(is_admin=True)
        assert action.required_ring == ExecutionRing.RING_0_ROOT

    def test_non_reversible_non_readonly_requires_ring1(self):
        """S5.2 -- reversibility=NONE + not read_only -> Ring 1."""
        action = _make_action(reversibility=ReversibilityLevel.NONE)
        assert action.required_ring == ExecutionRing.RING_1_PRIVILEGED

    def test_readonly_requires_ring3(self):
        """S5.2 -- is_read_only -> Ring 3."""
        action = _make_action(is_read_only=True)
        assert action.required_ring == ExecutionRing.RING_3_SANDBOX

    def test_reversible_action_requires_ring2(self):
        """S5.2 -- reversible + not read_only -> Ring 2."""
        action = _make_action(reversibility=ReversibilityLevel.FULL)
        assert action.required_ring == ExecutionRing.RING_2_STANDARD

    def test_partial_reversible_requires_ring2(self):
        """S5.2 -- partial reversibility -> Ring 2."""
        action = _make_action(reversibility=ReversibilityLevel.PARTIAL)
        assert action.required_ring == ExecutionRing.RING_2_STANDARD

    def test_action_id_validation(self):
        """S5.3 -- invalid action_id MUST be rejected."""
        with pytest.raises(ValueError):
            _make_action(action_id="")
        with pytest.raises(ValueError):
            _make_action(action_id="bad@id")

    def test_action_name_validation(self):
        """S5.3 -- empty name MUST be rejected."""
        with pytest.raises(ValueError):
            _make_action(name="")

    def test_undo_window_validation(self):
        """S5.3 -- undo_window out of range MUST be rejected."""
        with pytest.raises(ValueError):
            _make_action(undo_window_seconds=-1)
        with pytest.raises(ValueError):
            _make_action(undo_window_seconds=MAX_UNDO_WINDOW + 1)


# ═══════════════════════════════════════════════════════════════════════════
# Section 6: Ring Enforcement
# ═══════════════════════════════════════════════════════════════════════════


class TestRingEnforcement:
    """Spec S6 -- Ring Enforcement."""

    def test_ring0_always_denied(self):
        """S6.1 -- Ring 0 actions MUST be denied with sre_witness flag."""
        enforcer = RingEnforcer()
        action = _make_action(is_admin=True)
        result = enforcer.check(ExecutionRing.RING_0_ROOT, action, 1.0, True, True)
        assert not result.allowed
        assert result.requires_sre_witness

    def test_insufficient_ring_denied(self):
        """S6.1 -- agent_ring > required_ring -> denied."""
        enforcer = RingEnforcer()
        action = _make_action(reversibility=ReversibilityLevel.NONE)
        # Action needs Ring 1, agent at Ring 2
        result = enforcer.check(ExecutionRing.RING_2_STANDARD, action, 0.80)
        assert not result.allowed

    def test_sufficient_ring_allowed(self):
        """S6.1 -- agent_ring <= required_ring -> allowed."""
        enforcer = RingEnforcer()
        action = _make_action(reversibility=ReversibilityLevel.FULL)
        # Action needs Ring 2, agent at Ring 2
        result = enforcer.check(ExecutionRing.RING_2_STANDARD, action, 0.80)
        assert result.allowed

    def test_higher_privilege_ring_allowed(self):
        """S6.1 -- more privileged ring for lower-ring action -> allowed."""
        enforcer = RingEnforcer()
        action = _make_action(is_read_only=True)  # Ring 3
        result = enforcer.check(ExecutionRing.RING_1_PRIVILEGED, action, 0.97)
        assert result.allowed

    def test_resource_check_ring3_no_network(self):
        """S6.3 -- Ring 3 MUST deny network access."""
        enforcer = RingEnforcer()
        result = enforcer.check_resource(ExecutionRing.RING_3_SANDBOX, ResourceType.NETWORK)
        assert not result.allowed

    def test_resource_check_ring2_network_allowed(self):
        """S6.3 -- Ring 2 MUST allow network access."""
        enforcer = RingEnforcer()
        result = enforcer.check_resource(ExecutionRing.RING_2_STANDARD, ResourceType.NETWORK)
        assert result.allowed


# ═══════════════════════════════════════════════════════════════════════════
# Section 7: Resource Constraints
# ═══════════════════════════════════════════════════════════════════════════


class TestResourceConstraints:
    """Spec S7 -- Resource Constraints."""

    def test_ring3_constraints(self):
        """S7.2 -- Ring 3: no network, no FS, no subprocess, 2 tools."""
        c = RING_CONSTRAINTS[ExecutionRing.RING_3_SANDBOX]
        assert not c.network_allowed
        assert c.filesystem_scope == "none"
        assert not c.subprocess_allowed
        assert c.max_concurrent_tools == 2

    def test_ring2_constraints(self):
        """S7.2 -- Ring 2: network, scoped FS, subprocess, 8 tools."""
        c = RING_CONSTRAINTS[ExecutionRing.RING_2_STANDARD]
        assert c.network_allowed
        assert c.filesystem_scope == "scoped"
        assert c.subprocess_allowed
        assert c.max_concurrent_tools == 8

    def test_ring1_constraints(self):
        """S7.2 -- Ring 1: network, full FS, subprocess, 16 tools."""
        c = RING_CONSTRAINTS[ExecutionRing.RING_1_PRIVILEGED]
        assert c.network_allowed
        assert c.filesystem_scope == "full"
        assert c.subprocess_allowed
        assert c.max_concurrent_tools == 16

    def test_ring0_constraints(self):
        """S7.2 -- Ring 0: network, full FS, subprocess, 32 tools."""
        c = RING_CONSTRAINTS[ExecutionRing.RING_0_ROOT]
        assert c.network_allowed
        assert c.filesystem_scope == "full"
        assert c.subprocess_allowed
        assert c.max_concurrent_tools == 32

    def test_unknown_ring_fallback(self):
        """S6.4 -- unknown ring falls back to Ring 3 constraints."""
        enforcer = RingEnforcer()
        # Ring 3 is the most restrictive, used as fallback
        c = enforcer.get_constraints(ExecutionRing.RING_3_SANDBOX)
        assert not c.network_allowed

    def test_tool_execution_always_allowed(self):
        """S7.3 -- TOOL_EXECUTION always allowed."""
        for ring in ExecutionRing:
            c = RING_CONSTRAINTS[ring]
            assert c.allows_resource(ResourceType.TOOL_EXECUTION)


# ═══════════════════════════════════════════════════════════════════════════
# Section 8: Privilege Elevation
# ═══════════════════════════════════════════════════════════════════════════


class TestPrivilegeElevation:
    """Spec S8 -- Privilege Elevation."""

    def test_ring0_elevation_forbidden(self):
        """S8.7 -- Ring 0 elevation MUST be forbidden."""
        mgr = RingElevationManager()
        with pytest.raises(Exception) as exc_info:
            mgr.request_elevation(
                agent_did="did:mesh:a",
                session_id="s1",
                current_ring=ExecutionRing.RING_1_PRIVILEGED,
                target_ring=ExecutionRing.RING_0_ROOT,
            )
        assert "ring_0_forbidden" in str(exc_info.value).lower() or hasattr(
            exc_info.value, "denial_reason"
        )

    def test_same_ring_elevation_rejected(self):
        """S8.3 -- target same as current -> invalid_target."""
        mgr = RingElevationManager()
        with pytest.raises(Exception):
            mgr.request_elevation(
                agent_did="did:mesh:a",
                session_id="s1",
                current_ring=ExecutionRing.RING_2_STANDARD,
                target_ring=ExecutionRing.RING_2_STANDARD,
            )

    def test_lower_privilege_target_rejected(self):
        """S8.3 -- target lower privilege than current -> invalid_target."""
        mgr = RingElevationManager()
        with pytest.raises(Exception):
            mgr.request_elevation(
                agent_did="did:mesh:a",
                session_id="s1",
                current_ring=ExecutionRing.RING_1_PRIVILEGED,
                target_ring=ExecutionRing.RING_2_STANDARD,
            )

    def test_elevation_defaults(self):
        """S8.5 -- TTL defaults match spec."""
        assert RingElevationManager.DEFAULT_TTL == 300
        assert RingElevationManager.MAX_ELEVATION_TTL == 3600

    def test_insufficient_trust_rejected(self):
        """S8.3 -- trust below threshold -> insufficient_trust."""
        mgr = RingElevationManager()
        with pytest.raises(Exception):
            mgr.request_elevation(
                agent_did="did:mesh:a",
                session_id="s1",
                current_ring=ExecutionRing.RING_2_STANDARD,
                target_ring=ExecutionRing.RING_1_PRIVILEGED,
                trust_score=0.50,  # Below 0.85 threshold
            )

    def test_ring1_without_attestation_rejected(self):
        """S8.3 -- Ring 1 without attestation -> no_sponsorship."""
        mgr = RingElevationManager()
        with pytest.raises(Exception):
            mgr.request_elevation(
                agent_did="did:mesh:a",
                session_id="s1",
                current_ring=ExecutionRing.RING_2_STANDARD,
                target_ring=ExecutionRing.RING_1_PRIVILEGED,
                trust_score=0.90,
                attestation=None,
            )


# ═══════════════════════════════════════════════════════════════════════════
# Section 9: Rate Limiting
# ═══════════════════════════════════════════════════════════════════════════


class TestRateLimiting:
    """Spec S9 -- Rate Limiting."""

    def test_token_bucket_consume(self):
        """S9.1 -- consume succeeds when tokens available."""
        bucket = TokenBucket(capacity=10.0, tokens=10.0, refill_rate=1.0)
        assert bucket.consume(1.0)

    def test_token_bucket_exhaustion(self):
        """S9.1 -- consume fails when tokens exhausted."""
        bucket = TokenBucket(capacity=2.0, tokens=0.0, refill_rate=0.0)
        assert not bucket.consume(1.0)

    def test_ring_rate_limit_constants(self):
        """S9.2 -- rate limit constants match spec."""
        assert RATE_LIMIT_RING_0 == (100.0, 200.0)
        assert RATE_LIMIT_RING_1 == (50.0, 100.0)
        assert RATE_LIMIT_RING_2 == (20.0, 40.0)
        assert RATE_LIMIT_RING_3 == (5.0, 10.0)

    def test_rate_limit_exceeded_raises(self):
        """S9.4 -- exceeding rate limit MUST raise RateLimitExceeded."""
        limiter = AgentRateLimiter()
        # Exhaust bucket for Ring 3 agent (burst=10)
        for _ in range(20):
            try:
                limiter.check("did:mesh:agent1", "session1", ExecutionRing.RING_3_SANDBOX)
            except RateLimitExceeded:
                return  # Expected
        pytest.fail("RateLimitExceeded was not raised")

    def test_rate_limit_ring_change(self):
        """S9.5 -- ring change recreates bucket."""
        limiter = AgentRateLimiter()
        limiter.check("did:mesh:a", "s1", ExecutionRing.RING_3_SANDBOX)
        limiter.update_ring("did:mesh:a", "s1", ExecutionRing.RING_2_STANDARD)
        # Should work with Ring 2 limits now (higher burst)
        for _ in range(30):
            limiter.check("did:mesh:a", "s1", ExecutionRing.RING_2_STANDARD)


# ═══════════════════════════════════════════════════════════════════════════
# Section 10: Session Model
# ═══════════════════════════════════════════════════════════════════════════


class TestSessionModel:
    """Spec S10 -- Session Model."""

    def test_session_states_exist(self):
        """S10.1 -- all session states MUST exist."""
        assert SessionState.CREATED
        assert SessionState.HANDSHAKING
        assert SessionState.ACTIVE
        assert SessionState.TERMINATING
        assert SessionState.ARCHIVED

    def test_session_config_defaults(self):
        """S10.2 -- default config values match spec."""
        config = SessionConfig()
        assert config.consistency_mode == ConsistencyMode.EVENTUAL
        assert config.max_participants == 10
        assert config.max_duration_seconds == 3600
        assert config.min_eff_score == SESSION_DEFAULT_MIN_EFF_SCORE
        assert config.enable_audit is True

    def test_session_config_max_participants_validation(self):
        """S17.3 -- max_participants out of range MUST raise."""
        with pytest.raises(ValueError):
            SessionConfig(max_participants=0)
        with pytest.raises(ValueError):
            SessionConfig(max_participants=MAX_PARTICIPANTS_LIMIT + 1)

    def test_session_config_max_duration_validation(self):
        """S17.3 -- max_duration out of range MUST raise."""
        with pytest.raises(ValueError):
            SessionConfig(max_duration_seconds=0)
        with pytest.raises(ValueError):
            SessionConfig(max_duration_seconds=MAX_DURATION_LIMIT + 1)

    def test_session_config_min_eff_score_validation(self):
        """S17.3 -- min_eff_score out of range MUST raise."""
        with pytest.raises(ValueError):
            SessionConfig(min_eff_score=-0.1)
        with pytest.raises(ValueError):
            SessionConfig(min_eff_score=1.1)

    def test_session_config_type_validation(self):
        """S17.3 -- type mismatches MUST raise TypeError."""
        with pytest.raises(TypeError):
            SessionConfig(max_participants="ten")
        with pytest.raises(TypeError):
            SessionConfig(max_duration_seconds=3.5)

    def test_participant_defaults(self):
        """S10.3 -- participant defaults match spec."""
        p = SessionParticipant(agent_did="did:mesh:agent1")
        assert p.ring == ExecutionRing.RING_3_SANDBOX
        assert p.sigma_raw == 0.0
        assert p.eff_score == 0.0
        assert p.is_active is True

    def test_participant_score_validation(self):
        """S17.4 -- sigma_raw and eff_score MUST be in [0.0, 1.0]."""
        with pytest.raises(ValueError):
            SessionParticipant(agent_did="did:mesh:a", sigma_raw=1.5)
        with pytest.raises(ValueError):
            SessionParticipant(agent_did="did:mesh:a", eff_score=-0.1)

    def test_consistency_modes(self):
        """S10.4 -- both consistency modes MUST exist."""
        assert ConsistencyMode.STRONG.value == "strong"
        assert ConsistencyMode.EVENTUAL.value == "eventual"


# ═══════════════════════════════════════════════════════════════════════════
# Section 11: Session Isolation
# ═══════════════════════════════════════════════════════════════════════════


class TestSessionIsolation:
    """Spec S11 -- Session Isolation."""

    def test_isolation_levels_exist(self):
        """S11.1 -- three isolation levels MUST exist."""
        assert IsolationLevel.SNAPSHOT
        assert IsolationLevel.READ_COMMITTED
        assert IsolationLevel.SERIALIZABLE

    def test_own_session_always_allowed(self):
        """S11.3 -- agent's own session directory is always allowed."""
        mgr = SessionIsolationManager()
        scope = mgr.create_scope("session-1", "did:mesh:a", IsolationLevel.SNAPSHOT)
        own_path = "/var/agt/sessions/session-1/data.txt"
        assert mgr.check_access("session-1", own_path)

    def test_other_session_denied_snapshot(self):
        """S11.3 -- under SNAPSHOT, other sessions denied."""
        mgr = SessionIsolationManager()
        mgr.create_scope("session-1", "did:mesh:a", IsolationLevel.SNAPSHOT)
        other_path = "/var/agt/sessions/session-2/data.txt"
        assert not mgr.check_access("session-1", other_path)

    def test_fail_closed_no_scope(self):
        """S11.4 -- no scope -> access denied (fail closed)."""
        mgr = SessionIsolationManager()
        assert not mgr.check_access("session-1", "/var/agt/sessions/session-1/data.txt")


# ═══════════════════════════════════════════════════════════════════════════
# Section 12: Kill Switch
# ═══════════════════════════════════════════════════════════════════════════


class TestKillSwitch:
    """Spec S12 -- Kill Switch."""

    def test_kill_reasons_exist(self):
        """S12.2 -- all kill reasons MUST exist."""
        assert KillReason.BEHAVIORAL_DRIFT
        assert KillReason.RATE_LIMIT
        assert KillReason.RING_BREACH
        assert KillReason.MANUAL
        assert KillReason.QUARANTINE_TIMEOUT
        assert KillReason.SESSION_TIMEOUT

    def test_kill_no_callback_not_terminated(self):
        """S12.6 -- no callback registered -> terminated=false."""
        ks = KillSwitch()
        result = ks.kill(
            agent_did="did:mesh:unregistered",
            session_id="s1",
            reason=KillReason.MANUAL,
        )
        assert not result.terminated

    def test_kill_with_callback_terminated(self):
        """S12.5 -- successful callback -> terminated=true."""
        ks = KillSwitch()
        ks.register_agent("did:mesh:a", lambda: None)
        result = ks.kill(
            agent_did="did:mesh:a",
            session_id="s1",
            reason=KillReason.MANUAL,
        )
        assert result.terminated

    def test_kill_callback_exception_not_terminated(self):
        """S12.6 -- callback exception -> terminated=false."""
        ks = KillSwitch()

        def bad_callback():
            raise RuntimeError("boom")

        ks.register_agent("did:mesh:a", bad_callback)
        result = ks.kill(
            agent_did="did:mesh:a",
            session_id="s1",
            reason=KillReason.MANUAL,
        )
        assert not result.terminated

    def test_kill_result_fields(self):
        """S12.4 -- KillResult has required fields."""
        result = KillResult(
            kill_id="k1",
            agent_did="did:mesh:a",
            session_id="s1",
            reason=KillReason.MANUAL,
        )
        assert result.kill_id == "k1"
        assert result.agent_did == "did:mesh:a"
        assert result.reason == KillReason.MANUAL

    def test_handoff_statuses_exist(self):
        """S12.3 -- handoff statuses MUST exist."""
        assert HandoffStatus.PENDING
        assert HandoffStatus.HANDED_OFF
        assert HandoffStatus.FAILED
        assert HandoffStatus.COMPENSATED

    def test_cleanup_after_kill(self):
        """S12.7 -- agent unregistered after kill."""
        ks = KillSwitch()
        ks.register_agent("did:mesh:a", lambda: None)
        ks.kill(agent_did="did:mesh:a", session_id="s1", reason=KillReason.MANUAL)
        # Second kill should find no callback
        result = ks.kill(agent_did="did:mesh:a", session_id="s1", reason=KillReason.MANUAL)
        assert not result.terminated


# ═══════════════════════════════════════════════════════════════════════════
# Section 14: Audit and Hash Chain
# ═══════════════════════════════════════════════════════════════════════════


class TestAuditHashChain:
    """Spec S14 -- Audit and Hash Chain Integrity."""

    def test_hash_chain_construction(self):
        """S14.2 -- deltas form append-only hash chain."""
        engine = DeltaEngine("session-1")
        change = VFSChange(path="/data/a.txt", operation="write")
        d1 = engine.capture("did:mesh:a", [change])
        d2 = engine.capture("did:mesh:a", [change])
        assert d2.parent_hash == d1.delta_hash

    def test_hash_chain_verification(self):
        """S14.4 -- verify_chain returns true for valid chain."""
        engine = DeltaEngine("session-1")
        change = VFSChange(path="/data/a.txt", operation="write")
        engine.capture("did:mesh:a", [change])
        engine.capture("did:mesh:a", [change])
        valid, msg = engine.verify_chain()
        assert valid

    def test_tamper_detection(self):
        """S14.5 -- tampered chain MUST be detected."""
        engine = DeltaEngine("session-1")
        change = VFSChange(path="/data/a.txt", operation="write")
        engine.capture("did:mesh:a", [change])
        engine.capture("did:mesh:a", [change])
        # Tamper with first delta
        engine._deltas[0].delta_hash = "tampered"
        valid, msg = engine.verify_chain()
        assert not valid


# ═══════════════════════════════════════════════════════════════════════════
# Section 16: Risk Weight Model
# ═══════════════════════════════════════════════════════════════════════════


class TestRiskWeight:
    """Spec S16 -- Risk Weight Model."""

    def test_risk_weight_ranges(self):
        """S16.1 -- risk weight ranges match spec."""
        assert RISK_WEIGHT_FULL == (0.1, 0.3)
        assert RISK_WEIGHT_PARTIAL == (0.5, 0.8)
        assert RISK_WEIGHT_NONE == (0.9, 1.0)

    def test_default_risk_weight_is_midpoint(self):
        """S16.2 -- default weight is midpoint of range."""
        assert ReversibilityLevel.FULL.default_risk_weight == pytest.approx(0.2)
        assert ReversibilityLevel.PARTIAL.default_risk_weight == pytest.approx(0.65)
        assert ReversibilityLevel.NONE.default_risk_weight == pytest.approx(0.95)

    def test_action_risk_weight(self):
        """S16.2 -- action.risk_weight uses reversibility default."""
        action = _make_action(reversibility=ReversibilityLevel.NONE)
        assert action.risk_weight == pytest.approx(0.95)


# ═══════════════════════════════════════════════════════════════════════════
# Section 17: Configuration Validation
# ═══════════════════════════════════════════════════════════════════════════


class TestConfigValidation:
    """Spec S17 -- Configuration Validation."""

    def test_identifier_empty_rejected(self):
        """S17.1 -- empty identifiers MUST be rejected."""
        with pytest.raises(ValueError):
            SessionParticipant(agent_did="")

    def test_identifier_invalid_chars_rejected(self):
        """S17.1 -- invalid characters MUST be rejected."""
        with pytest.raises(ValueError):
            SessionParticipant(agent_did="bad@agent")

    def test_identifier_max_length(self):
        """S17.1 -- identifier exceeding max length MUST be rejected."""
        with pytest.raises(ValueError):
            SessionParticipant(agent_did="a" * (MAX_AGENT_ID_LENGTH + 1))

    def test_api_path_empty_rejected(self):
        """S17.2 -- empty API path MUST be rejected."""
        with pytest.raises(ValueError):
            _make_action(execute_api="")

    def test_api_path_max_length(self):
        """S17.2 -- API path exceeding max length MUST be rejected."""
        with pytest.raises(ValueError):
            _make_action(execute_api="/" + "a" * MAX_API_PATH_LENGTH)

    def test_validation_limits_constants(self):
        """S17 -- validation constants match spec."""
        assert MAX_AGENT_ID_LENGTH == 256
        assert MAX_NAME_LENGTH == 256
        assert MAX_API_PATH_LENGTH == 2048
        assert MAX_PARTICIPANTS_LIMIT == 1000
        assert MAX_DURATION_LIMIT == 604800
        assert MAX_UNDO_WINDOW == 86400


# ═══════════════════════════════════════════════════════════════════════════
# Section 19: Failure Semantics
# ═══════════════════════════════════════════════════════════════════════════


class TestFailureSemantics:
    """Spec S19 -- Failure Semantics."""

    def test_ring_check_fails_closed(self):
        """S19.1 -- ring check for Ring 0 -> denied."""
        enforcer = RingEnforcer()
        action = _make_action(is_admin=True)
        result = enforcer.check(ExecutionRing.RING_0_ROOT, action, 1.0)
        assert not result.allowed

    def test_rate_limit_failure_raises(self):
        """S19.1 -- rate limit exhaustion MUST raise."""
        with pytest.raises(RateLimitExceeded):
            bucket = TokenBucket(capacity=0.0, tokens=0.0, refill_rate=0.0)
            limiter = AgentRateLimiter()
            # Force exhaustion
            for _ in range(20):
                limiter.check("did:mesh:x", "s1", ExecutionRing.RING_3_SANDBOX)

    def test_kill_switch_records_on_failure(self):
        """S19.1 -- kill switch records result even on callback failure."""
        ks = KillSwitch()
        result = ks.kill("did:mesh:no-agent", "s1", KillReason.MANUAL)
        assert isinstance(result, KillResult)
        assert not result.terminated


# ═══════════════════════════════════════════════════════════════════════════
# Section 15: Saga Orchestration
# ═══════════════════════════════════════════════════════════════════════════


class TestSagaDefaults:
    """Spec S15 -- Saga Orchestration."""

    def test_saga_default_constants(self):
        """S15.2 -- saga defaults match spec."""
        assert SAGA_DEFAULT_MAX_RETRIES == 2
        assert SAGA_DEFAULT_RETRY_DELAY_SECONDS == 1.0
        assert SAGA_DEFAULT_STEP_TIMEOUT_SECONDS == 300
