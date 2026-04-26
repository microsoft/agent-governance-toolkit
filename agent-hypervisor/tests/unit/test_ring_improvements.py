# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for dynamic ring elevation, breach detection, and ring inheritance."""


import pytest

from hypervisor.models import ExecutionRing
from hypervisor.rings.breach_detector import (
    RingBreachDetector,
)
from hypervisor.rings.elevation import (
    ElevationDenialReason,
    RingElevationError,
    RingElevationManager,
)

# ── Ring Elevation Tests ────────────────────────────────────────


class TestRingElevation:
    @pytest.mark.skip("Feature not available in Public Preview")
    def test_request_elevation(self):
        mgr = RingElevationManager()
        elev = mgr.request_elevation(
            agent_did="a1",
            session_id="s1",
            current_ring=ExecutionRing.RING_3_SANDBOX,
            target_ring=ExecutionRing.RING_2_STANDARD,
            ttl_seconds=60,
            reason="Need write access",
        )
        assert elev.elevated_ring == ExecutionRing.RING_2_STANDARD
        assert elev.original_ring == ExecutionRing.RING_3_SANDBOX
        assert elev.is_active
        assert not elev.is_expired
        assert elev.remaining_seconds > 0

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_effective_ring_with_elevation(self):
        pass

    def test_effective_ring_without_elevation(self):
        mgr = RingElevationManager()
        effective = mgr.get_effective_ring("a1", "s1", ExecutionRing.RING_3_SANDBOX)
        assert effective == ExecutionRing.RING_3_SANDBOX

    def test_cannot_elevate_to_same_or_lower(self):
        mgr = RingElevationManager()
        with pytest.raises(RingElevationError):
            mgr.request_elevation(
                agent_did="a1", session_id="s1",
                current_ring=ExecutionRing.RING_2_STANDARD,
                target_ring=ExecutionRing.RING_3_SANDBOX,
            )

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_cannot_elevate_to_ring_0(self):
        pass

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_duplicate_elevation_rejected(self):
        pass

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_revoke_elevation(self):
        pass

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_tick_expires_elevations(self):
        pass

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_ttl_capped_at_max(self):
        pass

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_active_elevations_property(self):
        pass


# ── Ring Inheritance Tests ──────────────────────────────────────


class TestRingInheritance:
    def test_child_inherits_parent_minus_one(self):
        mgr = RingElevationManager()
        child_ring = mgr.register_child(
            "parent", "child", ExecutionRing.RING_1_PRIVILEGED
        )
        assert child_ring == ExecutionRing.RING_2_STANDARD

    def test_child_of_sandbox_stays_sandbox(self):
        mgr = RingElevationManager()
        child_ring = mgr.register_child(
            "parent", "child", ExecutionRing.RING_3_SANDBOX
        )
        assert child_ring == ExecutionRing.RING_3_SANDBOX

    def test_child_of_ring2_gets_ring3(self):
        mgr = RingElevationManager()
        child_ring = mgr.register_child(
            "parent", "child", ExecutionRing.RING_2_STANDARD
        )
        assert child_ring == ExecutionRing.RING_3_SANDBOX

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_parent_child_tracking(self):
        pass

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_max_child_ring(self):
        pass


# ── Breach Detector Tests ──────────────────────────────────────


class TestBreachDetector:
    def test_no_breach_with_normal_pattern(self):
        detector = RingBreachDetector()
        for _ in range(10):
            result = detector.record_call(
                "a1", "s1",
                ExecutionRing.RING_2_STANDARD,
                ExecutionRing.RING_2_STANDARD,
            )
        assert result is None

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_breach_detected_with_anomalous_calls(self):
        pass

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_circuit_breaker_tripped(self):
        pass

    def test_breaker_not_tripped_for_normal(self):
        detector = RingBreachDetector()
        for _ in range(10):
            detector.record_call(
                "a1", "s1",
                ExecutionRing.RING_2_STANDARD,
                ExecutionRing.RING_2_STANDARD,
            )
        assert not detector.is_breaker_tripped("a1", "s1")

    def test_reset_breaker(self):
        detector = RingBreachDetector()
        for _ in range(10):
            detector.record_call(
                "a1", "s1",
                ExecutionRing.RING_3_SANDBOX,
                ExecutionRing.RING_1_PRIVILEGED,
            )
        detector.reset_breaker("a1", "s1")
        assert not detector.is_breaker_tripped("a1", "s1")

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_agent_stats(self):
        pass

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_stats_for_unknown_agent(self):
        pass

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_breach_history(self):
        pass

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_mixed_call_pattern(self):
        pass


# ── Ring Elevation Error Message Tests ─────────────────────────


class TestRingElevationErrorMessages:
    """Tests for improved ring elevation error messages (issue #4)."""

    def test_error_includes_current_and_target_ring(self):
        mgr = RingElevationManager()
        with pytest.raises(RingElevationError) as exc_info:
            mgr.request_elevation(
                agent_did="did:mesh:agent-1",
                session_id="s1",
                current_ring=ExecutionRing.RING_3_SANDBOX,
                target_ring=ExecutionRing.RING_2_STANDARD,
            )
        msg = str(exc_info.value)
        assert "Ring 3 (Sandbox)" in msg
        assert "Ring 2 (Standard)" in msg

    def test_error_includes_agent_did(self):
        mgr = RingElevationManager()
        with pytest.raises(RingElevationError) as exc_info:
            mgr.request_elevation(
                agent_did="did:mesh:agent-1",
                session_id="s1",
                current_ring=ExecutionRing.RING_3_SANDBOX,
                target_ring=ExecutionRing.RING_2_STANDARD,
            )
        msg = str(exc_info.value)
        assert "did:mesh:agent-1" in msg

    def test_error_includes_denial_reason(self):
        mgr = RingElevationManager()
        with pytest.raises(RingElevationError) as exc_info:
            mgr.request_elevation(
                agent_did="a1",
                session_id="s1",
                current_ring=ExecutionRing.RING_3_SANDBOX,
                target_ring=ExecutionRing.RING_2_STANDARD,
            )
        err = exc_info.value
        assert err.denial_reason == ElevationDenialReason.COMMUNITY_EDITION

    def test_error_includes_remediation(self):
        mgr = RingElevationManager()
        with pytest.raises(RingElevationError) as exc_info:
            mgr.request_elevation(
                agent_did="a1",
                session_id="s1",
                current_ring=ExecutionRing.RING_3_SANDBOX,
                target_ring=ExecutionRing.RING_2_STANDARD,
            )
        msg = str(exc_info.value)
        assert "Remediation:" in msg

    def test_error_includes_docs_link(self):
        mgr = RingElevationManager()
        with pytest.raises(RingElevationError) as exc_info:
            mgr.request_elevation(
                agent_did="a1",
                session_id="s1",
                current_ring=ExecutionRing.RING_3_SANDBOX,
                target_ring=ExecutionRing.RING_2_STANDARD,
            )
        msg = str(exc_info.value)
        assert "Docs:" in msg
        assert "docs/rings.md" in msg

    def test_invalid_target_demotion(self):
        mgr = RingElevationManager()
        with pytest.raises(RingElevationError) as exc_info:
            mgr.request_elevation(
                agent_did="a1",
                session_id="s1",
                current_ring=ExecutionRing.RING_2_STANDARD,
                target_ring=ExecutionRing.RING_3_SANDBOX,
            )
        err = exc_info.value
        assert err.denial_reason == ElevationDenialReason.INVALID_TARGET
        assert err.current_ring == ExecutionRing.RING_2_STANDARD
        assert err.target_ring == ExecutionRing.RING_3_SANDBOX
        assert "Ring 2 (Standard)" in str(err)
        assert "Ring 3 (Sandbox)" in str(err)

    def test_invalid_target_same_ring(self):
        mgr = RingElevationManager()
        with pytest.raises(RingElevationError) as exc_info:
            mgr.request_elevation(
                agent_did="a1",
                session_id="s1",
                current_ring=ExecutionRing.RING_2_STANDARD,
                target_ring=ExecutionRing.RING_2_STANDARD,
            )
        err = exc_info.value
        assert err.denial_reason == ElevationDenialReason.INVALID_TARGET

    def test_ring_0_forbidden(self):
        mgr = RingElevationManager()
        with pytest.raises(RingElevationError) as exc_info:
            mgr.request_elevation(
                agent_did="a1",
                session_id="s1",
                current_ring=ExecutionRing.RING_1_PRIVILEGED,
                target_ring=ExecutionRing.RING_0_ROOT,
            )
        err = exc_info.value
        assert err.denial_reason == ElevationDenialReason.RING_0_FORBIDDEN
        assert "SRE Witness" in str(err)

    def test_error_structured_attributes(self):
        mgr = RingElevationManager()
        with pytest.raises(RingElevationError) as exc_info:
            mgr.request_elevation(
                agent_did="did:mesh:test",
                session_id="s1",
                current_ring=ExecutionRing.RING_3_SANDBOX,
                target_ring=ExecutionRing.RING_2_STANDARD,
            )
        err = exc_info.value
        assert err.current_ring == ExecutionRing.RING_3_SANDBOX
        assert err.target_ring == ExecutionRing.RING_2_STANDARD
        assert err.agent_did == "did:mesh:test"
        assert err.denial_reason == ElevationDenialReason.COMMUNITY_EDITION
