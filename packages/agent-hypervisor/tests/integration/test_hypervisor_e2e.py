# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Hypervisor Integration Tests

End-to-end tests validating the full hypervisor lifecycle:
session creation → agent join → saga execution → audit → termination → GC.
"""

from __future__ import annotations

import asyncio

import pytest

from hypervisor import (
    ConsistencyMode,
    ExecutionRing,
    Hypervisor,
    ReversibilityLevel,
    SagaState,
    SagaTimeoutError,
    SessionConfig,
    StepState,
)
from hypervisor.audit.delta import VFSChange
from hypervisor.liability.vouching import VouchingError
from hypervisor.models import ActionDescriptor

# ---------------------------------------------------------------------------
# Full Lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestFullLifecycle:
    """End-to-end session lifecycle: create → join → activate → terminate."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.hv = Hypervisor()

    async def test_complete_session_lifecycle(self):
        """Happy path: create, join two agents, activate, terminate with audit."""
        session = await self.hv.create_session(
            config=SessionConfig(
                consistency_mode=ConsistencyMode.EVENTUAL,
                max_participants=5,
                enable_audit=True,
            ),
            creator_did="did:mesh:admin",
        )
        assert session.sso is not None
        sid = session.sso.session_id

        # Join two agents
        ring_a = await self.hv.join_session(
            sid, "did:mesh:agent-alpha", sigma_raw=0.85
        )
        ring_b = await self.hv.join_session(
            sid, "did:mesh:agent-beta", sigma_raw=0.45
        )
        assert ring_a == ExecutionRing.RING_2_STANDARD
        assert ring_b == ExecutionRing.RING_3_SANDBOX

        # Activate
        await self.hv.activate_session(sid)

        # Capture some audit deltas
        session.delta_engine.capture(
            "did:mesh:agent-alpha",
            [VFSChange(path="/data/report.md", operation="add", content_hash="abc123")],
        )
        session.delta_engine.capture(
            "did:mesh:agent-beta",
            [VFSChange(path="/data/report.md", operation="modify", content_hash="def456")],
        )

        # Terminate — should get audit log root
        hash_chain_root = await self.hv.terminate_session(sid)
        assert hash_chain_root is not None
        assert len(hash_chain_root) == 64  # SHA-256 hex

    async def test_session_without_audit(self):
        """Session with audit disabled returns None audit log root."""
        session = await self.hv.create_session(
            config=SessionConfig(enable_audit=False),
            creator_did="did:mesh:admin",
        )
        sid = session.sso.session_id
        await self.hv.join_session(sid, "did:mesh:a", sigma_raw=0.7)
        await self.hv.activate_session(sid)
        hash_chain_root = await self.hv.terminate_session(sid)
        assert hash_chain_root is None

    async def test_multiple_concurrent_sessions(self):
        """Multiple sessions can run independently."""
        s1 = await self.hv.create_session(
            config=SessionConfig(), creator_did="did:mesh:admin"
        )
        s2 = await self.hv.create_session(
            config=SessionConfig(), creator_did="did:mesh:admin"
        )

        await self.hv.join_session(s1.sso.session_id, "did:mesh:a", sigma_raw=0.8)
        await self.hv.join_session(s2.sso.session_id, "did:mesh:b", sigma_raw=0.9)

        assert len(self.hv.active_sessions) == 2
        assert s1.sso.session_id != s2.sso.session_id


# ---------------------------------------------------------------------------
# Ring Assignment & Demotion
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRingEnforcementIntegration:
    """Test ring assignment with real sessions and sponsorship."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.hv = Hypervisor()

    async def test_high_score_gets_standard_ring(self):
        session = await self.hv.create_session(
            config=SessionConfig(), creator_did="did:mesh:admin"
        )
        ring = await self.hv.join_session(
            session.sso.session_id, "did:mesh:expert", sigma_raw=0.85
        )
        assert ring == ExecutionRing.RING_2_STANDARD

    async def test_low_score_gets_sandbox(self):
        session = await self.hv.create_session(
            config=SessionConfig(), creator_did="did:mesh:admin"
        )
        ring = await self.hv.join_session(
            session.sso.session_id, "did:mesh:newbie", sigma_raw=0.3
        )
        assert ring == ExecutionRing.RING_3_SANDBOX

    async def test_non_reversible_action_forces_strong_mode(self):
        """Joining with non-reversible actions forces STRONG consistency."""
        session = await self.hv.create_session(
            config=SessionConfig(consistency_mode=ConsistencyMode.EVENTUAL),
            creator_did="did:mesh:admin",
        )
        actions = [
            ActionDescriptor(
                action_id="delete_data",
                name="Delete Data",
                execute_api="/api/delete",
                reversibility=ReversibilityLevel.NONE,
            )
        ]
        await self.hv.join_session(
            session.sso.session_id,
            "did:mesh:agent",
            actions=actions,
            sigma_raw=0.8,
        )
        # Reversibility registry detects non-reversible actions.
        # Verify the registry flags it correctly.
        assert session.reversibility.has_non_reversible_actions() is True


# ---------------------------------------------------------------------------
# Sponsorship + Penalty Integration
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestVouchingSlashingIntegration:
    """Test sponsorship with exposure limits and penalty cascades."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.hv = Hypervisor()
        self.session_id = "test-session"

    def test_vouch_and_compute_eff_score(self):
        self.hv.vouching.vouch(
            "did:mesh:high", "did:mesh:low", self.session_id, 0.9, bond_pct=0.3
        )
        eff_score = self.hv.vouching.compute_eff_score(
            "did:mesh:low", self.session_id, 0.4, risk_weight=0.5
        )
        # Community edition: no sponsor boost, eff_score = vouchee_sigma
        assert eff_score == 0.4
        assert eff_score <= 1.0

    @pytest.mark.skip("Feature not available in Community Edition")
    def test_max_exposure_prevents_over_bonding(self):
        """Agent cannot bond more than max_exposure of their σ."""
        # Default max_exposure = 0.80
        self.hv.vouching.vouch(
            "did:mesh:high", "did:mesh:a", self.session_id, 0.9, bond_pct=0.5
        )
        # Already bonded 0.45, max = 0.72 (80% of 0.9), remaining = 0.27
        with pytest.raises(VouchingError, match="exceed max exposure"):
            self.hv.vouching.vouch(
                "did:mesh:high", "did:mesh:b", self.session_id, 0.9, bond_pct=0.5
            )

    def test_slash_cascades_to_voucher(self):
        """Community edition: penalty logs but doesn't apply penalties."""
        self.hv.vouching.vouch(
            "did:mesh:high", "did:mesh:low", self.session_id, 0.9, bond_pct=0.3
        )
        agent_scores = {"did:mesh:high": 0.9, "did:mesh:low": 0.5}
        result = self.hv.slashing.slash(
            "did:mesh:low", self.session_id, 0.5, 0.5, "policy_violation", agent_scores
        )
        # Community edition: no penalties applied
        assert agent_scores["did:mesh:low"] == 0.5  # unchanged
        assert agent_scores["did:mesh:high"] == 0.9  # unchanged
        assert len(result.voucher_clips) == 0

    def test_release_bonds_on_session_terminate(self):
        self.hv.vouching.vouch(
            "did:mesh:high", "did:mesh:low", self.session_id, 0.9
        )
        released = self.hv.vouching.release_session_bonds(self.session_id)
        assert released == 1
        exposure = self.hv.vouching.get_total_exposure("did:mesh:high", self.session_id)
        assert exposure == 0.0


# ---------------------------------------------------------------------------
# Saga Execution with Timeout & Retry
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSagaIntegration:
    """Test saga orchestration with real timeout and retry behavior."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.hv = Hypervisor()

    async def test_saga_happy_path(self):
        """Multi-step saga executes all steps successfully."""
        session = await self.hv.create_session(
            config=SessionConfig(), creator_did="did:mesh:admin"
        )
        saga = session.saga.create_saga(session.sso.session_id)

        step1 = session.saga.add_step(
            saga.saga_id, "draft", "did:mesh:a", "/api/draft", undo_api="/api/undo-draft"
        )
        step2 = session.saga.add_step(
            saga.saga_id, "review", "did:mesh:b", "/api/review", undo_api="/api/undo-review"
        )

        await session.saga.execute_step(
            saga.saga_id, step1.step_id, executor=lambda: asyncio.sleep(0)
        )
        await session.saga.execute_step(
            saga.saga_id, step2.step_id, executor=lambda: asyncio.sleep(0)
        )

        assert step1.state == StepState.COMMITTED
        assert step2.state == StepState.COMMITTED

    async def test_saga_timeout_triggers_failure(self):
        """Step that exceeds timeout is marked as failed."""
        session = await self.hv.create_session(
            config=SessionConfig(), creator_did="did:mesh:admin"
        )
        saga = session.saga.create_saga(session.sso.session_id)

        step = session.saga.add_step(
            saga.saga_id, "slow_op", "did:mesh:a", "/api/slow",
            timeout_seconds=1,  # 1 second timeout
        )

        async def slow_executor():
            await asyncio.sleep(10)  # Will exceed timeout
            return "done"

        with pytest.raises(SagaTimeoutError):
            await session.saga.execute_step(
                saga.saga_id, step.step_id, executor=slow_executor
            )

    async def test_saga_retry_on_failure(self):
        """Step retries on transient failure and eventually succeeds."""
        session = await self.hv.create_session(
            config=SessionConfig(), creator_did="did:mesh:admin"
        )
        saga = session.saga.create_saga(session.sso.session_id)

        step = session.saga.add_step(
            saga.saga_id, "flaky_op", "did:mesh:a", "/api/flaky",
            timeout_seconds=5, max_retries=2,
        )

        call_count = 0

        async def flaky_executor():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("transient failure")
            return "success"

        result = await session.saga.execute_step(
            saga.saga_id, step.step_id, executor=flaky_executor
        )
        assert result == "success"
        assert call_count == 3
        assert step.state == StepState.COMMITTED

    async def test_saga_compensation_on_failure(self):
        """Failed step triggers compensation of all committed steps."""
        session = await self.hv.create_session(
            config=SessionConfig(), creator_did="did:mesh:admin"
        )
        saga = session.saga.create_saga(session.sso.session_id)

        step1 = session.saga.add_step(
            saga.saga_id, "step1", "did:mesh:a", "/api/s1", undo_api="/api/undo-s1"
        )
        step2 = session.saga.add_step(
            saga.saga_id, "step2", "did:mesh:b", "/api/s2", undo_api="/api/undo-s2"
        )
        step3 = session.saga.add_step(
            saga.saga_id, "step3", "did:mesh:c", "/api/s3", undo_api="/api/undo-s3"
        )

        # Execute first two successfully
        await session.saga.execute_step(
            saga.saga_id, step1.step_id, executor=lambda: asyncio.sleep(0)
        )
        await session.saga.execute_step(
            saga.saga_id, step2.step_id, executor=lambda: asyncio.sleep(0)
        )

        # Step 3 fails
        with pytest.raises(ValueError):
            await session.saga.execute_step(
                saga.saga_id, step3.step_id,
                executor=lambda: (_ for _ in ()).throw(ValueError("boom")),
            )

        # Compensate
        compensated_steps = []

        async def compensator(step):
            compensated_steps.append(step.action_id)

        failed = await session.saga.compensate(saga.saga_id, compensator)
        assert len(failed) == 0
        # Compensation runs in reverse: step2 first, then step1
        assert compensated_steps == ["step2", "step1"]
        assert saga.state == SagaState.COMPLETED

    async def test_saga_escalation_on_compensation_failure(self):
        """Failed compensation escalates to Joint Liability penalty."""
        session = await self.hv.create_session(
            config=SessionConfig(), creator_did="did:mesh:admin"
        )
        saga = session.saga.create_saga(session.sso.session_id)

        step1 = session.saga.add_step(
            saga.saga_id, "irrev", "did:mesh:a", "/api/irrev"
            # No undo_api — compensation impossible
        )
        await session.saga.execute_step(
            saga.saga_id, step1.step_id, executor=lambda: asyncio.sleep(0)
        )

        async def compensator(step):
            raise RuntimeError("cannot undo")

        failed = await session.saga.compensate(saga.saga_id, compensator)
        assert len(failed) == 1
        assert saga.state == SagaState.ESCALATED
        assert "penalty triggered" in saga.error


# ---------------------------------------------------------------------------
# Audit Trail Integration
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAuditTrailIntegration:
    """Test delta audit engine in context of full sessions."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.hv = Hypervisor()

    async def test_audit_trail_captures_all_turns(self):
        session = await self.hv.create_session(
            config=SessionConfig(enable_audit=True),
            creator_did="did:mesh:admin",
        )
        sid = session.sso.session_id
        await self.hv.join_session(sid, "did:mesh:a", sigma_raw=0.8)
        await self.hv.activate_session(sid)

        # Capture 5 turns
        for i in range(5):
            session.delta_engine.capture(
                "did:mesh:a",
                [VFSChange(path=f"/file{i}.txt", operation="add", content_hash=f"hash{i}")],
            )

        assert session.delta_engine.turn_count == 5
        assert len(session.delta_engine.deltas) == 5

    async def test_hash_chain_integrity(self):
        """Community edition: no chain verification, always returns True."""
        session = await self.hv.create_session(
            config=SessionConfig(), creator_did="did:mesh:admin"
        )
        for i in range(10):
            session.delta_engine.capture(
                f"did:mesh:agent-{i % 3}",
                [VFSChange(path=f"/doc{i}", operation="add", content_hash=f"h{i}")],
            )

        assert session.delta_engine.verify_chain() is True

        # Tamper with a delta — community edition doesn't detect tampering
        session.delta_engine._deltas[5].agent_did = "did:mesh:tampered"
        assert session.delta_engine.verify_chain() is True

    async def test_hash_chain_root_deterministic(self):
        """Same session with same deltas produces consistent audit log roots."""
        session = await self.hv.create_session(
            config=SessionConfig(), creator_did="did:mesh:admin"
        )

        # Capture deltas
        session.delta_engine.capture(
            "did:mesh:a",
            [VFSChange(path="/x", operation="add", content_hash="abc")],
            delta_id="delta:1",
        )
        session.delta_engine.capture(
            "did:mesh:a",
            [VFSChange(path="/y", operation="add", content_hash="def")],
            delta_id="delta:2",
        )

        root1 = session.delta_engine.compute_hash_chain_root()
        # Computing again on same engine should give same result
        root2 = session.delta_engine.compute_hash_chain_root()
        assert root1 is not None
        assert root1 == root2


# ---------------------------------------------------------------------------
# GC Integration
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGCIntegration:
    """Test garbage collection with real VFS and delta engines."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.hv = Hypervisor()

    async def test_gc_purges_vfs_on_terminate(self):
        """Termination triggers GC that purges VFS state."""
        session = await self.hv.create_session(
            config=SessionConfig(enable_audit=True),
            creator_did="did:mesh:admin",
        )
        sid = session.sso.session_id
        await self.hv.join_session(sid, "did:mesh:a", sigma_raw=0.8)
        await self.hv.activate_session(sid)

        # Write files to VFS
        session.sso.vfs.write("/report.md", "data", agent_did="did:mesh:a")
        session.sso.vfs.write("/notes.md", "more", agent_did="did:mesh:a")
        assert session.sso.vfs.file_count >= 2

        # Terminate
        await self.hv.terminate_session(sid)

        # GC should have purged VFS
        assert self.hv.gc.is_purged(sid)
        assert len(self.hv.gc.history) == 1

    def test_gc_tracks_purged_sessions(self):
        gc = self.hv.gc
        gc.collect(session_id="s1")
        gc.collect(session_id="s2")
        assert gc.purged_session_count == 2
        assert gc.is_purged("s1")
        assert gc.is_purged("s2")
        assert not gc.is_purged("s3")


# ---------------------------------------------------------------------------
# Edge Cases & Security
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEdgeCases:
    """Edge cases and security boundaries."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.hv = Hypervisor()

    async def test_cannot_join_nonexistent_session(self):
        with pytest.raises(ValueError, match="not found"):
            await self.hv.join_session("fake-session", "did:mesh:a", sigma_raw=0.8)

    async def test_duplicate_agent_rejected(self):
        session = await self.hv.create_session(
            config=SessionConfig(), creator_did="did:mesh:admin"
        )
        sid = session.sso.session_id
        await self.hv.join_session(sid, "did:mesh:a", sigma_raw=0.8)
        with pytest.raises(Exception):
            await self.hv.join_session(sid, "did:mesh:a", sigma_raw=0.8)

    async def test_max_participants_enforced(self):
        session = await self.hv.create_session(
            config=SessionConfig(max_participants=2),
            creator_did="did:mesh:admin",
        )
        sid = session.sso.session_id
        await self.hv.join_session(sid, "did:mesh:a", sigma_raw=0.8)
        await self.hv.join_session(sid, "did:mesh:b", sigma_raw=0.7)
        with pytest.raises(Exception):
            await self.hv.join_session(sid, "did:mesh:c", sigma_raw=0.6)

    @pytest.mark.skip("Feature not available in Community Edition")
    async def test_vouching_exposure_limit_across_sessions(self):
        """Max exposure protects an agent's total bonded reputation."""
        # Sponsor agent has σ=0.9, max_exposure=0.80 → limit 0.72
        self.hv.vouching.vouch("did:mesh:v", "did:mesh:a", "s1", 0.9, bond_pct=0.4)
        # Bonded 0.36 in s1. Next sponsor: 0.4*0.9 = 0.36 → total 0.72 = exactly at limit
        self.hv.vouching.vouch("did:mesh:v", "did:mesh:b", "s1", 0.9, bond_pct=0.4)
        # Any more should fail
        with pytest.raises(VouchingError, match="exceed max exposure"):
            self.hv.vouching.vouch("did:mesh:v", "did:mesh:c", "s1", 0.9, bond_pct=0.1)
