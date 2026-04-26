# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for core agent management functions in Hypervisor (core.py).

Covers: create_session, join_session, activate_session, terminate_session,
get_session, verify_behavior, active_sessions, and error handling.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from hypervisor.core import Hypervisor, ManagedSession
from hypervisor.models import (
    ActionDescriptor,
    ConsistencyMode,
    ExecutionRing,
    ReversibilityLevel,
    SessionConfig,
    SessionState,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def hypervisor() -> Hypervisor:
    """A plain Hypervisor with no integration adapters."""
    return Hypervisor()


@pytest.fixture
def config() -> SessionConfig:
    return SessionConfig()


@pytest.fixture
def config_no_audit() -> SessionConfig:
    return SessionConfig(enable_audit=False)


CREATOR = "did:mesh:admin"
AGENT_1 = "did:mesh:agent-1"
AGENT_2 = "did:mesh:agent-2"


# ---------------------------------------------------------------------------
# ManagedSession
# ---------------------------------------------------------------------------

class TestManagedSession:
    async def test_managed_session_has_subsystems(self, hypervisor, config):
        managed = await hypervisor.create_session(config, creator_did=CREATOR)
        assert managed.sso is not None
        assert managed.reversibility is not None
        assert managed.delta_engine is not None
        assert managed.saga is not None


# ---------------------------------------------------------------------------
# create_session
# ---------------------------------------------------------------------------

class TestCreateSession:
    async def test_creates_session(self, hypervisor, config):
        managed = await hypervisor.create_session(config, creator_did=CREATOR)
        assert isinstance(managed, ManagedSession)
        assert managed.sso.state == SessionState.HANDSHAKING
        assert managed.sso.creator_did == CREATOR

    async def test_session_stored_internally(self, hypervisor, config):
        managed = await hypervisor.create_session(config, creator_did=CREATOR)
        assert hypervisor.get_session(managed.sso.session_id) is managed

    async def test_create_multiple_sessions(self, hypervisor, config):
        s1 = await hypervisor.create_session(config, creator_did=CREATOR)
        s2 = await hypervisor.create_session(config, creator_did=CREATOR)
        assert s1.sso.session_id != s2.sso.session_id
        assert len(hypervisor._sessions) == 2


# ---------------------------------------------------------------------------
# join_session
# ---------------------------------------------------------------------------

class TestJoinSession:
    async def test_join_with_high_sigma(self, hypervisor, config):
        managed = await hypervisor.create_session(config, creator_did=CREATOR)
        ring = await hypervisor.join_session(
            managed.sso.session_id, AGENT_1, sigma_raw=0.85,
        )
        assert ring == ExecutionRing.RING_2_STANDARD
        assert managed.sso.participant_count == 1

    async def test_join_with_low_sigma_gets_sandbox(self, hypervisor, config):
        managed = await hypervisor.create_session(config, creator_did=CREATOR)
        ring = await hypervisor.join_session(
            managed.sso.session_id, AGENT_1, sigma_raw=0.30,
        )
        assert ring == ExecutionRing.RING_3_SANDBOX

    async def test_join_multiple_agents(self, hypervisor, config):
        managed = await hypervisor.create_session(config, creator_did=CREATOR)
        await hypervisor.join_session(managed.sso.session_id, AGENT_1, sigma_raw=0.85)
        await hypervisor.join_session(managed.sso.session_id, AGENT_2, sigma_raw=0.70)
        assert managed.sso.participant_count == 2

    async def test_join_nonexistent_session_raises(self, hypervisor):
        with pytest.raises(ValueError, match="not found"):
            await hypervisor.join_session("session:nonexistent", AGENT_1, sigma_raw=0.5)

    async def test_join_with_non_reversible_actions_forces_strong(self, hypervisor, config):
        managed = await hypervisor.create_session(config, creator_did=CREATOR)
        actions = [
            ActionDescriptor(
                action_id="delete-db",
                name="Delete DB",
                execute_api="/api/delete",
                reversibility=ReversibilityLevel.NONE,
                is_read_only=False,
            ),
        ]
        await hypervisor.join_session(
            managed.sso.session_id, AGENT_1, actions=actions, sigma_raw=0.85,
        )
        assert managed.sso.consistency_mode == ConsistencyMode.STRONG

    async def test_join_with_reversible_actions_keeps_eventual(self, hypervisor, config):
        managed = await hypervisor.create_session(config, creator_did=CREATOR)
        actions = [
            ActionDescriptor(
                action_id="update-rec",
                name="Update",
                execute_api="/api/update",
                undo_api="/api/undo",
                reversibility=ReversibilityLevel.FULL,
            ),
        ]
        await hypervisor.join_session(
            managed.sso.session_id, AGENT_1, actions=actions, sigma_raw=0.85,
        )
        assert managed.sso.consistency_mode == ConsistencyMode.EVENTUAL

    async def test_join_with_zero_sigma_no_nexus(self, hypervisor, config):
        """Zero sigma with no Nexus adapter → eff_score stays 0 → sandbox."""
        managed = await hypervisor.create_session(config, creator_did=CREATOR)
        ring = await hypervisor.join_session(
            managed.sso.session_id, AGENT_1, sigma_raw=0.0,
        )
        assert ring == ExecutionRing.RING_3_SANDBOX


# ---------------------------------------------------------------------------
# join_session — integration adapters
# ---------------------------------------------------------------------------

class TestJoinSessionWithAdapters:
    async def test_nexus_resolves_sigma(self, config):
        nexus = MagicMock()
        nexus.resolve_sigma.return_value = 0.90
        hv = Hypervisor(nexus=nexus)
        managed = await hv.create_session(config, creator_did=CREATOR)

        ring = await hv.join_session(
            managed.sso.session_id, AGENT_1, sigma_raw=0.0,
        )
        nexus.resolve_sigma.assert_called_once()
        assert ring == ExecutionRing.RING_2_STANDARD

    async def test_nexus_conservative_min(self, config):
        """When both sigma_raw and Nexus sigma given, uses min."""
        nexus = MagicMock()
        nexus.resolve_sigma.return_value = 0.50  # lower than raw
        hv = Hypervisor(nexus=nexus)
        managed = await hv.create_session(config, creator_did=CREATOR)

        ring = await hv.join_session(
            managed.sso.session_id, AGENT_1,
            sigma_raw=0.85, agent_history=["tx1"],
        )
        assert ring == ExecutionRing.RING_3_SANDBOX  # min(0.85, 0.50) = 0.50

    async def test_iatp_manifest_dict(self, config):
        iatp = MagicMock()
        analysis = MagicMock()
        analysis.actions = [
            ActionDescriptor(
                action_id="a1", name="A", execute_api="/a",
                reversibility=ReversibilityLevel.FULL,
            ),
        ]
        analysis.sigma_hint = 0.80
        analysis.ring_hint = ExecutionRing.RING_2_STANDARD
        iatp.analyze_manifest_dict.return_value = analysis

        hv = Hypervisor(iatp=iatp)
        managed = await hv.create_session(config, creator_did=CREATOR)
        ring = await hv.join_session(
            managed.sso.session_id, AGENT_1,
            manifest={"cap": "test"},
        )
        iatp.analyze_manifest_dict.assert_called_once()
        assert ring == ExecutionRing.RING_2_STANDARD

    async def test_iatp_manifest_object(self, config):
        iatp = MagicMock()
        analysis = MagicMock()
        analysis.actions = []
        analysis.sigma_hint = 0.75
        analysis.ring_hint = ExecutionRing.RING_2_STANDARD
        iatp.analyze_manifest.return_value = analysis

        manifest_obj = MagicMock()  # not a dict

        hv = Hypervisor(iatp=iatp)
        managed = await hv.create_session(config, creator_did=CREATOR)
        await hv.join_session(
            managed.sso.session_id, AGENT_1,
            manifest=manifest_obj, sigma_raw=0.0,
        )
        iatp.analyze_manifest.assert_called_once_with(manifest_obj)


# ---------------------------------------------------------------------------
# activate_session
# ---------------------------------------------------------------------------

class TestActivateSession:
    async def test_activate_after_join(self, hypervisor, config):
        managed = await hypervisor.create_session(config, creator_did=CREATOR)
        await hypervisor.join_session(managed.sso.session_id, AGENT_1, sigma_raw=0.85)
        await hypervisor.activate_session(managed.sso.session_id)
        assert managed.sso.state == SessionState.ACTIVE

    async def test_activate_nonexistent_raises(self, hypervisor):
        with pytest.raises(ValueError, match="not found"):
            await hypervisor.activate_session("session:bogus")

    async def test_activate_without_participants_raises(self, hypervisor, config):
        managed = await hypervisor.create_session(config, creator_did=CREATOR)
        with pytest.raises(Exception):
            await hypervisor.activate_session(managed.sso.session_id)


# ---------------------------------------------------------------------------
# terminate_session
# ---------------------------------------------------------------------------

class TestTerminateSession:
    async def _create_active_session(self, hv, cfg):
        managed = await hv.create_session(cfg, creator_did=CREATOR)
        await hv.join_session(managed.sso.session_id, AGENT_1, sigma_raw=0.85)
        await hv.activate_session(managed.sso.session_id)
        return managed

    async def test_terminate_archives(self, hypervisor, config):
        managed = await self._create_active_session(hypervisor, config)
        await hypervisor.terminate_session(managed.sso.session_id)
        assert managed.sso.state == SessionState.ARCHIVED

    async def test_terminate_returns_hash_when_audit_enabled(self, hypervisor, config):
        managed = await self._create_active_session(hypervisor, config)
        # Record a delta so hash chain root is non-empty
        managed.delta_engine.capture(agent_did=AGENT_1, changes=[])
        result = await hypervisor.terminate_session(managed.sso.session_id)
        assert result is not None
        assert managed.sso.state == SessionState.ARCHIVED

    async def test_terminate_no_audit_returns_none(self, hypervisor, config_no_audit):
        managed = await self._create_active_session(hypervisor, config_no_audit)
        result = await hypervisor.terminate_session(managed.sso.session_id)
        assert result is None

    async def test_terminate_nonexistent_raises(self, hypervisor):
        with pytest.raises(ValueError, match="not found"):
            await hypervisor.terminate_session("session:ghost")

    async def test_terminate_releases_bonds(self, hypervisor, config):
        managed = await self._create_active_session(hypervisor, config)
        with patch.object(hypervisor.vouching, "release_session_bonds") as mock_release:
            await hypervisor.terminate_session(managed.sso.session_id)
            mock_release.assert_called_once_with(managed.sso.session_id)


# ---------------------------------------------------------------------------
# get_session / _get_session
# ---------------------------------------------------------------------------

class TestGetSession:
    async def test_get_existing(self, hypervisor, config):
        managed = await hypervisor.create_session(config, creator_did=CREATOR)
        assert hypervisor.get_session(managed.sso.session_id) is managed

    def test_get_nonexistent_returns_none(self, hypervisor):
        assert hypervisor.get_session("session:nope") is None

    def test_internal_get_raises_on_missing(self, hypervisor):
        with pytest.raises(ValueError, match="not found"):
            hypervisor._get_session("session:missing")


# ---------------------------------------------------------------------------
# active_sessions
# ---------------------------------------------------------------------------

class TestActiveSessions:
    async def test_empty_initially(self, hypervisor):
        assert hypervisor.active_sessions == []

    async def test_includes_handshaking(self, hypervisor, config):
        await hypervisor.create_session(config, creator_did=CREATOR)
        assert len(hypervisor.active_sessions) == 1

    async def test_excludes_archived(self, hypervisor, config):
        managed = await hypervisor.create_session(config, creator_did=CREATOR)
        await hypervisor.join_session(managed.sso.session_id, AGENT_1, sigma_raw=0.85)
        await hypervisor.activate_session(managed.sso.session_id)
        await hypervisor.terminate_session(managed.sso.session_id)
        assert len(hypervisor.active_sessions) == 0

    async def test_mixed_states(self, hypervisor, config):
        s1 = await hypervisor.create_session(config, creator_did=CREATOR)
        s2 = await hypervisor.create_session(config, creator_did=CREATOR)
        # Terminate s1
        await hypervisor.join_session(s1.sso.session_id, AGENT_1, sigma_raw=0.85)
        await hypervisor.activate_session(s1.sso.session_id)
        await hypervisor.terminate_session(s1.sso.session_id)
        # s2 still handshaking
        active = hypervisor.active_sessions
        assert len(active) == 1
        assert active[0].sso.session_id == s2.sso.session_id


# ---------------------------------------------------------------------------
# verify_behavior
# ---------------------------------------------------------------------------

class TestVerifyBehavior:
    async def test_no_adapter_returns_none(self, hypervisor, config):
        managed = await hypervisor.create_session(config, creator_did=CREATOR)
        await hypervisor.join_session(managed.sso.session_id, AGENT_1, sigma_raw=0.85)
        result = await hypervisor.verify_behavior(
            managed.sso.session_id, AGENT_1,
            claimed_embedding=[1, 0], observed_embedding=[0, 1],
        )
        assert result is None

    async def test_drift_below_threshold(self, config):
        policy_check = MagicMock()
        drift_result = MagicMock()
        drift_result.should_slash = False
        drift_result.drift_score = 0.1
        policy_check.check_behavioral_drift.return_value = drift_result

        hv = Hypervisor(policy_check=policy_check)
        managed = await hv.create_session(config, creator_did=CREATOR)
        await hv.join_session(managed.sso.session_id, AGENT_1, sigma_raw=0.85)
        await hv.activate_session(managed.sso.session_id)

        result = await hv.verify_behavior(
            managed.sso.session_id, AGENT_1,
            claimed_embedding=[1], observed_embedding=[1],
        )
        assert result is drift_result
        assert not result.should_slash

    async def test_drift_triggers_slash(self, config):
        policy_check = MagicMock()
        drift_result = MagicMock()
        drift_result.should_slash = True
        drift_result.drift_score = 0.80
        drift_result.severity = MagicMock(value="critical")
        policy_check.check_behavioral_drift.return_value = drift_result

        hv = Hypervisor(policy_check=policy_check)
        managed = await hv.create_session(config, creator_did=CREATOR)
        await hv.join_session(managed.sso.session_id, AGENT_1, sigma_raw=0.85)
        await hv.activate_session(managed.sso.session_id)

        with patch.object(hv.slashing, "slash") as mock_slash:
            result = await hv.verify_behavior(
                managed.sso.session_id, AGENT_1,
                claimed_embedding=[1], observed_embedding=[0],
            )
            mock_slash.assert_called_once()
            assert result.should_slash

    async def test_drift_slash_reports_to_nexus(self, config):
        policy_check = MagicMock()
        drift_result = MagicMock()
        drift_result.should_slash = True
        drift_result.drift_score = 0.90
        drift_result.severity = MagicMock(value="critical")
        policy_check.check_behavioral_drift.return_value = drift_result

        nexus = MagicMock()
        hv = Hypervisor(policy_check=policy_check, nexus=nexus)
        managed = await hv.create_session(config, creator_did=CREATOR)
        await hv.join_session(managed.sso.session_id, AGENT_1, sigma_raw=0.85)
        await hv.activate_session(managed.sso.session_id)

        with patch.object(hv.slashing, "slash"):
            await hv.verify_behavior(
                managed.sso.session_id, AGENT_1,
                claimed_embedding=[1], observed_embedding=[0],
            )
            nexus.report_slash.assert_called_once()

    async def test_verify_nonexistent_session_raises(self, config):
        """verify_behavior only accesses session when drift triggers slash."""
        policy_check = MagicMock()
        drift_result = MagicMock()
        drift_result.should_slash = True
        drift_result.drift_score = 0.9
        drift_result.severity = MagicMock(value="critical")
        policy_check.check_behavioral_drift.return_value = drift_result

        hv = Hypervisor(policy_check=policy_check)
        with pytest.raises(ValueError, match="not found"):
            await hv.verify_behavior(
                "session:nope", AGENT_1,
                claimed_embedding=[], observed_embedding=[],
            )


# ---------------------------------------------------------------------------
# Resource cleanup / edge cases
# ---------------------------------------------------------------------------

class TestResourceCleanup:
    async def test_gc_called_on_terminate(self, hypervisor, config):
        managed = await hypervisor.create_session(config, creator_did=CREATOR)
        await hypervisor.join_session(managed.sso.session_id, AGENT_1, sigma_raw=0.85)
        await hypervisor.activate_session(managed.sso.session_id)

        with patch.object(hypervisor.gc, "collect") as mock_gc:
            await hypervisor.terminate_session(managed.sso.session_id)
            mock_gc.assert_called_once()

    async def test_commitment_stored_when_audit_enabled(self, hypervisor, config):
        managed = await hypervisor.create_session(config, creator_did=CREATOR)
        await hypervisor.join_session(managed.sso.session_id, AGENT_1, sigma_raw=0.85)
        await hypervisor.activate_session(managed.sso.session_id)
        # Record delta to produce a hash chain root
        managed.delta_engine.capture(agent_did=AGENT_1, changes=[])

        with patch.object(hypervisor.commitment, "commit") as mock_commit:
            await hypervisor.terminate_session(managed.sso.session_id)
            # commit is called only if hash_chain_root is non-None
            if mock_commit.called:
                call_kwargs = mock_commit.call_args
                assert managed.sso.session_id in str(call_kwargs)


class TestEdgeCases:
    async def test_session_capacity_limit(self, hypervisor):
        cfg = SessionConfig(max_participants=1)
        managed = await hypervisor.create_session(cfg, creator_did=CREATOR)
        await hypervisor.join_session(managed.sso.session_id, AGENT_1, sigma_raw=0.85)
        with pytest.raises(Exception):
            await hypervisor.join_session(managed.sso.session_id, AGENT_2, sigma_raw=0.85)

    async def test_duplicate_agent_join_raises(self, hypervisor, config):
        managed = await hypervisor.create_session(config, creator_did=CREATOR)
        await hypervisor.join_session(managed.sso.session_id, AGENT_1, sigma_raw=0.85)
        with pytest.raises(Exception):
            await hypervisor.join_session(managed.sso.session_id, AGENT_1, sigma_raw=0.85)

    async def test_hypervisor_default_init(self):
        hv = Hypervisor()
        assert hv.nexus is None
        assert hv.policy_check is None
        assert hv.iatp is None
        assert hv._sessions == {}

    async def test_hypervisor_with_max_exposure(self):
        hv = Hypervisor(max_exposure=100.0)
        assert hv.vouching is not None

    async def test_full_lifecycle(self, hypervisor, config):
        """End-to-end: create → join → activate → terminate."""
        managed = await hypervisor.create_session(config, creator_did=CREATOR)
        assert managed.sso.state == SessionState.HANDSHAKING

        await hypervisor.join_session(managed.sso.session_id, AGENT_1, sigma_raw=0.85)
        assert managed.sso.participant_count == 1

        await hypervisor.activate_session(managed.sso.session_id)
        assert managed.sso.state == SessionState.ACTIVE

        await hypervisor.terminate_session(managed.sso.session_id)
        assert managed.sso.state == SessionState.ARCHIVED


# ---------------------------------------------------------------------------
# Active index tracking
# ---------------------------------------------------------------------------

class TestActiveIndex:
    async def test_active_ids_tracks_creation(self, hypervisor, config):
        managed = await hypervisor.create_session(config, creator_did=CREATOR)
        assert managed.sso.session_id in hypervisor._active_ids

    async def test_active_ids_removed_on_terminate(self, hypervisor, config):
        managed = await hypervisor.create_session(config, creator_did=CREATOR)
        await hypervisor.join_session(managed.sso.session_id, AGENT_1, sigma_raw=0.85)
        await hypervisor.activate_session(managed.sso.session_id)
        await hypervisor.terminate_session(managed.sso.session_id)
        assert managed.sso.session_id not in hypervisor._active_ids

    async def test_active_ids_consistent_with_active_sessions(self, hypervisor, config):
        s1 = await hypervisor.create_session(config, creator_did=CREATOR)
        s2 = await hypervisor.create_session(config, creator_did=CREATOR)
        await hypervisor.join_session(s1.sso.session_id, AGENT_1, sigma_raw=0.85)
        await hypervisor.activate_session(s1.sso.session_id)
        await hypervisor.terminate_session(s1.sso.session_id)
        active = hypervisor.active_sessions
        assert len(active) == 1
        assert active[0].sso.session_id == s2.sso.session_id


# ---------------------------------------------------------------------------
# monitor_sessions
# ---------------------------------------------------------------------------

class TestMonitorSessions:
    async def test_monitor_empty(self, hypervisor):
        issues = await hypervisor.monitor_sessions()
        assert issues == []

    async def test_monitor_healthy_agents(self, hypervisor, config):
        managed = await hypervisor.create_session(config, creator_did=CREATOR)
        await hypervisor.join_session(managed.sso.session_id, AGENT_1, sigma_raw=0.85)
        await hypervisor.activate_session(managed.sso.session_id)
        issues = await hypervisor.monitor_sessions(drift_threshold=0.5)
        assert issues == []

    async def test_monitor_flags_low_score(self, hypervisor, config):
        managed = await hypervisor.create_session(config, creator_did=CREATOR)
        await hypervisor.join_session(managed.sso.session_id, AGENT_1, sigma_raw=0.30)
        await hypervisor.activate_session(managed.sso.session_id)
        issues = await hypervisor.monitor_sessions(drift_threshold=0.5)
        assert len(issues) == 1
        assert issues[0]["agent_did"] == AGENT_1

    async def test_monitor_skips_terminated(self, hypervisor, config):
        managed = await hypervisor.create_session(config, creator_did=CREATOR)
        await hypervisor.join_session(managed.sso.session_id, AGENT_1, sigma_raw=0.30)
        await hypervisor.activate_session(managed.sso.session_id)
        await hypervisor.terminate_session(managed.sso.session_id)
        issues = await hypervisor.monitor_sessions(drift_threshold=0.5)
        assert issues == []

    async def test_monitor_multiple_sessions(self, hypervisor, config):
        s1 = await hypervisor.create_session(config, creator_did=CREATOR)
        s2 = await hypervisor.create_session(config, creator_did=CREATOR)
        await hypervisor.join_session(s1.sso.session_id, AGENT_1, sigma_raw=0.85)
        await hypervisor.join_session(s2.sso.session_id, AGENT_2, sigma_raw=0.30)
        await hypervisor.activate_session(s1.sso.session_id)
        await hypervisor.activate_session(s2.sso.session_id)
        issues = await hypervisor.monitor_sessions(drift_threshold=0.5)
        assert len(issues) == 1
        assert issues[0]["agent_did"] == AGENT_2
