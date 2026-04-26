# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for input validation on agent configuration models."""

import pytest

from hypervisor.models import (
    ActionDescriptor,
    ExecutionRing,
    SessionConfig,
    SessionParticipant,
)


class TestSessionConfigValidation:
    """Validation tests for SessionConfig."""

    def test_valid_defaults(self):
        config = SessionConfig()
        assert config.max_participants == 10
        assert config.max_duration_seconds == 3600

    def test_valid_custom_values(self):
        config = SessionConfig(max_participants=50, max_duration_seconds=7200, min_eff_score=0.8)
        assert config.max_participants == 50

    def test_max_participants_zero(self):
        with pytest.raises(ValueError, match="max_participants must be at least 1"):
            SessionConfig(max_participants=0)

    def test_max_participants_negative(self):
        with pytest.raises(ValueError, match="max_participants must be at least 1"):
            SessionConfig(max_participants=-5)

    def test_max_participants_exceeds_limit(self):
        with pytest.raises(ValueError, match="max_participants must not exceed 1000"):
            SessionConfig(max_participants=1001)

    def test_max_duration_zero(self):
        with pytest.raises(ValueError, match="max_duration_seconds must be at least 1"):
            SessionConfig(max_duration_seconds=0)

    def test_max_duration_negative(self):
        with pytest.raises(ValueError, match="max_duration_seconds must be at least 1"):
            SessionConfig(max_duration_seconds=-100)

    def test_max_duration_exceeds_limit(self):
        with pytest.raises(ValueError, match="max_duration_seconds must not exceed 604800"):
            SessionConfig(max_duration_seconds=700_000)

    def test_min_eff_score_negative(self):
        with pytest.raises(ValueError, match="min_eff_score must be between 0.0 and 1.0"):
            SessionConfig(min_eff_score=-0.1)

    def test_min_eff_score_above_one(self):
        with pytest.raises(ValueError, match="min_eff_score must be between 0.0 and 1.0"):
            SessionConfig(min_eff_score=1.5)

    def test_min_eff_score_boundary_zero(self):
        config = SessionConfig(min_eff_score=0.0)
        assert config.min_eff_score == 0.0

    def test_min_eff_score_boundary_one(self):
        config = SessionConfig(min_eff_score=1.0)
        assert config.min_eff_score == 1.0


class TestSessionParticipantValidation:
    """Validation tests for SessionParticipant."""

    def test_valid_participant(self):
        p = SessionParticipant(agent_did="did:mesh:agent-1")
        assert p.agent_did == "did:mesh:agent-1"

    def test_empty_agent_did(self):
        with pytest.raises(ValueError, match="agent_did must not be empty"):
            SessionParticipant(agent_did="")

    def test_whitespace_agent_did(self):
        with pytest.raises(ValueError, match="agent_did must not be empty"):
            SessionParticipant(agent_did="   ")

    def test_agent_did_special_characters(self):
        with pytest.raises(ValueError, match="agent_did contains invalid characters"):
            SessionParticipant(agent_did="agent<script>")

    def test_agent_did_path_traversal(self):
        with pytest.raises(ValueError, match="agent_did contains invalid characters"):
            SessionParticipant(agent_did="../../../etc/passwd")

    def test_agent_did_too_long(self):
        with pytest.raises(ValueError, match="agent_did exceeds maximum length"):
            SessionParticipant(agent_did="a" * 257)

    def test_agent_did_valid_formats(self):
        # DID format
        p1 = SessionParticipant(agent_did="did:mesh:agent-1")
        assert p1.agent_did == "did:mesh:agent-1"
        # Dotted format
        p2 = SessionParticipant(agent_did="agent.example.com")
        assert p2.agent_did == "agent.example.com"
        # Simple alphanumeric
        p3 = SessionParticipant(agent_did="agent_123")
        assert p3.agent_did == "agent_123"

    def test_sigma_raw_negative(self):
        with pytest.raises(ValueError, match="sigma_raw must be between 0.0 and 1.0"):
            SessionParticipant(agent_did="did:mesh:a", sigma_raw=-0.1)

    def test_sigma_raw_above_one(self):
        with pytest.raises(ValueError, match="sigma_raw must be between 0.0 and 1.0"):
            SessionParticipant(agent_did="did:mesh:a", sigma_raw=1.5)

    def test_eff_score_negative(self):
        with pytest.raises(ValueError, match="eff_score must be between 0.0 and 1.0"):
            SessionParticipant(agent_did="did:mesh:a", eff_score=-0.5)

    def test_eff_score_above_one(self):
        with pytest.raises(ValueError, match="eff_score must be between 0.0 and 1.0"):
            SessionParticipant(agent_did="did:mesh:a", eff_score=2.0)

    def test_valid_ring_assignment(self):
        for ring in ExecutionRing:
            p = SessionParticipant(agent_did="did:mesh:a", ring=ring)
            assert p.ring == ring

    def test_invalid_ring_int(self):
        with pytest.raises(ValueError, match="ring must be a valid ExecutionRing"):
            SessionParticipant(agent_did="did:mesh:a", ring=5)


class TestActionDescriptorValidation:
    """Validation tests for ActionDescriptor."""

    def test_valid_action(self):
        action = ActionDescriptor(
            action_id="search",
            name="Search",
            execute_api="/api/search",
        )
        assert action.action_id == "search"

    def test_empty_action_id(self):
        with pytest.raises(ValueError, match="action_id must not be empty"):
            ActionDescriptor(action_id="", name="Test", execute_api="/api/test")

    def test_action_id_special_characters(self):
        with pytest.raises(ValueError, match="action_id contains invalid characters"):
            ActionDescriptor(action_id="action;DROP TABLE", name="Test", execute_api="/api/test")

    def test_empty_name(self):
        with pytest.raises(ValueError, match="name must be a non-empty string"):
            ActionDescriptor(action_id="test", name="", execute_api="/api/test")

    def test_empty_execute_api(self):
        with pytest.raises(ValueError, match="execute_api must not be empty"):
            ActionDescriptor(action_id="test", name="Test", execute_api="")

    def test_undo_window_negative(self):
        with pytest.raises(ValueError, match="undo_window_seconds must not be negative"):
            ActionDescriptor(
                action_id="test", name="Test", execute_api="/api/test",
                undo_window_seconds=-1,
            )

    def test_undo_window_exceeds_limit(self):
        with pytest.raises(ValueError, match="undo_window_seconds must not exceed 86400"):
            ActionDescriptor(
                action_id="test", name="Test", execute_api="/api/test",
                undo_window_seconds=100_000,
            )

    def test_undo_window_valid_boundary(self):
        action = ActionDescriptor(
            action_id="test", name="Test", execute_api="/api/test",
            undo_window_seconds=86400,
        )
        assert action.undo_window_seconds == 86400

    def test_action_id_too_long(self):
        with pytest.raises(ValueError, match="action_id exceeds maximum length"):
            ActionDescriptor(
                action_id="a" * 257, name="Test", execute_api="/api/test",
            )

    def test_name_too_long(self):
        with pytest.raises(ValueError, match="name exceeds maximum length"):
            ActionDescriptor(
                action_id="test", name="x" * 257, execute_api="/api/test",
            )

    def test_valid_undo_api_validated(self):
        action = ActionDescriptor(
            action_id="test", name="Test",
            execute_api="/api/test", undo_api="/api/test/undo",
        )
        assert action.undo_api == "/api/test/undo"

    def test_empty_undo_api_rejected(self):
        with pytest.raises(ValueError, match="undo_api must not be empty"):
            ActionDescriptor(
                action_id="test", name="Test",
                execute_api="/api/test", undo_api="",
            )
