# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Shared Session Object — lifecycle manager for multi-agent sessions."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timezone
from typing import Any, Optional

from hypervisor.models import (
    ConsistencyMode,
    ExecutionRing,
    SessionConfig,
    SessionParticipant,
    SessionState,
)
from hypervisor.session.sso import SessionVFS


class SharedSessionObject:
    """
    Encapsulates a multi-agent interaction.

    Every Shared Session has:
    - SessionID: UUID bound to a DID
    - ConsistencyMode: Strong (consensus) or Eventual (gossip)
    - StateSubstrate: A VFS representing the shared world
    - LiabilityMatrix: Registry of who sponsors for whom

    Lifecycle: created → handshaking → active → terminating → archived
    """

    def __init__(
        self,
        config: SessionConfig,
        creator_did: str,
        session_id: str | None = None,
    ):
        self.session_id = session_id or f"session:{uuid.uuid4()}"
        self.creator_did = creator_did
        self.config = config
        self.state = SessionState.CREATED
        self.consistency_mode = config.consistency_mode

        # Participants
        self._participants: dict[str, SessionParticipant] = {}

        # VFS state substrate (namespace for this session)
        self.vfs_namespace = f"/sessions/{self.session_id}"
        self.vfs = SessionVFS(self.session_id, namespace=self.vfs_namespace)
        self._vfs_snapshots: dict[str, Any] = {}

        # Timestamps
        self.created_at = datetime.now(UTC)
        self.terminated_at: datetime | None = None

    @property
    def participants(self) -> list[SessionParticipant]:
        """Active participants in this session."""
        return [p for p in self._participants.values() if p.is_active]

    @property
    def participant_count(self) -> int:
        # Avoid building a filtered list just to count
        return sum(1 for p in self._participants.values() if p.is_active)

    def _assert_state(self, *allowed: SessionState) -> None:
        if self.state not in allowed:
            raise SessionLifecycleError(
                f"Operation not allowed in state {self.state.value}. "
                f"Allowed: {[s.value for s in allowed]}"
            )

    def begin_handshake(self) -> None:
        """Transition to handshaking phase."""
        self._assert_state(SessionState.CREATED)
        self.state = SessionState.HANDSHAKING

    def activate(self) -> None:
        """Transition to active execution phase."""
        self._assert_state(SessionState.HANDSHAKING)
        if not self._participants:
            raise SessionLifecycleError("Cannot activate session with no participants")
        self.state = SessionState.ACTIVE

    def join(
        self,
        agent_did: str,
        sigma_raw: float = 0.0,
        eff_score: float = 0.0,
        ring: ExecutionRing = ExecutionRing.RING_3_SANDBOX,
    ) -> SessionParticipant:
        """Add an agent to this session."""
        self._assert_state(SessionState.HANDSHAKING, SessionState.ACTIVE)

        if agent_did in self._participants:
            raise SessionParticipantError(f"Agent {agent_did} already in session")
        if self.participant_count >= self.config.max_participants:
            raise SessionParticipantError(
                f"Session at capacity ({self.config.max_participants})"
            )
        if eff_score < self.config.min_eff_score and ring != ExecutionRing.RING_3_SANDBOX:
            raise SessionParticipantError(
                f"eff_score {eff_score:.2f} below minimum {self.config.min_eff_score:.2f}"
            )

        participant = SessionParticipant(
            agent_did=agent_did,
            ring=ring,
            sigma_raw=sigma_raw,
            eff_score=eff_score,
        )
        self._participants[agent_did] = participant
        return participant

    def leave(self, agent_did: str) -> None:
        """Remove an agent from this session."""
        if agent_did not in self._participants:
            raise SessionParticipantError(f"Agent {agent_did} not in session")
        self._participants[agent_did].is_active = False

    def get_participant(self, agent_did: str) -> SessionParticipant:
        """Get a participant by DID."""
        if agent_did not in self._participants:
            raise SessionParticipantError(f"Agent {agent_did} not in session")
        return self._participants[agent_did]

    def update_ring(self, agent_did: str, new_ring: ExecutionRing) -> None:
        """Update an agent's ring level (escalation or demotion)."""
        participant = self.get_participant(agent_did)
        participant.ring = new_ring

    def force_consistency_mode(self, mode: ConsistencyMode) -> None:
        """Force a consistency mode (e.g., when non-reversible actions are detected)."""
        self.consistency_mode = mode

    def terminate(self) -> None:
        """Begin session termination."""
        self._assert_state(SessionState.ACTIVE, SessionState.HANDSHAKING)
        self.state = SessionState.TERMINATING
        self.terminated_at = datetime.now(UTC)

    def archive(self) -> None:
        """Archive the session after audit commitment."""
        self._assert_state(SessionState.TERMINATING)
        self.state = SessionState.ARCHIVED

    def create_vfs_snapshot(self, snapshot_id: str | None = None) -> str:
        """Create a VFS state snapshot for rollback.

        Captures both VFS file state (snapshot) and participant metadata.
        """
        self._assert_state(SessionState.ACTIVE)
        # Snapshot the VFS file state
        sid = self.vfs.create_snapshot(snapshot_id)
        # Also snapshot participant metadata for full restore
        self._vfs_snapshots[sid] = {
            "created_at": datetime.now(UTC).isoformat(),
            "participant_states": {
                did: {"ring": p.ring.value, "eff_score": p.eff_score}
                for did, p in self._participants.items()
            },
        }
        return sid

    def restore_vfs_snapshot(
        self, snapshot_id: str, agent_did: str
    ) -> None:
        """Restore VFS to a previous snapshot.

        Args:
            snapshot_id: ID returned by create_vfs_snapshot.
            agent_did: Agent requesting the restore (recorded in audit log).
        """
        self._assert_state(SessionState.ACTIVE)
        self.vfs.restore_snapshot(snapshot_id, agent_did)

    def __repr__(self) -> str:
        return (
            f"SharedSessionObject(id={self.session_id!r}, "
            f"state={self.state.value}, "
            f"participants={self.participant_count}, "
            f"mode={self.consistency_mode.value})"
        )


class SessionLifecycleError(Exception):
    """Raised when a session lifecycle transition is invalid."""


class SessionParticipantError(Exception):
    """Raised for participant-related errors."""
