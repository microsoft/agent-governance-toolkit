# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for session management and VFS."""

import pytest

from hypervisor.models import ConsistencyMode, ExecutionRing, SessionConfig
from hypervisor.session import (
    SessionLifecycleError,
    SessionParticipantError,
    SharedSessionObject,
)
from hypervisor.session.sso import SessionVFS


class TestSharedSessionObject:
    def setup_method(self):
        self.config = SessionConfig(max_participants=3, min_eff_score=0.5)
        self.sso = SharedSessionObject(config=self.config, creator_did="did:mesh:admin")

    def test_lifecycle_happy_path(self):
        self.sso.begin_handshake()
        self.sso.join("did:mesh:a", eff_score=0.7, ring=ExecutionRing.RING_2_STANDARD)
        self.sso.activate()
        self.sso.terminate()
        self.sso.archive()
        assert self.sso.state.value == "archived"

    def test_cannot_activate_without_participants(self):
        self.sso.begin_handshake()
        with pytest.raises(SessionLifecycleError, match="no participants"):
            self.sso.activate()

    def test_max_participants_enforced(self):
        self.sso.begin_handshake()
        self.sso.join("did:a", eff_score=0.7, ring=ExecutionRing.RING_2_STANDARD)
        self.sso.join("did:b", eff_score=0.7, ring=ExecutionRing.RING_2_STANDARD)
        self.sso.join("did:c", eff_score=0.7, ring=ExecutionRing.RING_2_STANDARD)
        with pytest.raises(SessionParticipantError, match="capacity"):
            self.sso.join("did:d", eff_score=0.7, ring=ExecutionRing.RING_2_STANDARD)

    def test_duplicate_agent_rejected(self):
        self.sso.begin_handshake()
        self.sso.join("did:a", eff_score=0.7, ring=ExecutionRing.RING_2_STANDARD)
        with pytest.raises(SessionParticipantError, match="already in session"):
            self.sso.join("did:a", eff_score=0.7, ring=ExecutionRing.RING_2_STANDARD)

    def test_force_consistency_mode(self):
        self.sso.force_consistency_mode(ConsistencyMode.STRONG)
        assert self.sso.consistency_mode == ConsistencyMode.STRONG

    def test_leave_marks_inactive(self):
        self.sso.begin_handshake()
        self.sso.join("did:a", eff_score=0.7, ring=ExecutionRing.RING_2_STANDARD)
        self.sso.leave("did:a")
        assert self.sso.participant_count == 0

    def test_invalid_state_transition(self):
        with pytest.raises(SessionLifecycleError):
            self.sso.activate()  # can't activate from CREATED


class TestSessionVFS:
    def setup_method(self):
        self.vfs = SessionVFS("session:test-vfs")

    def test_write_and_read(self):
        self.vfs.write("main.py", "print('hello')", "did:agent1")
        content = self.vfs.read("main.py")
        assert content == "print('hello')"

    def test_agent_attribution(self):
        edit = self.vfs.write("file.txt", "data", "did:agent1")
        assert edit.agent_did == "did:agent1"
        assert edit.operation == "create"

    def test_update_tracked(self):
        self.vfs.write("file.txt", "v1", "did:a")
        edit = self.vfs.write("file.txt", "v2", "did:b")
        assert edit.operation == "update"
        assert edit.previous_hash is not None

    def test_delete(self):
        self.vfs.write("file.txt", "data", "did:a")
        edit = self.vfs.delete("file.txt", "did:a")
        assert edit.operation == "delete"
        assert self.vfs.read("file.txt") is None

    def test_snapshot_and_restore(self):
        self.vfs.write("file.txt", "original", "did:a")
        snap = self.vfs.create_snapshot()
        self.vfs.write("file.txt", "modified", "did:b")
        assert self.vfs.read("file.txt") == "modified"
        self.vfs.restore_snapshot(snap, "did:a")
        assert self.vfs.read("file.txt") == "original"

    def test_session_isolation_via_namespace(self):
        vfs1 = SessionVFS("session:1")
        vfs2 = SessionVFS("session:2")
        vfs1.write("file.txt", "data1", "did:a")
        assert vfs2.read("file.txt") is None
