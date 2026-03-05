# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Comprehensive tests for VFS state substrate per session (issue #234).

Acceptance Criteria:
- Each session gets an isolated VFS namespace
- Writes by Agent A don't leak to Session B's VFS
- Agent attribution is recorded for every write
- Snapshots can be created and restored
- Permission enforcement works correctly
"""

import pytest

from hypervisor.models import ExecutionRing, SessionConfig
from hypervisor.session import (
    SessionLifecycleError,
    SharedSessionObject,
)
from hypervisor.session.sso import SessionVFS, VFSPermissionError

# ---------------------------------------------------------------------------
# SessionVFS — Core read/write operations
# ---------------------------------------------------------------------------


class TestVFSReadWrite:
    """Basic read/write/delete operations."""

    def setup_method(self):
        self.vfs = SessionVFS("session:rw-test")

    def test_write_creates_file(self):
        edit = self.vfs.write("main.py", "print('hello')", "did:agent1")
        assert edit.operation == "create"
        assert edit.content_hash is not None
        assert edit.previous_hash is None

    def test_read_returns_content(self):
        self.vfs.write("main.py", "print('hello')", "did:agent1")
        assert self.vfs.read("main.py") == "print('hello')"

    def test_read_nonexistent_returns_none(self):
        assert self.vfs.read("does_not_exist.py") is None

    def test_update_records_previous_hash(self):
        self.vfs.write("file.txt", "v1", "did:a")
        edit = self.vfs.write("file.txt", "v2", "did:b")
        assert edit.operation == "update"
        assert edit.previous_hash is not None

    def test_write_overwrites_content(self):
        self.vfs.write("file.txt", "v1", "did:a")
        self.vfs.write("file.txt", "v2", "did:a")
        assert self.vfs.read("file.txt") == "v2"

    def test_delete_removes_file(self):
        self.vfs.write("file.txt", "data", "did:a")
        edit = self.vfs.delete("file.txt", "did:a")
        assert edit.operation == "delete"
        assert edit.previous_hash is not None
        assert self.vfs.read("file.txt") is None

    def test_delete_nonexistent_raises(self):
        with pytest.raises(FileNotFoundError, match="not found"):
            self.vfs.delete("ghost.txt", "did:a")

    def test_list_files(self):
        self.vfs.write("a.py", "a", "did:a")
        self.vfs.write("b.py", "b", "did:a")
        files = self.vfs.list_files()
        assert sorted(files) == ["/a.py", "/b.py"]

    def test_list_files_empty(self):
        assert self.vfs.list_files() == []

    def test_file_count(self):
        assert self.vfs.file_count == 0
        self.vfs.write("a.py", "a", "did:a")
        assert self.vfs.file_count == 1
        self.vfs.write("b.py", "b", "did:a")
        assert self.vfs.file_count == 2
        self.vfs.delete("a.py", "did:a")
        assert self.vfs.file_count == 1


# ---------------------------------------------------------------------------
# SessionVFS — Namespace isolation
# ---------------------------------------------------------------------------


class TestVFSNamespaceIsolation:
    """Sessions get isolated VFS namespaces; writes don't leak."""

    def test_different_sessions_are_isolated(self):
        vfs1 = SessionVFS("session:1")
        vfs2 = SessionVFS("session:2")
        vfs1.write("file.txt", "data_from_session1", "did:a")
        assert vfs2.read("file.txt") is None

    def test_same_relative_path_different_sessions(self):
        vfs1 = SessionVFS("session:1")
        vfs2 = SessionVFS("session:2")
        vfs1.write("shared_name.txt", "content-1", "did:a")
        vfs2.write("shared_name.txt", "content-2", "did:b")
        assert vfs1.read("shared_name.txt") == "content-1"
        assert vfs2.read("shared_name.txt") == "content-2"

    def test_namespace_prefix_applied(self):
        vfs = SessionVFS("session:ns-test")
        edit = vfs.write("myfile.txt", "data", "did:a")
        assert edit.path.startswith("/sessions/session:ns-test/")

    def test_absolute_path_within_namespace(self):
        vfs = SessionVFS("session:abs-test")
        vfs.write("/sessions/session:abs-test/direct.txt", "data", "did:a")
        assert vfs.read("direct.txt") == "data"

    def test_custom_namespace(self):
        vfs = SessionVFS("session:custom", namespace="/custom/ns")
        edit = vfs.write("hello.txt", "world", "did:a")
        assert edit.path.startswith("/custom/ns/")
        assert vfs.read("hello.txt") == "world"

    def test_list_files_only_returns_own_namespace(self):
        """Even if multiple VFS instances existed, list_files only returns own."""
        vfs = SessionVFS("session:list-test")
        vfs.write("a.py", "x", "did:a")
        vfs.write("b.py", "y", "did:a")
        files = vfs.list_files()
        assert len(files) == 2


# ---------------------------------------------------------------------------
# SessionVFS — Agent attribution
# ---------------------------------------------------------------------------


class TestVFSAttribution:
    """Every VFS edit records which agent performed it."""

    def setup_method(self):
        self.vfs = SessionVFS("session:attr-test")

    def test_write_records_agent(self):
        edit = self.vfs.write("file.txt", "data", "did:writer")
        assert edit.agent_did == "did:writer"

    def test_update_records_different_agent(self):
        self.vfs.write("file.txt", "v1", "did:agent-a")
        edit = self.vfs.write("file.txt", "v2", "did:agent-b")
        assert edit.agent_did == "did:agent-b"

    def test_delete_records_agent(self):
        self.vfs.write("file.txt", "data", "did:creator")
        edit = self.vfs.delete("file.txt", "did:deleter")
        assert edit.agent_did == "did:deleter"

    def test_edit_log_captures_all_operations(self):
        self.vfs.write("a.txt", "1", "did:a")
        self.vfs.write("b.txt", "2", "did:b")
        self.vfs.write("a.txt", "3", "did:b")
        self.vfs.delete("b.txt", "did:a")
        log = self.vfs.edit_log
        assert len(log) == 4
        assert log[0].operation == "create"
        assert log[1].operation == "create"
        assert log[2].operation == "update"
        assert log[3].operation == "delete"

    def test_edit_log_is_immutable_copy(self):
        self.vfs.write("file.txt", "data", "did:a")
        log1 = self.vfs.edit_log
        log2 = self.vfs.edit_log
        assert log1 is not log2

    def test_edits_by_agent_filter(self):
        self.vfs.write("a.txt", "1", "did:agent-a")
        self.vfs.write("b.txt", "2", "did:agent-b")
        self.vfs.write("c.txt", "3", "did:agent-a")
        edits_a = self.vfs.edits_by_agent("did:agent-a")
        edits_b = self.vfs.edits_by_agent("did:agent-b")
        assert len(edits_a) == 2
        assert len(edits_b) == 1
        assert all(e.agent_did == "did:agent-a" for e in edits_a)

    def test_edits_by_agent_empty(self):
        self.vfs.write("a.txt", "1", "did:agent-a")
        assert self.vfs.edits_by_agent("did:ghost") == []

    def test_edit_has_timestamp(self):
        edit = self.vfs.write("file.txt", "data", "did:a")
        assert edit.timestamp is not None

    def test_content_hash_differs_for_different_content(self):
        edit1 = self.vfs.write("a.txt", "content-1", "did:a")
        edit2 = self.vfs.write("b.txt", "content-2", "did:a")
        assert edit1.content_hash != edit2.content_hash


# ---------------------------------------------------------------------------
# SessionVFS — Snapshot / Restore (snapshot)
# ---------------------------------------------------------------------------


class TestVFSSnapshots:
    """Snapshot create and restore with snapshot semantics."""

    def setup_method(self):
        self.vfs = SessionVFS("session:snap-test")

    def test_create_and_restore_snapshot(self):
        self.vfs.write("file.txt", "original", "did:a")
        snap_id = self.vfs.create_snapshot()
        self.vfs.write("file.txt", "modified", "did:b")
        assert self.vfs.read("file.txt") == "modified"
        self.vfs.restore_snapshot(snap_id, "did:a")
        assert self.vfs.read("file.txt") == "original"

    def test_snapshot_is_copy_on_write(self):
        """Mutating files after snapshot does NOT affect the snapshot."""
        self.vfs.write("file.txt", "v1", "did:a")
        snap_id = self.vfs.create_snapshot()
        self.vfs.write("file.txt", "v2", "did:a")
        self.vfs.write("new.txt", "new", "did:a")
        self.vfs.restore_snapshot(snap_id, "did:a")
        assert self.vfs.read("file.txt") == "v1"
        assert self.vfs.read("new.txt") is None

    def test_restore_nonexistent_snapshot_raises(self):
        with pytest.raises(KeyError, match="not found"):
            self.vfs.restore_snapshot("snap:ghost", "did:a")

    def test_multiple_snapshots(self):
        self.vfs.write("file.txt", "v1", "did:a")
        snap1 = self.vfs.create_snapshot()
        self.vfs.write("file.txt", "v2", "did:a")
        snap2 = self.vfs.create_snapshot()
        self.vfs.write("file.txt", "v3", "did:a")

        self.vfs.restore_snapshot(snap2, "did:a")
        assert self.vfs.read("file.txt") == "v2"

        self.vfs.restore_snapshot(snap1, "did:a")
        assert self.vfs.read("file.txt") == "v1"

    def test_restore_records_in_edit_log(self):
        self.vfs.write("file.txt", "data", "did:a")
        snap = self.vfs.create_snapshot()
        self.vfs.restore_snapshot(snap, "did:restorer")
        restore_edits = [e for e in self.vfs.edit_log if e.operation == "restore"]
        assert len(restore_edits) == 1
        assert restore_edits[0].agent_did == "did:restorer"

    def test_list_snapshots(self):
        s1 = self.vfs.create_snapshot()
        s2 = self.vfs.create_snapshot()
        snaps = self.vfs.list_snapshots()
        assert s1 in snaps
        assert s2 in snaps
        assert len(snaps) == 2

    def test_delete_snapshot(self):
        s1 = self.vfs.create_snapshot()
        self.vfs.delete_snapshot(s1)
        assert s1 not in self.vfs.list_snapshots()

    def test_delete_nonexistent_snapshot_raises(self):
        with pytest.raises(KeyError, match="not found"):
            self.vfs.delete_snapshot("snap:nope")

    def test_snapshot_count(self):
        assert self.vfs.snapshot_count == 0
        self.vfs.create_snapshot()
        assert self.vfs.snapshot_count == 1
        self.vfs.create_snapshot()
        assert self.vfs.snapshot_count == 2

    def test_named_snapshot(self):
        sid = self.vfs.create_snapshot("my-checkpoint")
        assert sid == "my-checkpoint"
        assert "my-checkpoint" in self.vfs.list_snapshots()

    def test_snapshot_of_empty_vfs(self):
        snap = self.vfs.create_snapshot()
        self.vfs.write("file.txt", "data", "did:a")
        self.vfs.restore_snapshot(snap, "did:a")
        assert self.vfs.read("file.txt") is None
        assert self.vfs.file_count == 0

    def test_snapshot_includes_permissions(self):
        """Restoring a snapshot also restores the permission state."""
        self.vfs.write("secret.txt", "classified", "did:owner")
        self.vfs.set_permissions("secret.txt", {"did:owner"}, "did:owner")
        snap = self.vfs.create_snapshot()

        # Clear permissions after the snapshot
        self.vfs.clear_permissions("secret.txt")
        # Now anyone can read
        assert self.vfs.read("secret.txt", agent_did="did:intruder") == "classified"

        # Restore snapshot — permissions should be back
        self.vfs.restore_snapshot(snap, "did:owner")
        with pytest.raises(VFSPermissionError):
            self.vfs.read("secret.txt", agent_did="did:intruder")
        assert self.vfs.read("secret.txt", agent_did="did:owner") == "classified"

    def test_snapshot_permissions_isolation(self):
        """Permissions added after snapshot are removed on restore."""
        self.vfs.write("file.txt", "open-data", "did:a")
        snap = self.vfs.create_snapshot()

        # Lock the file
        self.vfs.set_permissions("file.txt", {"did:a"}, "did:a")
        with pytest.raises(VFSPermissionError):
            self.vfs.read("file.txt", agent_did="did:b")

        # Restore — file should be open again
        self.vfs.restore_snapshot(snap, "did:a")
        assert self.vfs.read("file.txt", agent_did="did:b") == "open-data"


# ---------------------------------------------------------------------------
# SessionVFS — Permission enforcement
# ---------------------------------------------------------------------------


class TestVFSPermissions:
    """Path-level permission enforcement."""

    def setup_method(self):
        self.vfs = SessionVFS("session:perm-test")

    def test_unrestricted_by_default(self):
        """Any agent can write/read when no permissions are set."""
        self.vfs.write("file.txt", "data", "did:any-agent")
        assert self.vfs.read("file.txt") == "data"

    def test_set_permissions_restricts_write(self):
        self.vfs.write("secret.txt", "initial", "did:owner")
        self.vfs.set_permissions("secret.txt", {"did:owner"}, "did:owner")
        with pytest.raises(VFSPermissionError):
            self.vfs.write("secret.txt", "hacked", "did:intruder")

    def test_allowed_agent_can_write(self):
        self.vfs.write("shared.txt", "v1", "did:a")
        self.vfs.set_permissions("shared.txt", {"did:a", "did:b"}, "did:a")
        self.vfs.write("shared.txt", "v2", "did:b")
        assert self.vfs.read("shared.txt") == "v2"

    def test_permission_enforced_on_read(self):
        self.vfs.write("private.txt", "secret", "did:owner")
        self.vfs.set_permissions("private.txt", {"did:owner"}, "did:owner")
        with pytest.raises(VFSPermissionError):
            self.vfs.read("private.txt", agent_did="did:stranger")

    def test_read_without_agent_skips_check(self):
        """read() without agent_did bypasses permission (backward compat)."""
        self.vfs.write("private.txt", "secret", "did:owner")
        self.vfs.set_permissions("private.txt", {"did:owner"}, "did:owner")
        assert self.vfs.read("private.txt") == "secret"

    def test_permission_enforced_on_delete(self):
        self.vfs.write("guarded.txt", "data", "did:owner")
        self.vfs.set_permissions("guarded.txt", {"did:owner"}, "did:owner")
        with pytest.raises(VFSPermissionError):
            self.vfs.delete("guarded.txt", "did:intruder")

    def test_clear_permissions(self):
        self.vfs.write("file.txt", "data", "did:owner")
        self.vfs.set_permissions("file.txt", {"did:owner"}, "did:owner")
        self.vfs.clear_permissions("file.txt")
        # Now anyone can write
        self.vfs.write("file.txt", "new-data", "did:anyone")
        assert self.vfs.read("file.txt") == "new-data"

    def test_get_permissions(self):
        self.vfs.write("file.txt", "data", "did:a")
        assert self.vfs.get_permissions("file.txt") is None
        self.vfs.set_permissions("file.txt", {"did:a", "did:b"}, "did:a")
        perms = self.vfs.get_permissions("file.txt")
        assert perms == {"did:a", "did:b"}

    def test_delete_cleans_up_permissions(self):
        self.vfs.write("file.txt", "data", "did:owner")
        self.vfs.set_permissions("file.txt", {"did:owner"}, "did:owner")
        self.vfs.delete("file.txt", "did:owner")
        assert self.vfs.get_permissions("file.txt") is None

    def test_set_permissions_recorded_in_log(self):
        self.vfs.write("file.txt", "data", "did:a")
        self.vfs.set_permissions("file.txt", {"did:a"}, "did:admin")
        perm_edits = [e for e in self.vfs.edit_log if e.operation == "permission"]
        assert len(perm_edits) == 1
        assert perm_edits[0].agent_did == "did:admin"


# ---------------------------------------------------------------------------
# SharedSessionObject — VFS integration
# ---------------------------------------------------------------------------


class TestSSOVFSIntegration:
    """SharedSessionObject provides an integrated VFS per session."""

    def setup_method(self):
        self.config = SessionConfig(max_participants=5, min_eff_score=0.5)
        self.sso = SharedSessionObject(config=self.config, creator_did="did:admin")
        self.sso.begin_handshake()
        self.sso.join("did:agent-a", eff_score=0.7, ring=ExecutionRing.RING_2_STANDARD)
        self.sso.activate()

    def test_sso_has_vfs(self):
        assert isinstance(self.sso.vfs, SessionVFS)
        assert self.sso.vfs.session_id == self.sso.session_id

    def test_vfs_namespace_matches_session(self):
        assert self.sso.vfs.namespace == f"/sessions/{self.sso.session_id}"

    def test_vfs_write_through_sso(self):
        self.sso.vfs.write("report.md", "# Report", "did:agent-a")
        assert self.sso.vfs.read("report.md") == "# Report"

    def test_two_sessions_have_isolated_vfs(self):
        sso2 = SharedSessionObject(config=self.config, creator_did="did:admin2")
        sso2.begin_handshake()
        sso2.join("did:agent-b", eff_score=0.7, ring=ExecutionRing.RING_2_STANDARD)
        sso2.activate()
        self.sso.vfs.write("shared.txt", "session1-data", "did:agent-a")
        assert sso2.vfs.read("shared.txt") is None

    def test_create_vfs_snapshot_through_sso(self):
        self.sso.vfs.write("file.txt", "original", "did:agent-a")
        snap = self.sso.create_vfs_snapshot()
        self.sso.vfs.write("file.txt", "modified", "did:agent-a")
        self.sso.restore_vfs_snapshot(snap, "did:agent-a")
        assert self.sso.vfs.read("file.txt") == "original"

    def test_create_vfs_snapshot_only_when_active(self):
        sso = SharedSessionObject(config=self.config, creator_did="did:admin")
        with pytest.raises(SessionLifecycleError):
            sso.create_vfs_snapshot()

    def test_restore_vfs_snapshot_only_when_active(self):
        sso = SharedSessionObject(config=self.config, creator_did="did:admin")
        with pytest.raises(SessionLifecycleError):
            sso.restore_vfs_snapshot("snap:fake", "did:a")

    def test_vfs_snapshot_captures_participant_metadata(self):
        snap = self.sso.create_vfs_snapshot()
        assert snap in self.sso._vfs_snapshots
        meta = self.sso._vfs_snapshots[snap]
        assert "participant_states" in meta
        assert "did:agent-a" in meta["participant_states"]
