# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""Session-scoped VFS — simple dict-based storage."""

from __future__ import annotations

import collections
import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class VFSEdit:
    """A tracked edit to the session VFS."""

    path: str
    operation: str  # "create", "update", "delete", "permission", "restore"
    agent_did: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    content_hash: str | None = None
    previous_hash: str | None = None


class VFSPermissionError(Exception):
    """Raised when an agent lacks permission to access a VFS path."""


class SessionVFS:
    """
    Simple dict-based session storage.

    Public Preview: basic get/set/delete with a single global lock
    (threading.Lock omitted since Python GIL provides serialization).
    """

    def __init__(self, session_id: str, namespace: str | None = None):
        self.session_id = session_id
        self.namespace = namespace or f"/sessions/{session_id}"
        self._files: dict[str, str] = {}
        self._permissions: dict[str, set[str]] = {}
        self._edit_log: collections.deque[VFSEdit] = collections.deque(maxlen=10_000)
        self._snapshots: dict[str, dict[str, Any]] = {}

    def write(self, path: str, content: str, agent_did: str) -> VFSEdit:
        """Write a file."""
        full_path = self._resolve(path)
        self._check_permission(full_path, agent_did)
        operation = "update" if full_path in self._files else "create"
        previous_hash = _hash(self._files.get(full_path, "")) if operation == "update" else None
        self._files[full_path] = content
        edit = VFSEdit(
            path=full_path,
            operation=operation,
            agent_did=agent_did,
            content_hash=_hash(content),
            previous_hash=previous_hash,
        )
        self._edit_log.append(edit)
        return edit

    def read(self, path: str, agent_did: str | None = None) -> str | None:
        """Read a file."""
        full_path = self._resolve(path)
        if agent_did is not None:
            self._check_permission(full_path, agent_did)
        return self._files.get(full_path)

    def delete(self, path: str, agent_did: str) -> VFSEdit:
        """Delete a file."""
        full_path = self._resolve(path)
        if full_path not in self._files:
            raise FileNotFoundError(f"{full_path} not found in session VFS")
        self._check_permission(full_path, agent_did)
        previous_hash = _hash(self._files.pop(full_path))
        self._permissions.pop(full_path, None)
        edit = VFSEdit(
            path=full_path,
            operation="delete",
            agent_did=agent_did,
            previous_hash=previous_hash,
        )
        self._edit_log.append(edit)
        return edit

    def list_files(self) -> list[str]:
        """List all files in the session VFS."""
        prefix = self.namespace
        return [p.removeprefix(prefix) for p in self._files if p.startswith(prefix)]

    def set_permissions(
        self, path: str, allowed_agents: set[str], agent_did: str
    ) -> VFSEdit:
        """Set path-level permissions."""
        full_path = self._resolve(path)
        self._permissions[full_path] = set(allowed_agents)
        edit = VFSEdit(path=full_path, operation="permission", agent_did=agent_did)
        self._edit_log.append(edit)
        return edit

    def clear_permissions(self, path: str) -> None:
        full_path = self._resolve(path)
        self._permissions.pop(full_path, None)

    def get_permissions(self, path: str) -> set[str] | None:
        return self._permissions.get(self._resolve(path))

    def create_snapshot(self, snapshot_id: str | None = None) -> str:
        """Snapshot current state (simple deep copy)."""
        sid = snapshot_id or f"snap:{uuid.uuid4()}"
        self._snapshots[sid] = {
            "files": dict(self._files),
            "permissions": {k: set(v) for k, v in self._permissions.items()},
        }
        return sid

    def restore_snapshot(self, snapshot_id: str, agent_did: str) -> None:
        """Restore VFS to a previous snapshot."""
        if snapshot_id not in self._snapshots:
            raise KeyError(f"Snapshot {snapshot_id} not found")
        snapshot = self._snapshots[snapshot_id]
        self._files = dict(snapshot["files"])
        self._permissions = {k: set(v) for k, v in snapshot["permissions"].items()}
        self._edit_log.append(VFSEdit(
            path=self.namespace, operation="restore", agent_did=agent_did,
        ))

    def list_snapshots(self) -> list[str]:
        return list(self._snapshots.keys())

    def delete_snapshot(self, snapshot_id: str) -> None:
        if snapshot_id not in self._snapshots:
            raise KeyError(f"Snapshot {snapshot_id} not found")
        del self._snapshots[snapshot_id]

    @property
    def edit_log(self) -> list[VFSEdit]:
        return list(self._edit_log)

    def edits_by_agent(self, agent_did: str) -> list[VFSEdit]:
        return [e for e in self._edit_log if e.agent_did == agent_did]

    @property
    def file_count(self) -> int:
        return len(self._files)

    @property
    def snapshot_count(self) -> int:
        return len(self._snapshots)

    def _resolve(self, path: str) -> str:
        if path.startswith(self.namespace):
            return path
        clean = path.lstrip("/")
        return f"{self.namespace}/{clean}"

    def _check_permission(self, full_path: str, agent_did: str) -> None:
        allowed = self._permissions.get(full_path)
        if allowed is not None and agent_did not in allowed:
            raise VFSPermissionError(
                f"Agent {agent_did} not permitted to access {full_path}"
            )


def _hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()
