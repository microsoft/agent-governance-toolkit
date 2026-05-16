# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Session Isolation — enforced per-session working directories and data access control.

Provides isolation levels that control cross-session data access.
Sessions are assigned scoped working directories, and access to other
sessions' data requires explicit capability grants.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PurePosixPath
from typing import Optional


class IsolationLevel(str, Enum):
    """Session isolation levels.

    SNAPSHOT: Read from a point-in-time snapshot, writes go to session scope.
    READ_COMMITTED: Can read committed data from other sessions (with grants).
    SERIALIZABLE: Full isolation, no cross-session access.
    """

    SNAPSHOT = "snapshot"
    READ_COMMITTED = "read_committed"
    SERIALIZABLE = "serializable"

    @property
    def requires_vector_clocks(self) -> bool:
        return self == IsolationLevel.SERIALIZABLE

    @property
    def requires_intent_locks(self) -> bool:
        return self == IsolationLevel.SERIALIZABLE

    @property
    def allows_concurrent_writes(self) -> bool:
        return self != IsolationLevel.SERIALIZABLE

    @property
    def coordination_cost(self) -> str:
        costs = {
            IsolationLevel.SNAPSHOT: "low",
            IsolationLevel.READ_COMMITTED: "medium",
            IsolationLevel.SERIALIZABLE: "high",
        }
        return costs.get(self, "none")


@dataclass
class SessionScope:
    """Defines the isolated scope for a session.

    Each session gets a working directory under the base path.
    Cross-session access requires explicit grants.
    """

    session_id: str
    agent_did: str
    base_path: str = "/var/agt/sessions"
    isolation_level: IsolationLevel = IsolationLevel.SNAPSHOT
    granted_sessions: set[str] = field(default_factory=set)

    @property
    def working_directory(self) -> str:
        """Session-scoped working directory."""
        return str(PurePosixPath(self.base_path) / self.session_id)

    def is_path_allowed(self, path: str) -> bool:
        """Check if a path is accessible under this session's isolation.

        Args:
            path: Absolute path to check.

        Returns:
            True if the path is within the session scope or a granted scope.
        """
        normalized = str(PurePosixPath(path))
        # Always allow access within own working directory
        if normalized.startswith(self.working_directory):
            return True

        # Check granted session access (READ_COMMITTED only)
        if self.isolation_level == IsolationLevel.READ_COMMITTED:
            for granted_id in self.granted_sessions:
                granted_dir = str(PurePosixPath(self.base_path) / granted_id)
                if normalized.startswith(granted_dir):
                    return True

        return False

    def grant_access(self, other_session_id: str) -> None:
        """Grant this session read access to another session's data.

        Only effective under READ_COMMITTED isolation.

        Args:
            other_session_id: Session ID to grant access to.
        """
        self.granted_sessions.add(other_session_id)

    def revoke_access(self, other_session_id: str) -> None:
        """Revoke previously granted cross-session access."""
        self.granted_sessions.discard(other_session_id)


class SessionIsolationManager:
    """Manages session isolation scopes.

    Creates and tracks per-session scopes with configurable isolation levels.
    Enforces path-based access control for cross-session data.
    """

    def __init__(self, base_path: str = "/var/agt/sessions") -> None:
        self._base_path = base_path
        self._scopes: dict[str, SessionScope] = {}

    def create_scope(
        self,
        session_id: str,
        agent_did: str,
        isolation_level: IsolationLevel = IsolationLevel.SNAPSHOT,
    ) -> SessionScope:
        """Create an isolated scope for a session.

        Args:
            session_id: Unique session identifier.
            agent_did: DID of the agent owning this session.
            isolation_level: Desired isolation level.

        Returns:
            SessionScope with the assigned working directory.
        """
        scope = SessionScope(
            session_id=session_id,
            agent_did=agent_did,
            base_path=self._base_path,
            isolation_level=isolation_level,
        )
        self._scopes[session_id] = scope
        return scope

    def get_scope(self, session_id: str) -> Optional[SessionScope]:
        """Get the isolation scope for a session."""
        return self._scopes.get(session_id)

    def check_access(self, session_id: str, path: str) -> bool:
        """Check if a session can access a given path.

        Args:
            session_id: Session requesting access.
            path: Path being accessed.

        Returns:
            True if access is allowed under the session's isolation scope.
            True if no scope exists (permissive fallback for backward compat).
        """
        scope = self._scopes.get(session_id)
        if scope is None:
            return True  # No scope = no enforcement (backward compat)
        return scope.is_path_allowed(path)

    def grant_cross_session_access(
        self, session_id: str, target_session_id: str
    ) -> bool:
        """Grant one session access to another's data.

        Only works for READ_COMMITTED isolation.

        Returns:
            True if grant was applied, False if session not found or wrong isolation.
        """
        scope = self._scopes.get(session_id)
        if scope is None:
            return False
        if scope.isolation_level != IsolationLevel.READ_COMMITTED:
            return False
        scope.grant_access(target_session_id)
        return True

    def remove_scope(self, session_id: str) -> None:
        """Remove a session's isolation scope (session ended)."""
        self._scopes.pop(session_id, None)

    @property
    def active_sessions(self) -> int:
        """Number of sessions with active isolation scopes."""
        return len(self._scopes)
