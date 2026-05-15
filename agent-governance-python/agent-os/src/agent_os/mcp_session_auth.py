# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Cryptographic session authentication for MCP agents."""

from __future__ import annotations

import base64
import logging
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from agent_os.mcp_protocols import InMemorySessionStore, MCPSessionStore

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MCPSession:
    """An authenticated MCP session bound to an agent identity."""

    token: str
    agent_id: str
    user_id: str | None
    created_at: datetime
    expires_at: datetime | None
    rate_limit_key: str

    @property
    def is_expired(self) -> bool:
        return self.expires_at is not None and _utcnow() >= self.expires_at


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class MCPSessionAuthenticator:
    """Authenticate MCP sessions with cryptographic tokens and expiry checks.

    The authenticator creates short-lived session tokens, validates that a
    token belongs to a specific agent, and keeps internal indices synchronized
    with the injected session store under a thread-safe lock.
    """

    def __init__(
        self,
        *,
        session_ttl: timedelta = timedelta(hours=1),
        max_concurrent_sessions: int = 10,
        session_store: MCPSessionStore | None = None,
    ) -> None:
        """Initialize the session authenticator.

        Args:
            session_ttl: Lifetime applied to newly issued session tokens.
            max_concurrent_sessions: Maximum number of live sessions allowed
                per agent.
            session_store: Optional persistence backend for storing sessions.
                Defaults to the in-memory session store.
        """
        if session_ttl <= timedelta(0):
            raise ValueError("session_ttl must be positive")
        if max_concurrent_sessions <= 0:
            raise ValueError("max_concurrent_sessions must be positive")

        self.session_ttl = session_ttl
        self.max_concurrent_sessions = max_concurrent_sessions
        self._lock = threading.Lock()
        self._session_store = session_store or InMemorySessionStore()
        self._agent_sessions: dict[str, set[str]] = {}
        self._session_expirations: dict[str, datetime] = {}

    def create_session(self, agent_id: str, user_id: str | None = None) -> str:
        """Create a session token bound to an agent and optional user context.

        Args:
            agent_id: Agent identifier that will own the session.
            user_id: Optional user or tenant identifier associated with the
                session.

        Returns:
            A newly generated opaque session token.
        """
        if not agent_id or not agent_id.strip():
            raise ValueError("agent_id must not be empty")

        now = _utcnow()
        with self._lock:
            self._cleanup_expired_locked(now)
            active_for_agent = sum(
                1
                for token in self._agent_sessions.get(agent_id, set())
                if (
                    (session := self._session_store.get(token)) is not None
                    and (session.expires_at is None or session.expires_at > now)
                )
            )
            if active_for_agent >= self.max_concurrent_sessions:
                raise RuntimeError(
                    f"Agent '{agent_id}' exceeded maximum concurrent sessions "
                    f"({self.max_concurrent_sessions})."
                )

            token = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
            session = MCPSession(
                token=token,
                agent_id=agent_id,
                user_id=user_id,
                created_at=now,
                expires_at=now + self.session_ttl,
                rate_limit_key=f"{user_id}:{agent_id}" if user_id else agent_id,
            )
            self._store_session_locked(session)

        logger.info("Created MCP session for agent %s", agent_id)
        return token

    def bootstrap_session(
        self,
        agent_id: str,
        session_token: str,
        user_id: str | None = None,
        *,
        ttl: timedelta,
    ) -> str:
        """Persist a pre-provisioned session token bound to an agent.

        Intended for environments that need deterministic bootstrap
        credentials (for example, wiring a FastAPI server to a
        deployment-time token map). The caller MUST supply ``ttl`` —
        bootstrapped sessions expire on a clock just like sessions issued
        by :meth:`create_session`, and there is no never-expire mode.
        Long-lived deployment tokens should pass an explicitly long
        ``timedelta`` (e.g. ``timedelta(days=30)``) and rotate via
        redeployment.

        Args:
            agent_id: Agent identifier the session is bound to.
            session_token: Caller-supplied opaque session token.
            user_id: Optional user or tenant identifier.
            ttl: Positive lifetime applied to the bootstrap session.

        Raises:
            ValueError: If ``agent_id`` or ``session_token`` is empty, or
                ``ttl`` is not strictly positive.
        """
        if not agent_id or not agent_id.strip():
            raise ValueError("agent_id must not be empty")
        if not session_token or not session_token.strip():
            raise ValueError("session_token must not be empty")
        if ttl <= timedelta(0):
            raise ValueError("ttl must be positive — bootstrap sessions cannot be permanent")

        now = _utcnow()
        with self._lock:
            self._cleanup_expired_locked(now)
            active_for_agent = sum(
                1
                for token in self._agent_sessions.get(agent_id, set())
                if (
                    (session := self._session_store.get(token)) is not None
                    and (session.expires_at is None or session.expires_at > now)
                )
            )
            if active_for_agent >= self.max_concurrent_sessions:
                raise RuntimeError(
                    f"Agent '{agent_id}' exceeded maximum concurrent sessions "
                    f"({self.max_concurrent_sessions})."
                )

            existing = self._session_store.get(session_token)
            if existing is not None and not getattr(existing, "is_expired", False):
                raise RuntimeError("session_token is already bound to an active session")
            if existing is not None:
                self._delete_session_locked(session_token, existing)

            session = MCPSession(
                token=session_token,
                agent_id=agent_id,
                user_id=user_id,
                created_at=now,
                expires_at=now + ttl,
                rate_limit_key=f"{user_id}:{agent_id}" if user_id else agent_id,
            )
            self._store_session_locked(session)

        logger.info("Bootstrapped MCP session for agent %s (ttl=%s)", agent_id, ttl)
        return session_token

    def validate_session(self, agent_id: str, session_token: str) -> MCPSession | None:
        """Validate a session token for a specific agent.

        Args:
            agent_id: Agent identifier expected to own the session.
            session_token: Opaque session token previously issued by this
                authenticator.

        Returns:
            The active ``MCPSession`` when the token is valid for the supplied
            agent, otherwise ``None``. Errors fail closed.
        """
        if not agent_id or not agent_id.strip() or not session_token or not session_token.strip():
            logger.warning("MCP session validation failed due to missing agent_id or session token")
            return None

        try:
            with self._lock:
                session = self._get_valid_session_locked(session_token)
                if session is None or session.agent_id != agent_id:
                    return None
                return session
        except Exception:
            logger.error("MCP session validation failed closed", exc_info=True)
            return None

    def validate_token(self, session_token: str) -> MCPSession | None:
        """Validate a session token without trusting a caller-asserted agent ID."""
        if not session_token or not session_token.strip():
            logger.warning("MCP session token validation failed due to missing token")
            return None

        try:
            with self._lock:
                return self._get_valid_session_locked(session_token)
        except Exception:
            logger.error("MCP session token validation failed closed", exc_info=True)
            return None

    def revoke_session(self, session_token: str) -> bool:
        """Revoke a single session token.

        Args:
            session_token: Session token to revoke.

        Returns:
            ``True`` when the session existed and was removed, otherwise
            ``False``.
        """
        with self._lock:
            return self._delete_session_locked(session_token)

    def revoke_all_sessions(self, agent_id: str) -> int:
        """Revoke every session belonging to an agent.

        Args:
            agent_id: Agent identifier whose sessions should be revoked.

        Returns:
            The number of sessions removed for the agent.
        """
        with self._lock:
            tokens = list(self._agent_sessions.get(agent_id, set()))
            for token in tokens:
                session = self._session_store.get(token)
                if session is None or session.agent_id == agent_id:
                    self._delete_session_locked(token, session)
        return len(tokens)

    def cleanup_expired_sessions(self) -> int:
        """Remove expired sessions and return the number removed.

        Returns:
            The number of expired sessions removed from the store and internal
            indices.
        """
        with self._lock:
            return self._cleanup_expired_locked(_utcnow())

    @property
    def active_session_count(self) -> int:
        """Return the number of active sessions.

        Returns:
            The number of currently active, non-expired sessions.
        """
        with self._lock:
            self._cleanup_expired_locked(_utcnow())
            return len(self._session_expirations)

    def _cleanup_expired_locked(self, now: datetime) -> int:
        expired_tokens = [
            token
            for token, expires_at in self._session_expirations.items()
            if expires_at is not None and expires_at <= now
        ]
        for token in expired_tokens:
            session = self._session_store.get(token)
            self._delete_session_locked(token, session)
        return len(expired_tokens)

    def _store_session_locked(self, session: MCPSession) -> None:
        self._session_store.set(session)
        if session.expires_at is not None:
            self._session_expirations[session.token] = session.expires_at
        else:
            self._session_expirations.pop(session.token, None)
        self._agent_sessions.setdefault(session.agent_id, set()).add(session.token)

    def _delete_session_locked(
        self,
        session_token: str,
        session: MCPSession | None = None,
    ) -> bool:
        stored_session = session or self._session_store.get(session_token)
        deleted = self._session_store.delete(session_token)
        self._session_expirations.pop(session_token, None)
        if stored_session is not None:
            tokens = self._agent_sessions.get(stored_session.agent_id)
            if tokens is not None:
                tokens.discard(session_token)
                if not tokens:
                    self._agent_sessions.pop(stored_session.agent_id, None)
        return deleted or stored_session is not None

    def _get_valid_session_locked(self, session_token: str) -> MCPSession | None:
        session = self._session_store.get(session_token)
        if session is None:
            self._delete_session_locked(session_token)
            return None
        if session.is_expired:
            self._delete_session_locked(session_token, session)
            return None
        return session
