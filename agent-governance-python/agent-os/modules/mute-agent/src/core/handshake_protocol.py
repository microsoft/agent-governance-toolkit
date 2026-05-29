# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Dynamic Semantic Handshake Protocol - The negotiation mechanism between
The Face (Reasoning) and The Hands (Execution).

Security model
~~~~~~~~~~~~~~

This module is part of mute-agent's defense-in-depth surface against
*compromised in-process callers* (e.g. a malicious plugin that has
already been loaded into the same Python process).  The following
invariants are enforced through the public API and are the protocol's
contract; the underscored backing attributes are private by convention
and are not part of the contract:

* ``HandshakeSession.state`` is a read-only property.  Direct
  assignment (``session.state = X``) raises ``AttributeError``.  State
  transitions only happen through ``HandshakeProtocol`` methods, which
  validate the source state and acquire the protocol lock.
* Whether a confirmation gate is satisfied is sourced from the
  protocol's audited ``_confirmations`` table, not from the session's
  ``metadata`` dict.  Writing
  ``session.metadata["confirmation_satisfied"] = True`` does NOT
  bypass the gate.
* ``HandshakeProtocol.confirm_session`` requires an authenticated
  ``confirmed_by`` principal.  By default (``allowed_confirmers=None``)
  the protocol is **fail-closed**: no principal is accepted.  Callers
  must either pass an explicit allowlist or the ``ALLOW_ANY`` sentinel
  to opt back into permissive behavior.
* All reads/writes of the ``sessions`` dict and the ``_confirmations``
  table are serialized through ``self._lock`` (an ``RLock``) so that
  concurrent intervention paths (e.g. listener ``emergency_halt``)
  cannot observe a half-mutated state and cannot race with
  ``confirm_session`` / ``accept_proposal``.

Python does not enforce attribute privacy.  An attacker with arbitrary
code-execution inside the process can always rewrite private state.
The hardening here exists so that *accidental* misuse via the public
API surface is impossible, and so that the threat model lives at the
documented protocol boundary rather than at every caller.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Union


CONFIRMATION_REQUIRED_KEY = "confirmation_required"
CONFIRMATION_SATISFIED_KEY = "confirmation_satisfied"
# Legacy alias accepted on read so callers using the older "requires_confirmation"
# metadata key still trip the gate. Producers should write CONFIRMATION_REQUIRED_KEY.
_CONFIRMATION_REQUIRED_ALIASES = (CONFIRMATION_REQUIRED_KEY, "requires_confirmation")

# Maximum stored length for the ``confirmed_by`` principal in audit
# records. Anything beyond this is truncated so audit storage cannot be
# flooded by a malicious caller.
_CONFIRMED_BY_MAX_LEN = 256

# Strip control characters (C0 + DEL + C1) from ``confirmed_by`` to
# prevent log/UI injection (CRLF splitting, ANSI escapes, terminal
# control sequences) in downstream observability surfaces.
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


class _AllowAnySentinel:
    """Singleton used as a marker for "skip the confirmer allowlist"."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return "ALLOW_ANY"


ALLOW_ANY = _AllowAnySentinel()


class HandshakeState(Enum):
    """States in the handshake protocol."""
    INITIATED = "initiated"
    NEGOTIATING = "negotiating"
    VALIDATED = "validated"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"


TERMINAL_STATES = frozenset({
    HandshakeState.REJECTED,
    HandshakeState.COMPLETED,
    HandshakeState.FAILED,
})


@dataclass
class ActionProposal:
    """A proposed action from the Reasoning Agent."""
    action_id: str
    parameters: Dict[str, Any]
    context: Dict[str, Any]
    justification: str
    priority: float = 1.0
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ValidationResult:
    """Result of validating an action proposal."""
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    constraints_met: List[str] = field(default_factory=list)
    constraints_violated: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class ConfirmationRecord:
    """Audited record of an operator confirmation.

    Stored on the protocol (not the session) so that the
    "is confirmation satisfied?" check cannot be bypassed by writes to
    ``session.metadata``.
    """

    session_id: str
    confirmed_by: str
    confirmed_at: datetime


def _sanitize_confirmed_by(raw: str) -> str:
    """Normalize an operator id for audit storage and allowlist compare.

    Strips surrounding whitespace, removes control characters that
    would corrupt logs (CR/LF/ANSI/etc.), and caps the length.  Returns
    the cleaned value.  Raises ``ValueError`` if the input is not a
    non-empty string after cleaning.
    """
    if not isinstance(raw, str):
        raise ValueError("confirmed_by must be a non-empty string")
    cleaned = _CONTROL_CHAR_RE.sub("", raw).strip()
    if not cleaned:
        raise ValueError("confirmed_by must be a non-empty string")
    if len(cleaned) > _CONFIRMED_BY_MAX_LEN:
        cleaned = cleaned[:_CONFIRMED_BY_MAX_LEN]
    return cleaned


class HandshakeSession:
    """A session tracking the handshake process.

    The ``state`` attribute is a *read-only property*; the protocol
    mutates the underlying ``_state`` slot under its own lock.  See the
    module-level "Security model" docstring for the threat boundary.
    """

    __slots__ = (
        "session_id",
        "_state",
        "proposal",
        "validation_result",
        "execution_result",
        "created_at",
        "updated_at",
        "metadata",
    )

    def __init__(
        self,
        session_id: str,
        state: HandshakeState,
        proposal: Optional[ActionProposal] = None,
        validation_result: Optional[ValidationResult] = None,
        execution_result: Optional[Dict[str, Any]] = None,
        created_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.session_id = session_id
        self._state = state
        self.proposal = proposal
        self.validation_result = validation_result
        self.execution_result = execution_result
        now = datetime.now()
        self.created_at = created_at if created_at is not None else now
        self.updated_at = updated_at if updated_at is not None else now
        self.metadata = metadata if metadata is not None else {}

    @property
    def state(self) -> HandshakeState:
        """Current state. Read-only outside the protocol."""
        return self._state

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (
            f"HandshakeSession(session_id={self.session_id!r}, "
            f"state={self._state!r})"
        )


AllowedConfirmersArg = Optional[Union[Iterable[str], _AllowAnySentinel]]


class HandshakeProtocol:
    """
    The Dynamic Semantic Handshake Protocol manages the negotiation
    between the Reasoning Agent (The Face) and the Execution Agent (The Hands).

    Instead of free-text tool invocation, actions must be negotiated against
    the knowledge graph constraints.
    """

    def __init__(
        self,
        allowed_confirmers: AllowedConfirmersArg = None,
    ):
        """Initialize the protocol.

        Authorization model for ``confirm_session``:

        * ``confirmed_by`` is always required, must be a non-empty
          string after sanitization (control chars stripped, whitespace
          trimmed), and is capped to ``_CONFIRMED_BY_MAX_LEN``.
        * ``allowed_confirmers`` controls who may confirm:

          - ``None`` (default): **fail-closed**.  No principal is
            accepted; every ``confirm_session`` call raises.  This
            forces callers to make an explicit policy choice.
          - An iterable of operator ids: only those principals may
            confirm.  Entries are sanitized the same way as
            ``confirmed_by`` on insert.
          - ``ALLOW_ANY`` sentinel: skip the allowlist check.  Callers
            that wire their own upstream identity layer opt in
            explicitly.
        """
        self.sessions: Dict[str, HandshakeSession] = {}
        self._session_counter = 0
        self._lock = threading.RLock()
        self._confirmations: Dict[str, ConfirmationRecord] = {}

        if allowed_confirmers is None:
            self._allowed_confirmers: Optional[frozenset] = frozenset()
            self._skip_allowlist = False
        elif isinstance(allowed_confirmers, _AllowAnySentinel):
            self._allowed_confirmers = None
            self._skip_allowlist = True
        else:
            normalized = set()
            for entry in allowed_confirmers:
                if not isinstance(entry, str):
                    raise TypeError(
                        "allowed_confirmers entries must be strings; "
                        f"got {type(entry).__name__}"
                    )
                cleaned = _CONTROL_CHAR_RE.sub("", entry).strip()
                if cleaned:
                    normalized.add(cleaned)
            self._allowed_confirmers = frozenset(normalized)
            self._skip_allowlist = False

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------
    def initiate_handshake(
        self,
        proposal: ActionProposal,
    ) -> HandshakeSession:
        """Initiate a new handshake session with an action proposal."""
        with self._lock:
            session_id = self._generate_session_id()
            session = HandshakeSession(
                session_id=session_id,
                state=HandshakeState.INITIATED,
                proposal=proposal,
            )
            self.sessions[session_id] = session
            return session

    def validate_proposal(
        self,
        session_id: str,
        validation_result: ValidationResult,
    ) -> HandshakeSession:
        """Validate the proposal in a session."""
        with self._lock:
            session = self.sessions.get(session_id)
            if not session:
                raise ValueError(f"Session {session_id} not found")

            if session._state not in (
                HandshakeState.INITIATED,
                HandshakeState.NEGOTIATING,
            ):
                raise ValueError(
                    f"Cannot validate proposal in state {session._state}; "
                    "validation is only allowed from INITIATED or NEGOTIATING."
                )

            session.validation_result = validation_result
            session._state = (
                HandshakeState.VALIDATED
                if validation_result.is_valid
                else HandshakeState.REJECTED
            )
            session.updated_at = datetime.now()
            return session

    def accept_proposal(self, session_id: str) -> HandshakeSession:
        """Accept a validated proposal for execution."""
        with self._lock:
            session = self.sessions.get(session_id)
            if not session:
                raise ValueError(f"Session {session_id} not found")

            if session._state != HandshakeState.VALIDATED:
                raise ValueError(
                    f"Cannot accept proposal in state {session._state}"
                )

            if not session.validation_result or not session.validation_result.is_valid:
                raise ValueError("Cannot accept invalid proposal")

            self._ensure_confirmation_satisfied(session, "accept")

            session._state = HandshakeState.ACCEPTED
            session.updated_at = datetime.now()
            return session

    def reject_proposal(
        self,
        session_id: str,
        reason: str,
    ) -> HandshakeSession:
        """Reject a proposal with a reason."""
        with self._lock:
            session = self.sessions.get(session_id)
            if not session:
                raise ValueError(f"Session {session_id} not found")

            if session._state in TERMINAL_STATES:
                raise ValueError(
                    f"Cannot reject proposal in terminal state {session._state}"
                )

            session._state = HandshakeState.REJECTED
            session.metadata["rejection_reason"] = reason
            session.updated_at = datetime.now()
            return session

    def start_execution(self, session_id: str) -> HandshakeSession:
        """Start executing an accepted proposal."""
        with self._lock:
            session = self.sessions.get(session_id)
            if not session:
                raise ValueError(f"Session {session_id} not found")

            if session._state != HandshakeState.ACCEPTED:
                raise ValueError(
                    f"Cannot execute proposal in state {session._state}"
                )

            self._ensure_confirmation_satisfied(session, "execute")

            session._state = HandshakeState.EXECUTING
            session.updated_at = datetime.now()
            return session

    def complete_execution(
        self,
        session_id: str,
        result: Dict[str, Any],
    ) -> HandshakeSession:
        """Complete execution with results."""
        with self._lock:
            session = self.sessions.get(session_id)
            if not session:
                raise ValueError(f"Session {session_id} not found")

            if session._state != HandshakeState.EXECUTING:
                raise ValueError(
                    f"Cannot complete execution in state {session._state}"
                )

            self._ensure_confirmation_satisfied(session, "complete")

            session.execution_result = result
            session._state = HandshakeState.COMPLETED
            session.updated_at = datetime.now()
            return session

    def fail_execution(
        self,
        session_id: str,
        error: str,
    ) -> HandshakeSession:
        """Mark execution as failed."""
        with self._lock:
            session = self.sessions.get(session_id)
            if not session:
                raise ValueError(f"Session {session_id} not found")

            if session._state in TERMINAL_STATES:
                raise ValueError(
                    f"Cannot fail execution in terminal state {session._state}"
                )

            session._state = HandshakeState.FAILED
            session.metadata["error"] = error
            session.updated_at = datetime.now()
            return session

    def get_session(self, session_id: str) -> Optional[HandshakeSession]:
        """Get a session by ID."""
        with self._lock:
            return self.sessions.get(session_id)

    # ------------------------------------------------------------------
    # Confirmation
    # ------------------------------------------------------------------
    def mark_confirmation_required(
        self,
        session_id: str,
        reason: Optional[str] = None,
    ) -> HandshakeSession:
        """Mark a session as requiring operator confirmation.

        Called by the listener's soft-block path. Also clears any
        previously recorded confirmation so that a renewed gate cannot
        be auto-satisfied by an older audit record.
        """
        with self._lock:
            session = self.sessions.get(session_id)
            if not session:
                raise ValueError(f"Session {session_id} not found")
            if session._state in TERMINAL_STATES:
                raise ValueError(
                    f"Cannot mark confirmation required in terminal state {session._state}"
                )
            session.metadata[CONFIRMATION_REQUIRED_KEY] = True
            session.metadata[CONFIRMATION_SATISFIED_KEY] = False
            if reason is not None:
                session.metadata["confirmation_reason"] = reason
            # Revoke any prior confirmation: the gate has been renewed.
            self._confirmations.pop(session_id, None)
            session.updated_at = datetime.now()
            return session

    def confirm_session(
        self,
        session_id: str,
        confirmed_by: str,
    ) -> HandshakeSession:
        """Record that a required confirmation has been satisfied.

        ``confirmed_by`` must be a non-empty string after sanitization
        and must be present in the configured allowlist (unless the
        protocol was constructed with ``ALLOW_ANY``).
        """
        confirmer = _sanitize_confirmed_by(confirmed_by)

        with self._lock:
            if not self._skip_allowlist:
                if (
                    self._allowed_confirmers is None
                    or confirmer not in self._allowed_confirmers
                ):
                    raise ValueError(
                        f"confirmed_by '{confirmer}' is not in the allowed confirmers list"
                    )

            session = self.sessions.get(session_id)
            if not session:
                raise ValueError(f"Session {session_id} not found")

            if session._state in TERMINAL_STATES:
                raise ValueError(
                    f"Cannot confirm session in terminal state {session._state}"
                )

            if not self.requires_confirmation(session):
                raise ValueError("Session does not require confirmation")

            confirmed_at = datetime.now()
            self._confirmations[session_id] = ConfirmationRecord(
                session_id=session_id,
                confirmed_by=confirmer,
                confirmed_at=confirmed_at,
            )
            # Mirror to metadata for backward-compatible *read-only*
            # observability (dashboards, audit exporters). The
            # is_confirmation_satisfied gate does NOT trust these keys.
            session.metadata[CONFIRMATION_SATISFIED_KEY] = True
            session.metadata["confirmed_by"] = confirmer
            session.metadata["confirmed_at"] = confirmed_at.isoformat()
            session.updated_at = confirmed_at
            return session

    def requires_confirmation(self, session: HandshakeSession) -> bool:
        """Check whether a session is gated on explicit confirmation."""
        return any(
            bool(session.metadata.get(key)) for key in _CONFIRMATION_REQUIRED_ALIASES
        )

    def is_confirmation_satisfied(self, session: HandshakeSession) -> bool:
        """Check whether a confirmation gate is either absent or satisfied.

        The truth source is the protocol's audited ``_confirmations``
        table.  Mutations to ``session.metadata`` cannot bypass this
        check.
        """
        if not self.requires_confirmation(session):
            return True
        with self._lock:
            return session.session_id in self._confirmations

    def get_confirmation_record(
        self,
        session_id: str,
    ) -> Optional[ConfirmationRecord]:
        """Return the audited confirmation record for a session, if any."""
        with self._lock:
            return self._confirmations.get(session_id)

    def snapshot_sessions(self) -> List[HandshakeSession]:
        """Return a thread-safe snapshot of current sessions.

        Iterating ``protocol.sessions`` directly is unsafe when
        intervention paths (e.g. listener emergency_halt) may mutate
        the dict concurrently.  Use this method instead.
        """
        with self._lock:
            return list(self.sessions.values())

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _ensure_confirmation_satisfied(
        self,
        session: HandshakeSession,
        transition: str,
    ) -> None:
        # Called while ``self._lock`` is held by the public entrypoints.
        if self.is_confirmation_satisfied(session):
            return
        reason = session.metadata.get("confirmation_reason", "confirmation required")
        raise ValueError(
            f"Cannot {transition} proposal until confirmation is satisfied: {reason}"
        )

    def _generate_session_id(self) -> str:
        """Generate a unique session ID. Caller must hold ``self._lock``."""
        self._session_counter += 1
        return f"session_{self._session_counter}_{datetime.now().timestamp()}"
