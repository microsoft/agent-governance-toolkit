# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Dynamic Semantic Handshake Protocol - The negotiation mechanism between
The Face (Reasoning) and The Hands (Execution).
"""

from typing import Dict, List, Optional, Any, Iterable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


CONFIRMATION_REQUIRED_KEY = "confirmation_required"
CONFIRMATION_SATISFIED_KEY = "confirmation_satisfied"
# Legacy alias accepted on read so callers using the older "requires_confirmation"
# metadata key still trip the gate. Producers should write CONFIRMATION_REQUIRED_KEY.
_CONFIRMATION_REQUIRED_ALIASES = (CONFIRMATION_REQUIRED_KEY, "requires_confirmation")


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


@dataclass
class HandshakeSession:
    """A session tracking the handshake process."""
    session_id: str
    state: HandshakeState
    proposal: Optional[ActionProposal] = None
    validation_result: Optional[ValidationResult] = None
    execution_result: Optional[Dict[str, Any]] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


class HandshakeProtocol:
    """
    The Dynamic Semantic Handshake Protocol manages the negotiation
    between the Reasoning Agent (The Face) and the Execution Agent (The Hands).

    Instead of free-text tool invocation, actions must be negotiated against
    the knowledge graph constraints.
    """

    def __init__(
        self,
        allowed_confirmers: Optional[Iterable[str]] = None,
    ):
        """Initialize the protocol.

        Authorization model for ``confirm_session``:

        * ``confirmed_by`` is always required and must be a non-empty string;
          anonymous confirmations are rejected.
        * If ``allowed_confirmers`` is provided (an iterable of operator
          identifiers), ``confirm_session`` additionally rejects any
          ``confirmed_by`` value not contained in that set. This is a
          lightweight allowlist intended to gate confirmation authority to a
          known operator roster without pulling in a full ACL/identity stack.
        * If ``allowed_confirmers`` is ``None`` (the default), the allowlist
          check is skipped and only the non-empty requirement applies, so
          callers that wire their own identity system upstream are unaffected.
        """
        self.sessions: Dict[str, HandshakeSession] = {}
        self._session_counter = 0
        self._allowed_confirmers: Optional[frozenset] = (
            frozenset(allowed_confirmers) if allowed_confirmers is not None else None
        )

    def initiate_handshake(
        self,
        proposal: ActionProposal
    ) -> HandshakeSession:
        """
        Initiate a new handshake session with an action proposal.
        This is called by the Reasoning Agent.
        """
        session_id = self._generate_session_id()
        session = HandshakeSession(
            session_id=session_id,
            state=HandshakeState.INITIATED,
            proposal=proposal
        )
        self.sessions[session_id] = session
        return session

    def validate_proposal(
        self,
        session_id: str,
        validation_result: ValidationResult
    ) -> HandshakeSession:
        """
        Validate the proposal in a session.
        This is typically called after checking against the knowledge graph.
        """
        session = self.sessions.get(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")

        if session.state not in (HandshakeState.INITIATED, HandshakeState.NEGOTIATING):
            raise ValueError(
                f"Cannot validate proposal in state {session.state}; "
                "validation is only allowed from INITIATED or NEGOTIATING."
            )

        session.validation_result = validation_result
        session.state = HandshakeState.VALIDATED if validation_result.is_valid else HandshakeState.REJECTED
        session.updated_at = datetime.now()

        return session

    def accept_proposal(self, session_id: str) -> HandshakeSession:
        """
        Accept a validated proposal for execution.
        This transitions from validation to acceptance.
        """
        session = self.sessions.get(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")

        if session.state != HandshakeState.VALIDATED:
            raise ValueError(f"Cannot accept proposal in state {session.state}")

        if not session.validation_result or not session.validation_result.is_valid:
            raise ValueError("Cannot accept invalid proposal")

        self._ensure_confirmation_satisfied(session, "accept")

        session.state = HandshakeState.ACCEPTED
        session.updated_at = datetime.now()

        return session

    def reject_proposal(
        self,
        session_id: str,
        reason: str
    ) -> HandshakeSession:
        """Reject a proposal with a reason."""
        session = self.sessions.get(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")

        if session.state in TERMINAL_STATES:
            raise ValueError(
                f"Cannot reject proposal in terminal state {session.state}"
            )

        session.state = HandshakeState.REJECTED
        session.metadata["rejection_reason"] = reason
        session.updated_at = datetime.now()

        return session

    def start_execution(self, session_id: str) -> HandshakeSession:
        """
        Start executing an accepted proposal.
        This is called by the Execution Agent.
        """
        session = self.sessions.get(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")

        if session.state != HandshakeState.ACCEPTED:
            raise ValueError(f"Cannot execute proposal in state {session.state}")

        self._ensure_confirmation_satisfied(session, "execute")

        session.state = HandshakeState.EXECUTING
        session.updated_at = datetime.now()

        return session

    def complete_execution(
        self,
        session_id: str,
        result: Dict[str, Any]
    ) -> HandshakeSession:
        """Complete execution with results."""
        session = self.sessions.get(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")

        if session.state != HandshakeState.EXECUTING:
            raise ValueError(f"Cannot complete execution in state {session.state}")

        self._ensure_confirmation_satisfied(session, "complete")

        session.execution_result = result
        session.state = HandshakeState.COMPLETED
        session.updated_at = datetime.now()

        return session

    def fail_execution(
        self,
        session_id: str,
        error: str
    ) -> HandshakeSession:
        """Mark execution as failed."""
        session = self.sessions.get(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")

        if session.state in TERMINAL_STATES:
            raise ValueError(
                f"Cannot fail execution in terminal state {session.state}"
            )

        session.state = HandshakeState.FAILED
        session.metadata["error"] = error
        session.updated_at = datetime.now()

        return session

    def get_session(self, session_id: str) -> Optional[HandshakeSession]:
        """Get a session by ID."""
        return self.sessions.get(session_id)

    def confirm_session(
        self,
        session_id: str,
        confirmed_by: str,
    ) -> HandshakeSession:
        """Record that a required confirmation has been satisfied.

        ``confirmed_by`` must be a non-empty string identifying the operator
        or upstream confirmation principal. If the protocol was constructed
        with ``allowed_confirmers``, the value must also be present in that
        allowlist. Empty or unknown values are rejected to ensure
        confirmations carry attribution.
        """
        if not isinstance(confirmed_by, str) or not confirmed_by.strip():
            raise ValueError("confirmed_by must be a non-empty string")

        confirmer = confirmed_by.strip()
        if (
            self._allowed_confirmers is not None
            and confirmer not in self._allowed_confirmers
        ):
            raise ValueError(
                f"confirmed_by '{confirmer}' is not in the allowed confirmers list"
            )

        session = self.sessions.get(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")

        if session.state in TERMINAL_STATES:
            raise ValueError(
                f"Cannot confirm session in terminal state {session.state}"
            )

        if not self.requires_confirmation(session):
            raise ValueError("Session does not require confirmation")

        session.metadata[CONFIRMATION_SATISFIED_KEY] = True
        session.metadata["confirmed_by"] = confirmer
        session.metadata["confirmed_at"] = datetime.now().isoformat()
        session.updated_at = datetime.now()
        return session

    def requires_confirmation(self, session: HandshakeSession) -> bool:
        """Check whether a session is gated on explicit confirmation."""
        return any(
            bool(session.metadata.get(key)) for key in _CONFIRMATION_REQUIRED_ALIASES
        )

    def is_confirmation_satisfied(self, session: HandshakeSession) -> bool:
        """Check whether a confirmation gate is either absent or satisfied."""
        if not self.requires_confirmation(session):
            return True
        return session.metadata.get(CONFIRMATION_SATISFIED_KEY) is True

    def _ensure_confirmation_satisfied(
        self,
        session: HandshakeSession,
        transition: str,
    ) -> None:
        if self.is_confirmation_satisfied(session):
            return

        reason = session.metadata.get("confirmation_reason", "confirmation required")
        raise ValueError(f"Cannot {transition} proposal until confirmation is satisfied: {reason}")

    def _generate_session_id(self) -> str:
        """Generate a unique session ID."""
        self._session_counter += 1
        return f"session_{self._session_counter}_{datetime.now().timestamp()}"
