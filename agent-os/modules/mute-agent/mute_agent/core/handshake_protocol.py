# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Dynamic Semantic Handshake Protocol - The negotiation mechanism between
The Face (Reasoning) and The Hands (Execution).
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


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
    
    def __init__(self):
        self.sessions: Dict[str, HandshakeSession] = {}
        self._session_counter = 0
    
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
        
        session.state = HandshakeState.FAILED
        session.metadata["error"] = error
        session.updated_at = datetime.now()
        
        return session
    
    def get_session(self, session_id: str) -> Optional[HandshakeSession]:
        """Get a session by ID."""
        return self.sessions.get(session_id)
    
    def _generate_session_id(self) -> str:
        """Generate a unique session ID."""
        self._session_counter += 1
        return f"session_{self._session_counter}_{datetime.now().timestamp()}"
