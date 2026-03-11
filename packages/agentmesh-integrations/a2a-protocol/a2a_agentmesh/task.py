"""
A2A Task Envelope — trust-verified task request/response wrappers.

Implements the A2A task lifecycle (submitted → working → complete/failed/canceled)
with AgentMesh trust attestations embedded in each message.

Spec reference: https://a2a-protocol.org/latest/specification/
"""

from __future__ import annotations

import enum
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class TaskState(str, enum.Enum):
    """A2A task lifecycle states."""

    SUBMITTED = "submitted"
    WORKING = "working"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELED = "canceled"


@dataclass
class TaskMessage:
    """
    A single message in an A2A task conversation.

    Each message carries content (text or structured) plus optional
    AgentMesh trust metadata.
    """

    role: str  # "user" or "agent"
    content: str
    content_type: str = "text/plain"
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "role": self.role,
            "parts": [{"type": self.content_type, "text": self.content}],
        }
        if self.metadata:
            d["metadata"] = self.metadata
        return d


@dataclass
class TaskEnvelope:
    """
    A2A-compliant task with AgentMesh trust verification.

    Wraps the A2A task lifecycle with:
    - Source agent DID and trust score (from AgentMesh)
    - Target skill ID (from Agent Card)
    - JSON-RPC compatible serialisation
    - State machine enforcement
    """

    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    skill_id: str = ""
    state: TaskState = TaskState.SUBMITTED

    # Trust context
    source_did: str = ""
    target_did: str = ""
    source_trust_score: int = 0

    # Messages
    messages: List[TaskMessage] = field(default_factory=list)

    # Metadata
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    error: str = ""

    # Valid state transitions
    _TRANSITIONS: Dict[TaskState, List[TaskState]] = field(
        default=None,
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        self._TRANSITIONS = {
            TaskState.SUBMITTED: [TaskState.WORKING, TaskState.CANCELED, TaskState.FAILED],
            TaskState.WORKING: [TaskState.COMPLETE, TaskState.FAILED, TaskState.CANCELED],
            TaskState.COMPLETE: [],
            TaskState.FAILED: [],
            TaskState.CANCELED: [],
        }

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        *,
        skill_id: str,
        source_did: str,
        target_did: str = "",
        source_trust_score: int = 0,
        input_text: str = "",
    ) -> "TaskEnvelope":
        """Create a new task request."""
        envelope = cls(
            skill_id=skill_id,
            source_did=source_did,
            target_did=target_did,
            source_trust_score=source_trust_score,
        )
        if input_text:
            envelope.add_message("user", input_text)
        return envelope

    # ------------------------------------------------------------------
    # State machine
    # ------------------------------------------------------------------

    def transition(self, new_state: TaskState) -> None:
        """
        Transition to a new state.

        Raises ValueError if the transition is not allowed.
        """
        allowed = self._TRANSITIONS.get(self.state, [])
        if new_state not in allowed:
            raise ValueError(
                f"Invalid transition: {self.state.value} → {new_state.value}. "
                f"Allowed: {[s.value for s in allowed]}"
            )
        self.state = new_state
        self.updated_at = time.time()

    def start(self) -> None:
        """Mark task as working."""
        self.transition(TaskState.WORKING)

    def complete(self, result: str = "") -> None:
        """Mark task as complete with optional result message."""
        self.transition(TaskState.COMPLETE)
        if result:
            self.add_message("agent", result)

    def fail(self, error: str = "") -> None:
        """Mark task as failed."""
        self.error = error
        self.transition(TaskState.FAILED)

    def cancel(self) -> None:
        """Cancel the task."""
        self.transition(TaskState.CANCELED)

    @property
    def is_terminal(self) -> bool:
        """Check if task is in a terminal state."""
        return self.state in (TaskState.COMPLETE, TaskState.FAILED, TaskState.CANCELED)

    # ------------------------------------------------------------------
    # Messages
    # ------------------------------------------------------------------

    def add_message(self, role: str, content: str, **metadata: Any) -> TaskMessage:
        """Add a message to the task conversation."""
        msg = TaskMessage(role=role, content=content, metadata=metadata)
        self.messages.append(msg)
        self.updated_at = time.time()
        return msg

    # ------------------------------------------------------------------
    # Serialisation (JSON-RPC compatible)
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to A2A JSON-RPC compatible dict."""
        d: Dict[str, Any] = {
            "id": self.task_id,
            "status": {"state": self.state.value},
            "skill_id": self.skill_id,
        }
        if self.error:
            d["status"]["error"] = self.error
        if self.messages:
            d["messages"] = [m.to_dict() for m in self.messages]

        # AgentMesh trust metadata
        trust: Dict[str, Any] = {}
        if self.source_did:
            trust["source_did"] = self.source_did
        if self.target_did:
            trust["target_did"] = self.target_did
        if self.source_trust_score:
            trust["source_trust_score"] = self.source_trust_score
        if trust:
            d["x-agentmesh-trust"] = trust

        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TaskEnvelope":
        """Deserialise from a dict."""
        trust = data.get("x-agentmesh-trust", {})
        messages = []
        for m in data.get("messages", []):
            text = ""
            if "parts" in m:
                text = m["parts"][0].get("text", "")
            messages.append(
                TaskMessage(
                    role=m["role"],
                    content=text,
                    metadata=m.get("metadata", {}),
                )
            )
        return cls(
            task_id=data.get("id", str(uuid.uuid4())),
            skill_id=data.get("skill_id", ""),
            state=TaskState(data.get("status", {}).get("state", "submitted")),
            source_did=trust.get("source_did", ""),
            target_did=trust.get("target_did", ""),
            source_trust_score=trust.get("source_trust_score", 0),
            messages=messages,
            error=data.get("status", {}).get("error", ""),
        )
