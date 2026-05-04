# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Intent-Based Authorization for AI Agents.

First-class intent objects with a full lifecycle:
    declare_intent() -> approve_intent() -> execute actions -> verify_intent()

Intent is an opt-in layer that sits between the caller and StatelessKernel.
When an agent declares intent before acting, the system can detect drift
(actions that deviate from what was declared) and respond according to the
configured drift policy.

Design decisions:
    - Intent is a first-class object with its own lifecycle and state machine.
    - IntentManager is async and backed by StateBackend for stateless compat.
    - Optimistic concurrency via version fields prevents lost updates.
    - Child intents must narrow parent scope (subset of planned actions).
    - Three drift policies: soft_block (default), hard_block, re_declare.
    - Execution records are structured (not bare strings) for audit.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class IntentState(str, Enum):
    """Lifecycle states for an ExecutionIntent."""

    DECLARED = "declared"
    APPROVED = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    VIOLATED = "violated"
    EXPIRED = "expired"


class DriftPolicy(str, Enum):
    """How the system responds when an action drifts from declared intent.

    - SOFT_BLOCK: Action proceeds but trust score drops and alert fires.
    - HARD_BLOCK: Action is denied outright.
    - RE_DECLARE: Action is denied; agent must declare a new intent.
    """

    SOFT_BLOCK = "soft_block"
    HARD_BLOCK = "hard_block"
    RE_DECLARE = "re_declare"


# Terminal states: once entered, the intent cannot transition further.
_TERMINAL_STATES = frozenset({
    IntentState.COMPLETED,
    IntentState.VIOLATED,
    IntentState.EXPIRED,
})

# Valid state transitions (from -> set of allowed targets).
_TRANSITIONS: dict[IntentState, frozenset[IntentState]] = {
    IntentState.DECLARED: frozenset({IntentState.APPROVED, IntentState.EXPIRED}),
    IntentState.APPROVED: frozenset({
        IntentState.EXECUTING, IntentState.EXPIRED,
    }),
    IntentState.EXECUTING: frozenset({
        IntentState.COMPLETED, IntentState.VIOLATED, IntentState.EXPIRED,
    }),
}


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class IntentAction:
    """A single planned action within an intent declaration.

    Attributes:
        action: The action name (e.g. "database_query", "file_write").
        params_schema: Optional constraints on allowed parameters.
            Keys are param names, values are allowed values or patterns.
    """

    action: str
    params_schema: dict[str, Any] | None = None

    def matches(self, action: str, params: dict[str, Any] | None = None) -> bool:
        """Return True if the given action + params match this planned action."""
        if self.action != action:
            return False
        if self.params_schema and params:
            for key, allowed in self.params_schema.items():
                if key in params and params[key] != allowed:
                    return False
        return True

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"action": self.action}
        if self.params_schema:
            d["params_schema"] = self.params_schema
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> IntentAction:
        return cls(action=d["action"], params_schema=d.get("params_schema"))


@dataclass
class ExecutionRecord:
    """A structured record of an action attempted under an intent.

    Captures enough detail for audit and planned-vs-actual verification.
    """

    action: str
    agent_id: str
    request_id: str
    was_planned: bool
    outcome: str  # "executed", "blocked", "re_declare_required"
    drift_policy_applied: DriftPolicy | None = None
    trust_penalty: float = 0.0
    params_hash: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "agent_id": self.agent_id,
            "request_id": self.request_id,
            "was_planned": self.was_planned,
            "outcome": self.outcome,
            "drift_policy_applied": self.drift_policy_applied.value if self.drift_policy_applied else None,
            "trust_penalty": self.trust_penalty,
            "params_hash": self.params_hash,
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ExecutionRecord:
        return cls(
            action=d["action"],
            agent_id=d["agent_id"],
            request_id=d["request_id"],
            was_planned=d["was_planned"],
            outcome=d["outcome"],
            drift_policy_applied=DriftPolicy(d["drift_policy_applied"]) if d.get("drift_policy_applied") else None,
            trust_penalty=d.get("trust_penalty", 0.0),
            params_hash=d.get("params_hash"),
            timestamp=datetime.fromisoformat(d["timestamp"]),
        )


@dataclass
class DriftEvent:
    """An event recorded when an action drifts from declared intent."""

    intent_id: str
    agent_id: str
    request_id: str
    action_attempted: str
    was_planned: bool
    drift_policy_applied: DriftPolicy
    result: str  # "allowed_with_penalty", "blocked", "re_declare_required"
    trust_penalty: float
    params_hash: str | None = None
    parent_intent_id: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent_id": self.intent_id,
            "agent_id": self.agent_id,
            "request_id": self.request_id,
            "action_attempted": self.action_attempted,
            "was_planned": self.was_planned,
            "drift_policy_applied": self.drift_policy_applied.value,
            "result": self.result,
            "trust_penalty": self.trust_penalty,
            "params_hash": self.params_hash,
            "parent_intent_id": self.parent_intent_id,
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> DriftEvent:
        return cls(
            intent_id=d["intent_id"],
            agent_id=d["agent_id"],
            request_id=d["request_id"],
            action_attempted=d["action_attempted"],
            was_planned=d["was_planned"],
            drift_policy_applied=DriftPolicy(d["drift_policy_applied"]),
            result=d["result"],
            trust_penalty=d.get("trust_penalty", 0.0),
            params_hash=d.get("params_hash"),
            parent_intent_id=d.get("parent_intent_id"),
            timestamp=datetime.fromisoformat(d["timestamp"]),
        )


@dataclass
class ExecutionIntent:
    """A first-class intent object representing an agent's declared plan.

    Lifecycle: DECLARED -> APPROVED -> EXECUTING -> COMPLETED | VIOLATED | EXPIRED

    Attributes:
        intent_id: Unique identifier for this intent.
        agent_id: The agent that declared the intent.
        planned_actions: Actions the agent plans to perform.
        drift_policy: How to handle actions not in the plan.
        state: Current lifecycle state.
        version: Optimistic concurrency version (incremented on each update).
        parent_intent_id: If this is a child intent, the parent's ID.
        declared_at: When the intent was declared.
        approved_at: When the intent was approved (None if not yet approved).
        expires_at: When the intent expires (None for no expiry).
        execution_records: Structured records of all attempted actions.
        drift_events: Events recorded when drift is detected.
    """

    intent_id: str = field(default_factory=lambda: f"intent:{uuid.uuid4().hex[:12]}")
    agent_id: str = ""
    planned_actions: list[IntentAction] = field(default_factory=list)
    drift_policy: DriftPolicy = DriftPolicy.SOFT_BLOCK
    state: IntentState = IntentState.DECLARED
    version: int = 1
    parent_intent_id: str | None = None
    declared_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    approved_at: datetime | None = None
    expires_at: datetime | None = None
    execution_records: list[ExecutionRecord] = field(default_factory=list)
    drift_events: list[DriftEvent] = field(default_factory=list)

    @property
    def is_terminal(self) -> bool:
        return self.state in _TERMINAL_STATES

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(UTC) >= self.expires_at

    @property
    def planned_action_names(self) -> set[str]:
        return {a.action for a in self.planned_actions}

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent_id": self.intent_id,
            "agent_id": self.agent_id,
            "planned_actions": [a.to_dict() for a in self.planned_actions],
            "drift_policy": self.drift_policy.value,
            "state": self.state.value,
            "version": self.version,
            "parent_intent_id": self.parent_intent_id,
            "declared_at": self.declared_at.isoformat(),
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "execution_records": [r.to_dict() for r in self.execution_records],
            "drift_events": [e.to_dict() for e in self.drift_events],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ExecutionIntent:
        return cls(
            intent_id=d["intent_id"],
            agent_id=d["agent_id"],
            planned_actions=[IntentAction.from_dict(a) for a in d.get("planned_actions", [])],
            drift_policy=DriftPolicy(d.get("drift_policy", "soft_block")),
            state=IntentState(d.get("state", "declared")),
            version=d.get("version", 1),
            parent_intent_id=d.get("parent_intent_id"),
            declared_at=datetime.fromisoformat(d["declared_at"]),
            approved_at=datetime.fromisoformat(d["approved_at"]) if d.get("approved_at") else None,
            expires_at=datetime.fromisoformat(d["expires_at"]) if d.get("expires_at") else None,
            execution_records=[ExecutionRecord.from_dict(r) for r in d.get("execution_records", [])],
            drift_events=[DriftEvent.from_dict(e) for e in d.get("drift_events", [])],
        )


@dataclass
class IntentCheckResult:
    """Result of checking an action against a declared intent."""

    allowed: bool
    was_planned: bool
    drift_policy_applied: DriftPolicy | None = None
    trust_penalty: float = 0.0
    reason: str = ""
    drift_event: DriftEvent | None = None


@dataclass
class IntentVerification:
    """Summary produced when an intent is completed.

    Compares planned actions vs actual execution for audit.
    """

    intent_id: str
    agent_id: str
    planned_actions: list[str]
    executed_actions: list[str]
    unplanned_actions: list[str]
    missed_actions: list[str]
    total_drift_events: int
    total_trust_penalty: float
    state: IntentState
    duration_seconds: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent_id": self.intent_id,
            "agent_id": self.agent_id,
            "planned_actions": self.planned_actions,
            "executed_actions": self.executed_actions,
            "unplanned_actions": self.unplanned_actions,
            "missed_actions": self.missed_actions,
            "total_drift_events": self.total_drift_events,
            "total_trust_penalty": self.total_trust_penalty,
            "state": self.state.value,
            "duration_seconds": self.duration_seconds,
        }


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class IntentError(Exception):
    """Base exception for intent operations."""


class IntentNotFoundError(IntentError):
    """Raised when an intent_id does not exist."""


class IntentStateError(IntentError):
    """Raised for invalid state transitions."""


class IntentVersionConflict(IntentError):
    """Raised when optimistic concurrency check fails."""


class IntentScopeError(IntentError):
    """Raised when a child intent tries to expand parent scope."""


# ---------------------------------------------------------------------------
# IntentManager
# ---------------------------------------------------------------------------

# Default trust penalty for unplanned actions under soft_block.
DEFAULT_DRIFT_PENALTY = 50.0


class IntentManager:
    """Manages intent lifecycle backed by a StateBackend.

    All state is persisted externally, so multiple IntentManager instances
    can operate against the same backend without conflicts (optimistic
    concurrency via version fields).

    Usage:
        >>> from agent_os.stateless import MemoryBackend
        >>> manager = IntentManager(backend=MemoryBackend())
        >>> intent = await manager.declare_intent(
        ...     agent_id="agent-1",
        ...     planned_actions=[IntentAction(action="database_query")],
        ... )
        >>> intent = await manager.approve_intent(intent.intent_id)
        >>> check = await manager.check_action(
        ...     intent.intent_id, "database_query", {}, "agent-1", "req-1"
        ... )
        >>> assert check.allowed and check.was_planned
    """

    # Key prefix for intent storage.
    KEY_PREFIX = "intent:"

    def __init__(
        self,
        backend: Any,
        drift_penalty: float = DEFAULT_DRIFT_PENALTY,
    ) -> None:
        """Initialize IntentManager.

        Args:
            backend: A StateBackend instance (MemoryBackend, RedisBackend, etc.)
            drift_penalty: Trust penalty applied per unplanned action under soft_block.
        """
        self._backend = backend
        self._drift_penalty = drift_penalty

    # ----- persistence helpers -----

    def _key(self, intent_id: str) -> str:
        # intent_id already starts with "intent:" by default, so use it directly.
        return f"agt:{intent_id}"

    async def _load(self, intent_id: str) -> ExecutionIntent:
        data = await self._backend.get(self._key(intent_id))
        if data is None:
            raise IntentNotFoundError(f"Intent '{intent_id}' not found")
        return ExecutionIntent.from_dict(data)

    async def _save(
        self,
        intent: ExecutionIntent,
        expected_version: int | None = None,
        ttl: int | None = None,
    ) -> None:
        """Save intent with optional optimistic concurrency check."""
        if expected_version is not None:
            existing = await self._backend.get(self._key(intent.intent_id))
            if existing and existing.get("version", 1) != expected_version:
                raise IntentVersionConflict(
                    f"Version conflict for '{intent.intent_id}': "
                    f"expected {expected_version}, got {existing.get('version')}"
                )
        intent.version += 1
        await self._backend.set(self._key(intent.intent_id), intent.to_dict(), ttl)

    def _transition(self, intent: ExecutionIntent, target: IntentState) -> None:
        """Validate and apply a state transition."""
        if intent.is_terminal:
            raise IntentStateError(
                f"Intent '{intent.intent_id}' is in terminal state '{intent.state.value}'"
            )
        allowed = _TRANSITIONS.get(intent.state, frozenset())
        if target not in allowed:
            raise IntentStateError(
                f"Cannot transition from '{intent.state.value}' to '{target.value}'"
            )
        intent.state = target

    # ----- public API -----

    async def declare_intent(
        self,
        agent_id: str,
        planned_actions: list[IntentAction],
        drift_policy: DriftPolicy = DriftPolicy.SOFT_BLOCK,
        parent_intent_id: str | None = None,
        ttl_seconds: int | None = None,
    ) -> ExecutionIntent:
        """Declare an execution intent.

        Args:
            agent_id: The declaring agent's identifier.
            planned_actions: Actions the agent intends to perform.
            drift_policy: How to handle actions not in the plan.
            parent_intent_id: If set, this intent must narrow the parent's scope.
            ttl_seconds: Optional time-to-live in seconds.

        Returns:
            The newly created ExecutionIntent in DECLARED state.

        Raises:
            IntentScopeError: If child scope exceeds parent scope.
            IntentNotFoundError: If parent_intent_id does not exist.
        """
        expires_at = (
            datetime.now(UTC) + timedelta(seconds=ttl_seconds)
            if ttl_seconds else None
        )

        # Validate child scope against parent.
        if parent_intent_id:
            parent = await self._load(parent_intent_id)
            parent_action_names = parent.planned_action_names
            child_action_names = {a.action for a in planned_actions}
            excess = child_action_names - parent_action_names
            if excess:
                raise IntentScopeError(
                    f"Child intent cannot expand parent scope. "
                    f"Excess actions: {excess}"
                )

        intent = ExecutionIntent(
            agent_id=agent_id,
            planned_actions=planned_actions,
            drift_policy=drift_policy,
            parent_intent_id=parent_intent_id,
            expires_at=expires_at,
        )

        backend_ttl = ttl_seconds * 2 if ttl_seconds else None
        await self._save(intent, ttl=backend_ttl)

        logger.info(
            "Intent declared: %s by %s with %d planned actions",
            intent.intent_id, agent_id, len(planned_actions),
        )
        return intent

    async def approve_intent(self, intent_id: str) -> ExecutionIntent:
        """Approve a declared intent, allowing execution to begin.

        Args:
            intent_id: The intent to approve.

        Returns:
            The updated intent in APPROVED state.

        Raises:
            IntentNotFoundError: If intent does not exist.
            IntentStateError: If intent is not in DECLARED state.
        """
        intent = await self._load(intent_id)

        if intent.is_expired:
            self._transition(intent, IntentState.EXPIRED)
            await self._save(intent, expected_version=intent.version)
            raise IntentStateError(f"Intent '{intent_id}' has expired")

        self._transition(intent, IntentState.APPROVED)
        intent.approved_at = datetime.now(UTC)
        await self._save(intent, expected_version=intent.version)

        logger.info("Intent approved: %s", intent_id)
        return intent

    async def check_action(
        self,
        intent_id: str,
        action: str,
        params: dict[str, Any] | None,
        agent_id: str,
        request_id: str,
    ) -> IntentCheckResult:
        """Check whether an action is allowed under the declared intent.

        This is the core method called by the kernel before executing each action.
        It also transitions the intent to EXECUTING on first action.

        Args:
            intent_id: The active intent.
            action: The action being attempted.
            params: The action parameters.
            agent_id: The agent attempting the action.
            request_id: Correlation ID for the request.

        Returns:
            IntentCheckResult indicating whether the action is allowed.
        """
        intent = await self._load(intent_id)

        # Check expiry.
        if intent.is_expired:
            self._transition(intent, IntentState.EXPIRED)
            await self._save(intent, expected_version=intent.version)
            return IntentCheckResult(
                allowed=False,
                was_planned=False,
                reason=f"Intent '{intent_id}' has expired",
            )

        # Must be APPROVED or already EXECUTING.
        if intent.state not in (IntentState.APPROVED, IntentState.EXECUTING):
            return IntentCheckResult(
                allowed=False,
                was_planned=False,
                reason=f"Intent '{intent_id}' is in state '{intent.state.value}', "
                       f"must be APPROVED or EXECUTING",
            )

        # Transition to EXECUTING on first action.
        if intent.state == IntentState.APPROVED:
            self._transition(intent, IntentState.EXECUTING)

        # Check if action is in the plan.
        params_hash = _hash_params(params) if params else None
        was_planned = any(
            pa.matches(action, params) for pa in intent.planned_actions
        )

        if was_planned:
            record = ExecutionRecord(
                action=action,
                agent_id=agent_id,
                request_id=request_id,
                was_planned=True,
                outcome="executed",
                params_hash=params_hash,
            )
            intent.execution_records.append(record)
            await self._save(intent, expected_version=intent.version)
            return IntentCheckResult(allowed=True, was_planned=True)

        # Drift detected: apply drift policy.
        drift_policy = intent.drift_policy

        if drift_policy == DriftPolicy.SOFT_BLOCK:
            result_str = "allowed_with_penalty"
            allowed = True
            outcome = "executed"
        elif drift_policy == DriftPolicy.HARD_BLOCK:
            result_str = "blocked"
            allowed = False
            outcome = "blocked"
        else:  # RE_DECLARE
            result_str = "re_declare_required"
            allowed = False
            outcome = "re_declare_required"

        drift_event = DriftEvent(
            intent_id=intent.intent_id,
            agent_id=agent_id,
            request_id=request_id,
            action_attempted=action,
            was_planned=False,
            drift_policy_applied=drift_policy,
            result=result_str,
            trust_penalty=self._drift_penalty,
            params_hash=params_hash,
            parent_intent_id=intent.parent_intent_id,
        )

        record = ExecutionRecord(
            action=action,
            agent_id=agent_id,
            request_id=request_id,
            was_planned=False,
            outcome=outcome,
            drift_policy_applied=drift_policy,
            trust_penalty=self._drift_penalty,
            params_hash=params_hash,
        )

        intent.drift_events.append(drift_event)
        intent.execution_records.append(record)
        await self._save(intent, expected_version=intent.version)

        logger.warning(
            "Drift detected for intent %s: action '%s' not planned, policy=%s",
            intent.intent_id, action, drift_policy.value,
        )

        return IntentCheckResult(
            allowed=allowed,
            was_planned=False,
            drift_policy_applied=drift_policy,
            trust_penalty=self._drift_penalty,
            reason=f"Action '{action}' not in declared plan, policy={drift_policy.value}",
            drift_event=drift_event,
        )

    async def verify_intent(self, intent_id: str) -> IntentVerification:
        """Complete an intent and produce a verification report.

        Compares planned actions against what was actually executed.

        Args:
            intent_id: The intent to verify and complete.

        Returns:
            IntentVerification summary of planned vs actual.

        Raises:
            IntentNotFoundError: If intent does not exist.
            IntentStateError: If intent is not in EXECUTING state.
        """
        intent = await self._load(intent_id)

        if intent.state not in (IntentState.EXECUTING, IntentState.APPROVED):
            raise IntentStateError(
                f"Cannot verify intent in state '{intent.state.value}'"
            )

        # Compute planned vs actual.
        planned_names = [a.action for a in intent.planned_actions]
        executed_names = [
            r.action for r in intent.execution_records
            if r.outcome == "executed"
        ]
        unplanned = [
            r.action for r in intent.execution_records
            if not r.was_planned and r.outcome == "executed"
        ]
        executed_set = set(executed_names)
        missed = [a for a in planned_names if a not in executed_set]

        total_penalty = sum(e.trust_penalty for e in intent.drift_events)
        duration = None
        if intent.approved_at:
            duration = (datetime.now(UTC) - intent.approved_at).total_seconds()

        # Transition to terminal state.
        if intent.drift_events:
            self._transition(intent, IntentState.VIOLATED)
        else:
            self._transition(intent, IntentState.COMPLETED)

        await self._save(intent, expected_version=intent.version)

        return IntentVerification(
            intent_id=intent.intent_id,
            agent_id=intent.agent_id,
            planned_actions=planned_names,
            executed_actions=executed_names,
            unplanned_actions=unplanned,
            missed_actions=missed,
            total_drift_events=len(intent.drift_events),
            total_trust_penalty=total_penalty,
            state=intent.state,
            duration_seconds=duration,
        )

    async def get_intent(self, intent_id: str) -> ExecutionIntent | None:
        """Get an intent by ID, or None if not found."""
        try:
            return await self._load(intent_id)
        except IntentNotFoundError:
            return None

    async def create_child_intent(
        self,
        parent_intent_id: str,
        agent_id: str,
        planned_actions: list[IntentAction],
        drift_policy: DriftPolicy | None = None,
        ttl_seconds: int | None = None,
    ) -> ExecutionIntent:
        """Create a child intent that narrows the parent's scope.

        Child intents are used in multi-agent orchestration where the
        orchestrator declares intent and sub-agents inherit a narrowed scope.

        Args:
            parent_intent_id: The parent intent to inherit from.
            agent_id: The sub-agent's identifier.
            planned_actions: Must be a subset of parent's planned actions.
            drift_policy: Override drift policy, or inherit from parent.
            ttl_seconds: Optional TTL for the child intent.

        Returns:
            The child intent in DECLARED state.

        Raises:
            IntentScopeError: If child scope exceeds parent scope.
        """
        parent = await self._load(parent_intent_id)
        effective_policy = drift_policy if drift_policy is not None else parent.drift_policy

        return await self.declare_intent(
            agent_id=agent_id,
            planned_actions=planned_actions,
            drift_policy=effective_policy,
            parent_intent_id=parent_intent_id,
            ttl_seconds=ttl_seconds,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hash_params(params: dict[str, Any]) -> str:
    """Create a deterministic hash of action parameters for audit."""
    import json
    normalized = json.dumps(params, sort_keys=True, default=str)
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]
