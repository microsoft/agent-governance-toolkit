# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Kill Switch — agent termination with optional handoff.

Terminates agent processes via registered callbacks and hands off
in-flight saga steps to a substitute agent when one is available.
"""

from __future__ import annotations

import logging
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum

_logger = logging.getLogger(__name__)

# Maximum wall time we wait for an agent's termination callback to complete
# before declaring it hung. The kill switch must remain responsive — a slow
# callback should not block the entire kill flow.
DEFAULT_CALLBACK_TIMEOUT_SECONDS = 5.0


class KillReason(str, Enum):
    """Why an agent was killed."""

    BEHAVIORAL_DRIFT = "behavioral_drift"
    RATE_LIMIT = "rate_limit"
    RING_BREACH = "ring_breach"
    MANUAL = "manual"
    QUARANTINE_TIMEOUT = "quarantine_timeout"
    SESSION_TIMEOUT = "session_timeout"


class HandoffStatus(str, Enum):
    """Status of a saga step handoff."""

    PENDING = "pending"
    HANDED_OFF = "handed_off"
    FAILED = "failed"
    COMPENSATED = "compensated"


@dataclass
class StepHandoff:
    """A saga step being handed off to a substitute or compensated."""

    step_id: str
    saga_id: str
    from_agent: str
    to_agent: str | None = None
    status: HandoffStatus = HandoffStatus.COMPENSATED


@dataclass
class KillResult:
    """Result of a kill switch operation."""

    kill_id: str = field(default_factory=lambda: f"kill:{uuid.uuid4().hex[:8]}")
    agent_did: str = ""
    session_id: str = ""
    reason: KillReason = KillReason.MANUAL
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    handoffs: list[StepHandoff] = field(default_factory=list)
    handoff_success_count: int = 0
    compensation_triggered: bool = False
    terminated: bool = False
    details: str = ""


class KillSwitch:
    """
    Kill switch with agent process registry and handoff support.

    Agents register termination callbacks via ``register_agent``.  When
    ``kill`` is called the switch hands in-flight saga steps to a
    registered substitute (if any) and then invokes the termination
    callback to stop the agent process.
    """

    def __init__(
        self, callback_timeout: float = DEFAULT_CALLBACK_TIMEOUT_SECONDS
    ) -> None:
        self._kill_history: list[KillResult] = []
        self._substitutes: dict[str, list[str]] = {}
        self._agents: dict[str, Callable[[], None]] = {}
        self._callback_timeout = callback_timeout
        # RLock so a callback that itself re-enters the kill switch
        # (e.g. unregisters another agent) does not deadlock.
        self._lock = threading.RLock()

    # ── Agent process registry ─────────────────────────────────────

    def register_agent(
        self, agent_did: str, process_handle: Callable[[], None]
    ) -> None:
        """Register an agent with its termination callback."""
        with self._lock:
            self._agents[agent_did] = process_handle

    def unregister_agent(self, agent_did: str) -> None:
        """Remove an agent from the process registry."""
        with self._lock:
            self._agents.pop(agent_did, None)

    # ── Substitute management ──────────────────────────────────────

    def register_substitute(
        self, session_id: str, agent_did: str
    ) -> None:
        """Register a substitute agent for a session."""
        with self._lock:
            self._substitutes.setdefault(session_id, []).append(agent_did)

    def unregister_substitute(
        self, session_id: str, agent_did: str
    ) -> None:
        with self._lock:
            subs = self._substitutes.get(session_id, [])
            if agent_did in subs:
                subs.remove(agent_did)

    # ── Kill ───────────────────────────────────────────────────────

    def kill(
        self,
        agent_did: str,
        session_id: str,
        reason: KillReason,
        in_flight_steps: list[dict] | None = None,
        details: str = "",
    ) -> KillResult:
        """Kill an agent, handing off in-flight steps to a substitute if available.

        Registration invariant: the agent is unregistered from the
        process registry **unconditionally** at the end of this method,
        regardless of whether the termination callback succeeded
        (``terminated=True``) or failed/timed out (``terminated=False``).
        This is intentional. The kill *intent* is durably recorded in
        ``_kill_history`` and surfaced via the returned ``KillResult``;
        leaving the callback registered would falsely advertise the
        agent as live and re-callable when its process state is
        actually unknown. Callers who detect ``terminated=False`` and
        want to retry must re-register the agent (presumably with a
        new, working callback) before issuing the second ``kill()``.
        """
        in_flight = in_flight_steps or []

        with self._lock:
            substitute = self._find_substitute(session_id, agent_did)
            callback = self._agents.get(agent_did)

        handoffs: list[StepHandoff] = []
        handoff_success_count = 0
        for step_info in in_flight:
            if substitute is not None:
                handoffs.append(
                    StepHandoff(
                        step_id=step_info.get("step_id", ""),
                        saga_id=step_info.get("saga_id", ""),
                        from_agent=agent_did,
                        to_agent=substitute,
                        status=HandoffStatus.HANDED_OFF,
                    )
                )
                handoff_success_count += 1
            else:
                handoffs.append(
                    StepHandoff(
                        step_id=step_info.get("step_id", ""),
                        saga_id=step_info.get("saga_id", ""),
                        from_agent=agent_did,
                        status=HandoffStatus.COMPENSATED,
                    )
                )

        # Invoke the termination callback *outside* the lock and with a
        # wall-clock timeout. A slow or hung callback must not freeze the
        # kill flow — the whole point of a kill switch is responsiveness.
        terminated = False
        if callback is not None:
            terminated = self._invoke_callback_with_timeout(
                agent_did, callback
            )
        else:
            _logger.warning(
                "No termination callback registered for agent %s",
                agent_did,
            )

        result = KillResult(
            agent_did=agent_did,
            session_id=session_id,
            reason=reason,
            handoffs=handoffs,
            handoff_success_count=handoff_success_count,
            compensation_triggered=any(
                h.status == HandoffStatus.COMPENSATED for h in handoffs
            ),
            terminated=terminated,
            details=details,
        )
        with self._lock:
            self._kill_history.append(result)
        self.unregister_substitute(session_id, agent_did)
        self.unregister_agent(agent_did)
        return result

    def _invoke_callback_with_timeout(
        self, agent_did: str, callback: Callable[[], None]
    ) -> bool:
        """Run *callback* in a daemon thread bounded by ``callback_timeout``.

        Returns ``True`` if the callback completed cleanly within the
        timeout, ``False`` if it timed out or raised. A hung callback
        is left to its fate (daemon thread); the kill switch returns
        and remains usable for the next kill.
        """
        error_box: list[BaseException] = []

        def _runner() -> None:
            try:
                callback()
            except BaseException as exc:  # noqa: BLE001 — surface but don't propagate
                error_box.append(exc)

        thread = threading.Thread(
            target=_runner, name=f"kill-callback:{agent_did}", daemon=True
        )
        thread.start()
        thread.join(timeout=self._callback_timeout)

        if thread.is_alive():
            _logger.error(
                "Termination callback for %s exceeded %.2fs; leaving daemon thread to drain",
                agent_did,
                self._callback_timeout,
            )
            return False
        if error_box:
            _logger.error(
                "Termination callback for %s raised %s: %s",
                agent_did,
                type(error_box[0]).__name__,
                error_box[0],
            )
            return False
        return True

    def _find_substitute(
        self, session_id: str, exclude_did: str
    ) -> str | None:
        """Find a registered substitute for the session, excluding the given agent."""
        subs = self._substitutes.get(session_id, [])
        for sub in subs:
            if sub != exclude_did:
                return sub
        return None

    @property
    def kill_history(self) -> list[KillResult]:
        return list(self._kill_history)

    @property
    def total_kills(self) -> int:
        return len(self._kill_history)

    @property
    def total_handoffs(self) -> int:
        return sum(r.handoff_success_count for r in self._kill_history)
