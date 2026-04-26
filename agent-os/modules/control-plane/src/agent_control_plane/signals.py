# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Signal Handling - POSIX-style signals for AI Agents

This module implements a signal-based control mechanism for agents,
inspired by POSIX signals but designed for AI agent lifecycle management.

Unlike AIOS (which focuses on efficiency/throughput), this focuses on
SAFETY and CONTROL - enabling immediate intervention when agents misbehave.

Signals:
    SIGSTOP  - Pause agent execution (enter shadow mode for inspection)
    SIGCONT  - Resume agent execution
    SIGINT   - Graceful interrupt (complete current action, then stop)
    SIGKILL  - Immediate termination (kernel panic on policy violation)
    SIGTERM  - Request graceful shutdown
    SIGUSR1  - Enter diagnostic mode
    SIGUSR2  - Trigger checkpoint/snapshot

Design Philosophy:
    - Kernel survives agent crashes (Kernel/User space separation)
    - Policy violations trigger SIGKILL (0% violation tolerance)
    - All signals are logged to Flight Recorder
"""

from enum import IntEnum, auto
from typing import Dict, Optional, Callable, Any, List, Set
from dataclasses import dataclass, field
from datetime import datetime, timezone
import asyncio
import logging
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class AgentSignal(IntEnum):
    """
    POSIX-inspired signals for agent lifecycle control.
    
    These signals provide kernel-level control over agent execution,
    enabling immediate intervention without relying on the agent itself.
    """
    # Standard control signals
    SIGSTOP = 1    # Pause execution (enter shadow/inspection mode)
    SIGCONT = 2    # Resume execution
    SIGINT = 3     # Graceful interrupt
    SIGKILL = 4    # Immediate termination (non-maskable)
    SIGTERM = 5    # Request graceful shutdown
    
    # Diagnostic signals
    SIGUSR1 = 6    # Enter diagnostic mode
    SIGUSR2 = 7    # Trigger checkpoint/snapshot
    
    # Agent-specific signals
    SIGPOLICY = 8  # Policy violation detected
    SIGTRUST = 9   # Trust boundary crossed
    SIGBUDGET = 10 # Resource budget exceeded
    SIGLOOP = 11   # Infinite loop detected
    SIGDRIFT = 12  # Goal drift detected


class SignalDisposition(IntEnum):
    """How a signal should be handled."""
    DEFAULT = auto()    # Use default handler
    IGNORE = auto()     # Ignore the signal (not allowed for SIGKILL)
    CUSTOM = auto()     # Use custom handler
    BLOCK = auto()      # Block/queue the signal


@dataclass
class SignalInfo:
    """Information about a delivered signal."""
    signal: AgentSignal
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "kernel"  # Who sent the signal
    reason: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "signal": self.signal.name,
            "signal_value": self.signal.value,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "reason": self.reason,
            "context": self.context,
        }


@dataclass
class SignalMask:
    """
    Signal mask for blocking signals during critical sections.
    
    Note: SIGKILL and SIGPOLICY cannot be masked (kernel authority).
    """
    blocked: Set[AgentSignal] = field(default_factory=set)
    
    # These signals can NEVER be blocked (kernel authority)
    UNMASKABLE: Set[AgentSignal] = field(
        default_factory=lambda: {
            AgentSignal.SIGKILL,
            AgentSignal.SIGPOLICY,
        },
        init=False
    )
    
    def block(self, signal: AgentSignal) -> bool:
        """Block a signal. Returns False if signal is unmaskable."""
        if signal in self.UNMASKABLE:
            logger.warning(f"Cannot block unmaskable signal: {signal.name}")
            return False
        self.blocked.add(signal)
        return True
    
    def unblock(self, signal: AgentSignal) -> None:
        """Unblock a signal."""
        self.blocked.discard(signal)
    
    def is_blocked(self, signal: AgentSignal) -> bool:
        """Check if a signal is blocked."""
        if signal in self.UNMASKABLE:
            return False
        return signal in self.blocked


SignalHandler = Callable[[SignalInfo], None]


class SignalDispatcher:
    """
    Signal dispatcher for agent control.
    
    This is the kernel-space component that manages signal delivery.
    It survives agent crashes and maintains control even when agents fail.
    """
    
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self._handlers: Dict[AgentSignal, SignalHandler] = {}
        self._dispositions: Dict[AgentSignal, SignalDisposition] = {}
        self._mask = SignalMask()
        self._pending: List[SignalInfo] = []  # Queue for blocked signals
        self._signal_history: List[SignalInfo] = []
        self._is_stopped = False
        self._is_terminated = False
        
        # Install default handlers
        self._install_default_handlers()
    
    def _install_default_handlers(self) -> None:
        """Install default signal handlers."""
        self._handlers[AgentSignal.SIGSTOP] = self._handle_stop
        self._handlers[AgentSignal.SIGCONT] = self._handle_continue
        self._handlers[AgentSignal.SIGINT] = self._handle_interrupt
        self._handlers[AgentSignal.SIGKILL] = self._handle_kill
        self._handlers[AgentSignal.SIGTERM] = self._handle_term
        self._handlers[AgentSignal.SIGPOLICY] = self._handle_policy_violation
        self._handlers[AgentSignal.SIGTRUST] = self._handle_trust_violation
        self._handlers[AgentSignal.SIGBUDGET] = self._handle_budget_exceeded
        
        # Set all dispositions to DEFAULT
        for sig in AgentSignal:
            self._dispositions[sig] = SignalDisposition.DEFAULT
    
    def signal(
        self,
        sig: AgentSignal,
        source: str = "kernel",
        reason: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Send a signal to this agent.
        
        Returns True if signal was delivered, False if blocked/pending.
        """
        info = SignalInfo(
            signal=sig,
            source=source,
            reason=reason,
            context=context or {},
        )
        
        # Record in history (always, even if blocked)
        self._signal_history.append(info)
        
        logger.info(
            f"[Signal] {self.agent_id} received {sig.name} from {source}"
            + (f": {reason}" if reason else "")
        )
        
        # Check if signal is blocked
        if self._mask.is_blocked(sig):
            logger.debug(f"[Signal] {sig.name} blocked, adding to pending queue")
            self._pending.append(info)
            return False
        
        # Deliver the signal
        return self._deliver(info)
    
    def _deliver(self, info: SignalInfo) -> bool:
        """Actually deliver a signal to its handler."""
        sig = info.signal
        disposition = self._dispositions.get(sig, SignalDisposition.DEFAULT)
        
        if disposition == SignalDisposition.IGNORE and sig not in self._mask.UNMASKABLE:
            logger.debug(f"[Signal] {sig.name} ignored by disposition")
            return True
        
        handler = self._handlers.get(sig)
        if handler:
            try:
                handler(info)
                return True
            except Exception as e:
                logger.error(f"[Signal] Handler for {sig.name} failed: {e}")
                # On handler failure for critical signals, escalate to SIGKILL
                if sig in (AgentSignal.SIGPOLICY, AgentSignal.SIGTRUST):
                    self._handle_kill(SignalInfo(
                        signal=AgentSignal.SIGKILL,
                        source="kernel",
                        reason=f"Handler failure during {sig.name}: {e}",
                    ))
                return False
        
        logger.warning(f"[Signal] No handler for {sig.name}")
        return False
    
    def set_handler(
        self,
        sig: AgentSignal,
        handler: SignalHandler,
    ) -> Optional[SignalHandler]:
        """
        Set a custom signal handler.
        
        Returns the previous handler, or None.
        Note: SIGKILL handler cannot be changed.
        """
        if sig == AgentSignal.SIGKILL:
            logger.warning("Cannot override SIGKILL handler")
            return None
        
        old_handler = self._handlers.get(sig)
        self._handlers[sig] = handler
        self._dispositions[sig] = SignalDisposition.CUSTOM
        return old_handler
    
    def set_disposition(self, sig: AgentSignal, disposition: SignalDisposition) -> None:
        """Set signal disposition."""
        if sig in self._mask.UNMASKABLE and disposition == SignalDisposition.IGNORE:
            logger.warning(f"Cannot ignore unmaskable signal: {sig.name}")
            return
        self._dispositions[sig] = disposition
    
    def block_signals(self, signals: List[AgentSignal]) -> None:
        """Block multiple signals."""
        for sig in signals:
            self._mask.block(sig)
    
    def unblock_signals(self, signals: List[AgentSignal]) -> None:
        """Unblock signals and deliver any pending."""
        for sig in signals:
            self._mask.unblock(sig)
        
        # Deliver pending signals that are now unblocked
        still_pending = []
        for info in self._pending:
            if self._mask.is_blocked(info.signal):
                still_pending.append(info)
            else:
                self._deliver(info)
        self._pending = still_pending
    
    # ========== Default Signal Handlers ==========
    
    def _handle_stop(self, info: SignalInfo) -> None:
        """SIGSTOP: Pause execution, enter shadow/inspection mode."""
        logger.info(f"[SIGSTOP] Agent {self.agent_id} paused for inspection")
        self._is_stopped = True
        # The agent loop should check is_stopped and enter shadow mode
    
    def _handle_continue(self, info: SignalInfo) -> None:
        """SIGCONT: Resume execution from paused state."""
        if not self._is_stopped:
            logger.debug(f"[SIGCONT] Agent {self.agent_id} was not stopped")
            return
        logger.info(f"[SIGCONT] Agent {self.agent_id} resumed")
        self._is_stopped = False
    
    def _handle_interrupt(self, info: SignalInfo) -> None:
        """SIGINT: Graceful interrupt - complete current action, then stop."""
        logger.info(f"[SIGINT] Agent {self.agent_id} interrupt requested")
        # Set a flag that the agent loop should check after current action
        self._is_stopped = True
    
    def _handle_kill(self, info: SignalInfo) -> None:
        """
        SIGKILL: Immediate termination.
        
        This is a KERNEL PANIC for agents. Non-maskable, non-catchable.
        Used when policy violations occur or agent is unrecoverable.
        """
        logger.critical(
            f"[SIGKILL] Agent {self.agent_id} TERMINATED - "
            f"Reason: {info.reason or 'Unspecified'}"
        )
        self._is_terminated = True
        self._is_stopped = True
        # Raise exception to force immediate termination
        raise AgentKernelPanic(
            agent_id=self.agent_id,
            signal=info,
            message=f"Agent terminated: {info.reason or 'SIGKILL received'}",
        )
    
    def _handle_term(self, info: SignalInfo) -> None:
        """SIGTERM: Request graceful shutdown."""
        logger.info(f"[SIGTERM] Agent {self.agent_id} shutdown requested")
        self._is_terminated = True
    
    def _handle_policy_violation(self, info: SignalInfo) -> None:
        """
        SIGPOLICY: Policy violation detected.
        
        This is the 0% violation guarantee - escalate to SIGKILL.
        """
        logger.error(
            f"[SIGPOLICY] Agent {self.agent_id} POLICY VIOLATION: {info.reason}"
        )
        # Escalate to kernel panic
        self._handle_kill(SignalInfo(
            signal=AgentSignal.SIGKILL,
            source="policy_engine",
            reason=f"Policy violation: {info.reason}",
            context=info.context,
        ))
    
    def _handle_trust_violation(self, info: SignalInfo) -> None:
        """SIGTRUST: Trust boundary crossed."""
        logger.error(
            f"[SIGTRUST] Agent {self.agent_id} TRUST VIOLATION: {info.reason}"
        )
        # Escalate to kernel panic
        self._handle_kill(SignalInfo(
            signal=AgentSignal.SIGKILL,
            source="trust_engine",
            reason=f"Trust violation: {info.reason}",
            context=info.context,
        ))
    
    def _handle_budget_exceeded(self, info: SignalInfo) -> None:
        """SIGBUDGET: Resource budget exceeded."""
        logger.warning(
            f"[SIGBUDGET] Agent {self.agent_id} exceeded budget: {info.reason}"
        )
        # Don't kill, but pause for intervention
        self._is_stopped = True
    
    # ========== State Queries ==========
    
    @property
    def is_stopped(self) -> bool:
        """Check if agent is in stopped state."""
        return self._is_stopped
    
    @property
    def is_terminated(self) -> bool:
        """Check if agent has been terminated."""
        return self._is_terminated
    
    @property
    def is_running(self) -> bool:
        """Check if agent is in running state."""
        return not self._is_stopped and not self._is_terminated
    
    def get_signal_history(self) -> List[Dict[str, Any]]:
        """Get signal history for debugging/auditing."""
        return [s.to_dict() for s in self._signal_history]


class AgentKernelPanic(Exception):
    """
    Kernel panic exception for agent termination.
    
    This exception cannot be caught by user-space agent code.
    It indicates a fatal error that requires immediate termination.
    """
    
    def __init__(
        self,
        agent_id: str,
        signal: SignalInfo,
        message: str,
    ):
        self.agent_id = agent_id
        self.signal = signal
        super().__init__(message)


class SignalAwareAgent(ABC):
    """
    Abstract base class for agents that respond to signals.
    
    This implements the user-space side of signal handling.
    Agents inherit from this to gain signal awareness.
    """
    
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self._signal_dispatcher = SignalDispatcher(agent_id)
    
    @property
    def signals(self) -> SignalDispatcher:
        """Access the signal dispatcher."""
        return self._signal_dispatcher
    
    def check_signals(self) -> None:
        """
        Check signal state and respond appropriately.
        
        Call this at safe points in agent execution.
        """
        if self._signal_dispatcher.is_terminated:
            raise AgentKernelPanic(
                agent_id=self.agent_id,
                signal=SignalInfo(signal=AgentSignal.SIGKILL, source="check"),
                message="Agent was terminated",
            )
        
        if self._signal_dispatcher.is_stopped:
            # Agent should enter shadow/inspection mode
            self.on_pause()
    
    def on_pause(self) -> None:
        """
        Called when agent is paused (SIGSTOP).
        
        Override to implement shadow mode or inspection behavior.
        """
        pass
    
    @abstractmethod
    async def run(self) -> Any:
        """Main agent execution loop."""
        pass


# ========== Convenience Functions ==========

def kill_agent(dispatcher: SignalDispatcher, reason: str) -> None:
    """Send SIGKILL to an agent (kernel panic)."""
    dispatcher.signal(
        AgentSignal.SIGKILL,
        source="kernel",
        reason=reason,
    )


def pause_agent(dispatcher: SignalDispatcher, reason: str = "Inspection requested") -> None:
    """Send SIGSTOP to pause an agent."""
    dispatcher.signal(
        AgentSignal.SIGSTOP,
        source="kernel",
        reason=reason,
    )


def resume_agent(dispatcher: SignalDispatcher) -> None:
    """Send SIGCONT to resume an agent."""
    dispatcher.signal(
        AgentSignal.SIGCONT,
        source="kernel",
        reason="Resume requested",
    )


def policy_violation(
    dispatcher: SignalDispatcher,
    policy_name: str,
    details: str,
    context: Optional[Dict[str, Any]] = None,
) -> None:
    """Report a policy violation (triggers kernel panic)."""
    dispatcher.signal(
        AgentSignal.SIGPOLICY,
        source="policy_engine",
        reason=f"Violated policy '{policy_name}': {details}",
        context=context or {},
    )
