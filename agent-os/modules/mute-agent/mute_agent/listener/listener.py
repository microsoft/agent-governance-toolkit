# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Listener Agent - Layer 5 Reference Implementation

The Listener Agent is a passive observer that monitors graph states
without interfering until configured thresholds are exceeded.

Architecture:
- Consolidates: agent-control-plane, scak, iatp, caas
- Pattern: Observer with threshold-based intervention
- Principle: Monitor passively, intervene only when necessary

This module is pure wiring - it delegates to lower layers:
- Knowledge graph operations → scak (intelligence layer)
- Security validation → iatp (security layer)  
- Context management → caas (context layer)
- Base orchestration → agent-control-plane
"""

from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
import threading
import time
from collections import deque

from ..knowledge_graph.multidimensional_graph import MultidimensionalKnowledgeGraph
from ..core.handshake_protocol import HandshakeProtocol, HandshakeSession, HandshakeState
from ..core.reasoning_agent import ReasoningAgent
from ..core.execution_agent import ExecutionAgent
from ..super_system.router import SuperSystemRouter

from .threshold_config import (
    ThresholdConfig,
    ThresholdType,
    InterventionLevel,
    ThresholdRule,
    DEFAULT_THRESHOLDS,
)
from .state_observer import StateObserver, ObservationResult


class ListenerState(Enum):
    """States of the Listener Agent."""
    
    # Not actively observing
    IDLE = "idle"
    
    # Passively observing - no intervention
    OBSERVING = "observing"
    
    # Detected threshold breach - evaluating response
    EVALUATING = "evaluating"
    
    # Actively intervening
    INTERVENING = "intervening"
    
    # Intervention complete, returning to observation
    RECOVERING = "recovering"
    
    # Stopped - not operational
    STOPPED = "stopped"


@dataclass
class InterventionEvent:
    """
    Record of a Listener intervention.
    
    This provides an audit trail of when and why the Listener
    transitioned from passive observation to active intervention.
    """
    
    event_id: str
    timestamp: datetime
    triggered_rules: List[ThresholdRule]
    intervention_level: InterventionLevel
    metrics_snapshot: Dict[str, float]
    context: Dict[str, Any]
    action_taken: str
    outcome: Optional[str] = None
    duration_ms: Optional[float] = None


@dataclass
class ListenerConfig:
    """Configuration for the Listener Agent."""
    
    # Threshold configuration
    thresholds: ThresholdConfig = field(default_factory=lambda: DEFAULT_THRESHOLDS)
    
    # Observation settings
    observation_interval_seconds: float = 1.0
    max_observation_history: int = 1000
    
    # Intervention settings
    auto_intervention: bool = True
    require_confirmation: bool = False
    max_interventions_per_minute: int = 10
    
    # Recovery settings
    recovery_observation_count: int = 5
    recovery_success_threshold: float = 0.8


class ListenerAgent:
    """
    Layer 5 Reference Implementation: The Listener Agent
    
    A passive observer that monitors graph states and only intervenes
    when configured thresholds are exceeded.
    
    Design Principles:
    1. Passive by default - observe without interference
    2. Threshold-driven intervention - clear, configurable triggers
    3. Minimal footprint - delegate to lower layers
    4. Full audit trail - every intervention is logged
    
    Usage:
        ```python
        # Create core components
        kg = MultidimensionalKnowledgeGraph()
        protocol = HandshakeProtocol()
        router = SuperSystemRouter(kg)
        
        # Create and start listener
        listener = ListenerAgent(kg, protocol, router)
        listener.start()
        
        # Listener now monitors passively...
        # When thresholds are exceeded, it intervenes automatically
        
        # Stop when done
        listener.stop()
        ```
    """
    
    def __init__(
        self,
        knowledge_graph: MultidimensionalKnowledgeGraph,
        protocol: HandshakeProtocol,
        router: SuperSystemRouter,
        config: Optional[ListenerConfig] = None,
        # Optional lower-layer adapters
        security_adapter: Optional[Any] = None,  # iatp adapter
        context_adapter: Optional[Any] = None,   # caas adapter
    ):
        """
        Initialize the Listener Agent.
        
        Args:
            knowledge_graph: The graph to monitor (via scak)
            protocol: The handshake protocol to observe
            router: The super system router
            config: Listener configuration
            security_adapter: Optional adapter to iatp security layer
            context_adapter: Optional adapter to caas context layer
        """
        self.knowledge_graph = knowledge_graph
        self.protocol = protocol
        self.router = router
        self.config = config or ListenerConfig()
        
        # Lower-layer adapters (for consolidated stack)
        self._security_adapter = security_adapter
        self._context_adapter = context_adapter
        
        # State observer
        self.observer = StateObserver(
            knowledge_graph=knowledge_graph,
            protocol=protocol,
            router=router,
            sample_window_seconds=self.config.thresholds.window_size_seconds,
        )
        
        # Current state
        self._state = ListenerState.IDLE
        self._state_lock = threading.Lock()
        
        # Observation thread
        self._observation_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Intervention tracking
        self._interventions: deque = deque(
            maxlen=self.config.max_observation_history
        )
        self._intervention_count_this_minute = 0
        self._minute_start = datetime.now()
        self._event_counter = 0
        
        # Callbacks
        self._intervention_callbacks: List[Callable[[InterventionEvent], None]] = []
        self._state_change_callbacks: List[Callable[[ListenerState, ListenerState], None]] = []
    
    @property
    def state(self) -> ListenerState:
        """Get current listener state."""
        with self._state_lock:
            return self._state
    
    def _set_state(self, new_state: ListenerState) -> None:
        """Set listener state with callback notification."""
        with self._state_lock:
            old_state = self._state
            self._state = new_state
        
        # Notify callbacks outside lock
        for callback in self._state_change_callbacks:
            try:
                callback(old_state, new_state)
            except Exception:
                pass  # Don't let callback errors affect listener
    
    def start(self) -> None:
        """
        Start the Listener Agent.
        
        Begins passive observation of graph states. The listener will
        continue observing until stop() is called or an intervention
        threshold is exceeded.
        """
        if self._state != ListenerState.IDLE and self._state != ListenerState.STOPPED:
            raise RuntimeError(f"Cannot start listener in state {self._state}")
        
        self._stop_event.clear()
        self._set_state(ListenerState.OBSERVING)
        
        # Start observation thread
        self._observation_thread = threading.Thread(
            target=self._observation_loop,
            name="ListenerAgent-Observer",
            daemon=True,
        )
        self._observation_thread.start()
    
    def stop(self) -> None:
        """
        Stop the Listener Agent.
        
        Ceases observation and any ongoing intervention.
        """
        self._stop_event.set()
        self._set_state(ListenerState.STOPPED)
        
        if self._observation_thread and self._observation_thread.is_alive():
            self._observation_thread.join(timeout=5.0)
    
    def observe_once(self, context: Optional[Dict[str, Any]] = None) -> ObservationResult:
        """
        Perform a single observation cycle.
        
        This is useful for synchronous observation without starting
        the background observation loop.
        
        Args:
            context: Optional context to include
            
        Returns:
            ObservationResult from this cycle
        """
        return self.observer.observe(context)
    
    def evaluate_thresholds(
        self,
        observation: ObservationResult
    ) -> tuple[List[ThresholdRule], InterventionLevel]:
        """
        Evaluate observation against configured thresholds.
        
        Args:
            observation: The observation to evaluate
            
        Returns:
            Tuple of (triggered_rules, max_intervention_level)
        """
        # Convert observation to threshold metrics
        threshold_metrics = observation.to_threshold_metrics()
        
        # Evaluate against thresholds
        triggered_rules = self.config.thresholds.evaluate_all(
            threshold_metrics,
            context={"observation": observation},
        )
        
        # Get maximum intervention level
        max_level = self.config.thresholds.get_maximum_intervention_level(
            triggered_rules
        )
        
        return triggered_rules, max_level
    
    def _observation_loop(self) -> None:
        """Background observation loop."""
        while not self._stop_event.is_set():
            try:
                self._run_observation_cycle()
            except Exception as e:
                # Log error but continue observation
                # In production, this would integrate with logging framework
                pass
            
            # Wait for next observation interval
            self._stop_event.wait(self.config.observation_interval_seconds)
    
    def _run_observation_cycle(self) -> None:
        """Run a single observation cycle."""
        # Perform observation
        observation = self.observer.observe()
        
        # Evaluate thresholds
        triggered_rules, intervention_level = self.evaluate_thresholds(observation)
        
        if not triggered_rules:
            # No thresholds exceeded - continue passive observation
            return
        
        # Thresholds exceeded - evaluate intervention
        self._set_state(ListenerState.EVALUATING)
        
        # Check rate limiting
        if not self._can_intervene():
            self._set_state(ListenerState.OBSERVING)
            return
        
        # Determine if intervention is needed based on level
        if intervention_level == InterventionLevel.OBSERVE:
            # Log only
            self._set_state(ListenerState.OBSERVING)
            return
        
        # Perform intervention
        if self.config.auto_intervention:
            self._perform_intervention(
                triggered_rules,
                intervention_level,
                observation,
            )
        
        # Return to observation (or recovery)
        if self._state == ListenerState.INTERVENING:
            self._set_state(ListenerState.RECOVERING)
            # In recovery mode, continue observation with heightened awareness
            self._recovery_check()
    
    def _can_intervene(self) -> bool:
        """Check if intervention is allowed (rate limiting)."""
        now = datetime.now()
        
        # Reset counter if minute has passed
        if (now - self._minute_start).total_seconds() >= 60:
            self._intervention_count_this_minute = 0
            self._minute_start = now
        
        return self._intervention_count_this_minute < self.config.max_interventions_per_minute
    
    def _perform_intervention(
        self,
        triggered_rules: List[ThresholdRule],
        intervention_level: InterventionLevel,
        observation: ObservationResult,
    ) -> InterventionEvent:
        """
        Perform an intervention based on triggered rules.
        
        This is where the Listener transitions from passive to active.
        """
        self._set_state(ListenerState.INTERVENING)
        start_time = datetime.now()
        
        # Generate event ID
        self._event_counter += 1
        event_id = f"intervention_{self._event_counter}_{start_time.timestamp()}"
        
        # Determine action based on intervention level
        action_taken = self._determine_action(intervention_level, triggered_rules)
        
        # Execute intervention action
        outcome = self._execute_intervention_action(
            action_taken,
            intervention_level,
            triggered_rules,
        )
        
        # Calculate duration
        duration_ms = (datetime.now() - start_time).total_seconds() * 1000
        
        # Create event record
        event = InterventionEvent(
            event_id=event_id,
            timestamp=start_time,
            triggered_rules=triggered_rules,
            intervention_level=intervention_level,
            metrics_snapshot=observation.derived_metrics.copy(),
            context={
                "anomalies": observation.anomalies_detected,
                "graph_snapshot": observation.graph_snapshot,
            },
            action_taken=action_taken,
            outcome=outcome,
            duration_ms=duration_ms,
        )
        
        # Store and notify
        self._interventions.append(event)
        self._intervention_count_this_minute += 1
        
        for callback in self._intervention_callbacks:
            try:
                callback(event)
            except Exception:
                pass
        
        return event
    
    def _determine_action(
        self,
        level: InterventionLevel,
        rules: List[ThresholdRule],
    ) -> str:
        """Determine intervention action based on level and rules."""
        if level == InterventionLevel.WARN:
            return "emit_warning"
        elif level == InterventionLevel.SOFT_BLOCK:
            return "require_confirmation"
        elif level == InterventionLevel.HARD_BLOCK:
            return "block_pending_actions"
        elif level == InterventionLevel.EMERGENCY:
            return "emergency_halt"
        else:
            return "observe_only"
    
    def _execute_intervention_action(
        self,
        action: str,
        level: InterventionLevel,
        rules: List[ThresholdRule],
    ) -> str:
        """
        Execute the determined intervention action.
        
        This is where we wire together the lower layers:
        - Use iatp for security-related interventions
        - Use caas to update context
        - Use agent-control-plane for action blocking
        """
        if action == "emit_warning":
            # Log warning - in production, integrate with alerting system
            return f"Warning emitted for {len(rules)} triggered rules"
        
        elif action == "require_confirmation":
            # Mark pending sessions as requiring confirmation
            pending_blocked = 0
            for session_id, session in self.protocol.sessions.items():
                if session.state in [HandshakeState.VALIDATED, HandshakeState.ACCEPTED]:
                    session.metadata["requires_confirmation"] = True
                    session.metadata["confirmation_reason"] = (
                        f"Threshold breach: {[r.description for r in rules]}"
                    )
                    pending_blocked += 1
            return f"Soft block applied to {pending_blocked} pending sessions"
        
        elif action == "block_pending_actions":
            # Reject all pending sessions
            blocked = 0
            for session_id, session in list(self.protocol.sessions.items()):
                if session.state in [HandshakeState.INITIATED, HandshakeState.NEGOTIATING,
                                    HandshakeState.VALIDATED, HandshakeState.ACCEPTED]:
                    self.protocol.reject_proposal(
                        session_id,
                        reason=f"Listener intervention: {level.value}"
                    )
                    blocked += 1
            return f"Hard block applied, {blocked} sessions rejected"
        
        elif action == "emergency_halt":
            # Emergency halt - reject all and set protective state
            halted = 0
            for session_id, session in list(self.protocol.sessions.items()):
                if session.state != HandshakeState.COMPLETED:
                    try:
                        self.protocol.reject_proposal(
                            session_id,
                            reason="EMERGENCY: System halt by Listener"
                        )
                        halted += 1
                    except ValueError:
                        pass  # Session may already be in terminal state
            
            # If security adapter available, notify it
            if self._security_adapter:
                try:
                    self._security_adapter.emergency_alert(
                        reason="Listener emergency halt",
                        triggered_rules=[r.description for r in rules],
                    )
                except Exception:
                    pass
            
            return f"Emergency halt: {halted} sessions terminated"
        
        return "No action taken"
    
    def _recovery_check(self) -> None:
        """
        Check if system has recovered after intervention.
        
        Performs additional observations to verify system stability
        before returning to normal observation.
        """
        success_count = 0
        
        for _ in range(self.config.recovery_observation_count):
            if self._stop_event.is_set():
                break
            
            observation = self.observer.observe()
            triggered_rules, level = self.evaluate_thresholds(observation)
            
            # Check if we're back to safe levels
            if level in [InterventionLevel.OBSERVE, InterventionLevel.WARN]:
                success_count += 1
            
            time.sleep(self.config.observation_interval_seconds)
        
        # Calculate recovery success rate
        success_rate = success_count / self.config.recovery_observation_count
        
        if success_rate >= self.config.recovery_success_threshold:
            self._set_state(ListenerState.OBSERVING)
        else:
            # Still unstable - may need additional intervention
            self._set_state(ListenerState.EVALUATING)
    
    # === Public API for external integration ===
    
    def register_intervention_callback(
        self,
        callback: Callable[[InterventionEvent], None]
    ) -> None:
        """Register a callback to be notified of interventions."""
        self._intervention_callbacks.append(callback)
    
    def register_state_change_callback(
        self,
        callback: Callable[[ListenerState, ListenerState], None]
    ) -> None:
        """Register a callback to be notified of state changes."""
        self._state_change_callbacks.append(callback)
    
    def get_intervention_history(
        self,
        count: Optional[int] = None
    ) -> List[InterventionEvent]:
        """Get recent intervention events."""
        events = list(self._interventions)
        if count is not None:
            events = events[-count:]
        return events
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get listener statistics."""
        observation_history = self.observer.get_observation_history()
        
        return {
            "state": self._state.value,
            "total_observations": len(observation_history),
            "total_interventions": len(self._interventions),
            "interventions_this_minute": self._intervention_count_this_minute,
            "active_thresholds": len(self.config.thresholds.rules),
            "enabled_thresholds": sum(
                1 for r in self.config.thresholds.rules.values() if r.enabled
            ),
            "observer_baselines": len(self.observer._baselines),
        }
    
    def update_threshold(
        self,
        threshold_type: ThresholdType,
        new_value: float
    ) -> None:
        """Update a threshold value at runtime."""
        rule = self.config.thresholds.get_rule(threshold_type)
        if rule:
            rule.value = new_value
    
    def enable_threshold(self, threshold_type: ThresholdType) -> None:
        """Enable a threshold rule."""
        self.config.thresholds.enable_rule(threshold_type)
    
    def disable_threshold(self, threshold_type: ThresholdType) -> None:
        """Disable a threshold rule."""
        self.config.thresholds.disable_rule(threshold_type)
    
    def calibrate(self, observation_count: int = 10) -> None:
        """
        Calibrate baselines during known-good operation.
        
        Call this during normal operation to establish baseline
        metrics for anomaly detection.
        """
        # Collect observations
        for _ in range(observation_count):
            self.observer.observe()
            time.sleep(self.config.observation_interval_seconds)
        
        # Calibrate observer baselines
        self.observer.calibrate_baselines(observation_count)
