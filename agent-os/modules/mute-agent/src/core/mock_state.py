# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
MockState - Simulates Time and User History for Testing

This module provides utilities for simulating:
1. Time-based context decay (stale pointer detection)
2. User session history
3. Context focus with TTL (Time-To-Live)

These are critical for testing the "Stale Pointer" scenario from the PRD:
- User views Service-A logs 10 minutes ago
- User says "restart it"
- Should the context still point to Service-A?

The Mute Agent uses TTL on graph edges to expire stale context,
while the Interactive Agent may incorrectly use old context.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum


class ContextEventType(Enum):
    """Types of events that affect user context."""
    VIEW_SERVICE = "view_service"
    VIEW_LOGS = "view_logs"
    EXECUTE_ACTION = "execute_action"
    QUERY_STATE = "query_state"


@dataclass
class ContextEvent:
    """
    An event in the user's session history.
    
    Each event potentially changes what the "current focus" is.
    """
    event_type: ContextEventType
    timestamp: datetime
    service_id: Optional[str] = None
    action: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MockStateConfig:
    """Configuration for MockState behavior."""
    # Time-To-Live for context focus (in seconds)
    context_ttl_seconds: float = 300.0  # 5 minutes default
    
    # Whether to enforce strict TTL (expire context after TTL)
    enforce_ttl: bool = True
    
    # Simulated time speed multiplier (1.0 = real time, 10.0 = 10x faster)
    time_multiplier: float = 1.0


class MockState:
    """
    MockState - Simulates time-based context and user history
    
    This class helps test scenarios where context becomes stale over time.
    
    Example Usage:
    ```python
    # Create state tracker
    state = MockState()
    
    # User views Service A
    state.add_event(ContextEventType.VIEW_LOGS, service_id="svc-a")
    
    # Time passes (simulate 10 minutes)
    state.advance_time(minutes=10)
    
    # Is Service A still the current focus?
    focus = state.get_current_focus()  # Returns None (expired!)
    
    # Check if context is stale
    is_stale = state.is_context_stale()  # True
    ```
    
    The Mute Agent can use this to determine if graph edges should exist.
    The Interactive Agent may incorrectly use stale context from last_accessed.
    """
    
    def __init__(self, config: Optional[MockStateConfig] = None):
        """
        Initialize MockState.
        
        Args:
            config: Configuration for state behavior
        """
        self.config = config or MockStateConfig()
        self.current_time = datetime.now()
        self.event_history: List[ContextEvent] = []
        self.last_focus_service: Optional[str] = None
        self.last_focus_time: Optional[datetime] = None
    
    def add_event(
        self,
        event_type: ContextEventType,
        service_id: Optional[str] = None,
        action: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Add an event to the session history.
        
        This updates the current focus if the event is focus-changing.
        """
        event = ContextEvent(
            event_type=event_type,
            timestamp=self.current_time,
            service_id=service_id,
            action=action,
            metadata=metadata or {}
        )
        
        self.event_history.append(event)
        
        # Update focus for certain event types
        if event_type in [ContextEventType.VIEW_SERVICE, ContextEventType.VIEW_LOGS]:
            if service_id:
                self.last_focus_service = service_id
                self.last_focus_time = self.current_time
    
    def advance_time(
        self,
        seconds: float = 0,
        minutes: float = 0,
        hours: float = 0
    ):
        """
        Advance the simulated time.
        
        Args:
            seconds: Seconds to advance
            minutes: Minutes to advance
            hours: Hours to advance
        """
        total_seconds = seconds + (minutes * 60) + (hours * 3600)
        delta = timedelta(seconds=total_seconds * self.config.time_multiplier)
        self.current_time += delta
    
    def get_current_focus(self) -> Optional[str]:
        """
        Get the current focus service, respecting TTL.
        
        Returns:
            Service ID if focus is active, None if expired or no focus
        """
        if not self.last_focus_service or not self.last_focus_time:
            return None
        
        if self.config.enforce_ttl:
            time_since_focus = (self.current_time - self.last_focus_time).total_seconds()
            if time_since_focus > self.config.context_ttl_seconds:
                # Context has expired
                return None
        
        return self.last_focus_service
    
    def is_context_stale(self) -> bool:
        """
        Check if the current context is stale (past TTL).
        
        Returns:
            True if context exists but is past TTL
        """
        if not self.last_focus_service or not self.last_focus_time:
            return False
        
        time_since_focus = (self.current_time - self.last_focus_time).total_seconds()
        return time_since_focus > self.config.context_ttl_seconds
    
    def get_time_since_last_focus(self) -> Optional[float]:
        """
        Get seconds since last focus was set.
        
        Returns:
            Seconds since last focus, or None if no focus
        """
        if not self.last_focus_time:
            return None
        
        return (self.current_time - self.last_focus_time).total_seconds()
    
    def get_last_access(self, service_id: str) -> Optional[datetime]:
        """
        Get the last time a service was accessed.
        
        Args:
            service_id: Service to check
        
        Returns:
            Datetime of last access, or None if never accessed
        """
        for event in reversed(self.event_history):
            if event.service_id == service_id:
                return event.timestamp
        return None
    
    def get_recent_events(
        self,
        count: int = 10,
        event_type: Optional[ContextEventType] = None
    ) -> List[ContextEvent]:
        """
        Get recent events from history.
        
        Args:
            count: Number of events to return
            event_type: Filter by event type (optional)
        
        Returns:
            List of recent events (most recent first)
        """
        events = self.event_history
        
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        return list(reversed(events[-count:]))
    
    def reset(self):
        """Reset state to initial conditions."""
        self.current_time = datetime.now()
        self.event_history = []
        self.last_focus_service = None
        self.last_focus_time = None
    
    def __repr__(self) -> str:
        """String representation for debugging."""
        focus = self.get_current_focus()
        stale = self.is_context_stale()
        time_since = self.get_time_since_last_focus()
        
        return (
            f"MockState(current_time={self.current_time.isoformat()}, "
            f"focus={focus}, stale={stale}, "
            f"time_since_focus={time_since:.1f}s, "
            f"events={len(self.event_history)})"
        )


# Convenience functions for common scenarios

def create_stale_pointer_scenario(
    service_a: str = "svc-a",
    service_b: str = "svc-b",
    time_gap_minutes: float = 10.0
) -> MockState:
    """
    Create a "Stale Pointer" scenario from the PRD.
    
    Scenario:
    1. User views Service A logs
    2. Time passes (10 minutes)
    3. User views Service B logs
    4. User says "restart it"
    
    Expected:
    - Interactive Agent may use Service A (stale!)
    - Mute Agent should use Service B (current focus)
    
    Args:
        service_a: First service ID (default: "svc-a")
        service_b: Second service ID (default: "svc-b")
        time_gap_minutes: Minutes between service accesses (default: 10.0)
    
    Returns:
        MockState configured for this scenario
    """
    state = MockState()
    
    # User views Service A
    state.add_event(ContextEventType.VIEW_LOGS, service_id=service_a)
    
    # Time passes
    state.advance_time(minutes=time_gap_minutes)
    
    # User views Service B
    state.add_event(ContextEventType.VIEW_LOGS, service_id=service_b)
    
    return state


def create_zombie_resource_scenario(
    service_id: str = "svc-partial",
) -> MockState:
    """
    Create a "Zombie Resource" scenario from the PRD.
    
    Scenario:
    - Deployment failed 50% through
    - Service is in PARTIAL state
    - User says "rollback"
    
    Expected:
    - Interactive Agent tries rollback, fails, reflects, tries force=True (dangerous!)
    - Mute Agent: Graph shows no rollback edge for PARTIAL state, only nuke/force_delete
    
    Args:
        service_id: Service in zombie state (default: "svc-partial")
    
    Returns:
        MockState configured for this scenario
    """
    state = MockState()
    
    # Service was being deployed
    state.add_event(
        ContextEventType.EXECUTE_ACTION,
        service_id=service_id,
        action="deploy",
        metadata={"state": "partial", "progress": 0.5}
    )
    
    return state
