# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Time-Travel Debugger - Replay Agent History

Feature: "Time-Travel Debugging"
Problem: Need to understand and debug agent behavior after the fact.
Solution: Since all communication is on amb (message bus) and all history is in emk (event kernel),
         build a "Replay" tool. "Re-run the last 5 minutes of Agent A's life exactly as it happened."
Result: Complete observability and debugging capability for agent behavior.

This module provides infrastructure to replay agent execution history from
the audit logs and message history.
"""

from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import logging
import json


class ReplayMode(Enum):
    """Mode for replaying agent history"""
    STEP_BY_STEP = "step_by_step"
    CONTINUOUS = "continuous"
    FAST_FORWARD = "fast_forward"


class ReplayEventType(Enum):
    """Types of events that can be replayed"""
    MESSAGE_SENT = "message_sent"
    MESSAGE_RECEIVED = "message_received"
    TOOL_EXECUTION = "tool_execution"
    POLICY_CHECK = "policy_check"
    STATE_CHANGE = "state_change"
    ERROR = "error"


@dataclass
class ReplayEvent:
    """An event in the replay timeline"""
    event_id: str
    event_type: ReplayEventType
    timestamp: datetime
    agent_id: str
    data: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReplaySession:
    """A replay session for an agent"""
    session_id: str
    agent_id: str
    start_time: datetime
    end_time: datetime
    events: List[ReplayEvent]
    mode: ReplayMode
    current_index: int = 0
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class TimeTravelConfig:
    """Configuration for time-travel debugging"""
    enabled: bool = True
    max_replay_duration_minutes: int = 60
    enable_state_snapshots: bool = True
    snapshot_interval_seconds: int = 60
    max_stored_snapshots: int = 100
    enable_replay_cache: bool = True


class TimeTravelDebugger:
    """
    Time-Travel Debugger for replaying agent execution history.
    
    This class provides:
    - Replay of agent actions and decisions over a time period
    - Step-by-step or continuous replay modes
    - Integration with FlightRecorder for complete audit trails
    - State snapshot capture for point-in-time restoration
    """
    
    def __init__(
        self,
        flight_recorder: Optional[Any] = None,
        config: Optional[TimeTravelConfig] = None
    ):
        """
        Initialize the time-travel debugger.
        
        Args:
            flight_recorder: FlightRecorder instance for accessing audit logs
            config: Configuration for time-travel behavior
        """
        self.config = config or TimeTravelConfig()
        self.flight_recorder = flight_recorder
        self.logger = logging.getLogger("TimeTravelDebugger")
        
        # Store replay sessions
        self.active_sessions: Dict[str, ReplaySession] = {}
        
        # Store state snapshots for time-travel
        self.state_snapshots: Dict[str, List[Dict[str, Any]]] = {}
        
        # Cache for replay events
        self.event_cache: Dict[str, List[ReplayEvent]] = {}
        
        self.logger.info("TimeTravelDebugger initialized")
    
    def capture_state_snapshot(
        self,
        agent_id: str,
        agent_state: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Capture a point-in-time snapshot of agent state.
        
        Args:
            agent_id: Agent identifier
            agent_state: Complete agent state to snapshot
            metadata: Optional metadata about the snapshot
        """
        if not self.config.enable_state_snapshots:
            return
        
        snapshot = {
            "agent_id": agent_id,
            "timestamp": datetime.now().isoformat(),
            "state": agent_state,
            "metadata": metadata or {}
        }
        
        if agent_id not in self.state_snapshots:
            self.state_snapshots[agent_id] = []
        
        self.state_snapshots[agent_id].append(snapshot)
        
        # Limit number of snapshots
        if len(self.state_snapshots[agent_id]) > self.config.max_stored_snapshots:
            self.state_snapshots[agent_id] = self.state_snapshots[agent_id][-self.config.max_stored_snapshots:]
        
        self.logger.debug(f"Captured state snapshot for agent {agent_id}")
    
    def get_state_at_time(
        self,
        agent_id: str,
        target_time: datetime
    ) -> Optional[Dict[str, Any]]:
        """
        Get agent state at a specific point in time.
        
        Args:
            agent_id: Agent identifier
            target_time: Target timestamp
            
        Returns:
            Agent state snapshot closest to the target time, or None
        """
        if agent_id not in self.state_snapshots:
            return None
        
        snapshots = self.state_snapshots[agent_id]
        
        # Find closest snapshot before or at target time
        closest_snapshot = None
        min_diff = None
        
        for snapshot in snapshots:
            snapshot_time = datetime.fromisoformat(snapshot["timestamp"])
            if snapshot_time <= target_time:
                diff = (target_time - snapshot_time).total_seconds()
                if min_diff is None or diff < min_diff:
                    min_diff = diff
                    closest_snapshot = snapshot
        
        return closest_snapshot
    
    def collect_events_from_flight_recorder(
        self,
        agent_id: str,
        start_time: datetime,
        end_time: datetime
    ) -> List[ReplayEvent]:
        """
        Collect replay events from FlightRecorder audit logs.
        
        Args:
            agent_id: Agent identifier
            start_time: Start of time range
            end_time: End of time range
            
        Returns:
            List of replay events in chronological order
        """
        if not self.flight_recorder:
            self.logger.warning("No FlightRecorder available for event collection")
            return []
        
        events = []
        
        try:
            # Use the FlightRecorder's get_events_in_time_range method
            if hasattr(self.flight_recorder, 'get_events_in_time_range'):
                audit_entries = self.flight_recorder.get_events_in_time_range(
                    start_time, end_time, agent_id
                )
            else:
                # Fallback to get_log method
                audit_log = self.flight_recorder.get_log() if hasattr(self.flight_recorder, 'get_log') else []
                
                # Filter manually
                audit_entries = []
                for entry in audit_log:
                    entry_time = datetime.fromisoformat(entry.get("timestamp", ""))
                    agent_match = entry.get("agent_id") == agent_id
                    
                    if start_time <= entry_time <= end_time and agent_match:
                        audit_entries.append(entry)
            
            # Convert to ReplayEvents
            for entry in audit_entries:
                event = self._convert_audit_entry_to_replay_event(entry)
                if event:
                    events.append(event)
            
        except Exception as e:
            self.logger.error(f"Error collecting events from FlightRecorder: {e}")
        
        # Sort by timestamp
        events.sort(key=lambda e: e.timestamp)
        
        return events
    
    def _convert_audit_entry_to_replay_event(
        self,
        audit_entry: Dict[str, Any]
    ) -> Optional[ReplayEvent]:
        """Convert an audit log entry to a ReplayEvent"""
        try:
            # FlightRecorder format has: trace_id, timestamp, agent_id, tool_name, 
            # tool_args, input_prompt, policy_verdict, violation_reason, result
            
            # Determine event type based on policy verdict and tool name
            policy_verdict = audit_entry.get("policy_verdict", "")
            tool_name = audit_entry.get("tool_name", "")
            
            # Map to replay event type
            if policy_verdict == "blocked":
                event_type = ReplayEventType.POLICY_CHECK
            elif policy_verdict == "error":
                event_type = ReplayEventType.ERROR
            elif tool_name:
                event_type = ReplayEventType.TOOL_EXECUTION
            else:
                event_type = ReplayEventType.STATE_CHANGE
            
            # Parse tool_args if it's JSON string
            tool_args = audit_entry.get("tool_args")
            if tool_args and isinstance(tool_args, str):
                try:
                    tool_args = json.loads(tool_args)
                except (json.JSONDecodeError, ValueError) as e:
                    self.logger.debug("Could not parse tool_args as JSON: %s", e)
            
            # Parse result if it's JSON string
            result = audit_entry.get("result")
            if result and isinstance(result, str):
                try:
                    result = json.loads(result)
                except (json.JSONDecodeError, ValueError) as e:
                    self.logger.debug("Could not parse result as JSON: %s", e)
            
            return ReplayEvent(
                event_id=audit_entry.get("trace_id", str(id(audit_entry))),
                event_type=event_type,
                timestamp=datetime.fromisoformat(audit_entry["timestamp"]),
                agent_id=audit_entry.get("agent_id", ""),
                data={
                    "tool_name": tool_name,
                    "tool_args": tool_args,
                    "input_prompt": audit_entry.get("input_prompt"),
                    "policy_verdict": policy_verdict,
                    "violation_reason": audit_entry.get("violation_reason"),
                    "result": result,
                    "execution_time_ms": audit_entry.get("execution_time_ms"),
                },
                metadata={
                    "db_id": audit_entry.get("id"),
                    "trace_id": audit_entry.get("trace_id")
                }
            )
        except Exception as e:
            self.logger.error(f"Error converting audit entry: {e}")
            return None
    
    def create_replay_session(
        self,
        agent_id: str,
        start_time: datetime,
        end_time: datetime,
        mode: ReplayMode = ReplayMode.CONTINUOUS
    ) -> ReplaySession:
        """
        Create a new replay session for an agent.
        
        Args:
            agent_id: Agent identifier
            start_time: Start of replay period
            end_time: End of replay period
            mode: Replay mode (step-by-step, continuous, fast-forward)
            
        Returns:
            Created ReplaySession
        """
        # Validate time range
        duration = (end_time - start_time).total_seconds() / 60
        if duration > self.config.max_replay_duration_minutes:
            raise ValueError(
                f"Replay duration ({duration} min) exceeds maximum "
                f"({self.config.max_replay_duration_minutes} min)"
            )
        
        # Collect events
        events = self.collect_events_from_flight_recorder(agent_id, start_time, end_time)
        
        # Create session
        session = ReplaySession(
            session_id=f"replay_{agent_id}_{int(datetime.now().timestamp())}",
            agent_id=agent_id,
            start_time=start_time,
            end_time=end_time,
            events=events,
            mode=mode
        )
        
        self.active_sessions[session.session_id] = session
        
        self.logger.info(
            f"Created replay session {session.session_id} for agent {agent_id} "
            f"with {len(events)} events from {start_time} to {end_time}"
        )
        
        return session
    
    def replay_time_window(
        self,
        agent_id: str,
        minutes: int,
        mode: ReplayMode = ReplayMode.CONTINUOUS
    ) -> ReplaySession:
        """
        Replay the last N minutes of an agent's life.
        
        Args:
            agent_id: Agent identifier
            minutes: Number of minutes to replay
            mode: Replay mode
            
        Returns:
            Created ReplaySession
        """
        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=minutes)
        
        return self.create_replay_session(agent_id, start_time, end_time, mode)
    
    def replay_agent_history(
        self,
        agent_id: str,
        session_id: Optional[str] = None,
        callback: Optional[callable] = None
    ) -> List[ReplayEvent]:
        """
        Replay agent history, optionally with a callback for each event.
        
        Args:
            agent_id: Agent identifier
            session_id: Specific session to replay (uses most recent if None)
            callback: Optional callback function called for each event
            
        Returns:
            List of replayed events
        """
        # Find session
        if session_id:
            if session_id not in self.active_sessions:
                raise ValueError(f"Replay session {session_id} not found")
            session = self.active_sessions[session_id]
        else:
            # Find most recent session for this agent
            agent_sessions = [
                s for s in self.active_sessions.values()
                if s.agent_id == agent_id
            ]
            if not agent_sessions:
                raise ValueError(f"No replay sessions found for agent {agent_id}")
            session = max(agent_sessions, key=lambda s: s.created_at)
        
        replayed_events = []
        
        # Replay based on mode
        if session.mode == ReplayMode.STEP_BY_STEP:
            # Return events one at a time (user must call next_step)
            if session.current_index < len(session.events):
                if callback:
                    callback(session.events[session.current_index])
                replayed_events.append(session.events[session.current_index])
                session.current_index += 1
        else:
            # Continuous or fast-forward: replay all events
            for event in session.events:
                replayed_events.append(event)
                if callback:
                    callback(event)
                session.current_index += 1
        
        return replayed_events
    
    def next_step(self, session_id: str) -> Optional[ReplayEvent]:
        """
        Advance to the next event in a step-by-step replay session.
        
        Args:
            session_id: Replay session identifier
            
        Returns:
            Next event, or None if at end
        """
        if session_id not in self.active_sessions:
            raise ValueError(f"Replay session {session_id} not found")
        
        session = self.active_sessions[session_id]
        
        if session.current_index >= len(session.events):
            return None
        
        event = session.events[session.current_index]
        session.current_index += 1
        
        return event
    
    def get_session_progress(self, session_id: str) -> Dict[str, Any]:
        """Get progress information for a replay session"""
        if session_id not in self.active_sessions:
            raise ValueError(f"Replay session {session_id} not found")
        
        session = self.active_sessions[session_id]
        
        return {
            "session_id": session.session_id,
            "agent_id": session.agent_id,
            "total_events": len(session.events),
            "current_index": session.current_index,
            "completed": session.current_index >= len(session.events),
            "progress_percent": (session.current_index / len(session.events) * 100) if session.events else 0,
            "mode": session.mode.value,
            "time_range": {
                "start": session.start_time.isoformat(),
                "end": session.end_time.isoformat()
            }
        }
    
    def get_replay_summary(self, session_id: str) -> Dict[str, Any]:
        """Get a summary of a replay session"""
        if session_id not in self.active_sessions:
            raise ValueError(f"Replay session {session_id} not found")
        
        session = self.active_sessions[session_id]
        
        # Aggregate statistics
        event_type_counts = {}
        for event in session.events:
            event_type = event.event_type.value
            event_type_counts[event_type] = event_type_counts.get(event_type, 0) + 1
        
        return {
            "session_id": session.session_id,
            "agent_id": session.agent_id,
            "time_range": {
                "start": session.start_time.isoformat(),
                "end": session.end_time.isoformat(),
                "duration_seconds": (session.end_time - session.start_time).total_seconds()
            },
            "total_events": len(session.events),
            "event_type_breakdown": event_type_counts,
            "mode": session.mode.value,
            "created_at": session.created_at.isoformat()
        }
    
    def export_replay_session(
        self,
        session_id: str,
        format: str = "json"
    ) -> str:
        """
        Export a replay session for external analysis.
        
        Args:
            session_id: Replay session identifier
            format: Export format (currently only 'json')
            
        Returns:
            Serialized replay session
        """
        if session_id not in self.active_sessions:
            raise ValueError(f"Replay session {session_id} not found")
        
        session = self.active_sessions[session_id]
        
        export_data = {
            "session_id": session.session_id,
            "agent_id": session.agent_id,
            "start_time": session.start_time.isoformat(),
            "end_time": session.end_time.isoformat(),
            "mode": session.mode.value,
            "events": [
                {
                    "event_id": e.event_id,
                    "event_type": e.event_type.value,
                    "timestamp": e.timestamp.isoformat(),
                    "agent_id": e.agent_id,
                    "data": e.data,
                    "metadata": e.metadata
                }
                for e in session.events
            ],
            "summary": self.get_replay_summary(session_id)
        }
        
        return json.dumps(export_data, indent=2)
    
    def close_session(self, session_id: str):
        """Close and remove a replay session"""
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
            self.logger.info(f"Closed replay session {session_id}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about time-travel debugging"""
        total_snapshots = sum(len(snapshots) for snapshots in self.state_snapshots.values())
        
        return {
            "active_replay_sessions": len(self.active_sessions),
            "total_state_snapshots": total_snapshots,
            "agents_with_snapshots": len(self.state_snapshots),
            "config": {
                "enabled": self.config.enabled,
                "max_replay_duration_minutes": self.config.max_replay_duration_minutes,
                "enable_state_snapshots": self.config.enable_state_snapshots
            }
        }
