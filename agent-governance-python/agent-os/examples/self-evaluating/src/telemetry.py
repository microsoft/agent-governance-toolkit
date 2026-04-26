# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Telemetry and Event Stream System

This module provides event tracking and streaming capabilities
for decoupling execution from learning.
"""

import json
import os
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass, asdict


@dataclass
class TelemetryEvent:
    """Represents a single execution event."""
    
    event_type: str  # "task_start", "task_complete", "user_feedback", "signal_undo", "signal_abandonment", "signal_acceptance"
    timestamp: str
    query: str
    agent_response: Optional[str] = None
    success: Optional[bool] = None
    user_feedback: Optional[str] = None
    instructions_version: Optional[int] = None
    metadata: Optional[Dict[str, Any]] = None
    signal_type: Optional[str] = None  # "undo", "abandonment", "acceptance"
    signal_context: Optional[Dict[str, Any]] = None  # Additional context for the signal
    # Intent-based evaluation fields
    conversation_id: Optional[str] = None  # Groups related turns together
    turn_number: Optional[int] = None  # Position in conversation (1-indexed)
    intent_type: Optional[str] = None  # "troubleshooting", "brainstorming", "unknown"
    intent_confidence: Optional[float] = None  # Confidence in intent detection (0-1)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TelemetryEvent':
        """Create event from dictionary."""
        return cls(**data)


class EventStream:
    """
    Manages the event stream for telemetry.
    Uses a simple file-based append-only log.
    """
    
    def __init__(self, stream_file: str = "telemetry_events.jsonl"):
        self.stream_file = stream_file
    
    def emit(self, event: TelemetryEvent) -> None:
        """Emit an event to the stream."""
        with open(self.stream_file, 'a') as f:
            f.write(json.dumps(event.to_dict()) + '\n')
    
    def read_all(self) -> List[TelemetryEvent]:
        """Read all events from the stream."""
        if not os.path.exists(self.stream_file):
            return []
        
        events = []
        with open(self.stream_file, 'r') as f:
            for line in f:
                if line.strip():
                    data = json.loads(line)
                    events.append(TelemetryEvent.from_dict(data))
        return events
    
    def read_unprocessed(self, last_processed_timestamp: Optional[str] = None) -> List[TelemetryEvent]:
        """
        Read events that haven't been processed yet.
        If last_processed_timestamp is None, returns all events.
        """
        all_events = self.read_all()
        if last_processed_timestamp is None:
            return all_events
        
        # Return events after the last processed timestamp
        unprocessed = []
        for event in all_events:
            if event.timestamp > last_processed_timestamp:
                unprocessed.append(event)
        return unprocessed
    
    def clear(self) -> None:
        """Clear all events from the stream (for testing)."""
        if os.path.exists(self.stream_file):
            os.remove(self.stream_file)
    
    def get_last_timestamp(self) -> Optional[str]:
        """Get the timestamp of the last event in the stream."""
        events = self.read_all()
        if events:
            return events[-1].timestamp
        return None
    
    def get_signal_events(self, signal_type: Optional[str] = None) -> List[TelemetryEvent]:
        """
        Get all signal events, optionally filtered by signal type.
        
        Args:
            signal_type: Optional filter for signal type ("undo", "abandonment", "acceptance")
        """
        all_events = self.read_all()
        signal_events = [e for e in all_events if e.event_type.startswith("signal_")]
        
        if signal_type:
            signal_events = [e for e in signal_events if e.signal_type == signal_type]
        
        return signal_events
    
    def get_conversation_events(self, conversation_id: str) -> List[TelemetryEvent]:
        """
        Get all events for a specific conversation.
        
        Args:
            conversation_id: The conversation identifier
        
        Returns:
            List of events for this conversation, sorted by turn number
        """
        all_events = self.read_all()
        conversation_events = [
            e for e in all_events 
            if e.conversation_id == conversation_id
        ]
        
        # Sort by turn number if available
        conversation_events.sort(key=lambda e: e.turn_number or 0)
        
        return conversation_events
    
    def get_conversation_turn_count(self, conversation_id: str) -> int:
        """
        Get the number of turns in a conversation.
        
        Args:
            conversation_id: The conversation identifier
        
        Returns:
            Number of turns in the conversation
        """
        events = self.get_conversation_events(conversation_id)
        if not events:
            return 0
        
        # Count unique turn numbers (handles non-sequential turns)
        turn_numbers = [e.turn_number for e in events if e.turn_number is not None]
        return len(set(turn_numbers)) if turn_numbers else 0
