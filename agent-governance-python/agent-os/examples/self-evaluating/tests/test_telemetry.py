# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Test suite for the telemetry module.
Tests event stream functionality, event logging, and checkpoint management.
"""

import json
import os
import sys
import tempfile
import uuid
from datetime import datetime

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.telemetry import EventStream, TelemetryEvent


def test_telemetry_event_creation():
    """Test creating telemetry events."""
    print("Testing TelemetryEvent creation...")
    
    # Create a basic event
    event = TelemetryEvent(
        event_type="task_execution",
        timestamp=datetime.now().isoformat(),
        query="test query",
        agent_response="test response",
        success=True
    )
    
    assert event.event_type == "task_execution"
    assert event.timestamp is not None
    assert event.query == "test query"
    assert event.agent_response == "test response"
    assert event.success is True
    print("✓ TelemetryEvent creation works")


def test_telemetry_event_to_dict():
    """Test converting telemetry event to dictionary."""
    print("Testing TelemetryEvent to_dict...")
    
    event = TelemetryEvent(
        event_type="test_event",
        timestamp="2024-01-01T00:00:00",
        query="test query",
        agent_response="test response",
        metadata={"key": "value"}
    )
    
    event_dict = event.to_dict()
    
    assert isinstance(event_dict, dict)
    assert event_dict["event_type"] == "test_event"
    assert event_dict["query"] == "test query"
    assert event_dict["agent_response"] == "test response"
    assert event_dict["metadata"]["key"] == "value"
    print("✓ TelemetryEvent to_dict works")


def test_event_stream_initialization():
    """Test EventStream initialization."""
    print("Testing EventStream initialization...")
    
    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
        stream_file = f.name
    
    try:
        # Initialize event stream
        stream = EventStream(stream_file)
        
        assert stream.stream_file == stream_file
        assert os.path.exists(stream_file)
        print("✓ EventStream initialization works")
    finally:
        # Cleanup
        if os.path.exists(stream_file):
            os.remove(stream_file)


def test_event_stream_emit():
    """Test emitting events to stream."""
    print("Testing EventStream emit...")
    
    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
        stream_file = f.name
    
    try:
        stream = EventStream(stream_file)
        
        # Emit an event
        event = TelemetryEvent(
            event_type="test",
            timestamp=datetime.now().isoformat(),
            query="test query",
            agent_response="test response"
        )
        
        stream.emit(event)
        
        # Verify event was written
        with open(stream_file, 'r') as f:
            lines = f.readlines()
            assert len(lines) == 1
            event_data = json.loads(lines[0])
            assert event_data["event_type"] == "test"
            assert event_data["query"] == "test query"
        
        print("✓ EventStream emit works")
    finally:
        # Cleanup
        if os.path.exists(stream_file):
            os.remove(stream_file)


def test_event_stream_get_events():
    """Test getting events from stream."""
    print("Testing EventStream read_all...")
    
    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
        stream_file = f.name
    
    try:
        stream = EventStream(stream_file)
        
        # Emit multiple events
        for i in range(3):
            event = TelemetryEvent(
                event_type=f"test_{i}",
                timestamp=datetime.now().isoformat(),
                query=f"query_{i}",
                agent_response=f"response_{i}"
            )
            stream.emit(event)
        
        # Get all events
        events = stream.read_all()
        
        assert len(events) == 3
        assert events[0].event_type == "test_0"
        assert events[1].event_type == "test_1"
        assert events[2].event_type == "test_2"
        
        print("✓ EventStream read_all works")
    finally:
        # Cleanup
        if os.path.exists(stream_file):
            os.remove(stream_file)


def test_event_stream_with_checkpoint():
    """Test getting events after a checkpoint."""
    print("Testing EventStream read_unprocessed...")
    
    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
        stream_file = f.name
    
    try:
        stream = EventStream(stream_file)
        
        # Emit 5 events with different timestamps
        timestamps = []
        for i in range(5):
            timestamp = datetime.now().isoformat()
            event = TelemetryEvent(
                event_type=f"test_{i}",
                timestamp=timestamp,
                query=f"query_{i}",
                agent_response=f"response_{i}"
            )
            stream.emit(event)
            timestamps.append(timestamp)
        
        # Get events after checkpoint (after first 2 events)
        events = stream.read_unprocessed(last_processed_timestamp=timestamps[1])
        
        # Should get remaining events
        assert len(events) >= 3
        
        print("✓ EventStream read_unprocessed works")
    finally:
        # Cleanup
        if os.path.exists(stream_file):
            os.remove(stream_file)


def test_event_stream_limit():
    """Test reading events."""
    print("Testing EventStream read_all with multiple events...")
    
    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
        stream_file = f.name
    
    try:
        stream = EventStream(stream_file)
        
        # Emit 10 events
        for i in range(10):
            event = TelemetryEvent(
                event_type=f"test_{i}",
                timestamp=datetime.now().isoformat(),
                query=f"query_{i}",
                agent_response=f"response_{i}"
            )
            stream.emit(event)
        
        # Get all events
        events = stream.read_all()
        
        assert len(events) == 10
        assert events[0].event_type == "test_0"
        assert events[9].event_type == "test_9"
        
        print("✓ EventStream handles multiple events correctly")
    finally:
        # Cleanup
        if os.path.exists(stream_file):
            os.remove(stream_file)


def test_event_types():
    """Test different event types and signal events."""
    print("Testing different event types and signal filtering...")
    
    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
        stream_file = f.name
    
    try:
        stream = EventStream(stream_file)
        
        # Test various event types
        event_configs = [
            {"event_type": "task_start", "signal_type": None},
            {"event_type": "task_complete", "signal_type": None},
            {"event_type": "signal_undo", "signal_type": "undo"},
            {"event_type": "signal_abandonment", "signal_type": "abandonment"},
            {"event_type": "signal_acceptance", "signal_type": "acceptance"}
        ]
        
        for config in event_configs:
            event = TelemetryEvent(
                event_type=config["event_type"],
                timestamp=datetime.now().isoformat(),
                query="test query",
                signal_type=config["signal_type"]
            )
            stream.emit(event)
        
        # Get all events
        events = stream.read_all()
        assert len(events) == len(event_configs)
        
        # Test signal event filtering
        signal_events = stream.get_signal_events()
        assert len(signal_events) == 3  # Only signal events
        
        # Test specific signal type filtering
        undo_events = stream.get_signal_events(signal_type="undo")
        assert len(undo_events) == 1
        assert undo_events[0].signal_type == "undo"
        
        print("✓ Different event types and signal filtering work")
    finally:
        # Cleanup
        if os.path.exists(stream_file):
            os.remove(stream_file)


def main():
    """Run all tests."""
    print("="*60)
    print("Running Telemetry Tests")
    print("="*60)
    print()
    
    try:
        test_telemetry_event_creation()
        test_telemetry_event_to_dict()
        test_event_stream_initialization()
        test_event_stream_emit()
        test_event_stream_get_events()
        test_event_stream_with_checkpoint()
        test_event_stream_limit()
        test_event_types()
        
        print()
        print("="*60)
        print("All telemetry tests passed! ✓")
        print("="*60)
        return 0
    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
