# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Test script for decoupled architecture components.
Tests telemetry, DoerAgent, and ObserverAgent.
"""

import json
import os
import tempfile
import sys

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.telemetry import EventStream, TelemetryEvent


def test_telemetry_event():
    """Test telemetry event creation and serialization."""
    print("Testing TelemetryEvent...")
    
    event = TelemetryEvent(
        event_type="task_complete",
        timestamp="2024-01-01T12:00:00",
        query="Test query",
        agent_response="Test response",
        success=True,
        instructions_version=1
    )
    
    # Test to_dict
    event_dict = event.to_dict()
    assert event_dict["event_type"] == "task_complete"
    assert event_dict["query"] == "Test query"
    print("✓ Event serialization works")
    
    # Test from_dict
    event2 = TelemetryEvent.from_dict(event_dict)
    assert event2.event_type == event.event_type
    assert event2.query == event.query
    print("✓ Event deserialization works")
    
    print("TelemetryEvent: All tests passed!\n")


def test_event_stream():
    """Test event stream functionality."""
    print("Testing EventStream...")
    
    # Create a test stream file
    test_file = os.path.join(tempfile.gettempdir(), 'test_stream_temp.jsonl')
    
    # Remove if exists
    if os.path.exists(test_file):
        os.remove(test_file)
    
    try:
        stream = EventStream(test_file)
        
        # Test emit
        event1 = TelemetryEvent(
            event_type="task_start",
            timestamp="2024-01-01T12:00:00",
            query="Query 1"
        )
        stream.emit(event1)
        print("✓ Event emission works")
        
        # Test read_all
        events = stream.read_all()
        assert len(events) == 1
        assert events[0].query == "Query 1"
        print("✓ Read all events works")
        
        # Emit another event
        event2 = TelemetryEvent(
            event_type="task_complete",
            timestamp="2024-01-01T12:01:00",
            query="Query 1",
            agent_response="Response 1"
        )
        stream.emit(event2)
        
        # Test read_unprocessed
        unprocessed = stream.read_unprocessed("2024-01-01T12:00:00")
        assert len(unprocessed) == 1
        assert unprocessed[0].event_type == "task_complete"
        print("✓ Read unprocessed events works")
        
        # Test get_last_timestamp
        last_ts = stream.get_last_timestamp()
        assert last_ts == "2024-01-01T12:01:00"
        print("✓ Get last timestamp works")
        
        # Test clear
        stream.clear()
        events = stream.read_all()
        assert len(events) == 0
        print("✓ Clear stream works")
        
    finally:
        # Cleanup
        if os.path.exists(test_file):
            os.remove(test_file)
    
    print("EventStream: All tests passed!\n")


def test_doer_agent_structure():
    """Test DoerAgent structure (without API calls)."""
    print("Testing DoerAgent structure...")
    
    # Import here to avoid issues if telemetry not available
    from agent import DoerAgent
    
    # Set a dummy API key for testing structure
    original_key = os.getenv("OPENAI_API_KEY")
    if not original_key:
        os.environ["OPENAI_API_KEY"] = "test-placeholder-key"
    
    try:
        # Test initialization
        doer = DoerAgent(
            wisdom_file="system_instructions.json",
            enable_telemetry=False  # Disable for testing
        )
        
        assert doer.wisdom is not None
        assert doer.tools is not None
        assert doer.enable_telemetry == False
        print("✓ DoerAgent initialization works")
        
        print("DoerAgent: Structure tests passed!\n")
    finally:
        # Restore original state
        if not original_key:
            del os.environ["OPENAI_API_KEY"]


def test_observer_agent_structure():
    """Test ObserverAgent structure (without API calls)."""
    print("Testing ObserverAgent structure...")
    
    from observer import ObserverAgent
    
    # Set a dummy API key for testing structure
    original_key = os.getenv("OPENAI_API_KEY")
    if not original_key:
        os.environ["OPENAI_API_KEY"] = "test-placeholder-key"
    
    # Create temporary files
    test_checkpoint = os.path.join(tempfile.gettempdir(), 'test_checkpoint.json')
    if os.path.exists(test_checkpoint):
        os.remove(test_checkpoint)
    
    try:
        # Test initialization
        observer = ObserverAgent(
            wisdom_file="system_instructions.json",
            checkpoint_file=test_checkpoint
        )
        
        assert observer.wisdom is not None
        assert observer.event_stream is not None
        assert observer.checkpoint is not None
        print("✓ ObserverAgent initialization works")
        
        # Test checkpoint persistence
        observer.checkpoint["test_key"] = "test_value"
        observer._save_checkpoint()
        
        assert os.path.exists(test_checkpoint)
        print("✓ Checkpoint persistence works")
        
        # Load checkpoint
        observer2 = ObserverAgent(
            wisdom_file="system_instructions.json",
            checkpoint_file=test_checkpoint
        )
        assert observer2.checkpoint.get("test_key") == "test_value"
        print("✓ Checkpoint loading works")
        
    finally:
        if os.path.exists(test_checkpoint):
            os.remove(test_checkpoint)
        # Restore original state
        if not original_key:
            del os.environ["OPENAI_API_KEY"]
    
    print("ObserverAgent: Structure tests passed!\n")


def main():
    """Run all tests."""
    print("="*60)
    print("Running Decoupled Architecture Tests")
    print("="*60)
    print()
    
    try:
        test_telemetry_event()
        test_event_stream()
        test_doer_agent_structure()
        test_observer_agent_structure()
        
        print("="*60)
        print("All tests passed! ✓")
        print("="*60)
        print("\nNote: These tests validate structure and basic functionality.")
        print("To test with LLM calls, set up your .env file and run:")
        print("  python example_decoupled.py")
        
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
