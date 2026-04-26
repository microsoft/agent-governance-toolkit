# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Test script for Silent Signals feature.
Tests telemetry events, signal emission, and signal analysis.
"""

import json
import os
import tempfile
from datetime import datetime
import sys

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.telemetry import EventStream, TelemetryEvent


def test_telemetry_event_with_signals():
    """Test telemetry event creation with signal fields."""
    print("Testing TelemetryEvent with signal fields...")
    
    # Test undo signal
    undo_event = TelemetryEvent(
        event_type="signal_undo",
        timestamp="2024-01-01T12:00:00",
        query="Write code to delete all files",
        agent_response="Here's code to delete all files...",
        success=False,
        instructions_version=1,
        signal_type="undo",
        signal_context={"undo_action": "Ctrl+Z on code editor"}
    )
    
    event_dict = undo_event.to_dict()
    assert event_dict["event_type"] == "signal_undo"
    assert event_dict["signal_type"] == "undo"
    assert event_dict["signal_context"]["undo_action"] == "Ctrl+Z on code editor"
    print("✓ Undo signal event works")
    
    # Test abandonment signal
    abandonment_event = TelemetryEvent(
        event_type="signal_abandonment",
        timestamp="2024-01-01T12:01:00",
        query="Help me debug this",
        agent_response="Let me help with that...",
        success=False,
        instructions_version=1,
        signal_type="abandonment",
        signal_context={"interaction_count": 3}
    )
    
    event_dict = abandonment_event.to_dict()
    assert event_dict["event_type"] == "signal_abandonment"
    assert event_dict["signal_type"] == "abandonment"
    print("✓ Abandonment signal event works")
    
    # Test acceptance signal
    acceptance_event = TelemetryEvent(
        event_type="signal_acceptance",
        timestamp="2024-01-01T12:02:00",
        query="Calculate 10 + 20",
        agent_response="The result is 30",
        success=True,
        instructions_version=1,
        signal_type="acceptance",
        signal_context={"next_task": "Calculate 20 + 30"}
    )
    
    event_dict = acceptance_event.to_dict()
    assert event_dict["event_type"] == "signal_acceptance"
    assert event_dict["signal_type"] == "acceptance"
    print("✓ Acceptance signal event works")
    
    print("TelemetryEvent with signals: All tests passed!\n")


def test_event_stream_signal_filtering():
    """Test event stream signal filtering."""
    print("Testing EventStream signal filtering...")
    
    test_file = os.path.join(tempfile.gettempdir(), 'test_signals_stream.jsonl')
    
    if os.path.exists(test_file):
        os.remove(test_file)
    
    try:
        stream = EventStream(test_file)
        
        # Emit various events
        events = [
            TelemetryEvent(
                event_type="task_start",
                timestamp="2024-01-01T12:00:00",
                query="Query 1"
            ),
            TelemetryEvent(
                event_type="signal_undo",
                timestamp="2024-01-01T12:01:00",
                query="Query 2",
                agent_response="Bad response",
                signal_type="undo",
                signal_context={"undo_action": "reverted"}
            ),
            TelemetryEvent(
                event_type="signal_abandonment",
                timestamp="2024-01-01T12:02:00",
                query="Query 3",
                signal_type="abandonment",
                signal_context={"interaction_count": 2}
            ),
            TelemetryEvent(
                event_type="signal_acceptance",
                timestamp="2024-01-01T12:03:00",
                query="Query 4",
                agent_response="Good response",
                signal_type="acceptance",
                signal_context={"next_task": "Next"}
            ),
            TelemetryEvent(
                event_type="task_complete",
                timestamp="2024-01-01T12:04:00",
                query="Query 5",
                agent_response="Normal response"
            )
        ]
        
        for event in events:
            stream.emit(event)
        
        print("✓ Emitted 5 events (1 start, 3 signals, 1 complete)")
        
        # Test get_signal_events without filter
        all_signals = stream.get_signal_events()
        assert len(all_signals) == 3
        print(f"✓ Found 3 signal events (got {len(all_signals)})")
        
        # Test get_signal_events with undo filter
        undo_signals = stream.get_signal_events("undo")
        assert len(undo_signals) == 1
        assert undo_signals[0].signal_type == "undo"
        print(f"✓ Found 1 undo signal")
        
        # Test get_signal_events with abandonment filter
        abandonment_signals = stream.get_signal_events("abandonment")
        assert len(abandonment_signals) == 1
        assert abandonment_signals[0].signal_type == "abandonment"
        print(f"✓ Found 1 abandonment signal")
        
        # Test get_signal_events with acceptance filter
        acceptance_signals = stream.get_signal_events("acceptance")
        assert len(acceptance_signals) == 1
        assert acceptance_signals[0].signal_type == "acceptance"
        print(f"✓ Found 1 acceptance signal")
        
        stream.clear()
        
    finally:
        if os.path.exists(test_file):
            os.remove(test_file)
    
    print("EventStream signal filtering: All tests passed!\n")


def test_doer_agent_signal_emission():
    """Test DoerAgent signal emission methods (structure only)."""
    print("Testing DoerAgent signal emission methods...")
    
    from agent import DoerAgent
    
    # Set a dummy API key for testing structure
    original_key = os.getenv("OPENAI_API_KEY")
    if not original_key:
        os.environ["OPENAI_API_KEY"] = "test-placeholder-key"
    
    test_stream = os.path.join(tempfile.gettempdir(), 'test_doer_signals.jsonl')
    if os.path.exists(test_stream):
        os.remove(test_stream)
    
    try:
        # Test DoerAgent has signal emission methods
        doer = DoerAgent(
            stream_file=test_stream,
            enable_telemetry=True
        )
        
        assert hasattr(doer, 'emit_undo_signal')
        assert hasattr(doer, 'emit_abandonment_signal')
        assert hasattr(doer, 'emit_acceptance_signal')
        print("✓ DoerAgent has all signal emission methods")
        
        # Test signal emission (without verbose output)
        doer.emit_undo_signal(
            query="Test query",
            agent_response="Test response",
            undo_action="Test undo",
            verbose=False
        )
        
        doer.emit_abandonment_signal(
            query="Test query",
            agent_response="Test response",
            interaction_count=3,
            verbose=False
        )
        
        doer.emit_acceptance_signal(
            query="Test query",
            agent_response="Test response",
            next_task="Next task",
            verbose=False
        )
        
        # Verify signals were emitted
        stream = EventStream(test_stream)
        all_events = stream.read_all()
        assert len(all_events) == 3
        print(f"✓ Emitted 3 signals successfully")
        
        signal_events = stream.get_signal_events()
        assert len(signal_events) == 3
        print(f"✓ All 3 events are signal events")
        
        # Verify signal types
        signal_types = [e.signal_type for e in signal_events]
        assert "undo" in signal_types
        assert "abandonment" in signal_types
        assert "acceptance" in signal_types
        print("✓ All signal types present")
        
    finally:
        if os.path.exists(test_stream):
            os.remove(test_stream)
        if not original_key:
            del os.environ["OPENAI_API_KEY"]
    
    print("DoerAgent signal emission: All tests passed!\n")


def test_observer_signal_analysis():
    """Test ObserverAgent signal analysis (structure only)."""
    print("Testing ObserverAgent signal analysis...")
    
    from observer import ObserverAgent
    
    # Set a dummy API key for testing structure
    original_key = os.getenv("OPENAI_API_KEY")
    if not original_key:
        os.environ["OPENAI_API_KEY"] = "test-placeholder-key"
    
    test_checkpoint = os.path.join(tempfile.gettempdir(), 'test_observer_signals.json')
    if os.path.exists(test_checkpoint):
        os.remove(test_checkpoint)
    
    try:
        observer = ObserverAgent(
            checkpoint_file=test_checkpoint
        )
        
        # Test that analyze_signal method exists
        assert hasattr(observer, 'analyze_signal')
        print("✓ ObserverAgent has analyze_signal method")
        
        # Test undo signal analysis
        undo_event = TelemetryEvent(
            event_type="signal_undo",
            timestamp="2024-01-01T12:00:00",
            query="Test query",
            agent_response="Bad response",
            signal_type="undo",
            signal_context={"undo_action": "reverted"}
        )
        
        undo_analysis = observer.analyze_signal(undo_event, verbose=False)
        assert undo_analysis is not None
        assert undo_analysis["signal_type"] == "undo"
        assert undo_analysis["priority"] == "critical"
        assert undo_analysis["score"] == 0.0
        assert undo_analysis["needs_learning"] == True
        print("✓ Undo signal analysis works correctly")
        
        # Test abandonment signal analysis
        abandonment_event = TelemetryEvent(
            event_type="signal_abandonment",
            timestamp="2024-01-01T12:01:00",
            query="Test query",
            agent_response="Response",
            signal_type="abandonment",
            signal_context={"interaction_count": 2}
        )
        
        abandonment_analysis = observer.analyze_signal(abandonment_event, verbose=False)
        assert abandonment_analysis is not None
        assert abandonment_analysis["signal_type"] == "abandonment"
        assert abandonment_analysis["priority"] == "high"
        assert abandonment_analysis["score"] == 0.3
        assert abandonment_analysis["needs_learning"] == True
        print("✓ Abandonment signal analysis works correctly")
        
        # Test acceptance signal analysis
        acceptance_event = TelemetryEvent(
            event_type="signal_acceptance",
            timestamp="2024-01-01T12:02:00",
            query="Test query",
            agent_response="Good response",
            signal_type="acceptance",
            signal_context={"next_task": "Next"}
        )
        
        acceptance_analysis = observer.analyze_signal(acceptance_event, verbose=False)
        assert acceptance_analysis is not None
        assert acceptance_analysis["signal_type"] == "acceptance"
        assert acceptance_analysis["priority"] == "positive"
        assert acceptance_analysis["score"] == 1.0
        assert acceptance_analysis["needs_learning"] == False
        print("✓ Acceptance signal analysis works correctly")
        
        # Test non-signal event
        normal_event = TelemetryEvent(
            event_type="task_complete",
            timestamp="2024-01-01T12:03:00",
            query="Test",
            agent_response="Response"
        )
        
        normal_analysis = observer.analyze_signal(normal_event, verbose=False)
        assert normal_analysis is None
        print("✓ Non-signal events return None")
        
    finally:
        if os.path.exists(test_checkpoint):
            os.remove(test_checkpoint)
        if not original_key:
            del os.environ["OPENAI_API_KEY"]
    
    print("ObserverAgent signal analysis: All tests passed!\n")


def main():
    """Run all tests."""
    print("="*60)
    print("Running Silent Signals Tests")
    print("="*60)
    print()
    
    try:
        test_telemetry_event_with_signals()
        test_event_stream_signal_filtering()
        test_doer_agent_signal_emission()
        test_observer_signal_analysis()
        
        print("="*60)
        print("All Silent Signals tests passed! ✓")
        print("="*60)
        print("\nSilent Signals Feature Summary:")
        print("  🚨 Undo Signal: Captures when user reverses agent action")
        print("  ⚠️ Abandonment Signal: Captures when user stops responding")
        print("  ✅ Acceptance Signal: Captures when user accepts and moves on")
        print("\nThese signals provide implicit feedback without requiring")
        print("explicit user input, creating a better learning signal.")
        
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
