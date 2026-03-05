# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Test script for intent detection and intent-based evaluation.
Tests the core components without API calls where possible.
"""

import json
import os
import tempfile
import uuid
import sys

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.intent_detection import IntentMetrics
from src.telemetry import EventStream, TelemetryEvent
from datetime import datetime


def test_intent_metrics_troubleshooting():
    """Test troubleshooting intent evaluation."""
    print("Testing Troubleshooting Intent Metrics...")
    
    metrics = IntentMetrics()
    
    # Test SUCCESS: Quick resolution (2 turns)
    result = metrics.evaluate_troubleshooting(turn_count=2, resolved=True)
    assert result["success"] == True
    assert result["metric"] == "time_to_resolution"
    assert result["turn_count"] == 2
    print("✓ Quick resolution (2 turns) = SUCCESS")
    
    # Test SUCCESS: At threshold (3 turns)
    result = metrics.evaluate_troubleshooting(turn_count=3, resolved=True)
    assert result["success"] == True
    assert result["turn_count"] == 3
    print("✓ Threshold resolution (3 turns) = SUCCESS")
    
    # Test FAILURE: User trapped (5 turns)
    result = metrics.evaluate_troubleshooting(turn_count=5, resolved=True)
    assert result["success"] == False
    assert "trapped" in result["reasoning"].lower()
    print("✓ User trapped (5 turns) = FAILURE")
    
    # Test FAILURE: Not resolved
    result = metrics.evaluate_troubleshooting(turn_count=2, resolved=False)
    assert result["success"] == False
    print("✓ Not resolved = FAILURE")
    
    print("Troubleshooting Intent Metrics: All tests passed!\n")


def test_intent_metrics_brainstorming():
    """Test brainstorming intent evaluation."""
    print("Testing Brainstorming Intent Metrics...")
    
    metrics = IntentMetrics()
    
    # Test SUCCESS: Deep exploration (10 turns, high depth)
    result = metrics.evaluate_brainstorming(turn_count=10, context_depth_score=0.8)
    assert result["success"] == True
    assert result["metric"] == "depth_of_context"
    assert result["turn_count"] == 10
    print("✓ Deep exploration (10 turns, 0.8 depth) = SUCCESS")
    
    # Test FAILURE: Too short (2 turns)
    result = metrics.evaluate_brainstorming(turn_count=2, context_depth_score=0.8)
    assert result["success"] == False
    assert "too short" in result["reasoning"].lower()
    print("✓ Too short (2 turns) = FAILURE")
    
    # Test FAILURE: Insufficient depth (10 turns, low depth)
    result = metrics.evaluate_brainstorming(turn_count=10, context_depth_score=0.4)
    assert result["success"] == False
    assert "insufficient depth" in result["reasoning"].lower()
    print("✓ Insufficient depth (10 turns, 0.4 depth) = FAILURE")
    
    print("Brainstorming Intent Metrics: All tests passed!\n")


def test_context_depth_calculation():
    """Test context depth calculation."""
    print("Testing Context Depth Calculation...")
    
    metrics = IntentMetrics()
    
    # Test empty conversation
    depth = metrics.calculate_context_depth([])
    assert depth == 0.0
    print("✓ Empty conversation depth = 0.0")
    
    # Test short responses
    conversation = [
        {"content": "Yes"},
        {"content": "No"},
        {"content": "OK"}
    ]
    depth = metrics.calculate_context_depth(conversation)
    assert depth < 0.2
    print(f"✓ Short responses depth = {depth:.2f} (< 0.2)")
    
    # Test long responses
    conversation = [
        {"content": "This is a detailed explanation " * 50},
        {"content": "Here's another comprehensive answer " * 50},
    ]
    depth = metrics.calculate_context_depth(conversation)
    assert depth > 0.5
    print(f"✓ Long responses depth = {depth:.2f} (> 0.5)")
    
    print("Context Depth Calculation: All tests passed!\n")


def test_telemetry_conversation_tracking():
    """Test telemetry conversation tracking features."""
    print("Testing Telemetry Conversation Tracking...")
    
    # Create a test stream file
    test_file = os.path.join(tempfile.gettempdir(), 'test_intent_stream.jsonl')
    
    # Remove if exists from previous test
    if os.path.exists(test_file):
        os.remove(test_file)
    
    try:
        stream = EventStream(test_file)
        conversation_id = str(uuid.uuid4())
        
        # Emit events for a conversation
        for i in range(1, 4):
            event = TelemetryEvent(
                event_type="task_complete",
                timestamp=datetime.now().isoformat(),
                query=f"Query {i}",
                agent_response=f"Response {i}",
                conversation_id=conversation_id,
                turn_number=i,
                intent_type="troubleshooting",
                intent_confidence=0.9
            )
            stream.emit(event)
        
        # Test get_conversation_events
        events = stream.get_conversation_events(conversation_id)
        assert len(events) == 3
        assert events[0].turn_number == 1
        assert events[-1].turn_number == 3
        print("✓ get_conversation_events works")
        
        # Test get_conversation_turn_count
        turn_count = stream.get_conversation_turn_count(conversation_id)
        assert turn_count == 3
        print("✓ get_conversation_turn_count works")
        
        # Test with non-existent conversation
        empty_events = stream.get_conversation_events("non-existent")
        assert len(empty_events) == 0
        print("✓ Non-existent conversation returns empty list")
        
    finally:
        # Cleanup
        if os.path.exists(test_file):
            os.remove(test_file)
    
    print("Telemetry Conversation Tracking: All tests passed!\n")


def test_telemetry_event_with_intent_fields():
    """Test that TelemetryEvent supports intent fields."""
    print("Testing TelemetryEvent Intent Fields...")
    
    event = TelemetryEvent(
        event_type="task_complete",
        timestamp=datetime.now().isoformat(),
        query="Test query",
        agent_response="Test response",
        conversation_id="conv-123",
        turn_number=1,
        intent_type="troubleshooting",
        intent_confidence=0.95
    )
    
    # Test that fields are accessible
    assert event.conversation_id == "conv-123"
    assert event.turn_number == 1
    assert event.intent_type == "troubleshooting"
    assert event.intent_confidence == 0.95
    print("✓ Intent fields accessible")
    
    # Test serialization
    event_dict = event.to_dict()
    assert "conversation_id" in event_dict
    assert "intent_type" in event_dict
    print("✓ Intent fields serializable")
    
    # Test deserialization
    reconstructed = TelemetryEvent.from_dict(event_dict)
    assert reconstructed.conversation_id == "conv-123"
    assert reconstructed.intent_type == "troubleshooting"
    print("✓ Intent fields deserializable")
    
    print("TelemetryEvent Intent Fields: All tests passed!\n")


def test_intent_detection_structure():
    """Test that intent detection module structure is correct."""
    print("Testing Intent Detection Module Structure...")
    
    # Test that IntentMetrics class exists and has required methods
    metrics = IntentMetrics()
    assert hasattr(metrics, 'evaluate_troubleshooting')
    assert hasattr(metrics, 'evaluate_brainstorming')
    assert hasattr(metrics, 'calculate_context_depth')
    print("✓ IntentMetrics has required methods")
    
    # Test static methods work
    result = IntentMetrics.evaluate_troubleshooting(turn_count=2, resolved=True)
    assert "success" in result
    assert "metric" in result
    assert "reasoning" in result
    print("✓ Static methods work correctly")
    
    print("Intent Detection Module Structure: All tests passed!\n")


def main():
    """Run all tests."""
    print("="*60)
    print("Running Intent Detection Tests")
    print("="*60)
    print()
    
    try:
        test_intent_metrics_troubleshooting()
        test_intent_metrics_brainstorming()
        test_context_depth_calculation()
        test_telemetry_conversation_tracking()
        test_telemetry_event_with_intent_fields()
        test_intent_detection_structure()
        
        print("="*60)
        print("All tests passed! ✓")
        print("="*60)
        print("\nNote: These tests validate structure and basic functionality.")
        print("For full intent detection with LLM calls, set up your .env file")
        print("and run: python example_intent_detection.py")
        
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
