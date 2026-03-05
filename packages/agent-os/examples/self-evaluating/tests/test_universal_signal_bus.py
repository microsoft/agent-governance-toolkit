# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for Universal Signal Bus (Omni-Channel Ingestion)
"""

from datetime import datetime
import sys
import os

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.universal_signal_bus import (
    UniversalSignalBus,
    SignalType,
    ContextObject,
    TextSignalNormalizer,
    FileChangeSignalNormalizer,
    LogStreamSignalNormalizer,
    AudioStreamSignalNormalizer,
    create_signal_from_text,
    create_signal_from_file_change,
    create_signal_from_log,
    create_signal_from_audio
)


def test_text_signal_normalizer():
    """Test text signal normalization."""
    print("\n" + "="*60)
    print("TEST: Text Signal Normalizer")
    print("="*60)
    
    normalizer = TextSignalNormalizer()
    
    # Test basic text signal
    raw_signal = {
        "text": "Hello, how are you?",
        "user_id": "user123"
    }
    
    assert normalizer.validate(raw_signal), "Text signal should be valid"
    
    context = normalizer.normalize(raw_signal)
    assert context.signal_type == SignalType.TEXT
    assert context.intent == "user_query"
    assert context.query == "Hello, how are you?"
    assert context.user_id == "user123"
    assert context.priority == "normal"
    
    print("✓ Basic text signal normalized correctly")
    
    # Test with "query" field instead of "text"
    raw_signal2 = {"query": "What is 10 + 20?"}
    assert normalizer.validate(raw_signal2), "Signal with 'query' should be valid"
    context2 = normalizer.normalize(raw_signal2)
    assert context2.query == "What is 10 + 20?"
    
    print("✓ Text signal with 'query' field works")
    print("✅ Text Signal Normalizer: PASSED")


def test_file_change_signal_normalizer():
    """Test file change signal normalization."""
    print("\n" + "="*60)
    print("TEST: File Change Signal Normalizer")
    print("="*60)
    
    normalizer = FileChangeSignalNormalizer()
    
    # Test file creation
    raw_signal = {
        "file_path": "/workspace/app.py",
        "change_type": "created",
        "content_after": "print('Hello')",
        "language": "python"
    }
    
    assert normalizer.validate(raw_signal), "File change signal should be valid"
    
    context = normalizer.normalize(raw_signal)
    assert context.signal_type == SignalType.FILE_CHANGE
    assert context.intent == "file_creation"
    assert "app.py" in context.query
    assert context.context["file_path"] == "/workspace/app.py"
    
    print("✓ File creation signal normalized correctly")
    
    # Test file modification with security context
    raw_signal2 = {
        "file_path": "/workspace/auth/security.py",
        "change_type": "modified",
        "content_before": "password = 'admin'",
        "content_after": "password = bcrypt.hashpw(...)",
        "user_id": "dev123"
    }
    
    context2 = normalizer.normalize(raw_signal2)
    assert context2.intent == "code_modification"
    assert context2.priority == "high"  # Security files are high priority
    assert context2.urgency_score == 0.8
    
    print("✓ Security file modification detected as high priority")
    
    # Test file deletion
    raw_signal3 = {
        "file_path": "/workspace/config.json",
        "change_type": "deleted"
    }
    
    context3 = normalizer.normalize(raw_signal3)
    assert context3.intent == "file_deletion"
    assert context3.priority == "high"  # Deletions are high priority
    
    print("✓ File deletion detected as high priority")
    print("✅ File Change Signal Normalizer: PASSED")


def test_log_stream_signal_normalizer():
    """Test log stream signal normalization."""
    print("\n" + "="*60)
    print("TEST: Log Stream Signal Normalizer")
    print("="*60)
    
    normalizer = LogStreamSignalNormalizer()
    
    # Test 500 error
    raw_signal = {
        "level": "ERROR",
        "message": "Internal Server Error: Database timeout",
        "error_code": "500",
        "service": "user-api"
    }
    
    assert normalizer.validate(raw_signal), "Log signal should be valid"
    
    context = normalizer.normalize(raw_signal)
    assert context.signal_type == SignalType.LOG_STREAM
    assert context.intent == "server_error_500"
    assert context.priority == "critical"
    assert context.urgency_score == 0.9
    assert "[ERROR]" in context.query
    
    print("✓ 500 error detected as critical")
    
    # Test warning
    raw_signal2 = {
        "level": "WARNING",
        "message": "High memory usage: 85%"
    }
    
    context2 = normalizer.normalize(raw_signal2)
    assert context2.intent == "system_warning"
    assert context2.priority == "normal"
    
    print("✓ Warning detected with normal priority")
    
    # Test critical error
    raw_signal3 = {
        "level": "CRITICAL",
        "message": "Payment service down"
    }
    
    context3 = normalizer.normalize(raw_signal3)
    assert context3.priority == "critical"
    assert context3.urgency_score == 0.95
    
    print("✓ Critical error detected with highest urgency")
    print("✅ Log Stream Signal Normalizer: PASSED")


def test_audio_stream_signal_normalizer():
    """Test audio stream signal normalization."""
    print("\n" + "="*60)
    print("TEST: Audio Stream Signal Normalizer")
    print("="*60)
    
    normalizer = AudioStreamSignalNormalizer()
    
    # Test help request
    raw_signal = {
        "transcript": "Can someone help me with this urgent issue?",
        "speaker_id": "john_doe"
    }
    
    assert normalizer.validate(raw_signal), "Audio signal should be valid"
    
    context = normalizer.normalize(raw_signal)
    assert context.signal_type == SignalType.AUDIO_STREAM
    assert context.intent in ["help_request", "urgent_request"]
    assert context.user_id == "john_doe"
    
    print("✓ Help request detected from transcript")
    
    # Test urgent/emergency keywords
    raw_signal2 = {
        "transcript": "Emergency! The server is down!",
        "speaker_id": "admin"
    }
    
    context2 = normalizer.normalize(raw_signal2)
    assert context2.intent == "urgent_request"
    assert context2.priority == "critical"
    assert context2.urgency_score == 0.9
    
    print("✓ Emergency keywords detected as critical")
    
    # Test question
    raw_signal3 = {
        "transcript": "I have a question about the API"
    }
    
    context3 = normalizer.normalize(raw_signal3)
    assert context3.intent == "question"
    
    print("✓ Question detected from transcript")
    print("✅ Audio Stream Signal Normalizer: PASSED")


def test_universal_signal_bus_basic():
    """Test basic Universal Signal Bus functionality."""
    print("\n" + "="*60)
    print("TEST: Universal Signal Bus - Basic Functionality")
    print("="*60)
    
    bus = UniversalSignalBus()
    
    # Test text signal
    signal = create_signal_from_text("Hello agent")
    context = bus.ingest(signal)
    assert context.signal_type == SignalType.TEXT
    assert context.query == "Hello agent"
    
    print("✓ Text signal ingested successfully")
    
    # Test file change signal
    signal2 = create_signal_from_file_change(
        "/app.py",
        "created",
        content_after="print('test')"
    )
    context2 = bus.ingest(signal2)
    assert context2.signal_type == SignalType.FILE_CHANGE
    
    print("✓ File change signal ingested successfully")
    
    # Test log signal
    signal3 = create_signal_from_log("ERROR", "Failed to connect")
    context3 = bus.ingest(signal3)
    assert context3.signal_type == SignalType.LOG_STREAM
    
    print("✓ Log signal ingested successfully")
    
    # Test audio signal
    signal4 = create_signal_from_audio("Help me please")
    context4 = bus.ingest(signal4)
    assert context4.signal_type == SignalType.AUDIO_STREAM
    
    print("✓ Audio signal ingested successfully")
    print("✅ Universal Signal Bus - Basic: PASSED")


def test_universal_signal_bus_auto_detection():
    """Test automatic signal type detection."""
    print("\n" + "="*60)
    print("TEST: Universal Signal Bus - Auto-Detection")
    print("="*60)
    
    bus = UniversalSignalBus()
    
    # Test auto-detection without explicit signal_type
    test_cases = [
        ({"text": "Hello"}, SignalType.TEXT),
        ({"file_path": "/app.py", "change_type": "modified"}, SignalType.FILE_CHANGE),
        ({"level": "ERROR", "message": "Failed"}, SignalType.LOG_STREAM),
        ({"transcript": "Hello world"}, SignalType.AUDIO_STREAM),
    ]
    
    for raw_signal, expected_type in test_cases:
        context = bus.ingest(raw_signal)
        assert context.signal_type == expected_type, \
            f"Expected {expected_type}, got {context.signal_type}"
        print(f"✓ Auto-detected {expected_type.value} correctly")
    
    print("✅ Universal Signal Bus - Auto-Detection: PASSED")


def test_universal_signal_bus_batch():
    """Test batch ingestion."""
    print("\n" + "="*60)
    print("TEST: Universal Signal Bus - Batch Ingestion")
    print("="*60)
    
    bus = UniversalSignalBus()
    
    signals = [
        create_signal_from_text("Query 1"),
        create_signal_from_text("Query 2"),
        create_signal_from_log("ERROR", "Error 1"),
    ]
    
    contexts = bus.batch_ingest(signals)
    
    assert len(contexts) == 3, "Should return 3 contexts"
    assert contexts[0].signal_type == SignalType.TEXT
    assert contexts[1].signal_type == SignalType.TEXT
    assert contexts[2].signal_type == SignalType.LOG_STREAM
    
    print(f"✓ Batch ingested {len(contexts)} signals")
    print("✅ Universal Signal Bus - Batch Ingestion: PASSED")


def test_universal_signal_bus_history():
    """Test event history tracking."""
    print("\n" + "="*60)
    print("TEST: Universal Signal Bus - History Tracking")
    print("="*60)
    
    bus = UniversalSignalBus()
    
    # Ingest multiple signals
    bus.ingest(create_signal_from_text("Text 1"))
    bus.ingest(create_signal_from_log("ERROR", "Error 1"))
    bus.ingest(create_signal_from_text("Text 2"))
    
    # Get all history
    history = bus.get_history()
    assert len(history) == 3, "Should have 3 events in history"
    
    print(f"✓ History contains {len(history)} events")
    
    # Get filtered history
    text_history = bus.get_history(signal_type=SignalType.TEXT)
    assert len(text_history) == 2, "Should have 2 text events"
    
    print(f"✓ Filtered to {len(text_history)} TEXT events")
    
    # Get limited history
    limited_history = bus.get_history(limit=2)
    assert len(limited_history) == 2, "Should limit to 2 events"
    
    print(f"✓ Limited to {len(limited_history)} most recent events")
    
    # Clear history
    bus.clear_history()
    assert len(bus.get_history()) == 0, "History should be empty"
    
    print("✓ History cleared")
    print("✅ Universal Signal Bus - History: PASSED")


def test_context_object_serialization():
    """Test ContextObject to JSON conversion."""
    print("\n" + "="*60)
    print("TEST: ContextObject Serialization")
    print("="*60)
    
    context = ContextObject(
        signal_type=SignalType.TEXT,
        timestamp=datetime.now().isoformat(),
        intent="user_query",
        query="Test query",
        context={"key": "value"},
        metadata={"meta": "data"},
        source_id="test_source",
        user_id="user123",
        priority="normal",
        urgency_score=0.5
    )
    
    # Test to_dict
    data = context.to_dict()
    assert data["signal_type"] == "text"
    assert data["intent"] == "user_query"
    assert data["query"] == "Test query"
    assert data["user_id"] == "user123"
    
    print("✓ to_dict() works correctly")
    
    # Test to_json
    json_str = context.to_json()
    assert isinstance(json_str, str)
    assert "user_query" in json_str
    
    print("✓ to_json() works correctly")
    print("✅ ContextObject Serialization: PASSED")


def test_priority_and_urgency():
    """Test priority and urgency assessment."""
    print("\n" + "="*60)
    print("TEST: Priority and Urgency Assessment")
    print("="*60)
    
    bus = UniversalSignalBus()
    
    # Critical log should be high priority
    critical_log = create_signal_from_log(
        "CRITICAL",
        "Payment service down",
        error_code="500"
    )
    context = bus.ingest(critical_log)
    assert context.priority == "critical"
    assert context.urgency_score >= 0.9
    
    print("✓ Critical log: priority=critical, urgency=0.95")
    
    # Security file changes should be high priority
    security_file = create_signal_from_file_change(
        "/auth/security.py",
        "modified",
        content_before="old",
        content_after="new"
    )
    context2 = bus.ingest(security_file)
    assert context2.priority == "high"
    assert context2.urgency_score == 0.8
    
    print("✓ Security file: priority=high, urgency=0.8")
    
    # Urgent audio should be high priority
    urgent_audio = create_signal_from_audio(
        "Emergency! Need help immediately!"
    )
    context3 = bus.ingest(urgent_audio)
    assert context3.priority == "critical"
    assert context3.urgency_score >= 0.9
    
    print("✓ Urgent audio: priority=critical, urgency=0.9")
    
    # Normal text should be normal priority
    normal_text = create_signal_from_text("Hello")
    context4 = bus.ingest(normal_text)
    assert context4.priority == "normal"
    assert context4.urgency_score == 0.5
    
    print("✓ Normal text: priority=normal, urgency=0.5")
    print("✅ Priority and Urgency Assessment: PASSED")


def test_edge_cases():
    """Test edge cases and error handling."""
    print("\n" + "="*60)
    print("TEST: Edge Cases")
    print("="*60)
    
    bus = UniversalSignalBus()
    
    # Empty text should still work
    empty_text = create_signal_from_text("")
    context = bus.ingest(empty_text)
    assert context.signal_type == SignalType.TEXT
    
    print("✓ Empty text handled")
    
    # File with no content changes
    no_change_file = create_signal_from_file_change(
        "/app.py",
        "modified",
        content_before="",
        content_after=""
    )
    context2 = bus.ingest(no_change_file)
    assert context2.signal_type == SignalType.FILE_CHANGE
    
    print("✓ File with no content changes handled")
    
    # Log with only message and service (indicates it's a log)
    message_only_log = {"message": "Something happened", "service": "api"}
    context3 = bus.ingest(message_only_log)
    assert context3.signal_type == SignalType.LOG_STREAM
    
    print("✓ Log with only message and service handled")
    
    # Invalid signal type should raise error
    try:
        invalid_signal = {}  # No identifiable fields
        bus.ingest(invalid_signal)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Cannot detect signal type" in str(e)
        print("✓ Invalid signal raises ValueError")
    
    print("✅ Edge Cases: PASSED")


def run_all_tests():
    """Run all test functions."""
    print("\n" + "="*70)
    print("  UNIVERSAL SIGNAL BUS - TEST SUITE")
    print("="*70)
    
    tests = [
        test_text_signal_normalizer,
        test_file_change_signal_normalizer,
        test_log_stream_signal_normalizer,
        test_audio_stream_signal_normalizer,
        test_universal_signal_bus_basic,
        test_universal_signal_bus_auto_detection,
        test_universal_signal_bus_batch,
        test_universal_signal_bus_history,
        test_context_object_serialization,
        test_priority_and_urgency,
        test_edge_cases,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"\n❌ FAILED: {test.__name__}")
            print(f"   Error: {e}")
            failed += 1
        except Exception as e:
            print(f"\n❌ ERROR: {test.__name__}")
            print(f"   Error: {type(e).__name__}: {e}")
            failed += 1
    
    # Final summary
    print("\n" + "="*70)
    print("  TEST SUMMARY")
    print("="*70)
    print(f"Total Tests: {len(tests)}")
    print(f"✅ Passed: {passed}")
    if failed > 0:
        print(f"❌ Failed: {failed}")
    else:
        print("🎉 ALL TESTS PASSED!")
    print("="*70)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)
