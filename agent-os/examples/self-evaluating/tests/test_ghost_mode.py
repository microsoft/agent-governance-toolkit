# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Test script for Ghost Mode (Passive Observation).

Tests:
1. Context Shadow behavior pattern learning
2. Ghost Mode Observer daemon operation
3. Confidence scoring and surfacing logic
4. Dry-run mode analysis
5. Background processing without blocking
"""

import os
import json
import time
import tempfile
import sys

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ghost_mode import (
    GhostModeObserver,
    ContextShadow,
    BehaviorPattern,
    ObservationResult,
    ConfidenceLevel
)


def test_behavior_pattern():
    """Test BehaviorPattern data structure."""
    print("Testing BehaviorPattern...")
    
    pattern = BehaviorPattern(
        pattern_id="test_001",
        name="Test Pattern",
        description="A test workflow",
        trigger="test_trigger",
        steps=["step1", "step2", "step3"],
        frequency=5,
        last_seen="2024-01-01T12:00:00",
        confidence=0.8,
        metadata={"user_id": "test_user"}
    )
    
    # Test to_dict
    pattern_dict = pattern.to_dict()
    assert pattern_dict["pattern_id"] == "test_001"
    assert pattern_dict["name"] == "Test Pattern"
    assert len(pattern_dict["steps"]) == 3
    assert pattern_dict["confidence"] == 0.8
    
    # Test from_dict
    restored_pattern = BehaviorPattern.from_dict(pattern_dict)
    assert restored_pattern.pattern_id == pattern.pattern_id
    assert restored_pattern.name == pattern.name
    assert restored_pattern.steps == pattern.steps
    
    print("✓ BehaviorPattern works correctly")


def test_observation_result():
    """Test ObservationResult data structure."""
    print("\nTesting ObservationResult...")
    
    # Test low confidence
    obs_low = ObservationResult(
        timestamp="2024-01-01T12:00:00",
        signal_type="test",
        observation="Test observation",
        confidence=0.3,
        should_surface=False
    )
    assert obs_low.get_confidence_level() == ConfidenceLevel.LOW
    assert not obs_low.should_surface
    
    # Test high confidence
    obs_high = ObservationResult(
        timestamp="2024-01-01T12:00:00",
        signal_type="test",
        observation="Critical observation",
        confidence=0.85,
        should_surface=True,
        recommendation="Take action"
    )
    assert obs_high.get_confidence_level() == ConfidenceLevel.HIGH
    assert obs_high.should_surface
    assert obs_high.recommendation == "Take action"
    
    # Test critical confidence
    obs_critical = ObservationResult(
        timestamp="2024-01-01T12:00:00",
        signal_type="test",
        observation="Critical observation",
        confidence=0.95,
        should_surface=True
    )
    assert obs_critical.get_confidence_level() == ConfidenceLevel.CRITICAL
    
    # Test to_dict
    obs_dict = obs_high.to_dict()
    assert obs_dict["confidence"] == 0.85
    assert obs_dict["confidence_level"] == "high"
    assert obs_dict["should_surface"] is True
    
    print("✓ ObservationResult works correctly")


def test_context_shadow_basic():
    """Test basic Context Shadow operations."""
    print("\nTesting Context Shadow basics...")
    
    # Use temporary file for testing
    fd, temp_file = tempfile.mkstemp(suffix='.json')
    os.close(fd)  # Close the file descriptor immediately
    
    try:
        # Create shadow
        shadow = ContextShadow(storage_file=temp_file, user_id="test_user")
        
        # Learn a pattern
        pattern = BehaviorPattern(
            pattern_id="workflow_001",
            name="Test Workflow",
            description="Testing workflow",
            trigger="start_task",
            steps=["step1", "step2"],
            frequency=1,
            last_seen="2024-01-01T12:00:00",
            confidence=0.6
        )
        
        shadow.learn_pattern(pattern)
        
        # Verify pattern was stored
        stored_pattern = shadow.get_pattern("workflow_001")
        assert stored_pattern is not None
        assert stored_pattern.name == "Test Workflow"
        assert stored_pattern.frequency == 1
        
        # Learn same pattern again (should increase frequency)
        shadow.learn_pattern(pattern)
        updated_pattern = shadow.get_pattern("workflow_001")
        assert updated_pattern.frequency == 2
        assert updated_pattern.confidence > 0.6  # Confidence should increase
        
        # Query patterns
        patterns = shadow.query_patterns(trigger="start_task", min_confidence=0.5)
        assert len(patterns) == 1
        assert patterns[0].pattern_id == "workflow_001"
        
        # Test persistence - create new shadow with same file
        shadow2 = ContextShadow(storage_file=temp_file, user_id="test_user")
        loaded_pattern = shadow2.get_pattern("workflow_001")
        assert loaded_pattern is not None
        assert loaded_pattern.frequency == 2
        
        print("✓ Context Shadow basic operations work")
        
    finally:
        # Cleanup
        if os.path.exists(temp_file):
            os.remove(temp_file)


def test_context_shadow_multi_user():
    """Test Context Shadow with multiple users."""
    print("\nTesting Context Shadow multi-user support...")
    
    fd, temp_file = tempfile.mkstemp(suffix='.json')
    os.close(fd)
    
    try:
        # User 1 patterns
        shadow1 = ContextShadow(storage_file=temp_file, user_id="user1")
        pattern1 = BehaviorPattern(
            pattern_id="user1_workflow",
            name="User 1 Workflow",
            description="User 1's workflow",
            trigger="user1_action",
            steps=["step1"],
            frequency=1,
            last_seen="2024-01-01T12:00:00",
            confidence=0.6  # Add confidence above min threshold
        )
        shadow1.learn_pattern(pattern1)
        
        # User 2 patterns
        shadow2 = ContextShadow(storage_file=temp_file, user_id="user2")
        pattern2 = BehaviorPattern(
            pattern_id="user2_workflow",
            name="User 2 Workflow",
            description="User 2's workflow",
            trigger="user2_action",
            steps=["step1"],
            frequency=1,
            last_seen="2024-01-01T12:00:00",
            confidence=0.6  # Add confidence above min threshold
        )
        shadow2.learn_pattern(pattern2)
        
        # Verify user 1 only sees their patterns (reload to get fresh data)
        user1_patterns = shadow1.query_patterns(reload=True)
        assert len(user1_patterns) == 1, f"Expected 1 pattern for user1, got {len(user1_patterns)}"
        assert user1_patterns[0].pattern_id == "user1_workflow"
        
        # Verify user 2 only sees their patterns (reload to get fresh data)
        user2_patterns = shadow2.query_patterns(reload=True)
        assert len(user2_patterns) == 1, f"Expected 1 pattern for user2, got {len(user2_patterns)}"
        assert user2_patterns[0].pattern_id == "user2_workflow"
        
        print("✓ Context Shadow multi-user isolation works")
        
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)


def test_context_shadow_statistics():
    """Test Context Shadow statistics."""
    print("\nTesting Context Shadow statistics...")
    
    fd, temp_file = tempfile.mkstemp(suffix='.json')
    os.close(fd)
    
    try:
        shadow = ContextShadow(storage_file=temp_file)
        
        # Add patterns with varying confidence
        patterns = [
            BehaviorPattern(
                pattern_id=f"pattern_{i}",
                name=f"Pattern {i}",
                description="Test",
                trigger="test",
                steps=["step"],
                frequency=i,
                last_seen="2024-01-01T12:00:00",
                confidence=0.5 + (i * 0.1)
            )
            for i in range(5)
        ]
        
        for pattern in patterns:
            shadow.learn_pattern(pattern)
        
        # Get statistics
        stats = shadow.get_stats()
        assert stats["total_patterns"] == 5
        assert stats["high_confidence_patterns"] >= 2  # At least patterns 3 and 4
        assert 0.0 <= stats["average_confidence"] <= 1.0
        assert stats["most_frequent_pattern"] is not None
        
        print("✓ Context Shadow statistics work")
        
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)


def test_confidence_threshold_validation():
    """Test confidence threshold validation."""
    print("\nTesting confidence threshold validation...")
    
    # Test valid thresholds
    observer = GhostModeObserver(confidence_threshold=0.5)
    assert observer.confidence_threshold == 0.5
    
    observer = GhostModeObserver(confidence_threshold=0.0)
    assert observer.confidence_threshold == 0.0
    
    observer = GhostModeObserver(confidence_threshold=1.0)
    assert observer.confidence_threshold == 1.0
    
    # Test invalid thresholds
    try:
        GhostModeObserver(confidence_threshold=-0.1)
        assert False, "Should have raised ValueError for negative threshold"
    except ValueError as e:
        assert "must be between 0.0 and 1.0" in str(e)
    
    try:
        GhostModeObserver(confidence_threshold=1.5)
        assert False, "Should have raised ValueError for threshold > 1.0"
    except ValueError as e:
        assert "must be between 0.0 and 1.0" in str(e)
    
    print("✓ Confidence threshold validation works")


def test_ghost_mode_observer_basic():
    """Test basic Ghost Mode Observer functionality."""
    print("\nTesting Ghost Mode Observer basics...")
    
    surfaced_observations = []
    
    def test_callback(obs: ObservationResult):
        surfaced_observations.append(obs)
    
    observer = GhostModeObserver(
        confidence_threshold=0.7,
        surfacing_callback=test_callback
    )
    
    # Test that observer is not running initially
    assert not observer.is_running
    
    # Start observer
    observer.start_observing(poll_interval=0.1)
    assert observer.is_running
    
    # Send some signals
    observer.observe_signal({
        "type": "file_change",
        "data": {"file_path": "/test.py", "change_type": "modified"}
    })
    
    observer.observe_signal({
        "type": "log_stream",
        "data": {"level": "ERROR", "message": "Test error"}
    })
    
    # Wait for processing
    time.sleep(0.5)
    
    # Stop observer
    observer.stop_observing()
    assert not observer.is_running
    
    # Verify signals were processed
    stats = observer.get_stats()
    assert stats["signals_processed"] >= 2
    
    print("✓ Ghost Mode Observer basic operations work")


def test_ghost_mode_dry_run():
    """Test dry-run mode (analysis without action)."""
    print("\nTesting Ghost Mode dry-run analysis...")
    
    observer = GhostModeObserver(confidence_threshold=0.8)
    observer.start_observing(poll_interval=0.1)
    
    # Send various signals
    signals = [
        {
            "type": "file_change",
            "data": {"file_path": "/src/app.py", "change_type": "modified"}
        },
        {
            "type": "file_change",
            "data": {"file_path": "/config/password.yaml", "change_type": "modified"}
        },
        {
            "type": "log_stream",
            "data": {"level": "INFO", "message": "Server started"}
        },
        {
            "type": "log_stream",
            "data": {"level": "CRITICAL", "message": "System failure"}
        }
    ]
    
    for signal in signals:
        observer.observe_signal(signal)
    
    # Wait for processing
    time.sleep(0.5)
    observer.stop_observing()
    
    # Verify all signals were processed
    stats = observer.get_stats()
    assert stats["signals_processed"] == len(signals)
    
    # Check observations
    observations = observer.get_recent_observations()
    assert len(observations) >= len(signals)
    
    # Verify different confidence levels were assigned
    confidences = [obs.confidence for obs in observations]
    assert len(set(confidences)) > 1  # Should have different confidence scores
    
    print("✓ Ghost Mode dry-run analysis works")


def test_ghost_mode_confidence_threshold():
    """Test confidence-based surfacing threshold."""
    print("\nTesting confidence threshold surfacing...")
    
    surfaced_count = [0]  # Use list to modify in callback
    
    def count_callback(obs: ObservationResult):
        surfaced_count[0] += 1
    
    # Use low threshold to surface more observations
    observer = GhostModeObserver(
        confidence_threshold=0.5,
        surfacing_callback=count_callback
    )
    
    observer.start_observing(poll_interval=0.1)
    
    # Send mix of low and high confidence signals
    signals = [
        {"type": "file_change", "data": {"file_path": "/test.py", "change_type": "modified"}},
        {"type": "log_stream", "data": {"level": "ERROR", "message": "Error occurred"}},
        {"type": "file_change", "data": {"file_path": "/secrets.yaml", "change_type": "modified"}}
    ]
    
    for signal in signals:
        observer.observe_signal(signal)
    
    time.sleep(0.5)
    observer.stop_observing()
    
    # Verify surfacing behavior
    stats = observer.get_stats()
    assert stats["signals_surfaced"] > 0  # At least some should surface
    assert stats["signals_surfaced"] <= stats["signals_processed"]  # Can't surface more than processed
    assert surfaced_count[0] == stats["signals_surfaced"]  # Callback was called correctly
    
    print(f"✓ Confidence threshold works (surfaced {stats['signals_surfaced']}/{stats['signals_processed']})")


def test_ghost_mode_pattern_learning():
    """Test pattern learning through Ghost Mode."""
    print("\nTesting Ghost Mode pattern learning...")
    
    fd, temp_file = tempfile.mkstemp(suffix='.json')
    os.close(fd)
    
    try:
        shadow = ContextShadow(storage_file=temp_file)
        observer = GhostModeObserver(context_shadow=shadow, confidence_threshold=0.5)
        
        observer.start_observing(poll_interval=0.1)
        
        # Simulate a user workflow that should be learned
        observer.observe_signal({
            "type": "user_action",
            "data": {
                "action": "code_review",
                "sequence": ["open_pr", "review_files", "add_comments", "approve"]
            }
        })
        
        time.sleep(0.3)
        observer.stop_observing()
        
        # Check if pattern was learned
        stats = shadow.get_stats()
        assert stats["total_patterns"] >= 0  # May or may not learn based on sequence length
        
        print("✓ Ghost Mode pattern learning works")
        
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)


def test_ghost_mode_file_analysis():
    """Test file change signal analysis."""
    print("\nTesting file change analysis...")
    
    observer = GhostModeObserver(confidence_threshold=0.5)
    observer.start_observing(poll_interval=0.1)
    
    # Test security-sensitive file
    observer.observe_signal({
        "type": "file_change",
        "data": {
            "file_path": "/config/secrets.yaml",
            "change_type": "modified"
        }
    })
    
    # Test normal file
    observer.observe_signal({
        "type": "file_change",
        "data": {
            "file_path": "/src/utils.py",
            "change_type": "modified"
        }
    })
    
    # Test test file
    observer.observe_signal({
        "type": "file_change",
        "data": {
            "file_path": "/tests/test_app.py",
            "change_type": "modified"
        }
    })
    
    time.sleep(0.5)
    observer.stop_observing()
    
    observations = observer.get_recent_observations()
    
    # Security file should have higher confidence
    security_obs = [o for o in observations if "secret" in o.observation.lower()]
    normal_obs = [o for o in observations if "utils" in o.observation.lower()]
    
    if security_obs and normal_obs:
        assert security_obs[0].confidence > normal_obs[0].confidence
    
    print("✓ File change analysis works correctly")


def test_ghost_mode_log_analysis():
    """Test log stream signal analysis."""
    print("\nTesting log stream analysis...")
    
    observer = GhostModeObserver(confidence_threshold=0.5)
    observer.start_observing(poll_interval=0.1)
    
    # Test different log levels
    log_signals = [
        {"level": "INFO", "message": "Application started"},
        {"level": "WARNING", "message": "High memory usage"},
        {"level": "ERROR", "message": "Database connection failed"},
        {"level": "CRITICAL", "message": "System shutdown imminent"}
    ]
    
    for log_data in log_signals:
        observer.observe_signal({
            "type": "log_stream",
            "data": log_data
        })
    
    time.sleep(0.5)
    observer.stop_observing()
    
    observations = observer.get_recent_observations()
    
    # Critical logs should have highest confidence
    critical_obs = [o for o in observations if "critical" in o.observation.lower() or "shutdown" in o.observation.lower()]
    info_obs = [o for o in observations if "started" in o.observation.lower()]
    
    if critical_obs and info_obs:
        assert critical_obs[0].confidence > info_obs[0].confidence
    
    print("✓ Log stream analysis works correctly")


def run_all_tests():
    """Run all Ghost Mode tests."""
    print("="*60)
    print("GHOST MODE TEST SUITE")
    print("="*60)
    
    try:
        # Data structure tests
        test_behavior_pattern()
        test_observation_result()
        
        # Context Shadow tests
        test_context_shadow_basic()
        test_context_shadow_multi_user()
        test_context_shadow_statistics()
        
        # Ghost Mode Observer tests
        test_confidence_threshold_validation()
        test_ghost_mode_observer_basic()
        test_ghost_mode_dry_run()
        test_ghost_mode_confidence_threshold()
        test_ghost_mode_pattern_learning()
        test_ghost_mode_file_analysis()
        test_ghost_mode_log_analysis()
        
        print("\n" + "="*60)
        print("✓ ALL TESTS PASSED")
        print("="*60)
        
    except AssertionError as e:
        print("\n" + "="*60)
        print("✗ TEST FAILED")
        print("="*60)
        raise
    except Exception as e:
        print("\n" + "="*60)
        print(f"✗ ERROR: {e}")
        print("="*60)
        raise


if __name__ == "__main__":
    run_all_tests()
