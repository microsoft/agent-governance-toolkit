# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Test script for prioritization framework.
Tests the core prioritization components and integration.
"""

import json
import os
import tempfile
import sys

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.prioritization import (
    PrioritizationFramework,
    PrioritizedContext,
    SafetyCorrection,
    UserPreference,
)


def test_safety_correction():
    """Test safety correction creation and serialization."""
    print("Testing SafetyCorrection...")
    
    correction = SafetyCorrection(
        task_pattern="mathematical calculation",
        failure_description="Agent didn't use calculator",
        correction="Must use calculate() tool",
        timestamp="2024-01-01T12:00:00",
        user_id="user123"
    )
    
    # Test serialization
    data = correction.to_dict()
    assert data["task_pattern"] == "mathematical calculation"
    print("✓ SafetyCorrection serialization works")
    
    # Test deserialization
    correction2 = SafetyCorrection.from_dict(data)
    assert correction2.task_pattern == correction.task_pattern
    print("✓ SafetyCorrection deserialization works")
    
    print("SafetyCorrection: All tests passed!\n")


def test_user_preference():
    """Test user preference creation and serialization."""
    print("Testing UserPreference...")
    
    pref = UserPreference(
        user_id="user123",
        preference_key="output_format",
        preference_value="JSON",
        description="Always use JSON format",
        priority=9
    )
    
    # Test serialization
    data = pref.to_dict()
    assert data["user_id"] == "user123"
    assert data["priority"] == 9
    print("✓ UserPreference serialization works")
    
    # Test deserialization
    pref2 = UserPreference.from_dict(data)
    assert pref2.preference_key == pref.preference_key
    print("✓ UserPreference deserialization works")
    
    print("UserPreference: All tests passed!\n")


def test_prioritized_context():
    """Test prioritized context building."""
    print("Testing PrioritizedContext...")
    
    context = PrioritizedContext(
        safety_items=["Warning: Don't do X", "Critical: Must do Y"],
        personalization_items=["User prefers JSON", "Keep it concise"],
        global_wisdom="You are a helpful assistant."
    )
    
    # Build system prompt
    prompt = context.build_system_prompt()
    
    # Verify structure
    assert "You are a helpful assistant." in prompt
    assert "USER PREFERENCES" in prompt
    assert "CRITICAL SAFETY WARNINGS" in prompt
    assert "Don't do X" in prompt
    assert "User prefers JSON" in prompt
    print("✓ System prompt building works")
    
    # Verify ordering (safety should come last for highest visibility)
    safety_pos = prompt.find("CRITICAL SAFETY WARNINGS")
    pref_pos = prompt.find("USER PREFERENCES")
    assert safety_pos > pref_pos, "Safety warnings should appear after preferences"
    print("✓ Priority ordering is correct")
    
    print("PrioritizedContext: All tests passed!\n")


def test_prioritization_framework():
    """Test the prioritization framework functionality."""
    print("Testing PrioritizationFramework...")
    
    # Create temporary files for testing
    safety_file = os.path.join(tempfile.gettempdir(), 'test_safety.json')
    prefs_file = os.path.join(tempfile.gettempdir(), 'test_prefs.json')
    
    # Clean up if exists
    for f in [safety_file, prefs_file]:
        if os.path.exists(f):
            os.remove(f)
    
    try:
        # Initialize framework
        framework = PrioritizationFramework(
            safety_db_file=safety_file,
            preferences_db_file=prefs_file,
            failure_window_hours=168
        )
        print("✓ Framework initialization works")
        
        # Test adding safety correction
        framework.add_safety_correction(
            task_pattern="calculate math expression",
            failure_description="Didn't use tool",
            correction="Must use calculate() tool",
            user_id="user123"
        )
        assert len(framework.safety_corrections) == 1
        print("✓ Adding safety correction works")
        
        # Test persistence
        assert os.path.exists(safety_file)
        framework2 = PrioritizationFramework(
            safety_db_file=safety_file,
            preferences_db_file=prefs_file
        )
        assert len(framework2.safety_corrections) == 1
        print("✓ Safety correction persistence works")
        
        # Test adding user preference
        framework.add_user_preference(
            user_id="user123",
            preference_key="output_format",
            preference_value="JSON",
            description="Use JSON format",
            priority=9
        )
        assert "user123" in framework.user_preferences
        assert len(framework.user_preferences["user123"]) == 1
        print("✓ Adding user preference works")
        
        # Test getting prioritized context
        context = framework.get_prioritized_context(
            query="What is 5 + 5?",
            global_wisdom="You are a helpful assistant.",
            user_id="user123",
            verbose=False
        )
        assert context is not None
        assert context.global_wisdom == "You are a helpful assistant."
        assert len(context.personalization_items) == 1
        print("✓ Getting prioritized context works")
        
        # Test system prompt building
        prompt = context.build_system_prompt()
        assert "helpful assistant" in prompt
        assert "JSON format" in prompt
        print("✓ System prompt generation works")
        
        # Test stats
        stats = framework.get_stats()
        assert stats["total_safety_corrections"] == 1
        assert stats["total_users_with_preferences"] == 1
        print("✓ Statistics generation works")
        
    finally:
        # Cleanup
        for f in [safety_file, prefs_file]:
            if os.path.exists(f):
                os.remove(f)
    
    print("PrioritizationFramework: All tests passed!\n")


def test_learning_from_failure():
    """Test learning from failure."""
    print("Testing learning from failure...")
    
    safety_file = os.path.join(tempfile.gettempdir(), 'test_safety2.json')
    prefs_file = os.path.join(tempfile.gettempdir(), 'test_prefs2.json')
    
    # Clean up if exists
    for f in [safety_file, prefs_file]:
        if os.path.exists(f):
            os.remove(f)
    
    try:
        framework = PrioritizationFramework(
            safety_db_file=safety_file,
            preferences_db_file=prefs_file
        )
        
        # Learn from failure
        framework.learn_from_failure(
            query="Calculate 10 * 20",
            critique="The agent should use the calculator tool instead of calculating in its head.",
            user_id="user456",
            verbose=False
        )
        
        assert len(framework.safety_corrections) == 1
        correction = framework.safety_corrections[0]
        assert correction.user_id == "user456"
        assert "should" in correction.correction.lower()
        print("✓ Learning from failure works")
        
    finally:
        # Cleanup
        for f in [safety_file, prefs_file]:
            if os.path.exists(f):
                os.remove(f)
    
    print("Learning from failure: All tests passed!\n")


def test_learning_user_preference():
    """Test learning user preferences from feedback."""
    print("Testing learning user preferences...")
    
    safety_file = os.path.join(tempfile.gettempdir(), 'test_safety3.json')
    prefs_file = os.path.join(tempfile.gettempdir(), 'test_prefs3.json')
    
    # Clean up if exists
    for f in [safety_file, prefs_file]:
        if os.path.exists(f):
            os.remove(f)
    
    try:
        framework = PrioritizationFramework(
            safety_db_file=safety_file,
            preferences_db_file=prefs_file
        )
        
        # Learn from feedback - JSON format
        framework.learn_user_preference(
            user_id="user789",
            query="Give me the data",
            user_feedback="Please always use JSON format for output",
            verbose=False
        )
        
        assert "user789" in framework.user_preferences
        prefs = framework.user_preferences["user789"]
        assert len(prefs) > 0
        assert any(p.preference_key == "output_format" for p in prefs)
        print("✓ Learning JSON format preference works")
        
        # Learn from feedback - concise
        framework.learn_user_preference(
            user_id="user789",
            query="Tell me about AI",
            user_feedback="Please be more concise",
            verbose=False
        )
        
        prefs = framework.user_preferences["user789"]
        assert any(p.preference_key == "verbosity" for p in prefs)
        print("✓ Learning verbosity preference works")
        
    finally:
        # Cleanup
        for f in [safety_file, prefs_file]:
            if os.path.exists(f):
                os.remove(f)
    
    print("Learning user preferences: All tests passed!\n")


def main():
    """Run all tests."""
    print("="*60)
    print("Running Prioritization Framework Tests")
    print("="*60)
    print()
    
    try:
        test_safety_correction()
        test_user_preference()
        test_prioritized_context()
        test_prioritization_framework()
        test_learning_from_failure()
        test_learning_user_preference()
        
        print("="*60)
        print("All tests passed! ✓")
        print("="*60)
        print("\nNote: These tests validate the prioritization framework.")
        print("For integration tests with DoerAgent and ObserverAgent,")
        print("run: python example_prioritization.py")
        
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
