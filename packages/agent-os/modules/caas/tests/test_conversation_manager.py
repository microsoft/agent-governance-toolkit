# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Test suite for the Conversation Manager (Sliding Window / FIFO) implementation.

The Brutal Squeeze Philosophy:
Testing that Chopping (FIFO) is better than Summarizing.
"""

from caas.conversation import ConversationManager


def test_basic_sliding_window():
    """Test basic sliding window functionality."""
    print("\n=== Testing Basic Sliding Window (FIFO) ===")
    
    # Create manager with small window for testing
    manager = ConversationManager(max_turns=3)
    
    # Add 3 turns (should all fit)
    id1 = manager.add_turn("Hello, how are you?", "I'm doing well, thanks!")
    print(f"✓ Added turn 1: {id1[:8]}...")
    
    id2 = manager.add_turn("Can you help me with Python?", "Of course! What do you need?")
    print(f"✓ Added turn 2: {id2[:8]}...")
    
    id3 = manager.add_turn("How do I read a file?", "Use open('file.txt', 'r')")
    print(f"✓ Added turn 3: {id3[:8]}...")
    
    # Check we have 3 turns
    state = manager.get_state()
    assert len(state.turns) == 3
    assert state.total_turns_ever == 3
    print("✓ All 3 turns stored (window not exceeded)")
    
    # Add 4th turn - should trigger FIFO deletion
    print("\n--- Adding 4th turn (should delete oldest) ---")
    id4 = manager.add_turn("What about writing?", "Use open('file.txt', 'w')")
    print(f"✓ Added turn 4: {id4[:8]}...")
    
    # Check we still have 3 turns, but turn 1 is gone
    state = manager.get_state()
    assert len(state.turns) == 3
    assert state.total_turns_ever == 4
    assert state.turns[0].id == id2  # Turn 1 deleted, turn 2 is now oldest
    assert state.turns[-1].id == id4  # Turn 4 is newest
    print("✓ FIFO worked: Turn 1 deleted, turns 2-4 kept intact")
    print(f"✓ Total turns ever: {state.total_turns_ever} (1 deleted, 3 kept)")


def test_no_summarization_loss():
    """Test that no information is lost through summarization."""
    print("\n=== Testing No Summarization Loss ===")
    
    manager = ConversationManager(max_turns=2)
    
    # Add turn with specific error code
    specific_message = "I tried X and it failed with error code 500"
    specific_response = "Error 500 is an internal server error. Check your logs at /var/log/app.log"
    manager.add_turn(specific_message, specific_response)
    print(f"✓ Added turn with specific error code: 500")
    
    # Get history - should have EXACT message
    history = manager.get_conversation_history(format_as_text=False)
    assert history[0].user_message == specific_message
    assert "500" in history[0].user_message
    assert "/var/log/app.log" in history[0].ai_response
    print("✓ Exact message preserved (no lossy summarization)")
    print(f"  Original: '{specific_message}'")
    print(f"  Retrieved: '{history[0].user_message}'")
    print("  ✅ Perfect match! No detail lost!")
    
    # Add 2 more turns to push the first one out
    manager.add_turn("Another question", "Another answer")
    manager.add_turn("Yet another question", "Yet another answer")
    
    # First turn should be gone, but recent turns are PERFECTLY intact
    history = manager.get_conversation_history(format_as_text=False)
    assert len(history) == 2
    assert history[0].user_message == "Another question"
    assert history[1].user_message == "Yet another question"
    print("\n✓ After FIFO deletion:")
    print(f"  - First turn (with error 500) is deleted")
    print(f"  - Recent 2 turns are PERFECTLY intact")
    print(f"  - No summarization = No information loss")


def test_recent_turns_priority():
    """Test that recent turns take priority."""
    print("\n=== Testing Recent Turns Priority ===")
    
    manager = ConversationManager(max_turns=5)
    
    # Simulate conversation over time
    turns = [
        ("20 minutes ago: Old question", "Old answer"),
        ("15 minutes ago: Another old question", "Another old answer"),
        ("10 minutes ago: Yet another old", "Yet another old answer"),
        ("5 minutes ago: Getting recent", "Recent answer"),
        ("1 minute ago: Very recent", "Very recent answer"),
        ("30 seconds ago: Code snippet: def foo():", "That's a function definition"),
    ]
    
    for user_msg, ai_msg in turns:
        manager.add_turn(user_msg, ai_msg)
    
    # Should have last 5 turns
    history = manager.get_conversation_history(format_as_text=False)
    assert len(history) == 5
    assert "Old question" not in history[0].user_message  # First turn deleted
    assert "Code snippet" in history[-1].user_message  # Most recent kept
    print("✓ Recent precision maintained")
    print(f"  - Oldest turn kept: '{history[0].user_message[:30]}...'")
    print(f"  - Newest turn kept: '{history[-1].user_message[:30]}...'")
    print("  ✅ User can still see their exact code snippet from 30 seconds ago!")


def test_get_recent_turns():
    """Test getting N most recent turns."""
    print("\n=== Testing Get Recent Turns ===")
    
    manager = ConversationManager(max_turns=10)
    
    # Add 10 turns
    for i in range(10):
        manager.add_turn(f"Question {i+1}", f"Answer {i+1}")
    
    # Get last 3 turns
    recent = manager.get_recent_turns(n=3)
    assert len(recent) == 3
    assert "Question 8" in recent[0].user_message
    assert "Question 9" in recent[1].user_message
    assert "Question 10" in recent[2].user_message
    print("✓ Got last 3 turns correctly")
    
    # Get recent turns when we have fewer than requested
    manager.clear_conversation()
    manager.add_turn("Only one", "Only one answer")
    recent = manager.get_recent_turns(n=5)
    assert len(recent) == 1
    print("✓ Handles case where we have fewer turns than requested")


def test_update_turn_response():
    """Test updating a turn's AI response."""
    print("\n=== Testing Update Turn Response ===")
    
    manager = ConversationManager(max_turns=5)
    
    # Add turn without AI response
    turn_id = manager.add_turn("What is Python?")
    print(f"✓ Added turn without AI response: {turn_id[:8]}...")
    
    # Update with AI response
    success = manager.update_turn_response(turn_id, "Python is a programming language")
    assert success
    print("✓ Updated turn with AI response")
    
    # Verify update
    history = manager.get_conversation_history(format_as_text=False)
    assert history[0].ai_response == "Python is a programming language"
    print("✓ AI response correctly updated")
    
    # Try updating non-existent turn
    success = manager.update_turn_response("fake-id", "Fake response")
    assert not success
    print("✓ Correctly handles non-existent turn ID")


def test_conversation_statistics():
    """Test conversation statistics."""
    print("\n=== Testing Conversation Statistics ===")
    
    manager = ConversationManager(max_turns=3)
    
    # Add 5 turns (2 should be deleted)
    for i in range(5):
        manager.add_turn(f"Question {i+1}", f"Answer {i+1}")
    
    stats = manager.get_statistics()
    assert stats["current_turns"] == 3
    assert stats["max_turns"] == 3
    assert stats["total_turns_ever"] == 5
    assert stats["deleted_turns"] == 2
    print("✓ Statistics correctly calculated:")
    print(f"  - Current turns: {stats['current_turns']}")
    print(f"  - Max turns: {stats['max_turns']}")
    print(f"  - Total turns ever: {stats['total_turns_ever']}")
    print(f"  - Deleted turns: {stats['deleted_turns']}")
    print(f"  ✅ Sliding window deleted {stats['deleted_turns']} old turns, kept {stats['current_turns']} recent!")


def test_formatted_output():
    """Test formatted text output."""
    print("\n=== Testing Formatted Output ===")
    
    manager = ConversationManager(max_turns=3)
    
    # Add some turns
    manager.add_turn("Hello", "Hi there!", {"source": "user"})
    manager.add_turn("How are you?", "I'm great!", {"source": "user"})
    
    # Get formatted text
    text = manager.get_conversation_history(format_as_text=True, include_metadata=True)
    assert "Conversation History" in text
    assert "Sliding Window" in text
    assert "Hello" in text
    assert "Hi there!" in text
    assert "source" in text
    print("✓ Formatted output looks good:")
    print(text)


def test_clear_conversation():
    """Test clearing conversation."""
    print("\n=== Testing Clear Conversation ===")
    
    manager = ConversationManager(max_turns=5)
    
    # Add some turns
    for i in range(3):
        manager.add_turn(f"Question {i+1}", f"Answer {i+1}")
    
    assert len(manager.get_state().turns) == 3
    print("✓ Added 3 turns")
    
    # Clear
    manager.clear_conversation()
    assert len(manager.get_state().turns) == 0
    print("✓ Conversation cleared")
    
    # Total turns ever should still be 3
    assert manager.get_state().total_turns_ever == 3
    print("✓ Total turns ever counter preserved")


def test_state_management():
    """Test state get/set."""
    print("\n=== Testing State Management ===")
    
    manager1 = ConversationManager(max_turns=5)
    manager1.add_turn("Question 1", "Answer 1")
    manager1.add_turn("Question 2", "Answer 2")
    
    # Get state
    state = manager1.get_state()
    assert len(state.turns) == 2
    print("✓ Got state from manager 1")
    
    # Create new manager and set state
    manager2 = ConversationManager(max_turns=5)
    manager2.set_state(state)
    assert len(manager2.get_state().turns) == 2
    print("✓ Set state on manager 2")
    
    # Verify turns are the same
    assert manager2.get_state().turns[0].user_message == "Question 1"
    print("✓ State correctly transferred between managers")


def run_all_tests():
    """Run all conversation manager tests."""
    print("\n" + "="*70)
    print("CONVERSATION MANAGER TEST SUITE")
    print("Testing: The Brutal Squeeze (Chopping > Summarizing)")
    print("="*70)
    
    test_basic_sliding_window()
    test_no_summarization_loss()
    test_recent_turns_priority()
    test_get_recent_turns()
    test_update_turn_response()
    test_conversation_statistics()
    test_formatted_output()
    test_clear_conversation()
    test_state_management()
    
    print("\n" + "="*70)
    print("✅ ALL TESTS PASSED!")
    print("="*70)
    print("\nKey Takeaways:")
    print("1. ✅ Sliding Window (FIFO) keeps recent turns PERFECTLY intact")
    print("2. ✅ No summarization = No information loss")
    print("3. ✅ Users can see exact code snippets from 30 seconds ago")
    print("4. ✅ Zero AI cost for context management")
    print("5. ✅ Predictable behavior: Always know what's in context")
    print("\n🎯 Recent Precision > Vague History!")


if __name__ == "__main__":
    run_all_tests()
