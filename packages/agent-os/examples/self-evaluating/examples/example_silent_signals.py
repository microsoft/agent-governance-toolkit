# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example usage of Silent Signals feature.

This demonstrates how the system captures implicit feedback through:
1. Undo Signal: When user reverses an agent action
2. Abandonment Signal: When user stops responding mid-workflow
3. Acceptance Signal: When user accepts output and moves on

These signals provide a better learning signal than explicit feedback alone.

Required environment variables:
    OPENAI_API_KEY - Your OpenAI API key
"""

import os
import tempfile
import sys

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agent import DoerAgent
from src.observer import ObserverAgent
from src.telemetry import EventStream


def scenario_undo_signal():
    """
    Scenario 1: Undo Signal - Critical Failure
    
    The agent provides a dangerous response and the user immediately
    reverts it (Ctrl+Z). This is the loudest "Thumbs Down" possible.
    """
    print("\n" + "="*70)
    print("SCENARIO 1: UNDO SIGNAL - Critical Failure")
    print("="*70)
    print("User asks: 'Write code to delete temporary files'")
    print("Agent provides dangerous code that deletes all files")
    print("User hits Ctrl+Z immediately")
    print("="*70)
    
    # Use temporary files for this demo
    stream_file = os.path.join(tempfile.gettempdir(), 'demo_signals.jsonl')
    if os.path.exists(stream_file):
        os.remove(stream_file)
    
    # Use API key from environment
    os.environ.setdefault("OPENAI_API_KEY", "test-placeholder")
    
    doer = DoerAgent(
        stream_file=stream_file,
        enable_telemetry=True
    )
    
    # Simulate the interaction
    query = "Write code to delete temporary files"
    dangerous_response = "Here's code: os.system('rm -rf /*')  # Deletes ALL files!"
    
    # User immediately undoes this
    doer.emit_undo_signal(
        query=query,
        agent_response=dangerous_response,
        undo_action="Ctrl+Z in code editor - reverted dangerous code",
        user_id="user123",
        verbose=True
    )
    
    print("\n💡 Impact: Observer will learn this is a critical failure")
    print("   and update wisdom to avoid similar dangerous responses.")


def scenario_abandonment_signal():
    """
    Scenario 2: Abandonment Signal - Loss
    
    The agent starts helping but fails to engage the user effectively.
    User stops responding halfway through.
    """
    print("\n" + "="*70)
    print("SCENARIO 2: ABANDONMENT SIGNAL - Loss")
    print("="*70)
    print("User asks: 'Help me debug this error'")
    print("Agent provides generic response without specifics")
    print("User has 3 back-and-forth exchanges but gives up")
    print("="*70)
    
    stream_file = os.path.join(tempfile.gettempdir(), 'demo_signals.jsonl')
    
    # Use API key from environment
    os.environ.setdefault("OPENAI_API_KEY", "test-placeholder")
    
    doer = DoerAgent(
        stream_file=stream_file,
        enable_telemetry=True
    )
    
    # Simulate the interaction
    query = "Help me debug this TypeError in my code"
    last_response = "You should check your code for type errors. Make sure variables are correct type."
    
    # User abandons after 3 interactions
    doer.emit_abandonment_signal(
        query=query,
        agent_response=last_response,
        interaction_count=3,
        last_interaction_time="2024-01-01T12:05:00",
        user_id="user456",
        verbose=True
    )
    
    print("\n💡 Impact: Observer will learn the response wasn't engaging enough")
    print("   and update wisdom to provide more specific, helpful guidance.")


def scenario_acceptance_signal():
    """
    Scenario 3: Acceptance Signal - Success
    
    The agent provides a good response and the user immediately
    moves on to the next task without follow-up questions.
    """
    print("\n" + "="*70)
    print("SCENARIO 3: ACCEPTANCE SIGNAL - Success")
    print("="*70)
    print("User asks: 'Calculate 15 * 24 + 100'")
    print("Agent provides clear, correct answer")
    print("User accepts and moves to next calculation immediately")
    print("="*70)
    
    stream_file = os.path.join(tempfile.gettempdir(), 'demo_signals.jsonl')
    
    # Use API key from environment
    os.environ.setdefault("OPENAI_API_KEY", "test-placeholder")
    
    doer = DoerAgent(
        stream_file=stream_file,
        enable_telemetry=True
    )
    
    # Simulate the interaction
    query = "Calculate 15 * 24 + 100"
    good_response = "I'll use the calculate tool: 15 * 24 + 100 = 460"
    
    # User accepts and moves on
    doer.emit_acceptance_signal(
        query=query,
        agent_response=good_response,
        next_task="Calculate 20 * 30 + 50",
        time_to_next_task=2.5,
        user_id="user789",
        verbose=True
    )
    
    print("\n💡 Impact: Observer recognizes this as a success pattern")
    print("   and can reinforce similar response styles.")


def observer_processing():
    """
    Demonstrate the Observer processing the signals and learning.
    """
    print("\n" + "="*70)
    print("OBSERVER AGENT: Processing Silent Signals")
    print("="*70)
    
    stream_file = os.path.join(tempfile.gettempdir(), 'demo_signals.jsonl')
    checkpoint_file = os.path.join(tempfile.gettempdir(), 'demo_checkpoint.json')
    
    if os.path.exists(checkpoint_file):
        os.remove(checkpoint_file)
    
    # Use API key from environment
    os.environ.setdefault("OPENAI_API_KEY", "test-placeholder")
    
    observer = ObserverAgent(
        stream_file=stream_file,
        checkpoint_file=checkpoint_file
    )
    
    # Check what signals were captured
    stream = EventStream(stream_file)
    undo_signals = stream.get_signal_events("undo")
    abandonment_signals = stream.get_signal_events("abandonment")
    acceptance_signals = stream.get_signal_events("acceptance")
    
    print(f"\nCaptured Signals:")
    print(f"  🚨 Undo Signals: {len(undo_signals)}")
    print(f"  ⚠️ Abandonment Signals: {len(abandonment_signals)}")
    print(f"  ✅ Acceptance Signals: {len(acceptance_signals)}")
    print(f"\nTotal Silent Signals: {len(undo_signals) + len(abandonment_signals) + len(acceptance_signals)}")
    
    print("\n" + "-"*70)
    print("Note: In a real system, the Observer would now:")
    print("  1. Analyze each signal with appropriate priority")
    print("  2. Generate critiques based on signal type")
    print("  3. Update wisdom database for critical failures (undo)")
    print("  4. Learn engagement patterns from abandonment")
    print("  5. Reinforce success patterns from acceptance")
    print("  6. All without requiring explicit user feedback!")
    print("-"*70)
    
    # Cleanup
    if os.path.exists(stream_file):
        os.remove(stream_file)
    if os.path.exists(checkpoint_file):
        os.remove(checkpoint_file)


def main():
    print("="*70)
    print("SILENT SIGNALS DEMONSTRATION")
    print("="*70)
    print("\nExplicit feedback is a relic. We capture implicit signals:")
    print("  🚨 Undo: User reverses action = Critical failure")
    print("  ⚠️ Abandonment: User stops responding = Loss of engagement")
    print("  ✅ Acceptance: User moves to next task = Success")
    
    # Check for API key (not needed for this demo, but good to check)
    if not os.getenv("OPENAI_API_KEY"):
        print("\nNote: OPENAI_API_KEY not set, but not needed for this demo")
        print("      (We're only demonstrating signal emission, not LLM calls)")
    
    # Run scenarios
    scenario_undo_signal()
    scenario_abandonment_signal()
    scenario_acceptance_signal()
    
    # Show observer processing
    observer_processing()
    
    print("\n" + "="*70)
    print("DEMO COMPLETE")
    print("="*70)
    print("\n✨ Key Insight:")
    print("   Silent signals eliminate the blind spot of explicit feedback.")
    print("   The system learns from what users DO, not just what they SAY.")
    print("\n📊 Benefits:")
    print("   • No user friction from feedback requests")
    print("   • Captures true sentiment through actions")
    print("   • Critical failures (undo) get immediate attention")
    print("   • Success patterns (acceptance) are reinforced")
    print("   • Abandonment reveals engagement problems")


if __name__ == "__main__":
    main()
