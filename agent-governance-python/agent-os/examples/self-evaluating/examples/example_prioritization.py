# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example demonstrating the Prioritization Framework.

This example shows how the three-layer prioritization system works:
1. Safety Layer (Highest Priority): Recent failures and corrections
2. Personalization Layer (Medium Priority): User-specific preferences
3. Global Wisdom Layer (Low Priority): Generic best practices
"""

import os
from dotenv import load_dotenv
import sys

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agent import DoerAgent
from src.observer import ObserverAgent
from src.prioritization import PrioritizationFramework

load_dotenv()


def check_api_key_available() -> bool:
    """Check if API key is available."""
    return bool(os.getenv("OPENAI_API_KEY"))


def setup_prioritization_demo():
    """Set up the prioritization framework with demo data."""
    print("="*60)
    print("Setting up Prioritization Framework Demo")
    print("="*60)
    
    # Initialize framework
    framework = PrioritizationFramework()
    
    # Add some safety corrections (simulating past failures)
    print("\n1. Adding safety corrections from past failures...")
    framework.add_safety_correction(
        task_pattern="calculate mathematical expression",
        failure_description="Agent calculated mentally instead of using calculator tool",
        correction="MUST explicitly use the calculate() tool for any mathematical operations",
        user_id="alice"
    )
    
    framework.add_safety_correction(
        task_pattern="string length computation",
        failure_description="Agent estimated length instead of using string_length tool",
        correction="MUST use the string_length() tool to get accurate length",
        user_id="bob"
    )
    
    # Add user preferences
    print("2. Adding user preferences...")
    framework.add_user_preference(
        user_id="alice",
        preference_key="output_format",
        preference_value="JSON",
        description="Always provide responses in JSON format",
        priority=9
    )
    
    framework.add_user_preference(
        user_id="alice",
        preference_key="verbosity",
        preference_value="concise",
        description="Keep responses brief and to the point",
        priority=6
    )
    
    framework.add_user_preference(
        user_id="bob",
        preference_key="tool_explanation",
        preference_value="detailed",
        description="Always explain which tools are being used and why",
        priority=8
    )
    
    print("\n✓ Prioritization framework configured!")
    
    # Show stats
    stats = framework.get_stats()
    print(f"\nFramework Stats:")
    print(f"  - Safety Corrections: {stats['total_safety_corrections']}")
    print(f"  - Users with Preferences: {stats['total_users_with_preferences']}")
    print(f"  - Total Preferences: {stats['total_preferences']}")
    
    return framework


def demo_prioritized_context():
    """Demonstrate prioritized context generation."""
    print("\n\n" + "="*60)
    print("DEMO: Prioritized Context Generation")
    print("="*60)
    
    framework = PrioritizationFramework()
    
    # Example 1: Query that matches safety correction for alice
    print("\n--- Example 1: Math Query for Alice ---")
    query = "What is 25 * 4 + 100?"
    global_wisdom = "You are a helpful AI assistant with access to tools."
    
    context = framework.get_prioritized_context(
        query=query,
        global_wisdom=global_wisdom,
        user_id="alice",
        verbose=True
    )
    
    print("\nGenerated System Prompt:")
    print("-" * 60)
    print(context.build_system_prompt())
    print("-" * 60)
    
    # Example 2: Query that matches safety correction for bob
    print("\n\n--- Example 2: String Query for Bob ---")
    query = "How long is the word 'supercalifragilisticexpialidocious'?"
    
    context = framework.get_prioritized_context(
        query=query,
        global_wisdom=global_wisdom,
        user_id="bob",
        verbose=True
    )
    
    print("\nGenerated System Prompt:")
    print("-" * 60)
    print(context.build_system_prompt())
    print("-" * 60)
    
    # Example 3: Anonymous user (no personalization, no user-specific safety)
    print("\n\n--- Example 3: Query for Anonymous User ---")
    query = "What is 10 + 20?"
    
    context = framework.get_prioritized_context(
        query=query,
        global_wisdom=global_wisdom,
        user_id=None,
        verbose=True
    )
    
    print("\nGenerated System Prompt:")
    print("-" * 60)
    print(context.build_system_prompt())
    print("-" * 60)


def demo_with_doer_agent():
    """Demonstrate DoerAgent with prioritization."""
    
    # Check for API key
    if not check_api_key_available():
        print("\n" + "="*60)
        print("SKIPPING DOER AGENT DEMO")
        print("="*60)
        print("Set OPENAI_API_KEY in .env file to run with actual LLM calls")
        return
    
    print("\n\n" + "="*60)
    print("DEMO: DoerAgent with Prioritization")
    print("="*60)
    
    # Set up framework first
    setup_prioritization_demo()
    
    # Initialize DoerAgent with prioritization enabled
    doer = DoerAgent(enable_prioritization=True)
    
    print("\n\n--- Task 1: Math query for Alice (with safety warning) ---")
    result = doer.run(
        query="What is 15 * 24 + 50?",
        user_id="alice",
        verbose=True
    )
    
    print("\n\n--- Task 2: String query for Bob (with safety warning) ---")
    result = doer.run(
        query="What is the length of 'hello world'?",
        user_id="bob",
        verbose=True
    )
    
    print("\n\n--- Task 3: Anonymous query (no personalization) ---")
    result = doer.run(
        query="What is the current time?",
        user_id=None,
        verbose=True
    )


def demo_with_observer_agent():
    """Demonstrate ObserverAgent learning with prioritization."""
    
    # Check for API key
    if not check_api_key_available():
        print("\n" + "="*60)
        print("SKIPPING OBSERVER AGENT DEMO")
        print("="*60)
        print("Set OPENAI_API_KEY in .env file to run with actual LLM calls")
        return
    
    print("\n\n" + "="*60)
    print("DEMO: ObserverAgent with Prioritization Learning")
    print("="*60)
    
    # Initialize ObserverAgent with prioritization enabled
    observer = ObserverAgent(enable_prioritization=True)
    
    print("\nProcessing telemetry events...")
    print("(The Observer will learn from failures and user feedback)")
    
    results = observer.process_events(verbose=True)
    
    print("\n\nObserver Results:")
    print(f"  - Events Processed: {results['events_processed']}")
    print(f"  - Lessons Learned: {results['lessons_learned']}")


def main():
    """Run all demos."""
    print("="*60)
    print("PRIORITIZATION FRAMEWORK - COMPREHENSIVE DEMO")
    print("="*60)
    print("\nThis demo shows the three-layer prioritization system:")
    print("1. Safety Layer (Highest): Recent failures → Critical warnings")
    print("2. Personalization Layer (Medium): User preferences → Constraints")
    print("3. Global Wisdom Layer (Low): Base instructions → Foundation")
    print()
    
    # Demo 1: Setup and context generation (no API key needed)
    setup_prioritization_demo()
    demo_prioritized_context()
    
    # Demo 2 & 3: Agent integration (requires API key)
    if check_api_key_available():
        demo_with_doer_agent()
        demo_with_observer_agent()
    else:
        print("\n\n" + "="*60)
        print("NOTE: Set OPENAI_API_KEY to see agent integration demos")
        print("="*60)
        print("\nThe prioritization framework is working!")
        print("To see it in action with actual agents:")
        print("1. Copy .env.example to .env")
        print("2. Add your OPENAI_API_KEY")
        print("3. Run this example again")
    
    print("\n\n" + "="*60)
    print("DEMO COMPLETE")
    print("="*60)
    print("\nKey Takeaways:")
    print("✓ Safety corrections prevent repeating past mistakes")
    print("✓ User preferences customize agent behavior per user")
    print("✓ Prioritization ensures critical info is most visible")
    print("✓ System learns from failures and feedback automatically")


if __name__ == "__main__":
    main()
