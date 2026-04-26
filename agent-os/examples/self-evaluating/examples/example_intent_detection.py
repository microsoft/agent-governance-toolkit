# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example: Intent Detection and Intent-Based Evaluation

This example demonstrates how the system detects user intent from the first
interaction and applies appropriate success metrics:

1. Troubleshooting (Short-Lived): Fast resolution is success (<=3 turns)
2. Brainstorming (Long-Lived): Deep exploration is success (>=5 turns)

This solves the key problem: "Engagement is often Failure" in productivity tools.
"""

import os
import time
import uuid
from dotenv import load_dotenv

load_dotenv()


def simulate_troubleshooting_conversation(verbose: bool = True):
    """
    Simulate a troubleshooting conversation.
    This should be evaluated as SUCCESS if resolved quickly (<= 3 turns).
    """
    from agent import DoerAgent
    from observer import ObserverAgent
    
    if verbose:
        print("\n" + "="*80)
        print("SCENARIO 1: TROUBLESHOOTING - Quick Resolution (SUCCESS)")
        print("="*80)
    
    # Initialize agent
    doer = DoerAgent()
    
    # Generate conversation ID
    conversation_id = str(uuid.uuid4())
    user_id = "user_troubleshoot_1"
    
    # Turn 1: User asks for help
    query1 = "How do I reset my password?"
    result1 = doer.run(
        query=query1,
        verbose=verbose,
        user_id=user_id,
        conversation_id=conversation_id,
        turn_number=1
    )
    
    time.sleep(1)
    
    # Turn 2: User confirms resolution
    query2 = "Got it, thanks!"
    result2 = doer.run(
        query=query2,
        verbose=verbose,
        user_id=user_id,
        conversation_id=conversation_id,
        turn_number=2
    )
    
    if verbose:
        print(f"\n✅ Conversation completed in 2 turns")
        print(f"Detected Intent: {result1['intent_type']}")
        print(f"Expected Evaluation: SUCCESS (resolved quickly)")
    
    return conversation_id


def simulate_troubleshooting_trapped(verbose: bool = True):
    """
    Simulate a troubleshooting conversation where user gets trapped.
    This should be evaluated as FAILURE (> 3 turns = trapped, not engaged).
    """
    from agent import DoerAgent
    
    if verbose:
        print("\n" + "="*80)
        print("SCENARIO 2: TROUBLESHOOTING - User Trapped (FAILURE)")
        print("="*80)
    
    doer = DoerAgent()
    conversation_id = str(uuid.uuid4())
    user_id = "user_troubleshoot_2"
    
    # Multiple back-and-forth turns (user is stuck)
    queries = [
        "My code won't compile, what's wrong?",
        "I tried that but it still doesn't work",
        "What about this error message?",
        "Still having issues after 4 attempts"
    ]
    
    for i, query in enumerate(queries, 1):
        result = doer.run(
            query=query,
            verbose=verbose,
            user_id=user_id,
            conversation_id=conversation_id,
            turn_number=i
        )
        time.sleep(1)
    
    if verbose:
        print(f"\n❌ Conversation took {len(queries)} turns")
        print(f"Detected Intent: {result['intent_type']}")
        print(f"Expected Evaluation: FAILURE (user trapped, not engaged)")
    
    return conversation_id


def simulate_brainstorming_success(verbose: bool = True):
    """
    Simulate a brainstorming conversation with deep exploration.
    This should be evaluated as SUCCESS (many turns = deep discussion).
    """
    from agent import DoerAgent
    
    if verbose:
        print("\n" + "="*80)
        print("SCENARIO 3: BRAINSTORMING - Deep Exploration (SUCCESS)")
        print("="*80)
    
    doer = DoerAgent()
    conversation_id = str(uuid.uuid4())
    user_id = "user_brainstorm_1"
    
    # Many turns exploring different aspects
    queries = [
        "Help me design a microservices architecture for an e-commerce platform",
        "What about the data consistency between services?",
        "How should we handle authentication across services?",
        "Tell me more about event-driven architecture",
        "What are the trade-offs with message queues?",
        "How do we ensure scalability?",
        "What monitoring strategy should we use?"
    ]
    
    for i, query in enumerate(queries, 1):
        result = doer.run(
            query=query,
            verbose=verbose,
            user_id=user_id,
            conversation_id=conversation_id,
            turn_number=i
        )
        time.sleep(1)
    
    if verbose:
        print(f"\n✅ Deep conversation with {len(queries)} turns")
        print(f"Detected Intent: {result['intent_type']}")
        print(f"Expected Evaluation: SUCCESS (deep exploration)")
    
    return conversation_id


def simulate_brainstorming_failure(verbose: bool = True):
    """
    Simulate a brainstorming conversation that's too short.
    This should be evaluated as FAILURE (too short = not creative enough).
    """
    from agent import DoerAgent
    
    if verbose:
        print("\n" + "="*80)
        print("SCENARIO 4: BRAINSTORMING - Too Shallow (FAILURE)")
        print("="*80)
    
    doer = DoerAgent()
    conversation_id = str(uuid.uuid4())
    user_id = "user_brainstorm_2"
    
    # Too few turns for brainstorming
    queries = [
        "Let's explore different database options",
        "Okay, I'll go with that"
    ]
    
    for i, query in enumerate(queries, 1):
        result = doer.run(
            query=query,
            verbose=verbose,
            user_id=user_id,
            conversation_id=conversation_id,
            turn_number=i
        )
        time.sleep(1)
    
    if verbose:
        print(f"\n❌ Conversation ended too quickly with {len(queries)} turns")
        print(f"Detected Intent: {result['intent_type']}")
        print(f"Expected Evaluation: FAILURE (not creative enough)")
    
    return conversation_id


def run_observer_evaluation(verbose: bool = True):
    """
    Run the Observer to evaluate all conversations with intent-based metrics.
    """
    from observer import ObserverAgent
    
    if verbose:
        print("\n" + "="*80)
        print("OBSERVER: Evaluating with Intent-Based Metrics")
        print("="*80)
    
    observer = ObserverAgent()
    results = observer.process_events(verbose=verbose)
    
    return results


def main():
    """Run the complete intent detection demo."""
    
    # Check for API key
    if not os.getenv("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY not found in environment variables")
        print("Please create a .env file with your OpenAI API key")
        return
    
    print("="*80)
    print("Intent Detection Demo")
    print("="*80)
    print("\nThis demo shows how we detect intent and apply appropriate metrics:")
    print("  - Troubleshooting: Success = Quick resolution (<=3 turns)")
    print("  - Brainstorming: Success = Deep exploration (>=5 turns)")
    print("\nKey Insight: Engagement is often Failure!")
    print("  - If troubleshooting takes 20 turns, user is TRAPPED, not engaged")
    print("  - If brainstorming is 2 turns, we FAILED to be creative enough")
    print("="*80)
    
    # Run scenarios
    conv1 = simulate_troubleshooting_conversation(verbose=True)
    conv2 = simulate_troubleshooting_trapped(verbose=True)
    conv3 = simulate_brainstorming_success(verbose=True)
    conv4 = simulate_brainstorming_failure(verbose=True)
    
    # Wait a moment for file writes
    time.sleep(2)
    
    # Run observer evaluation
    results = run_observer_evaluation(verbose=True)
    
    # Summary
    print("\n" + "="*80)
    print("SUMMARY: Intent-Based Evaluation")
    print("="*80)
    
    intent_evals = results.get("intent_evaluations", {})
    
    print(f"\nTroubleshooting Conversations:")
    print(f"  Total: {intent_evals.get('troubleshooting_conversations', 0)}")
    print(f"  Failures (trapped >3 turns): {intent_evals.get('troubleshooting_failures', 0)}")
    
    print(f"\nBrainstorming Conversations:")
    print(f"  Total: {intent_evals.get('brainstorming_conversations', 0)}")
    print(f"  Failures (too shallow): {intent_evals.get('brainstorming_failures', 0)}")
    
    print(f"\nTotal Lessons Learned: {results.get('lessons_learned', 0)}")
    
    print("\n" + "="*80)
    print("Key Takeaway:")
    print("="*80)
    print("We cannot use a single metric for success.")
    print("We must detect Intent in the first interaction and apply appropriate metrics:")
    print("  - Troubleshooting: Minimize turns (trapped = failure)")
    print("  - Brainstorming: Maximize depth (too short = failure)")
    print("="*80)


if __name__ == "__main__":
    main()
