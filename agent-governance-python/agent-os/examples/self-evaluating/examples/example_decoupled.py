# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example demonstrating the decoupled execution/learning architecture.

This example shows:
1. DoerAgent executing tasks synchronously with telemetry
2. ObserverAgent learning offline from the telemetry stream
"""

import os
from dotenv import load_dotenv
import sys

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agent import DoerAgent
from src.observer import ObserverAgent

load_dotenv()


def run_decoupled_example():
    """Run an example with decoupled execution and learning."""
    
    # Check for API key
    if not os.getenv("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY not found in environment variables")
        print("Please create a .env file based on .env.example")
        return
    
    print("="*60)
    print("Decoupled Architecture Example")
    print("="*60)
    print("\nThis demonstrates the separation of:")
    print("- DOER (Synchronous): Executes tasks, emits telemetry")
    print("- OBSERVER (Asynchronous): Learns offline from telemetry")
    print()
    
    # Phase 1: Execute tasks with DoerAgent
    print("\n" + "#"*60)
    print("PHASE 1: Task Execution (Doer Agent)")
    print("#"*60)
    
    doer = DoerAgent(
        wisdom_file="system_instructions.json",
        stream_file="telemetry_events.jsonl",
        enable_telemetry=True
    )
    
    queries = [
        "What is 25 * 4 + 50?",
        "What is the length of the word 'supercalifragilisticexpialidocious'?",
        "What time is it right now?"
    ]
    
    for i, query in enumerate(queries, 1):
        print(f"\n--- Task {i} ---")
        result = doer.run(query, verbose=True)
        
        if i < len(queries):
            print()
    
    # Phase 2: Learn from executions with ObserverAgent
    print("\n\n" + "#"*60)
    print("PHASE 2: Offline Learning (Observer Agent)")
    print("#"*60)
    print("\nThe Observer now processes the telemetry stream...")
    print("This happens asynchronously, separate from execution.\n")
    
    observer = ObserverAgent(
        wisdom_file="system_instructions.json",
        stream_file="telemetry_events.jsonl"
    )
    
    results = observer.process_events(verbose=True)
    
    # Summary
    print("\n\n" + "="*60)
    print("DECOUPLED ARCHITECTURE SUMMARY")
    print("="*60)
    print(f"\nDoer Phase:")
    print(f"  - Executed {len(queries)} tasks")
    print(f"  - Emitted {len(queries)} telemetry events")
    print(f"  - Runtime: Fast (no reflection/learning)")
    
    print(f"\nObserver Phase:")
    print(f"  - Processed {results['events_processed']} events")
    print(f"  - Learned {results['lessons_learned']} new lessons")
    print(f"  - Can run offline, asynchronously")
    
    print("\n" + "="*60)
    print("Key Benefits:")
    print("- Low latency execution (Doer doesn't wait for learning)")
    print("- Persistent learning (Observer builds wisdom over time)")
    print("- Scalable (Observer can process events in batch)")
    print("="*60)


if __name__ == "__main__":
    run_decoupled_example()
