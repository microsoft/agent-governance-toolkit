# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Simple example demonstrating the self-evolving agent.
"""

import os
from dotenv import load_dotenv
import sys

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agent import SelfEvolvingAgent

load_dotenv()

def run_simple_example():
    """Run a simple example with a single query."""
    
    # Check for API key
    if not os.getenv("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY not found in environment variables")
        print("Please create a .env file based on .env.example")
        return
    
    print("="*60)
    print("Self-Evolving Agent - Simple Example")
    print("="*60)
    
    # Initialize agent with default settings
    agent = SelfEvolvingAgent(
        memory_file="system_instructions.json",
        score_threshold=0.8,
        max_retries=3
    )
    
    # Run a single query
    query = "What is 25 * 4 + 50?"
    print(f"\nQuery: {query}\n")
    
    results = agent.run(query, verbose=True)
    
    # Print summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print(f"Success: {results['success']}")
    print(f"Final Score: {results['final_score']:.2f}")
    print(f"Attempts: {len(results['attempts'])}")
    print(f"\nFinal Response:\n{results['final_response']}")


if __name__ == "__main__":
    run_simple_example()
