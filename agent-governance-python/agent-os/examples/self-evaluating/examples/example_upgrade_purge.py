# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example: Model Upgrade Purge Strategy

This example demonstrates the "Upgrade Purge" strategy for lifecycle management
of the wisdom database. When upgrading to a new model, we audit existing lessons
and remove those that the new model can handle natively.

The philosophy:
- Lessons are band-aids for model weaknesses
- Upgrading the model makes many band-aids redundant
- The wisdom database should shrink over time, keeping only specialized edge cases
"""

import os
from dotenv import load_dotenv

import sys

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agent import SelfEvolvingAgent
from src.model_upgrade import ModelUpgradeManager

# Load environment variables
load_dotenv()


def simulate_learning_phase():
    """
    Simulate the learning phase where the agent learns lessons
    from various failure scenarios.
    """
    print("="*70)
    print("PHASE 1: LEARNING - Building Wisdom Database")
    print("="*70)
    print("\nSimulating a series of tasks where the agent learns from failures...")
    print("(In a real scenario, this would happen over time through actual usage)")
    
    # Initialize agent with a baseline model
    agent = SelfEvolvingAgent(
        memory_file="system_instructions.json",
        score_threshold=0.8,
        max_retries=2
    )
    
    # Example queries that might cause the agent to learn lessons
    example_queries = [
        "What is 156 * 23 + 789?",
        "Calculate the length of 'artificial intelligence'",
        "What is the current date and time?"
    ]
    
    print("\nRunning example queries to build up lessons...")
    for i, query in enumerate(example_queries, 1):
        print(f"\n--- Query {i}: {query}")
        # In a real scenario, these would run and potentially learn lessons
        # For demo purposes, we're just showing the concept
    
    print(f"\n✅ Learning phase complete.")
    print(f"   Wisdom database has {len(agent.memory.instructions.get('improvements', []))} lessons")
    

def demonstrate_upgrade_purge():
    """
    Demonstrate the upgrade purge process.
    """
    print("\n\n" + "="*70)
    print("PHASE 2: UPGRADE PURGE - Auditing Wisdom Against New Model")
    print("="*70)
    
    # Initialize upgrade manager
    manager = ModelUpgradeManager()
    
    # Check current state
    current_lessons = len(manager.wisdom.instructions.get("improvements", []))
    print(f"\nCurrent wisdom database:")
    print(f"  Version: {manager.wisdom.instructions.get('version', 1)}")
    print(f"  Total lessons: {current_lessons}")
    
    if current_lessons == 0:
        print("\n⚠️ No lessons in wisdom database. Run the learning phase first.")
        print("   For demo purposes, we'll show the process with a hypothetical scenario.\n")
        
        print("="*70)
        print("HYPOTHETICAL UPGRADE SCENARIO")
        print("="*70)
        print("\nScenario: Upgrading from GPT-3.5-turbo to GPT-4o")
        print("\nHypothetical lessons in database:")
        print("  1. Lesson about using calculator for math (learned from GPT-3.5)")
        print("  2. Lesson about string operations (learned from GPT-3.5)")
        print("  3. Lesson about time/date queries (learned from GPT-3.5)")
        
        print("\nUpgrade Audit Process:")
        print("  → Testing each lesson against GPT-4o without the lesson")
        print("  → Checking if GPT-4o solves it natively")
        
        print("\nHypothetical Results:")
        print("  ✅ Lesson 1 (calculator): GPT-4o solves natively (score: 0.9)")
        print("     → REDUNDANT - Can be purged")
        print("  ✅ Lesson 2 (string ops): GPT-4o solves natively (score: 0.85)")
        print("     → REDUNDANT - Can be purged")
        print("  ⚠️  Lesson 3 (time/date): GPT-4o still struggles (score: 0.6)")
        print("     → CRITICAL - Must be kept")
        
        print("\nPurge Results:")
        print("  📉 Database reduced from 3 lessons to 1 lesson (66% reduction)")
        print("  🎯 Only specialized edge cases remain")
        
        print("\n" + "="*70)
        print("KEY BENEFIT: As models improve, wisdom database gets smaller and more focused!")
        print("="*70)
        
        return
    
    # Define baseline instructions for new model
    baseline_instructions = """You are a helpful AI assistant. Your goal is to provide accurate and useful responses to user queries. You have access to tools that you can use to help answer questions. Always think step-by-step and provide clear, concise answers."""
    
    # Scenario 1: Audit only (review before purging)
    print("\n" + "-"*70)
    print("AUDIT MODE: Review lessons before purging")
    print("-"*70)
    
    # Perform audit
    audit_results = manager.audit_wisdom_database(
        new_model="gpt-4o",  # Upgrading to GPT-4o
        baseline_instructions=baseline_instructions,
        score_threshold=0.8,
        verbose=True
    )
    
    # Show recommendations
    print("\n" + "-"*70)
    print("RECOMMENDATIONS")
    print("-"*70)
    
    redundant_count = len(audit_results['redundant_lessons'])
    critical_count = len(audit_results['critical_lessons'])
    
    if redundant_count > 0:
        print(f"\n✅ Found {redundant_count} redundant lesson(s) that can be purged:")
        for lesson in audit_results['redundant_lessons']:
            print(f"   - Version {lesson['version']}: Score {lesson['new_model_score']:.2f}")
            print(f"     Query: {lesson['query'][:60]}...")
    
    if critical_count > 0:
        print(f"\n⚠️  Found {critical_count} critical lesson(s) that should be kept:")
        for lesson in audit_results['critical_lessons']:
            print(f"   - Version {lesson['version']}: Score {lesson['new_model_score']:.2f}")
            print(f"     Query: {lesson['query'][:60]}...")
    
    # Option to purge
    if redundant_count > 0:
        print("\n" + "-"*70)
        print("Would you like to purge redundant lessons? (yes/no)")
        print("-"*70)
        
        # For demo purposes, we'll do a simulated purge
        print("\n[DEMO MODE] Simulating purge...")
        
        purge_results = manager.purge_redundant_lessons(
            audit_results=audit_results,
            verbose=True
        )
        
        print("\n" + "="*70)
        print("UPGRADE COMPLETE!")
        print("="*70)
        print(f"  Before: {current_lessons} lessons")
        print(f"  After: {purge_results['remaining_count']} lessons")
        print(f"  Reduction: {purge_results['purged_count']} lessons removed")
        print(f"  Efficiency gain: {(purge_results['purged_count'] / max(current_lessons, 1)) * 100:.1f}%")
        print("\n  🎯 Wisdom database is now more specialized and efficient!")
    else:
        print("\n✅ No redundant lessons found. Database is already optimal for this model!")


def show_lifecycle_benefits():
    """
    Show the long-term benefits of the upgrade purge strategy.
    """
    print("\n\n" + "="*70)
    print("LIFECYCLE BENEFITS: Why Upgrade Purge Matters")
    print("="*70)
    
    print("""
The Upgrade Purge strategy treats wisdom like a high-performance cache:

1. 📈 LEARNING PHASE (Normal Operation)
   - Agent encounters failures
   - Learns lessons to compensate for model weaknesses
   - Wisdom database grows over time

2. 🔄 UPGRADE PHASE (Model Improvement)
   - You upgrade the base model (e.g., GPT-3.5 → GPT-4)
   - Many model weaknesses are now fixed
   - Lessons become redundant "band-aids"

3. 🗑️ PURGE PHASE (Active Management)
   - Audit: Test old failure scenarios against new model
   - Identify: Which lessons are now redundant?
   - Remove: Purge redundant lessons automatically
   - Result: Smaller, more specialized wisdom database

4. 🎯 LONG-TERM BENEFIT
   - Database stays focused on real edge cases
   - Faster context loading (less to process)
   - Clearer signal-to-noise ratio
   - More maintainable over time

═══════════════════════════════════════════════════════════════════

Example Timeline:

Month 1 (GPT-3.5):
  - 0 lessons → Learn 50 lessons → 50 lessons total

Month 3 (Still GPT-3.5):
  - 50 lessons → Learn 30 more → 80 lessons total

Month 6 (Upgrade to GPT-4):
  - 80 lessons → Purge 40 redundant → 40 lessons remaining ✅
  - Database is 50% smaller but more effective!

Month 9 (Still GPT-4):
  - 40 lessons → Learn 15 more → 55 lessons total

Month 12 (Upgrade to GPT-4.5):
  - 55 lessons → Purge 30 redundant → 25 lessons remaining ✅
  - Database continues to refine and specialize!

═══════════════════════════════════════════════════════════════════

Without Upgrade Purge:
  ❌ Database grows forever
  ❌ Contains obsolete lessons
  ❌ Wastes context window space
  ❌ Harder to maintain

With Upgrade Purge:
  ✅ Database stays lean and focused
  ✅ Contains only relevant edge cases
  ✅ Efficient use of context
  ✅ Self-maintaining system
    """)


def main():
    """
    Main example execution demonstrating the upgrade purge strategy.
    
    Shows:
    1. Conceptual explanation of the upgrade purge process
    2. Hypothetical scenario with sample data
    3. Long-term benefits and lifecycle management
    """
    print("\n")
    print("╔" + "="*68 + "╗")
    print("║" + " "*68 + "║")
    print("║" + "  UPGRADE PURGE STRATEGY: Active Wisdom Lifecycle Management".center(68) + "║")
    print("║" + " "*68 + "║")
    print("╚" + "="*68 + "╝")
    
    # Check for API key
    if not os.getenv("OPENAI_API_KEY"):
        print("\n⚠️  Warning: OPENAI_API_KEY not found")
        print("Set it in .env to run live demonstrations")
        print("\nFor now, showing conceptual demonstration...\n")
    
    # Show the phases
    # simulate_learning_phase()  # Commented out to avoid API calls in demo
    demonstrate_upgrade_purge()
    show_lifecycle_benefits()
    
    print("\n" + "="*70)
    print("Demo complete! Check model_upgrade.py for implementation details.")
    print("="*70)


if __name__ == "__main__":
    main()
