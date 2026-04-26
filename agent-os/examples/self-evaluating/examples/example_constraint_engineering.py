# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example: Constraint Engineering (The Logic Firewall)

This demonstrates how the constraint engine acts as a deterministic safety layer
between the AI "Brain" and the execution "Hand".

The Old World:
"Prompt Engineering. We need to find the perfect magic words to tell the AI not to delete the database."

The New World:
The AI can be creative (high temperature) because we have a Logic Firewall that
deterministically blocks dangerous actions.

Architecture:
1. Brain (LLM): Generates creative plans
2. Firewall (Constraint Engine): Deterministic Python validation
3. Hand (Executor): Only executes if firewall approves
"""

import sys
import os

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.constraint_engine import create_default_engine


def simulate_ai_plan(description: str):
    """
    In a real system, this would be an LLM generating a plan.
    For this demo, we manually create plans to show the firewall in action.
    """
    print(f"\n{'='*60}")
    print(f"🧠 AI BRAIN: {description}")
    print(f"{'='*60}")


def demo_dangerous_sql_blocked():
    """Demo: Firewall blocks dangerous SQL operations."""
    simulate_ai_plan("I'll query the database and clean up old users")
    
    # AI generates a plan (could be creative/wrong)
    plan = {
        "action_type": "sql_query",
        "action_data": {
            "query": "DELETE FROM users WHERE 1=1",  # Dangerous!
            "estimated_cost": 0.01
        }
    }
    
    print("\n📋 Generated Plan:")
    print(f"   SQL: {plan['action_data']['query']}")
    
    # Firewall intercepts
    engine = create_default_engine()
    result = engine.validate_plan(plan, verbose=True)
    
    if not result.approved:
        print("\n🛡️  FIREWALL DECISION: BLOCKED")
        print("   The AI was creative, but the firewall caught the danger!")
        for violation in result.get_blocking_violations():
            print(f"   - {violation.message}")
            print(f"   - Suggested Fix: {violation.suggested_fix}")


def demo_dangerous_file_operation_blocked():
    """Demo: Firewall blocks dangerous file operations."""
    simulate_ai_plan("I'll clean up the system by removing temporary files")
    
    # AI generates a plan (could be creative/wrong)
    plan = {
        "action_type": "file_operation",
        "action_data": {
            "command": "rm -rf /tmp/*",  # This seems OK, but...
            "path": "/etc/config.txt"    # Wrong path!
        }
    }
    
    print("\n📋 Generated Plan:")
    print(f"   Command: {plan['action_data']['command']}")
    print(f"   Path: {plan['action_data']['path']}")
    
    # Firewall intercepts
    engine = create_default_engine()
    result = engine.validate_plan(plan, verbose=True)
    
    if not result.approved:
        print("\n🛡️  FIREWALL DECISION: BLOCKED")
        print("   The AI tried to touch a protected path!")
        for violation in result.get_blocking_violations():
            print(f"   - {violation.message}")


def demo_cost_limit_enforced():
    """Demo: Firewall enforces cost limits."""
    simulate_ai_plan("I'll send a comprehensive email to all 10,000 users")
    
    # AI generates a plan (expensive!)
    plan = {
        "action_type": "email",
        "action_data": {
            "recipient": "all-users@example.com",
            "estimated_cost": 0.50  # Too expensive!
        }
    }
    
    print("\n📋 Generated Plan:")
    print(f"   Recipients: All users (10,000)")
    print(f"   Estimated Cost: ${plan['action_data']['estimated_cost']}")
    
    # Firewall intercepts
    engine = create_default_engine(max_cost=0.05)
    result = engine.validate_plan(plan, verbose=True)
    
    if not result.approved:
        print("\n🛡️  FIREWALL DECISION: BLOCKED")
        print("   The cost exceeds the limit!")
        for violation in result.get_blocking_violations():
            print(f"   - {violation.message}")
            print(f"   - Suggested Fix: {violation.suggested_fix}")


def demo_email_domain_restricted():
    """Demo: Firewall restricts email domains."""
    simulate_ai_plan("I'll email the report to the user")
    
    # AI generates a plan (wrong domain!)
    plan = {
        "action_type": "email",
        "action_data": {
            "recipient": "hacker@malicious.com",  # Not approved!
            "estimated_cost": 0.01
        }
    }
    
    print("\n📋 Generated Plan:")
    print(f"   Recipient: {plan['action_data']['recipient']}")
    
    # Firewall intercepts
    engine = create_default_engine(allowed_domains=["example.com", "company.com"])
    result = engine.validate_plan(plan, verbose=True)
    
    if not result.approved:
        print("\n🛡️  FIREWALL DECISION: BLOCKED")
        print("   The email domain is not approved!")
        for violation in result.violations:
            print(f"   - {violation.message}")
            print(f"   - Suggested Fix: {violation.suggested_fix}")


def demo_safe_operation_approved():
    """Demo: Firewall approves safe operations."""
    simulate_ai_plan("I'll query the database for the user's information")
    
    # AI generates a safe plan
    plan = {
        "action_type": "sql_query",
        "action_data": {
            "query": "SELECT * FROM users WHERE id = ?",  # Safe!
            "estimated_cost": 0.01
        }
    }
    
    print("\n📋 Generated Plan:")
    print(f"   SQL: {plan['action_data']['query']}")
    print(f"   Cost: ${plan['action_data']['estimated_cost']}")
    
    # Firewall intercepts
    engine = create_default_engine()
    result = engine.validate_plan(plan, verbose=True)
    
    if result.approved:
        print("\n🛡️  FIREWALL DECISION: APPROVED")
        print("   ✅ Safe to execute!")
        
        # Simulate execution
        print("\n⚙️  EXECUTING ACTION...")
        print("   Query executed successfully")
        print("   Result: [User data retrieved]")


def demo_creative_ai_with_firewall():
    """
    Demo: The key insight - AI can be creative (high temperature)
    because the firewall provides safety.
    """
    print("\n" + "#"*60)
    print("THE KEY INSIGHT: Creative AI + Strict Firewall")
    print("#"*60)
    print("\nOld World: Low temperature AI (0.1) to avoid mistakes")
    print("   Problem: AI is boring and predictable")
    print("\nNew World: High temperature AI (0.9) for creativity")
    print("   Solution: Deterministic firewall catches mistakes")
    print("\nWe can use 'Wild/Creative' models for the Brain")
    print("because we have a 'Strict/Boring' Firewall guarding the door!")
    
    print("\n" + "="*60)
    print("DEMONSTRATION: Multiple Creative Plans")
    print("="*60)
    
    # The AI is creative and generates multiple plans
    # Some are good, some are bad - the firewall decides
    
    creative_plans = [
        {
            "description": "Creative idea: Query all users",
            "plan": {
                "action_type": "sql_query",
                "action_data": {
                    "query": "SELECT * FROM users",
                    "estimated_cost": 0.01
                }
            }
        },
        {
            "description": "Creative idea: Clean up database",
            "plan": {
                "action_type": "sql_query",
                "action_data": {
                    "query": "DROP TABLE old_logs",  # Dangerous!
                    "estimated_cost": 0.01
                }
            }
        },
        {
            "description": "Creative idea: Send notification",
            "plan": {
                "action_type": "email",
                "action_data": {
                    "recipient": "user@example.com",
                    "estimated_cost": 0.01
                }
            }
        }
    ]
    
    engine = create_default_engine()
    approved_count = 0
    blocked_count = 0
    
    for item in creative_plans:
        print(f"\n🧠 AI Idea: {item['description']}")
        result = engine.validate_plan(item['plan'], verbose=False)
        
        if result.approved:
            print("   🛡️  Firewall: ✅ APPROVED")
            approved_count += 1
        else:
            print("   🛡️  Firewall: 🚫 BLOCKED")
            for violation in result.get_blocking_violations():
                print(f"      Reason: {violation.message}")
            blocked_count += 1
    
    print("\n" + "="*60)
    print(f"Results: {approved_count} approved, {blocked_count} blocked")
    print("The AI was creative. The Firewall kept us safe.")
    print("="*60)


def main():
    """Run all demonstrations."""
    print("\n" + "#"*60)
    print("CONSTRAINT ENGINEERING DEMONSTRATION")
    print("The Logic Firewall in Action")
    print("#"*60)
    print("\nKey Principle:")
    print("'Never let the AI touch the infrastructure directly.'")
    print("'The Human builds the walls; the AI plays inside them.'")
    
    demos = [
        ("Dangerous SQL Blocked", demo_dangerous_sql_blocked),
        ("Dangerous File Operation Blocked", demo_dangerous_file_operation_blocked),
        ("Cost Limit Enforced", demo_cost_limit_enforced),
        ("Email Domain Restricted", demo_email_domain_restricted),
        ("Safe Operation Approved", demo_safe_operation_approved),
        ("Creative AI with Firewall", demo_creative_ai_with_firewall)
    ]
    
    for i, (name, demo_func) in enumerate(demos, 1):
        print(f"\n\n{'#'*60}")
        print(f"DEMO {i}: {name}")
        print("#"*60)
        demo_func()
        
        if i < len(demos):
            input("\nPress Enter to continue to next demo...")
    
    print("\n\n" + "#"*60)
    print("SUMMARY")
    print("#"*60)
    print("\n✅ The Constraint Engine (Logic Firewall) successfully:")
    print("   1. Blocked dangerous SQL operations (DROP TABLE, DELETE)")
    print("   2. Blocked dangerous file operations (rm -rf, protected paths)")
    print("   3. Enforced cost limits (prevent expensive operations)")
    print("   4. Restricted email domains (prevent unauthorized emails)")
    print("   5. Approved safe operations (allow legitimate actions)")
    print("   6. Enabled creative AI with deterministic safety")
    print("\n🎯 Key Insight:")
    print("   We can use high-temperature (creative) AI models because")
    print("   the deterministic firewall provides safety guarantees.")
    print("\n💡 The Future:")
    print("   Prompt Engineering is fragile.")
    print("   Constraint Engineering is deterministic.")
    print("   The Human builds the walls; the AI plays inside them.")
    print("#"*60 + "\n")


if __name__ == "__main__":
    main()
