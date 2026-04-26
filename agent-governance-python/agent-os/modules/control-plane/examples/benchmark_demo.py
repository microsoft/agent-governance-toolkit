#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Quick demonstration of the comparative safety benchmark.

This script runs a subset of the red team dataset and displays
the key differences between prompt-based safety and the Control Plane.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from benchmark.red_team_dataset import (
    get_prompts_by_category,
    PromptCategory,
    get_dataset_stats
)


def show_dataset_overview():
    """Display an overview of the red team dataset"""
    stats = get_dataset_stats()
    
    print("\n" + "="*70)
    print("RED TEAM DATASET OVERVIEW")
    print("="*70)
    print(f"\nTotal Prompts: {stats['total']}")
    print(f"\nBreakdown by Category:")
    print(f"  • Direct Violations:     {stats['direct_violations']:>2} (obvious attacks)")
    print(f"  • Prompt Injections:     {stats['prompt_injections']:>2} (jailbreaks)")
    print(f"  • Contextual Confusion:  {stats['contextual_confusion']:>2} (social engineering)")
    print(f"  • Valid Requests:        {stats['valid_requests']:>2} (legitimate operations)")
    print(f"\nExpected Outcomes:")
    print(f"  • Should be blocked:     {stats['expected_blocked']:>2}")
    print(f"  • Should be allowed:     {stats['expected_allowed']:>2}")
    print()


def show_sample_prompts():
    """Display sample prompts from each category"""
    print("="*70)
    print("SAMPLE PROMPTS FROM EACH CATEGORY")
    print("="*70)
    
    # Direct Violations
    print("\n1. DIRECT VIOLATIONS (Obvious Attacks)")
    print("-" * 70)
    violations = get_prompts_by_category(PromptCategory.DIRECT_VIOLATION)[:3]
    for i, prompt in enumerate(violations, 1):
        print(f"   {i}. {prompt.prompt}")
        print(f"      → {prompt.description}")
    
    # Prompt Injections
    print("\n2. PROMPT INJECTIONS (Jailbreaks)")
    print("-" * 70)
    injections = get_prompts_by_category(PromptCategory.PROMPT_INJECTION)[:3]
    for i, prompt in enumerate(injections, 1):
        print(f"   {i}. {prompt.prompt[:65]}...")
        print(f"      → {prompt.description}")
    
    # Contextual Confusion
    print("\n3. CONTEXTUAL CONFUSION (Social Engineering)")
    print("-" * 70)
    confusion = get_prompts_by_category(PromptCategory.CONTEXTUAL_CONFUSION)[:3]
    for i, prompt in enumerate(confusion, 1):
        print(f"   {i}. {prompt.prompt[:65]}...")
        print(f"      → {prompt.description}")
    
    # Valid Requests
    print("\n4. VALID REQUESTS (Legitimate Operations)")
    print("-" * 70)
    valid = get_prompts_by_category(PromptCategory.VALID_REQUEST)[:3]
    for i, prompt in enumerate(valid, 1):
        print(f"   {i}. {prompt.prompt}")
        print(f"      → {prompt.description}")
    print()


def show_methodology():
    """Display the benchmark methodology"""
    print("="*70)
    print("BENCHMARK METHODOLOGY")
    print("="*70)
    print("""
The benchmark compares two approaches:

┌─────────────────────────────────────────────────────────────────┐
│ BASELINE: Prompt-Based Safety (Probabilistic)                   │
├─────────────────────────────────────────────────────────────────┤
│ • Uses a system prompt to instruct the LLM                      │
│ • Relies on the model to interpret and follow instructions      │
│ • Vulnerable to jailbreaks and prompt injection                 │
│ • Generates verbose refusal messages (~25-50 tokens)            │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ EXPERIMENTAL: Control Plane Governance (Deterministic)          │
├─────────────────────────────────────────────────────────────────┤
│ • Uses Mute Agent with strict capability definitions            │
│ • Enforces boundaries at the kernel level (before execution)    │
│ • Immune to jailbreaks (validates actions, not prompts)         │
│ • Returns "NULL" for out-of-scope requests (0-2 tokens)         │
└─────────────────────────────────────────────────────────────────┘

Key Metrics Tracked:
  1. Safety Violation Rate (SVR) - % of bad actions that got through
  2. False Positive Rate (FPR)   - % of good actions that were blocked
  3. Token Efficiency            - Average tokens per response
  4. Latency                     - Time to rejection/approval
""")


def show_expected_results():
    """Display expected results"""
    print("="*70)
    print("EXPECTED RESULTS")
    print("="*70)
    print("""
Based on our hypothesis:

H1 (Safety): Control Plane achieves 0% SVR, Baseline has >5% SVR
H2 (Efficiency): Control Plane uses 95%+ fewer tokens

Typical Outcome:
┌───────────────────────────────┬──────────────┬────────────────┐
│ Metric                        │   Baseline   │ Control Plane  │
├───────────────────────────────┼──────────────┼────────────────┤
│ Safety Violation Rate         │   20-30%     │     0.00%      │
│ False Positive Rate           │    0-5%      │     0.00%      │
│ Avg Output Tokens             │   25-50      │     0-2        │
│ Token Reduction               │      -       │    95-98%      │
└───────────────────────────────┴──────────────┴────────────────┘

Why the difference?
• Baseline fails on sophisticated jailbreaks and social engineering
• Control Plane validates ACTIONS, not PROMPTS (architectural enforcement)
• Mute Agent knows when to shut up (returns NULL, not explanations)
""")


def show_run_instructions():
    """Show how to run the full benchmark"""
    print("="*70)
    print("RUNNING THE FULL BENCHMARK")
    print("="*70)
    print("""
To run the complete comparative study:

    python3 benchmark.py

This will:
  1. Test all 60 prompts on both approaches
  2. Calculate safety and efficiency metrics
  3. Generate CSV reports:
     - benchmark_results.csv (detailed per-prompt results)
     - benchmark_summary.csv (aggregate metrics)

Expected runtime: < 1 second
Output format: Console summary + CSV files for analysis

For more details, see: benchmark/README.md
""")


def main():
    """Main demo function"""
    print("\n" + "="*70)
    print("COMPARATIVE SAFETY STUDY DEMO")
    print("Agent Control Plane vs Prompt-Based Safety")
    print("="*70)
    
    show_dataset_overview()
    show_sample_prompts()
    show_methodology()
    show_expected_results()
    show_run_instructions()
    
    print("="*70)
    print("Ready to run the benchmark? Execute: python3 benchmark.py")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()
