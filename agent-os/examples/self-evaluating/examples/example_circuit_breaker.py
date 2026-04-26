# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example: Automated Circuit Breaker System

This example demonstrates the automated circuit breaker system for
managing agent rollouts with deterministic metrics.

Key Features:
1. The Probe: Gradual rollout (1% → 5% → 20% → 100%)
2. The Watchdog: Real-time monitoring of metrics
3. Auto-Scale: Automatic advancement when metrics hold
4. Auto-Rollback: Immediate rollback when metrics degrade

Deterministic Metrics:
- Task Completion Rate: Must stay above 85%
- Latency: Must stay below 2000ms
"""

import time
import random
import sys
import os

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.circuit_breaker import (
    CircuitBreakerConfig,
    CircuitBreakerController,
    RolloutPhase
)


def simulate_agent_execution(version: str, scenario: str = "normal") -> tuple:
    """
    Simulate agent execution with different performance characteristics.
    
    Args:
        version: "old" or "new"
        scenario: "normal", "degraded_new", "excellent_new"
    
    Returns:
        (success, latency_ms) tuple
    """
    if scenario == "degraded_new" and version == "new":
        # New version has problems
        success = random.random() > 0.3  # 70% failure rate
        latency_ms = random.uniform(2500, 3000)  # High latency
    elif scenario == "excellent_new" and version == "new":
        # New version performs excellently
        success = random.random() > 0.01  # 99% success rate
        latency_ms = random.uniform(800, 1200)  # Low latency
    elif version == "old":
        # Old version is stable
        success = random.random() > 0.1  # 90% success rate
        latency_ms = random.uniform(1400, 1800)  # Moderate latency
    else:
        # Normal new version performance
        success = random.random() > 0.05  # 95% success rate
        latency_ms = random.uniform(1000, 1500)  # Good latency
    
    return success, latency_ms


def run_scenario_1_successful_rollout():
    """
    Scenario 1: Successful rollout through all phases.
    
    The new version performs excellently, so it advances through:
    PROBE (1%) → SMALL (5%) → MEDIUM (20%) → FULL (100%)
    """
    print("\n" + "="*80)
    print("SCENARIO 1: Successful Rollout with Excellent Metrics")
    print("="*80)
    print("\nThe new agent version has better performance than the old version.")
    print("Circuit breaker should automatically advance through all phases.\n")
    
    # Create controller with custom config
    config = CircuitBreakerConfig(
        min_task_completion_rate=0.85,
        max_latency_ms=2000.0,
        min_samples_per_phase=10,
        advancement_threshold=0.90,
        monitoring_window_minutes=60
    )
    controller = CircuitBreakerController(
        config=config,
        state_file="circuit_breaker_example_1.json"
    )
    
    print(f"Initial Configuration:")
    print(f"  Min Task Completion Rate: {config.min_task_completion_rate:.0%}")
    print(f"  Max Latency: {config.max_latency_ms:.0f}ms")
    print(f"  Starting Phase: {controller.watchdog.current_phase.name}\n")
    
    # Simulate traffic
    request_count = 0
    evaluation_count = 0
    
    while controller.watchdog.current_phase != RolloutPhase.FULL and request_count < 200:
        request_count += 1
        
        # Determine version based on traffic split
        version = "new" if controller.should_use_new_version(f"req_{request_count}") else "old"
        
        # Simulate execution (new version is excellent)
        success, latency_ms = simulate_agent_execution(version, scenario="excellent_new")
        
        # Record execution
        controller.record_execution(version, success, latency_ms)
        
        # Evaluate every 10 requests
        if request_count % 10 == 0:
            evaluation_count += 1
            decision = controller.evaluate_and_decide(verbose=False)
            
            old_pct, new_pct = controller.watchdog.get_traffic_split()
            status = controller.get_status()
            
            new_metrics = status.get("new_version_metrics")
            
            if new_metrics:
                print(f"[Request {request_count:3d}] Phase: {controller.watchdog.current_phase.name:8s} | "
                      f"Traffic: {new_pct:5.1%} new | "
                      f"New Metrics: {new_metrics['task_completion_rate']:5.1%} completion, "
                      f"{new_metrics['avg_latency_ms']:6.0f}ms latency | "
                      f"Action: {decision['action'].upper()}")
            
            # Show phase changes
            if decision["action"] == "advance":
                print(f"  → ADVANCING to {decision['next_phase']}! Reason: {decision['reason']}\n")
    
    # Final status
    print("\n" + "-"*80)
    print("FINAL STATUS:")
    status = controller.get_status()
    print(f"  State: {status['state'].upper()}")
    print(f"  Phase: {status['current_phase']}")
    print(f"  Traffic Split: {status['traffic_split']['old']} old, {status['traffic_split']['new']} new")
    
    new_metrics = status.get("new_version_metrics")
    if new_metrics:
        print(f"  New Version Performance:")
        print(f"    - Completion Rate: {new_metrics['task_completion_rate']:.2%}")
        print(f"    - Avg Latency: {new_metrics['avg_latency_ms']:.0f}ms")
        print(f"    - Sample Count: {new_metrics['sample_count']}")
    
    print("\n✓ Rollout completed successfully! All traffic now on new version.\n")
    
    # Cleanup
    import os
    if os.path.exists("circuit_breaker_example_1.json"):
        os.remove("circuit_breaker_example_1.json")


def run_scenario_2_automatic_rollback():
    """
    Scenario 2: Automatic rollback when new version degrades.
    
    The new version starts well but then performance degrades.
    Circuit breaker should detect this and automatically roll back.
    """
    print("\n" + "="*80)
    print("SCENARIO 2: Automatic Rollback on Performance Degradation")
    print("="*80)
    print("\nThe new agent version starts well but then degrades.")
    print("Circuit breaker should detect this and automatically roll back.\n")
    
    config = CircuitBreakerConfig(
        min_task_completion_rate=0.85,
        max_latency_ms=2000.0,
        min_samples_per_phase=10,
        monitoring_window_minutes=60
    )
    controller = CircuitBreakerController(
        config=config,
        state_file="circuit_breaker_example_2.json"
    )
    
    print(f"Initial Phase: {controller.watchdog.current_phase.name}\n")
    
    # Phase 1: Good performance
    print("PHASE 1: New version performing well...")
    for i in range(20):
        version = "new" if controller.should_use_new_version(f"req_{i}") else "old"
        success, latency_ms = simulate_agent_execution(version, scenario="excellent_new")
        controller.record_execution(version, success, latency_ms)
    
    decision = controller.evaluate_and_decide(verbose=True)
    print(f"\nResult: {decision['action'].upper()} - {decision['reason']}\n")
    
    # Phase 2: Performance degrades
    print("\nPHASE 2: New version performance degrades significantly...")
    print("(Simulating high latency and low completion rate)\n")
    
    # Clear old good metrics to make degradation clear
    controller.metrics.clear_metrics()
    
    for i in range(15):
        version = "new" if controller.should_use_new_version(f"req_{20+i}") else "old"
        success, latency_ms = simulate_agent_execution(version, scenario="degraded_new")
        controller.record_execution(version, success, latency_ms)
    
    decision = controller.evaluate_and_decide(verbose=True)
    
    # Final status
    print("\n" + "-"*80)
    print("FINAL STATUS AFTER DEGRADATION:")
    status = controller.get_status()
    print(f"  State: {status['state'].upper()}")
    print(f"  Phase: {status['current_phase']}")
    print(f"  Traffic Split: {status['traffic_split']['old']} old, {status['traffic_split']['new']} new")
    
    new_metrics = status.get("new_version_metrics")
    if new_metrics:
        print(f"  New Version Performance:")
        print(f"    - Completion Rate: {new_metrics['task_completion_rate']:.2%}")
        print(f"    - Avg Latency: {new_metrics['avg_latency_ms']:.0f}ms")
    
    if status['state'] == 'open':
        print("\n✓ Circuit breaker TRIPPED! Traffic automatically rolled back to old version.")
        print("  The team has been alerted and no users are affected by the degraded version.\n")
    
    # Cleanup
    import os
    if os.path.exists("circuit_breaker_example_2.json"):
        os.remove("circuit_breaker_example_2.json")


def run_scenario_3_gradual_advancement():
    """
    Scenario 3: Observe gradual advancement through phases.
    
    Shows the traffic split changes as we progress through phases.
    """
    print("\n" + "="*80)
    print("SCENARIO 3: Gradual Advancement Through Rollout Phases")
    print("="*80)
    print("\nDemonstrating traffic split at each phase of the rollout.\n")
    
    config = CircuitBreakerConfig(
        min_task_completion_rate=0.85,
        max_latency_ms=2000.0,
        min_samples_per_phase=8,
        monitoring_window_minutes=60
    )
    controller = CircuitBreakerController(
        config=config,
        state_file="circuit_breaker_example_3.json"
    )
    
    phases_seen = set()
    
    for i in range(150):
        version = "new" if controller.should_use_new_version(f"req_{i}") else "old"
        success, latency_ms = simulate_agent_execution(version, scenario="excellent_new")
        controller.record_execution(version, success, latency_ms)
        
        current_phase = controller.watchdog.current_phase.name
        
        # Print traffic split when we see a new phase
        if current_phase not in phases_seen:
            phases_seen.add(current_phase)
            old_pct, new_pct = controller.watchdog.get_traffic_split()
            
            print(f"Phase: {current_phase:8s}")
            print(f"  Traffic Split: {old_pct:5.1%} old, {new_pct:5.1%} new")
            print(f"  Description: ", end="")
            
            if current_phase == "PROBE":
                print("Initial probe with 1% of traffic")
            elif current_phase == "SMALL":
                print("Small rollout with 5% of traffic")
            elif current_phase == "MEDIUM":
                print("Medium rollout with 20% of traffic")
            elif current_phase == "FULL":
                print("Full rollout with 100% of traffic")
            
            print()
        
        # Evaluate periodically
        if (i + 1) % 8 == 0:
            controller.evaluate_and_decide(verbose=False)
        
        if controller.watchdog.current_phase == RolloutPhase.FULL:
            break
    
    print("✓ Gradual rollout completed through all phases!\n")
    
    # Cleanup
    import os
    if os.path.exists("circuit_breaker_example_3.json"):
        os.remove("circuit_breaker_example_3.json")


def main():
    """Run all example scenarios."""
    print("\n" + "="*80)
    print("AUTOMATED CIRCUIT BREAKER EXAMPLES")
    print("="*80)
    print("\nThis demonstrates automated circuit breaker system for managing")
    print("agent rollouts with deterministic metrics.")
    print("\nKey Concepts:")
    print("  • The Probe: Start with 1% traffic to new version")
    print("  • The Watchdog: Monitor Task Completion Rate and Latency")
    print("  • Auto-Scale: Advance to 5% → 20% → 100% when metrics are good")
    print("  • Auto-Rollback: Revert to old version if metrics degrade")
    
    # Run scenarios
    run_scenario_1_successful_rollout()
    
    input("\nPress Enter to continue to Scenario 2...")
    run_scenario_2_automatic_rollback()
    
    input("\nPress Enter to continue to Scenario 3...")
    run_scenario_3_gradual_advancement()
    
    print("\n" + "="*80)
    print("EXAMPLES COMPLETED")
    print("="*80)
    print("\nKey Takeaways:")
    print("  1. Circuit breaker manages rollouts automatically based on metrics")
    print("  2. No manual A/B testing required - system self-regulates")
    print("  3. Fast rollback prevents user impact from degraded versions")
    print("  4. Gradual rollout minimizes risk during deployment")
    print("\nThis solves the problem of 'Old World thinking applied to New World speed'")
    print("by replacing static manual experiments with dynamic automated controls.\n")


if __name__ == "__main__":
    main()
