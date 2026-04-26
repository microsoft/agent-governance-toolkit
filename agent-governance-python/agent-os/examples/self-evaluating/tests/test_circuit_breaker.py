# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Test script for automated circuit breaker system.
Tests metrics tracking, watchdog decisions, and rollout phases.
"""

import os
import tempfile
import time
import sys

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.circuit_breaker import (
    CircuitBreakerConfig,
    CircuitBreakerMetrics,
    CircuitBreakerWatchdog,
    CircuitBreakerController,
    RolloutPhase,
    CircuitBreakerState
)


def test_circuit_breaker_config():
    """Test circuit breaker configuration."""
    print("Testing CircuitBreakerConfig...")
    
    config = CircuitBreakerConfig(
        min_task_completion_rate=0.85,
        max_latency_ms=2000.0,
        initial_phase=RolloutPhase.PROBE
    )
    
    assert config.min_task_completion_rate == 0.85
    assert config.max_latency_ms == 2000.0
    assert config.initial_phase == RolloutPhase.PROBE
    print("✓ Config initialization works")
    
    config_dict = config.to_dict()
    assert "min_task_completion_rate" in config_dict
    assert "max_latency_ms" in config_dict
    print("✓ Config serialization works")
    
    print("CircuitBreakerConfig: All tests passed!\n")


def test_metrics_tracking():
    """Test metrics tracking and calculation."""
    print("Testing CircuitBreakerMetrics...")
    
    config = CircuitBreakerConfig(min_samples_per_phase=5)
    metrics = CircuitBreakerMetrics(config)
    
    # Record some executions
    for i in range(10):
        metrics.record_execution(
            version="new",
            success=i < 9,  # 90% success rate
            latency_ms=1500.0,
            phase="PROBE"
        )
    
    assert len(metrics.metrics_log) == 10
    print("✓ Metric recording works")
    
    # Get metrics snapshot
    snapshot = metrics.get_metrics_for_version("new")
    assert snapshot is not None
    assert snapshot.sample_count == 10
    assert 0.89 <= snapshot.task_completion_rate <= 0.91  # ~90%
    assert snapshot.avg_latency_ms == 1500.0
    print(f"✓ Metrics calculation works (completion: {snapshot.task_completion_rate:.2%}, latency: {snapshot.avg_latency_ms:.0f}ms)")
    
    # Test threshold checking
    passes, reason = metrics.check_thresholds(snapshot)
    assert passes  # Should pass (90% > 85%, 1500ms < 2000ms)
    print(f"✓ Threshold checking works: {reason}")
    
    print("CircuitBreakerMetrics: All tests passed!\n")


def test_watchdog_decisions():
    """Test watchdog decision making."""
    print("Testing CircuitBreakerWatchdog...")
    
    config = CircuitBreakerConfig(
        min_samples_per_phase=5,
        advancement_threshold=0.90,
        monitoring_window_minutes=60  # Use longer window for testing
    )
    metrics = CircuitBreakerMetrics(config)
    watchdog = CircuitBreakerWatchdog(config, metrics)
    
    # Initial state
    assert watchdog.current_phase == RolloutPhase.PROBE
    assert watchdog.state == CircuitBreakerState.MONITORING
    print("✓ Watchdog initialization works")
    
    # Test with insufficient samples
    decision = watchdog.evaluate()
    assert decision["action"] == "wait"
    print(f"✓ Wait decision works: {decision['reason']}")
    
    # Add excellent metrics
    for i in range(10):
        metrics.record_execution(
            version="new",
            success=True,  # 100% success
            latency_ms=1000.0,
            phase="PROBE"
        )
    
    # Should advance
    decision = watchdog.evaluate()
    assert decision["action"] == "advance"
    assert watchdog.current_phase == RolloutPhase.SMALL
    print(f"✓ Advance decision works: moved to {watchdog.current_phase.name}")
    
    # Test rollback with poor metrics
    # Clear ALL previous metrics to test rollback scenario cleanly
    metrics.clear_metrics()
    
    for i in range(10):
        metrics.record_execution(
            version="new",
            success=i < 7,  # 70% success (below 85% threshold)
            latency_ms=1500.0,
            phase="SMALL"
        )
    
    decision = watchdog.evaluate()
    print(f"  Decision: {decision}")
    assert decision["action"] == "rollback", f"Expected rollback but got {decision['action']}: {decision.get('reason', 'no reason')}"
    assert watchdog.state == CircuitBreakerState.OPEN
    print(f"✓ Rollback decision works: {decision['reason']}")
    
    # Test traffic split
    old_pct, new_pct = watchdog.get_traffic_split()
    assert new_pct == 0.0  # Should be 0 after rollback
    assert old_pct == 1.0
    print(f"✓ Traffic split after rollback: old={old_pct:.1%}, new={new_pct:.1%}")
    
    print("CircuitBreakerWatchdog: All tests passed!\n")


def test_controller_full_cycle():
    """Test full controller cycle through phases."""
    print("Testing CircuitBreakerController full cycle...")
    
    # Create temp state file
    state_file = os.path.join(tempfile.gettempdir(), 'test_cb_state.json')
    if os.path.exists(state_file):
        os.remove(state_file)
    
    try:
        config = CircuitBreakerConfig(
            min_samples_per_phase=5,
            advancement_threshold=0.90,
            monitoring_window_minutes=60  # Long window for testing
        )
        controller = CircuitBreakerController(config=config, state_file=state_file)
        
        print(f"  Initial phase: {controller.watchdog.current_phase.name}")
        
        # Simulate excellent performance through all phases
        phases_completed = [controller.watchdog.current_phase.name]  # Capture initial phase
        
        for cycle in range(200):  # Enough cycles to go through all phases
            # Always record to "new" version for faster progression in tests
            # In real scenarios, traffic split would be respected
            controller.record_execution(
                version="new",
                success=True,
                latency_ms=1200.0
            )
            
            # Evaluate every 5 executions
            if (cycle + 1) % 5 == 0:
                decision = controller.evaluate_and_decide()
                current_phase = controller.watchdog.current_phase.name
                
                if current_phase not in phases_completed:
                    phases_completed.append(current_phase)
                    print(f"  Cycle {cycle + 1}: {decision['action'].upper()} - Phase: {current_phase}")
                
                # Break if we reach FULL
                if controller.watchdog.current_phase == RolloutPhase.FULL:
                    break
        
        # Verify we advanced through phases
        assert RolloutPhase.PROBE.name in phases_completed
        assert RolloutPhase.FULL.name in phases_completed
        print(f"✓ Advanced through phases: {' → '.join(phases_completed)}")
        
        # Get status
        status = controller.get_status()
        assert status["state"] == CircuitBreakerState.CLOSED.value
        assert status["current_phase"] == RolloutPhase.FULL.name
        print(f"✓ Final state: {status['state']}, phase: {status['current_phase']}")
        
        # Test state persistence
        assert os.path.exists(state_file)
        print("✓ State persistence works")
        
    finally:
        if os.path.exists(state_file):
            os.remove(state_file)
    
    print("CircuitBreakerController: All tests passed!\n")


def test_rollback_scenario():
    """Test automatic rollback when metrics degrade."""
    print("Testing automatic rollback scenario...")
    
    state_file = os.path.join(tempfile.gettempdir(), 'test_cb_rollback.json')
    if os.path.exists(state_file):
        os.remove(state_file)
    
    try:
        config = CircuitBreakerConfig(
            min_samples_per_phase=5,
            min_task_completion_rate=0.85,
            max_latency_ms=2000.0,
            monitoring_window_minutes=60  # Long window for testing
        )
        controller = CircuitBreakerController(config=config, state_file=state_file)
        
        # Start with good metrics
        print("  Phase 1: Good metrics at PROBE phase")
        for i in range(10):
            controller.record_execution(version="new", success=True, latency_ms=1000.0)
        
        decision = controller.evaluate_and_decide()
        print(f"    Action: {decision['action']}, Phase: {controller.watchdog.current_phase.name}")
        assert decision["action"] in ["advance", "maintain"]
        
        # Clear metrics to simulate clean degradation
        controller.metrics.clear_metrics()
        
        # Simulate degraded metrics
        print("  Phase 2: Degraded metrics (high latency)")
        for i in range(10):
            controller.record_execution(version="new", success=True, latency_ms=2500.0)  # Too high!
        
        decision = controller.evaluate_and_decide()
        print(f"    Action: {decision['action']}, Reason: {decision['reason']}")
        assert decision["action"] == "rollback"
        assert controller.watchdog.state == CircuitBreakerState.OPEN
        
        # Verify traffic is routed to old version
        old_pct, new_pct = controller.watchdog.get_traffic_split()
        assert new_pct == 0.0
        print(f"✓ Rollback successful: traffic split = old:{old_pct:.0%}, new:{new_pct:.0%}")
        
    finally:
        if os.path.exists(state_file):
            os.remove(state_file)
    
    print("Automatic rollback: All tests passed!\n")


def test_traffic_splitting():
    """Test deterministic traffic splitting."""
    print("Testing traffic splitting...")
    
    config = CircuitBreakerConfig()
    controller = CircuitBreakerController(config=config)
    
    # At PROBE phase (1%)
    controller.watchdog.current_phase = RolloutPhase.PROBE
    new_count = sum(1 for i in range(1000) if controller.should_use_new_version(f"request_{i}"))
    new_percentage = new_count / 1000
    
    # Should be close to 1%
    assert 0.005 <= new_percentage <= 0.015  # 0.5% to 1.5% tolerance
    print(f"✓ PROBE phase traffic split: {new_percentage:.1%} (expected ~1%)")
    
    # At SMALL phase (5%)
    controller.watchdog.current_phase = RolloutPhase.SMALL
    new_count = sum(1 for i in range(1000) if controller.should_use_new_version(f"request_{i}"))
    new_percentage = new_count / 1000
    
    # Should be close to 5%
    assert 0.03 <= new_percentage <= 0.07  # 3% to 7% tolerance
    print(f"✓ SMALL phase traffic split: {new_percentage:.1%} (expected ~5%)")
    
    # At FULL phase (100%)
    controller.watchdog.current_phase = RolloutPhase.FULL
    new_count = sum(1 for i in range(100) if controller.should_use_new_version(f"request_{i}"))
    assert new_count == 100
    print(f"✓ FULL phase traffic split: 100% (expected 100%)")
    
    # After rollback (0%)
    controller.watchdog.state = CircuitBreakerState.OPEN
    new_count = sum(1 for i in range(100) if controller.should_use_new_version(f"request_{i}"))
    assert new_count == 0
    print(f"✓ OPEN state traffic split: 0% (expected 0%)")
    
    print("Traffic splitting: All tests passed!\n")


def test_metric_thresholds():
    """Test various metric threshold scenarios."""
    print("Testing metric threshold scenarios...")
    
    config = CircuitBreakerConfig(
        min_task_completion_rate=0.85,
        max_latency_ms=2000.0
    )
    metrics = CircuitBreakerMetrics(config)
    
    # Scenario 1: Low completion rate
    for i in range(10):
        metrics.record_execution(version="new", success=i < 8, latency_ms=1500.0, phase="PROBE")
    
    snapshot = metrics.get_metrics_for_version("new")
    passes, reason = metrics.check_thresholds(snapshot)
    assert not passes  # 80% < 85%
    assert "completion rate" in reason.lower()
    print(f"✓ Scenario 1 (low completion): {reason}")
    
    # Clear and test scenario 2: High latency
    metrics.clear_metrics()
    for i in range(10):
        metrics.record_execution(version="new", success=True, latency_ms=2500.0, phase="PROBE")
    
    snapshot = metrics.get_metrics_for_version("new")
    passes, reason = metrics.check_thresholds(snapshot)
    assert not passes  # 2500ms > 2000ms
    assert "latency" in reason.lower()
    print(f"✓ Scenario 2 (high latency): {reason}")
    
    # Clear and test scenario 3: Both metrics good
    metrics.clear_metrics()
    for i in range(10):
        metrics.record_execution(version="new", success=True, latency_ms=1500.0, phase="PROBE")
    
    snapshot = metrics.get_metrics_for_version("new")
    passes, reason = metrics.check_thresholds(snapshot)
    assert passes
    print(f"✓ Scenario 3 (good metrics): {reason}")
    
    print("Metric thresholds: All tests passed!\n")


def main():
    """Run all tests."""
    print("="*60)
    print("Running Circuit Breaker Tests")
    print("="*60)
    print()
    
    try:
        test_circuit_breaker_config()
        test_metrics_tracking()
        test_watchdog_decisions()
        test_controller_full_cycle()
        test_rollback_scenario()
        test_traffic_splitting()
        test_metric_thresholds()
        
        print("="*60)
        print("All tests passed! ✓")
        print("="*60)
        
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
