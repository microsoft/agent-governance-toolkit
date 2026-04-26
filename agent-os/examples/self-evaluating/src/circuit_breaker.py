# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Automated Circuit Breaker System

This module implements an automated circuit breaker for managing agent rollouts
with deterministic metrics. It provides:

1. The Probe: Gradual rollout of new agent behavior (1% → 5% → 20% → 100%)
2. The Watchdog: Real-time monitoring of deterministic metrics
3. Auto-Scale: Automatic expansion when metrics hold
4. Auto-Rollback: Immediate rollback when metrics degrade

Key Metrics:
- Task Completion Rate: Must stay above threshold (default 85%)
- Latency: Must stay below threshold (default 2000ms)
"""

import json
import os
import random
import time
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum


class RolloutPhase(Enum):
    """Rollout phases for gradual deployment."""
    OFF = 0.0
    PROBE = 0.01  # 1%
    SMALL = 0.05  # 5%
    MEDIUM = 0.20  # 20%
    FULL = 1.0  # 100%


class CircuitBreakerState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"  # Normal operation, traffic flows to new version
    OPEN = "open"  # Breaker tripped, traffic routed to old version
    MONITORING = "monitoring"  # Collecting data before decision


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker thresholds and behavior."""
    
    # Metric thresholds
    min_task_completion_rate: float = 0.85  # 85%
    max_latency_ms: float = 2000.0  # 2000ms
    
    # Rollout configuration
    initial_phase: RolloutPhase = RolloutPhase.PROBE
    min_samples_per_phase: int = 10  # Minimum samples before advancing
    monitoring_window_minutes: int = 5  # Time window for metric calculation
    
    # Auto-scale configuration
    advancement_threshold: float = 0.95  # Metrics must be this good to advance
    rollback_threshold: float = 0.80  # Trip if metrics fall below this
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            "min_task_completion_rate": self.min_task_completion_rate,
            "max_latency_ms": self.max_latency_ms,
            "initial_phase": self.initial_phase.value,
            "min_samples_per_phase": self.min_samples_per_phase,
            "monitoring_window_minutes": self.monitoring_window_minutes,
            "advancement_threshold": self.advancement_threshold,
            "rollback_threshold": self.rollback_threshold
        }


@dataclass
class MetricSnapshot:
    """A snapshot of metrics at a point in time."""
    timestamp: str
    version: str  # "old" or "new"
    task_completion_rate: float
    avg_latency_ms: float
    sample_count: int
    phase: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class CircuitBreakerMetrics:
    """
    Tracks and calculates metrics for circuit breaker decisions.
    
    Monitors:
    - Task Completion Rate: Percentage of successful task completions
    - Latency: Average response time in milliseconds
    """
    
    def __init__(self, config: CircuitBreakerConfig):
        self.config = config
        self.metrics_log: List[Dict[str, Any]] = []
    
    def record_execution(self, version: str, success: bool, latency_ms: float,
                        phase: str, timestamp: Optional[str] = None) -> None:
        """
        Record a single execution for metrics tracking.
        
        Args:
            version: "old" or "new"
            success: True if task completed successfully
            latency_ms: Execution latency in milliseconds
            phase: Current rollout phase
            timestamp: Optional timestamp, defaults to now
        """
        if timestamp is None:
            timestamp = datetime.now().isoformat()
        
        self.metrics_log.append({
            "timestamp": timestamp,
            "version": version,
            "success": success,
            "latency_ms": latency_ms,
            "phase": phase
        })
    
    def get_metrics_for_version(self, version: str, 
                               window_minutes: Optional[int] = None) -> Optional[MetricSnapshot]:
        """
        Calculate metrics for a specific version within a time window.
        
        Args:
            version: "old" or "new"
            window_minutes: Time window in minutes, defaults to config setting
            
        Returns:
            MetricSnapshot or None if insufficient data
        """
        if window_minutes is None:
            window_minutes = self.config.monitoring_window_minutes
        
        # Filter to version and time window
        cutoff_time = datetime.now() - timedelta(minutes=window_minutes)
        
        version_metrics = [
            m for m in self.metrics_log
            if m["version"] == version and 
            datetime.fromisoformat(m["timestamp"]) >= cutoff_time
        ]
        
        if not version_metrics:
            return None
        
        # Calculate metrics
        total_count = len(version_metrics)
        success_count = sum(1 for m in version_metrics if m["success"])
        task_completion_rate = success_count / total_count if total_count > 0 else 0.0
        avg_latency = sum(m["latency_ms"] for m in version_metrics) / total_count
        
        # Get the most recent phase
        phase = version_metrics[-1]["phase"] if version_metrics else "unknown"
        
        return MetricSnapshot(
            timestamp=datetime.now().isoformat(),
            version=version,
            task_completion_rate=task_completion_rate,
            avg_latency_ms=avg_latency,
            sample_count=total_count,
            phase=phase
        )
    
    def check_thresholds(self, snapshot: MetricSnapshot) -> Tuple[bool, str]:
        """
        Check if metrics meet minimum thresholds.
        
        Returns:
            (passes, reason) tuple
        """
        if snapshot.task_completion_rate < self.config.min_task_completion_rate:
            return False, f"Task completion rate {snapshot.task_completion_rate:.2%} below threshold {self.config.min_task_completion_rate:.2%}"
        
        if snapshot.avg_latency_ms > self.config.max_latency_ms:
            return False, f"Latency {snapshot.avg_latency_ms:.0f}ms exceeds threshold {self.config.max_latency_ms:.0f}ms"
        
        return True, "All metrics within thresholds"
    
    def clear_old_metrics(self, hours: int = 24) -> None:
        """Clear metrics older than specified hours."""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        self.metrics_log = [
            m for m in self.metrics_log
            if datetime.fromisoformat(m["timestamp"]) >= cutoff_time
        ]
    
    def clear_metrics(self) -> None:
        """Clear all metrics. Useful for testing or reset scenarios."""
        self.metrics_log = []


class CircuitBreakerWatchdog:
    """
    Real-time monitoring and decision engine for circuit breaker.
    
    Continuously monitors metrics and makes decisions about:
    - Advancing to next rollout phase
    - Tripping the breaker (rollback)
    - Maintaining current phase
    """
    
    def __init__(self, config: CircuitBreakerConfig, metrics: CircuitBreakerMetrics):
        self.config = config
        self.metrics = metrics
        self.state = CircuitBreakerState.MONITORING
        self.current_phase = config.initial_phase
        self.decision_history: List[Dict[str, Any]] = []
    
    def evaluate(self, verbose: bool = False) -> Dict[str, Any]:
        """
        Evaluate current metrics and make rollout decision.
        
        Returns:
            Decision dictionary with action, reason, and next phase
        """
        if verbose:
            print(f"\n[WATCHDOG] Evaluating metrics at phase {self.current_phase.name}")
        
        # Get metrics for new version
        new_snapshot = self.metrics.get_metrics_for_version("new")
        
        if new_snapshot is None or new_snapshot.sample_count < self.config.min_samples_per_phase:
            decision = {
                "action": "wait",
                "reason": f"Insufficient samples ({new_snapshot.sample_count if new_snapshot else 0}/{self.config.min_samples_per_phase})",
                "current_phase": self.current_phase.name,
                "next_phase": self.current_phase.name,
                "state": self.state.value,
                "timestamp": datetime.now().isoformat()
            }
            
            if verbose:
                print(f"  Action: WAIT - {decision['reason']}")
            
            self.decision_history.append(decision)
            return decision
        
        # Check if metrics meet thresholds
        passes, reason = self.metrics.check_thresholds(new_snapshot)
        
        if verbose:
            print(f"  Metrics - Completion: {new_snapshot.task_completion_rate:.2%}, Latency: {new_snapshot.avg_latency_ms:.0f}ms")
            print(f"  Threshold Check: {'PASS' if passes else 'FAIL'} - {reason}")
        
        # Decision logic
        if not passes:
            # Metrics degraded - trip the breaker
            decision = {
                "action": "rollback",
                "reason": reason,
                "current_phase": self.current_phase.name,
                "next_phase": RolloutPhase.OFF.name,
                "state": CircuitBreakerState.OPEN.value,
                "metrics": new_snapshot.to_dict(),
                "timestamp": datetime.now().isoformat()
            }
            
            self.state = CircuitBreakerState.OPEN
            self.current_phase = RolloutPhase.OFF
            
            if verbose:
                print(f"  Action: ROLLBACK - Circuit breaker tripped!")
        
        elif self.current_phase == RolloutPhase.FULL:
            # Already at full rollout
            decision = {
                "action": "maintain",
                "reason": "Full rollout active, metrics stable",
                "current_phase": self.current_phase.name,
                "next_phase": self.current_phase.name,
                "state": CircuitBreakerState.CLOSED.value,
                "metrics": new_snapshot.to_dict(),
                "timestamp": datetime.now().isoformat()
            }
            
            self.state = CircuitBreakerState.CLOSED
            
            if verbose:
                print(f"  Action: MAINTAIN - Full rollout stable")
        
        elif new_snapshot.task_completion_rate >= self.config.advancement_threshold and \
             new_snapshot.avg_latency_ms <= self.config.max_latency_ms * 0.9:  # 10% buffer
            # Metrics are excellent - advance to next phase
            next_phase = self._get_next_phase()
            
            decision = {
                "action": "advance",
                "reason": f"Metrics excellent (completion: {new_snapshot.task_completion_rate:.2%}, latency: {new_snapshot.avg_latency_ms:.0f}ms)",
                "current_phase": self.current_phase.name,
                "next_phase": next_phase.name,
                "state": CircuitBreakerState.MONITORING.value,
                "metrics": new_snapshot.to_dict(),
                "timestamp": datetime.now().isoformat()
            }
            
            self.current_phase = next_phase
            self.state = CircuitBreakerState.MONITORING if next_phase != RolloutPhase.FULL else CircuitBreakerState.CLOSED
            
            if verbose:
                print(f"  Action: ADVANCE - Moving to {next_phase.name}")
        
        else:
            # Metrics acceptable but not excellent - maintain current phase
            decision = {
                "action": "maintain",
                "reason": "Metrics acceptable, continuing monitoring",
                "current_phase": self.current_phase.name,
                "next_phase": self.current_phase.name,
                "state": self.state.value,
                "metrics": new_snapshot.to_dict(),
                "timestamp": datetime.now().isoformat()
            }
            
            if verbose:
                print(f"  Action: MAINTAIN - Continuing at {self.current_phase.name}")
        
        self.decision_history.append(decision)
        return decision
    
    def _get_next_phase(self) -> RolloutPhase:
        """Get the next rollout phase."""
        phase_order = [RolloutPhase.PROBE, RolloutPhase.SMALL, RolloutPhase.MEDIUM, RolloutPhase.FULL]
        
        try:
            current_index = phase_order.index(self.current_phase)
            if current_index < len(phase_order) - 1:
                return phase_order[current_index + 1]
        except ValueError:
            pass
        
        return RolloutPhase.FULL
    
    def get_traffic_split(self) -> Tuple[float, float]:
        """
        Get current traffic split between old and new versions.
        
        Returns:
            (old_percentage, new_percentage) tuple
        """
        if self.state == CircuitBreakerState.OPEN:
            # Breaker tripped - all traffic to old version
            return (1.0, 0.0)
        
        new_percentage = self.current_phase.value
        old_percentage = 1.0 - new_percentage
        
        return (old_percentage, new_percentage)


class CircuitBreakerController:
    """
    Main controller for automated circuit breaker system.
    
    Orchestrates the probe, watchdog, and auto-scale functionality.
    """
    
    def __init__(self, 
                 config: Optional[CircuitBreakerConfig] = None,
                 state_file: str = "circuit_breaker_state.json"):
        self.config = config or CircuitBreakerConfig()
        self.state_file = state_file
        self.metrics = CircuitBreakerMetrics(self.config)
        self.watchdog = CircuitBreakerWatchdog(self.config, self.metrics)
        
        # Load saved state if exists
        self._load_state()
    
    def _load_state(self) -> None:
        """Load circuit breaker state from file."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    state_data = json.load(f)
                
                # Restore state
                if "current_phase" in state_data:
                    phase_name = state_data["current_phase"]
                    self.watchdog.current_phase = RolloutPhase[phase_name]
                
                if "state" in state_data:
                    state_name = state_data["state"]
                    self.watchdog.state = CircuitBreakerState(state_name)
                
                if "metrics_log" in state_data:
                    self.metrics.metrics_log = state_data["metrics_log"]
                
            except Exception as e:
                print(f"Warning: Could not load circuit breaker state: {e}")
    
    def _save_state(self) -> None:
        """Save circuit breaker state to file."""
        state_data = {
            "current_phase": self.watchdog.current_phase.name,
            "state": self.watchdog.state.value,
            "metrics_log": self.metrics.metrics_log[-1000:],  # Keep last 1000 entries
            "timestamp": datetime.now().isoformat()
        }
        
        with open(self.state_file, 'w') as f:
            json.dump(state_data, f, indent=2)
    
    def should_use_new_version(self, request_id: Optional[str] = None) -> bool:
        """
        Determine if this request should use the new version.
        
        Uses deterministic hash-based routing if request_id provided,
        otherwise uses random selection based on traffic split.
        
        Args:
            request_id: Optional identifier for consistent routing
            
        Returns:
            True if should use new version, False for old version
        """
        old_pct, new_pct = self.watchdog.get_traffic_split()
        
        if new_pct == 0.0:
            return False
        
        if new_pct == 1.0:
            return True
        
        # Deterministic routing based on request_id
        if request_id:
            hash_val = hash(request_id) % 100
            return hash_val < (new_pct * 100)
        
        # Random routing
        return random.random() < new_pct
    
    def record_execution(self, version: str, success: bool, latency_ms: float) -> None:
        """
        Record an execution and save state.
        
        Args:
            version: "old" or "new"
            success: True if task completed successfully
            latency_ms: Execution latency in milliseconds
        """
        self.metrics.record_execution(
            version=version,
            success=success,
            latency_ms=latency_ms,
            phase=self.watchdog.current_phase.name
        )
        self._save_state()
    
    def evaluate_and_decide(self, verbose: bool = False) -> Dict[str, Any]:
        """
        Evaluate metrics and make rollout decision.
        
        Returns:
            Decision dictionary from watchdog
        """
        decision = self.watchdog.evaluate(verbose=verbose)
        self._save_state()
        return decision
    
    def get_status(self) -> Dict[str, Any]:
        """Get current circuit breaker status."""
        old_pct, new_pct = self.watchdog.get_traffic_split()
        
        new_metrics = self.metrics.get_metrics_for_version("new")
        old_metrics = self.metrics.get_metrics_for_version("old")
        
        return {
            "state": self.watchdog.state.value,
            "current_phase": self.watchdog.current_phase.name,
            "traffic_split": {
                "old": f"{old_pct:.1%}",
                "new": f"{new_pct:.1%}"
            },
            "new_version_metrics": new_metrics.to_dict() if new_metrics else None,
            "old_version_metrics": old_metrics.to_dict() if old_metrics else None,
            "recent_decisions": self.watchdog.decision_history[-5:] if self.watchdog.decision_history else []
        }
    
    def reset(self) -> None:
        """Reset circuit breaker to initial state."""
        self.metrics.metrics_log = []
        self.watchdog.state = CircuitBreakerState.MONITORING
        self.watchdog.current_phase = self.config.initial_phase
        self.watchdog.decision_history = []
        
        if os.path.exists(self.state_file):
            os.remove(self.state_file)
