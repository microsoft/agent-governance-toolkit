# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Threshold Configuration for Listener Agent

Defines the configurable thresholds that determine when the Listener
should intervene in graph state changes.

This module provides:
- ThresholdType: Categories of monitored conditions
- InterventionLevel: Severity levels for responses
- ThresholdConfig: Configuration container
"""

from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from enum import Enum, auto


class ThresholdType(Enum):
    """Categories of conditions the Listener monitors."""
    
    # Graph state thresholds
    CONSTRAINT_VIOLATION_COUNT = auto()
    DIMENSION_CONFLICT_RATIO = auto()
    ACTION_REJECTION_RATE = auto()
    
    # Security thresholds (from iatp)
    TRUST_SCORE_MINIMUM = auto()
    PERMISSION_ESCALATION_COUNT = auto()
    ANOMALY_SCORE_MAXIMUM = auto()
    
    # Context thresholds (from caas)
    CONTEXT_DRIFT_MAXIMUM = auto()
    STALE_CONTEXT_AGE_SECONDS = auto()
    AMBIGUITY_SCORE_MAXIMUM = auto()
    
    # Performance thresholds
    GRAPH_TRAVERSAL_LATENCY_MS = auto()
    HANDSHAKE_TIMEOUT_MS = auto()
    QUEUE_DEPTH_MAXIMUM = auto()


class InterventionLevel(Enum):
    """Severity levels for Listener intervention responses."""
    
    # Passive observation only - log and continue
    OBSERVE = "observe"
    
    # Warning - emit event but allow action to proceed
    WARN = "warn"
    
    # Soft block - require confirmation before proceeding
    SOFT_BLOCK = "soft_block"
    
    # Hard block - prevent action entirely
    HARD_BLOCK = "hard_block"
    
    # Emergency - trigger system-wide alert/shutdown
    EMERGENCY = "emergency"


@dataclass
class ThresholdRule:
    """A single threshold rule configuration."""
    
    threshold_type: ThresholdType
    value: float
    intervention_level: InterventionLevel
    description: str = ""
    enabled: bool = True
    
    # Optional custom evaluation function
    # Signature: (current_value: float, threshold: float, context: Dict) -> bool
    custom_evaluator: Optional[Callable[[float, float, Dict], bool]] = None
    
    def evaluate(self, current_value: float, context: Optional[Dict[str, Any]] = None) -> bool:
        """
        Evaluate if the threshold has been exceeded.
        
        Returns True if threshold is exceeded (intervention needed).
        """
        if not self.enabled:
            return False
        
        if self.custom_evaluator:
            return self.custom_evaluator(current_value, self.value, context or {})
        
        # Default evaluation: current exceeds threshold
        # For MINIMUM thresholds, we check if current is below
        if "MINIMUM" in self.threshold_type.name:
            return current_value < self.value
        else:
            return current_value > self.value


@dataclass
class ThresholdConfig:
    """
    Complete threshold configuration for the Listener Agent.
    
    This configuration determines when the Listener transitions from
    passive observation to active intervention.
    """
    
    rules: Dict[ThresholdType, ThresholdRule] = field(default_factory=dict)
    
    # Global settings
    global_intervention_level: InterventionLevel = InterventionLevel.OBSERVE
    escalation_enabled: bool = True
    cooldown_seconds: float = 5.0
    
    # Aggregation settings
    window_size_seconds: float = 60.0
    sample_rate_hz: float = 1.0
    
    def add_rule(self, rule: ThresholdRule) -> None:
        """Add or update a threshold rule."""
        self.rules[rule.threshold_type] = rule
    
    def remove_rule(self, threshold_type: ThresholdType) -> None:
        """Remove a threshold rule."""
        self.rules.pop(threshold_type, None)
    
    def get_rule(self, threshold_type: ThresholdType) -> Optional[ThresholdRule]:
        """Get a threshold rule by type."""
        return self.rules.get(threshold_type)
    
    def enable_rule(self, threshold_type: ThresholdType) -> None:
        """Enable a specific rule."""
        if threshold_type in self.rules:
            self.rules[threshold_type].enabled = True
    
    def disable_rule(self, threshold_type: ThresholdType) -> None:
        """Disable a specific rule."""
        if threshold_type in self.rules:
            self.rules[threshold_type].enabled = False
    
    def evaluate_all(
        self,
        metrics: Dict[ThresholdType, float],
        context: Optional[Dict[str, Any]] = None
    ) -> List[ThresholdRule]:
        """
        Evaluate all rules against current metrics.
        
        Returns list of rules that were triggered (threshold exceeded).
        """
        triggered = []
        for threshold_type, value in metrics.items():
            rule = self.rules.get(threshold_type)
            if rule and rule.evaluate(value, context):
                triggered.append(rule)
        return triggered
    
    def get_maximum_intervention_level(
        self,
        triggered_rules: List[ThresholdRule]
    ) -> InterventionLevel:
        """
        Get the highest intervention level from triggered rules.
        
        Intervention levels ordered: OBSERVE < WARN < SOFT_BLOCK < HARD_BLOCK < EMERGENCY
        """
        if not triggered_rules:
            return self.global_intervention_level
        
        level_order = [
            InterventionLevel.OBSERVE,
            InterventionLevel.WARN,
            InterventionLevel.SOFT_BLOCK,
            InterventionLevel.HARD_BLOCK,
            InterventionLevel.EMERGENCY,
        ]
        
        max_level = self.global_intervention_level
        for rule in triggered_rules:
            if level_order.index(rule.intervention_level) > level_order.index(max_level):
                max_level = rule.intervention_level
        
        return max_level


# Default threshold configuration for production use
DEFAULT_THRESHOLDS = ThresholdConfig(
    rules={
        ThresholdType.CONSTRAINT_VIOLATION_COUNT: ThresholdRule(
            threshold_type=ThresholdType.CONSTRAINT_VIOLATION_COUNT,
            value=3.0,
            intervention_level=InterventionLevel.WARN,
            description="Warn after 3 constraint violations in observation window",
        ),
        ThresholdType.DIMENSION_CONFLICT_RATIO: ThresholdRule(
            threshold_type=ThresholdType.DIMENSION_CONFLICT_RATIO,
            value=0.5,
            intervention_level=InterventionLevel.SOFT_BLOCK,
            description="Soft block when >50% of dimensions conflict",
        ),
        ThresholdType.ACTION_REJECTION_RATE: ThresholdRule(
            threshold_type=ThresholdType.ACTION_REJECTION_RATE,
            value=0.8,
            intervention_level=InterventionLevel.HARD_BLOCK,
            description="Hard block when >80% of actions are rejected",
        ),
        ThresholdType.TRUST_SCORE_MINIMUM: ThresholdRule(
            threshold_type=ThresholdType.TRUST_SCORE_MINIMUM,
            value=0.3,
            intervention_level=InterventionLevel.HARD_BLOCK,
            description="Hard block when trust score falls below 0.3",
        ),
        ThresholdType.PERMISSION_ESCALATION_COUNT: ThresholdRule(
            threshold_type=ThresholdType.PERMISSION_ESCALATION_COUNT,
            value=2.0,
            intervention_level=InterventionLevel.EMERGENCY,
            description="Emergency alert on 2+ permission escalation attempts",
        ),
        ThresholdType.ANOMALY_SCORE_MAXIMUM: ThresholdRule(
            threshold_type=ThresholdType.ANOMALY_SCORE_MAXIMUM,
            value=0.9,
            intervention_level=InterventionLevel.EMERGENCY,
            description="Emergency alert on anomaly score >0.9",
        ),
        ThresholdType.CONTEXT_DRIFT_MAXIMUM: ThresholdRule(
            threshold_type=ThresholdType.CONTEXT_DRIFT_MAXIMUM,
            value=0.7,
            intervention_level=InterventionLevel.WARN,
            description="Warn when context drift exceeds 0.7",
        ),
        ThresholdType.STALE_CONTEXT_AGE_SECONDS: ThresholdRule(
            threshold_type=ThresholdType.STALE_CONTEXT_AGE_SECONDS,
            value=300.0,
            intervention_level=InterventionLevel.SOFT_BLOCK,
            description="Soft block on context older than 5 minutes",
        ),
        ThresholdType.AMBIGUITY_SCORE_MAXIMUM: ThresholdRule(
            threshold_type=ThresholdType.AMBIGUITY_SCORE_MAXIMUM,
            value=0.6,
            intervention_level=InterventionLevel.SOFT_BLOCK,
            description="Soft block when ambiguity score exceeds 0.6",
        ),
        ThresholdType.GRAPH_TRAVERSAL_LATENCY_MS: ThresholdRule(
            threshold_type=ThresholdType.GRAPH_TRAVERSAL_LATENCY_MS,
            value=100.0,
            intervention_level=InterventionLevel.WARN,
            description="Warn on graph traversal >100ms",
        ),
        ThresholdType.HANDSHAKE_TIMEOUT_MS: ThresholdRule(
            threshold_type=ThresholdType.HANDSHAKE_TIMEOUT_MS,
            value=5000.0,
            intervention_level=InterventionLevel.HARD_BLOCK,
            description="Hard block on handshake timeout >5s",
        ),
        ThresholdType.QUEUE_DEPTH_MAXIMUM: ThresholdRule(
            threshold_type=ThresholdType.QUEUE_DEPTH_MAXIMUM,
            value=100.0,
            intervention_level=InterventionLevel.WARN,
            description="Warn when action queue exceeds 100 items",
        ),
    },
    global_intervention_level=InterventionLevel.OBSERVE,
    escalation_enabled=True,
    cooldown_seconds=5.0,
    window_size_seconds=60.0,
    sample_rate_hz=1.0,
)


# Strict threshold configuration for high-security environments
STRICT_THRESHOLDS = ThresholdConfig(
    rules={
        ThresholdType.CONSTRAINT_VIOLATION_COUNT: ThresholdRule(
            threshold_type=ThresholdType.CONSTRAINT_VIOLATION_COUNT,
            value=1.0,
            intervention_level=InterventionLevel.SOFT_BLOCK,
            description="Soft block on any constraint violation",
        ),
        ThresholdType.TRUST_SCORE_MINIMUM: ThresholdRule(
            threshold_type=ThresholdType.TRUST_SCORE_MINIMUM,
            value=0.7,
            intervention_level=InterventionLevel.HARD_BLOCK,
            description="Hard block when trust score falls below 0.7",
        ),
        ThresholdType.PERMISSION_ESCALATION_COUNT: ThresholdRule(
            threshold_type=ThresholdType.PERMISSION_ESCALATION_COUNT,
            value=1.0,
            intervention_level=InterventionLevel.EMERGENCY,
            description="Emergency alert on any permission escalation attempt",
        ),
    },
    global_intervention_level=InterventionLevel.WARN,
    escalation_enabled=True,
    cooldown_seconds=1.0,
    window_size_seconds=30.0,
    sample_rate_hz=10.0,
)


# Permissive threshold configuration for development/testing
PERMISSIVE_THRESHOLDS = ThresholdConfig(
    rules={
        ThresholdType.ANOMALY_SCORE_MAXIMUM: ThresholdRule(
            threshold_type=ThresholdType.ANOMALY_SCORE_MAXIMUM,
            value=0.95,
            intervention_level=InterventionLevel.WARN,
            description="Only warn on extreme anomaly scores",
        ),
    },
    global_intervention_level=InterventionLevel.OBSERVE,
    escalation_enabled=False,
    cooldown_seconds=30.0,
    window_size_seconds=300.0,
    sample_rate_hz=0.1,
)
