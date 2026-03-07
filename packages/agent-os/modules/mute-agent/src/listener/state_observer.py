# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
State Observer for Listener Agent

Provides passive observation capabilities for monitoring graph states
without interfering with normal operations.

This observer is designed to:
1. Collect metrics from the knowledge graph
2. Track state changes over time
3. Calculate derived metrics for threshold evaluation
"""

from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import deque
from enum import Enum, auto

from ..knowledge_graph.multidimensional_graph import MultidimensionalKnowledgeGraph
from ..knowledge_graph.graph_elements import EdgeType
from ..core.handshake_protocol import HandshakeProtocol, HandshakeState
from ..super_system.router import SuperSystemRouter


class MetricType(Enum):
    """Types of metrics the observer can collect."""
    
    # Graph metrics
    NODE_COUNT = auto()
    EDGE_COUNT = auto()
    DIMENSION_COUNT = auto()
    ACTION_SPACE_SIZE = auto()
    CONFLICT_EDGE_COUNT = auto()
    
    # Session metrics
    ACTIVE_SESSIONS = auto()
    COMPLETED_SESSIONS = auto()
    FAILED_SESSIONS = auto()
    REJECTED_SESSIONS = auto()
    
    # Performance metrics
    LAST_TRAVERSAL_TIME_MS = auto()
    AVG_TRAVERSAL_TIME_MS = auto()
    
    # Derived metrics
    REJECTION_RATE = auto()
    CONFLICT_RATIO = auto()
    SESSION_SUCCESS_RATE = auto()


@dataclass
class MetricSample:
    """A single metric sample with timestamp."""
    
    metric_type: MetricType
    value: float
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ObservationResult:
    """Result of a state observation cycle."""
    
    timestamp: datetime
    metrics: Dict[MetricType, float]
    derived_metrics: Dict[str, float]
    anomalies_detected: List[str]
    graph_snapshot: Optional[Dict[str, Any]] = None
    
    def to_threshold_metrics(self) -> Dict:
        """
        Convert observation result to threshold-compatible metrics.
        
        Maps MetricType to ThresholdType for threshold evaluation.
        """
        from .threshold_config import ThresholdType
        
        mapping = {
            "constraint_violation_count": ThresholdType.CONSTRAINT_VIOLATION_COUNT,
            "dimension_conflict_ratio": ThresholdType.DIMENSION_CONFLICT_RATIO,
            "action_rejection_rate": ThresholdType.ACTION_REJECTION_RATE,
            "context_drift": ThresholdType.CONTEXT_DRIFT_MAXIMUM,
            "ambiguity_score": ThresholdType.AMBIGUITY_SCORE_MAXIMUM,
            "traversal_latency_ms": ThresholdType.GRAPH_TRAVERSAL_LATENCY_MS,
        }
        
        result = {}
        for key, threshold_type in mapping.items():
            if key in self.derived_metrics:
                result[threshold_type] = self.derived_metrics[key]
        
        return result


class StateObserver:
    """
    Passive state observer for the Listener Agent.
    
    Collects metrics from the knowledge graph, handshake protocol,
    and router without interfering with their operation.
    
    This class implements the Observer pattern - it watches but does not act.
    The Listener Agent is responsible for deciding when to intervene.
    """
    
    # Maximum samples to retain in memory per metric
    MAX_SAMPLES_PER_METRIC = 1000
    
    def __init__(
        self,
        knowledge_graph: MultidimensionalKnowledgeGraph,
        protocol: HandshakeProtocol,
        router: SuperSystemRouter,
        sample_window_seconds: float = 60.0,
    ):
        """
        Initialize the state observer.
        
        Args:
            knowledge_graph: The graph to observe
            protocol: The handshake protocol to observe
            router: The super system router to observe
            sample_window_seconds: Window for calculating rolling metrics
        """
        self.knowledge_graph = knowledge_graph
        self.protocol = protocol
        self.router = router
        self.sample_window = timedelta(seconds=sample_window_seconds)
        
        # Sample storage - bounded deques for memory safety
        self._samples: Dict[MetricType, deque] = {
            metric_type: deque(maxlen=self.MAX_SAMPLES_PER_METRIC)
            for metric_type in MetricType
        }
        
        # Observation history
        self._observations: deque = deque(maxlen=1000)
        
        # Custom metric collectors
        self._custom_collectors: Dict[str, Callable[[], float]] = {}
        
        # Baseline metrics for anomaly detection
        self._baselines: Dict[MetricType, float] = {}
    
    def observe(self, context: Optional[Dict[str, Any]] = None) -> ObservationResult:
        """
        Perform a single observation cycle.
        
        Collects all metrics from the observed components and calculates
        derived metrics for threshold evaluation.
        
        Args:
            context: Optional context to include in observation
            
        Returns:
            ObservationResult with all collected metrics
        """
        timestamp = datetime.now()
        metrics = {}
        anomalies = []
        
        # Collect graph metrics
        metrics.update(self._collect_graph_metrics())
        
        # Collect session metrics
        metrics.update(self._collect_session_metrics())
        
        # Collect performance metrics
        metrics.update(self._collect_performance_metrics())
        
        # Store samples
        for metric_type, value in metrics.items():
            sample = MetricSample(metric_type=metric_type, value=value, timestamp=timestamp)
            self._samples[metric_type].append(sample)
        
        # Calculate derived metrics
        derived_metrics = self._calculate_derived_metrics(metrics, context)
        
        # Detect anomalies
        anomalies = self._detect_anomalies(metrics)
        
        # Create observation result
        result = ObservationResult(
            timestamp=timestamp,
            metrics={k: v for k, v in metrics.items()},
            derived_metrics=derived_metrics,
            anomalies_detected=anomalies,
            graph_snapshot=self._create_graph_snapshot() if context else None,
        )
        
        # Store observation
        self._observations.append(result)
        
        return result
    
    def _collect_graph_metrics(self) -> Dict[MetricType, float]:
        """Collect metrics from the knowledge graph."""
        metrics = {}
        
        # Count dimensions
        metrics[MetricType.DIMENSION_COUNT] = float(len(self.knowledge_graph.dimensions))
        
        # Count total nodes and edges across all subgraphs
        total_nodes = 0
        total_edges = 0
        conflict_edges = 0
        
        for dim_name, subgraph in self.knowledge_graph.subgraphs.items():
            total_nodes += len(subgraph.nodes)
            for edges in subgraph._adjacency_list.values():
                total_edges += len(edges)
                conflict_edges += sum(
                    1 for e in edges if e.edge_type == EdgeType.CONFLICTS_WITH
                )
        
        metrics[MetricType.NODE_COUNT] = float(total_nodes)
        metrics[MetricType.EDGE_COUNT] = float(total_edges)
        metrics[MetricType.CONFLICT_EDGE_COUNT] = float(conflict_edges)
        
        return metrics
    
    def _collect_session_metrics(self) -> Dict[MetricType, float]:
        """Collect metrics from the handshake protocol."""
        metrics = {}
        
        sessions = self.protocol.sessions
        
        active = sum(
            1 for s in sessions.values()
            if s.state in [HandshakeState.INITIATED, HandshakeState.NEGOTIATING,
                          HandshakeState.VALIDATED, HandshakeState.ACCEPTED,
                          HandshakeState.EXECUTING]
        )
        completed = sum(
            1 for s in sessions.values()
            if s.state == HandshakeState.COMPLETED
        )
        failed = sum(
            1 for s in sessions.values()
            if s.state == HandshakeState.FAILED
        )
        rejected = sum(
            1 for s in sessions.values()
            if s.state == HandshakeState.REJECTED
        )
        
        metrics[MetricType.ACTIVE_SESSIONS] = float(active)
        metrics[MetricType.COMPLETED_SESSIONS] = float(completed)
        metrics[MetricType.FAILED_SESSIONS] = float(failed)
        metrics[MetricType.REJECTED_SESSIONS] = float(rejected)
        
        return metrics
    
    def _collect_performance_metrics(self) -> Dict[MetricType, float]:
        """Collect performance-related metrics."""
        metrics = {}
        
        # Get routing statistics
        routing_stats = self.router.get_routing_statistics()
        
        # Use routing history for latency estimation
        # In production, this would integrate with actual timing measurements
        metrics[MetricType.LAST_TRAVERSAL_TIME_MS] = 0.0
        metrics[MetricType.AVG_TRAVERSAL_TIME_MS] = 0.0
        
        # Action space size from last routing
        if self.router.routing_history:
            last_routing = self.router.routing_history[-1]
            metrics[MetricType.ACTION_SPACE_SIZE] = float(
                len(last_routing.pruned_action_space)
            )
        else:
            metrics[MetricType.ACTION_SPACE_SIZE] = 0.0
        
        return metrics
    
    def _calculate_derived_metrics(
        self,
        metrics: Dict[MetricType, float],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, float]:
        """Calculate derived metrics from raw metrics."""
        derived = {}
        
        # Rejection rate
        total_sessions = (
            metrics.get(MetricType.COMPLETED_SESSIONS, 0) +
            metrics.get(MetricType.FAILED_SESSIONS, 0) +
            metrics.get(MetricType.REJECTED_SESSIONS, 0)
        )
        if total_sessions > 0:
            derived["action_rejection_rate"] = (
                metrics.get(MetricType.REJECTED_SESSIONS, 0) / total_sessions
            )
        else:
            derived["action_rejection_rate"] = 0.0
        
        # Conflict ratio
        total_edges = metrics.get(MetricType.EDGE_COUNT, 0)
        if total_edges > 0:
            derived["dimension_conflict_ratio"] = (
                metrics.get(MetricType.CONFLICT_EDGE_COUNT, 0) / total_edges
            )
        else:
            derived["dimension_conflict_ratio"] = 0.0
        
        # Session success rate
        if total_sessions > 0:
            derived["session_success_rate"] = (
                metrics.get(MetricType.COMPLETED_SESSIONS, 0) / total_sessions
            )
        else:
            derived["session_success_rate"] = 1.0
        
        # Constraint violation count (from recent history)
        derived["constraint_violation_count"] = self._count_recent_violations()
        
        # Placeholder for context-aware metrics
        # These would integrate with caas (context-as-a-service) in production
        derived["context_drift"] = 0.0
        derived["ambiguity_score"] = 0.0
        derived["traversal_latency_ms"] = metrics.get(MetricType.AVG_TRAVERSAL_TIME_MS, 0.0)
        
        return derived
    
    def _count_recent_violations(self) -> float:
        """Count constraint violations in the recent observation window."""
        cutoff = datetime.now() - self.sample_window
        
        # Count rejected sessions in window
        violations = 0
        for session in self.protocol.sessions.values():
            if session.state == HandshakeState.REJECTED:
                if session.updated_at >= cutoff:
                    violations += 1
        
        return float(violations)
    
    def _detect_anomalies(self, metrics: Dict[MetricType, float]) -> List[str]:
        """Detect anomalies based on baseline comparison."""
        anomalies = []
        
        for metric_type, value in metrics.items():
            if metric_type in self._baselines:
                baseline = self._baselines[metric_type]
                # Simple anomaly detection: >2x deviation from baseline
                if baseline > 0 and abs(value - baseline) / baseline > 2.0:
                    anomalies.append(
                        f"Anomaly in {metric_type.name}: "
                        f"current={value:.2f}, baseline={baseline:.2f}"
                    )
        
        return anomalies
    
    def _create_graph_snapshot(self) -> Dict[str, Any]:
        """Create a lightweight snapshot of graph state."""
        snapshot = {
            "dimensions": list(self.knowledge_graph.dimensions.keys()),
            "node_counts": {},
            "edge_counts": {},
        }
        
        for dim_name, subgraph in self.knowledge_graph.subgraphs.items():
            snapshot["node_counts"][dim_name] = len(subgraph._nodes)
            snapshot["edge_counts"][dim_name] = sum(
                len(edges) for edges in subgraph._adjacency_list.values()
            )
        
        return snapshot
    
    def set_baseline(self, metric_type: MetricType, value: float) -> None:
        """Set a baseline value for anomaly detection."""
        self._baselines[metric_type] = value
    
    def calibrate_baselines(self, num_samples: int = 10) -> None:
        """
        Calibrate baselines by averaging recent samples.
        
        Call this during a known-good operational period to establish
        baseline metrics for anomaly detection.
        """
        for metric_type, samples in self._samples.items():
            if len(samples) >= num_samples:
                recent = list(samples)[-num_samples:]
                avg_value = sum(s.value for s in recent) / len(recent)
                self._baselines[metric_type] = avg_value
    
    def register_custom_collector(
        self,
        name: str,
        collector: Callable[[], float]
    ) -> None:
        """
        Register a custom metric collector.
        
        Args:
            name: Unique name for the custom metric
            collector: Function that returns the metric value
        """
        self._custom_collectors[name] = collector
    
    def get_metric_history(
        self,
        metric_type: MetricType,
        window_seconds: Optional[float] = None
    ) -> List[MetricSample]:
        """
        Get historical samples for a metric.
        
        Args:
            metric_type: The metric to retrieve
            window_seconds: Optional time window (None = all samples)
            
        Returns:
            List of metric samples
        """
        samples = list(self._samples.get(metric_type, []))
        
        if window_seconds is not None:
            cutoff = datetime.now() - timedelta(seconds=window_seconds)
            samples = [s for s in samples if s.timestamp >= cutoff]
        
        return samples
    
    def get_observation_history(
        self,
        count: Optional[int] = None
    ) -> List[ObservationResult]:
        """Get recent observation results."""
        observations = list(self._observations)
        if count is not None:
            observations = observations[-count:]
        return observations
