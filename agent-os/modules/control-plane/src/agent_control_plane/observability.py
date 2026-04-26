# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Observability and Metrics - Real-time Monitoring and Prometheus Integration

This module provides production-grade observability features including real-time
metrics, Prometheus integration, trace visualization, and monitoring dashboards.

Research Foundations:
    - Prometheus monitoring best practices
    - OpenTelemetry for distributed tracing
    - "Observability Engineering" (O'Reilly, 2022) - metrics, logs, traces
    - SRE principles from Google SRE Book

See docs/RESEARCH_FOUNDATION.md for complete references.
"""

from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from collections import defaultdict, deque
import time


class MetricType(Enum):
    """Types of metrics"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class Metric:
    """
    A metric measurement.
    
    Attributes:
        name: Metric name
        metric_type: Type of metric
        value: Current value
        labels: Key-value labels
        timestamp: When measured
        help_text: Description of metric
    """
    name: str
    metric_type: MetricType
    value: float
    labels: Dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    help_text: str = ""


@dataclass
class Alert:
    """
    An alert notification.
    
    Attributes:
        alert_id: Unique identifier
        name: Alert name
        severity: Severity level
        message: Alert message
        labels: Context labels
        firing: Whether alert is currently firing
        started_at: When alert started firing
    """
    alert_id: str
    name: str
    severity: AlertSeverity
    message: str
    labels: Dict[str, str] = field(default_factory=dict)
    firing: bool = True
    started_at: datetime = field(default_factory=datetime.now)
    resolved_at: Optional[datetime] = None


@dataclass
class Trace:
    """
    A distributed trace for a request/operation.
    
    Attributes:
        trace_id: Unique trace identifier
        spans: List of spans in this trace
        started_at: Trace start time
        duration_ms: Total duration
        metadata: Additional trace metadata
    """
    trace_id: str
    spans: List['Span'] = field(default_factory=list)
    started_at: datetime = field(default_factory=datetime.now)
    duration_ms: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Span:
    """
    A span within a trace.
    
    Attributes:
        span_id: Unique span identifier
        parent_span_id: Parent span if nested
        operation_name: Name of operation
        started_at: Span start time
        duration_ms: Span duration
        tags: Span tags
        logs: Span logs
    """
    span_id: str
    parent_span_id: Optional[str]
    operation_name: str
    started_at: datetime = field(default_factory=datetime.now)
    duration_ms: Optional[float] = None
    tags: Dict[str, Any] = field(default_factory=dict)
    logs: List[Dict[str, Any]] = field(default_factory=list)


class PrometheusExporter:
    """
    Prometheus metrics exporter.
    
    Exports metrics in Prometheus text format for scraping.
    
    Features:
    - Counter, gauge, histogram, summary metrics
    - Multi-dimensional labels
    - Automatic metric registration
    - Text format export for Prometheus scraping
    
    Usage:
        exporter = PrometheusExporter()
        
        # Record metrics
        exporter.increment_counter(
            "agent_requests_total",
            labels={"agent_id": "agent1", "status": "success"}
        )
        
        exporter.set_gauge(
            "agent_active_sessions",
            value=5,
            labels={"agent_id": "agent1"}
        )
        
        # Export for Prometheus
        metrics_text = exporter.export()
    """
    
    def __init__(self):
        self._metrics: Dict[str, Dict[str, Metric]] = defaultdict(dict)
        self._metric_metadata: Dict[str, Dict[str, Any]] = {}
        
    def increment_counter(
        self,
        name: str,
        value: float = 1.0,
        labels: Optional[Dict[str, str]] = None,
        help_text: str = ""
    ):
        """
        Increment a counter metric.
        
        Args:
            name: Metric name
            value: Amount to increment
            labels: Metric labels
            help_text: Help text for metric
        """
        labels = labels or {}
        label_key = self._make_label_key(labels)
        
        if name not in self._metric_metadata:
            self._metric_metadata[name] = {
                "type": MetricType.COUNTER,
                "help": help_text or f"Counter metric {name}"
            }
        
        if label_key in self._metrics[name]:
            self._metrics[name][label_key].value += value
            self._metrics[name][label_key].timestamp = datetime.now()
        else:
            self._metrics[name][label_key] = Metric(
                name=name,
                metric_type=MetricType.COUNTER,
                value=value,
                labels=labels,
                help_text=help_text
            )
    
    def set_gauge(
        self,
        name: str,
        value: float,
        labels: Optional[Dict[str, str]] = None,
        help_text: str = ""
    ):
        """
        Set a gauge metric.
        
        Args:
            name: Metric name
            value: Value to set
            labels: Metric labels
            help_text: Help text
        """
        labels = labels or {}
        label_key = self._make_label_key(labels)
        
        if name not in self._metric_metadata:
            self._metric_metadata[name] = {
                "type": MetricType.GAUGE,
                "help": help_text or f"Gauge metric {name}"
            }
        
        self._metrics[name][label_key] = Metric(
            name=name,
            metric_type=MetricType.GAUGE,
            value=value,
            labels=labels,
            help_text=help_text
        )
    
    def observe_histogram(
        self,
        name: str,
        value: float,
        labels: Optional[Dict[str, str]] = None,
        help_text: str = ""
    ):
        """
        Observe a histogram metric.
        
        Args:
            name: Metric name
            value: Observed value
            labels: Metric labels
            help_text: Help text
        """
        # Simplified histogram - in production would have buckets
        labels = labels or {}
        label_key = self._make_label_key(labels)
        
        if name not in self._metric_metadata:
            self._metric_metadata[name] = {
                "type": MetricType.HISTOGRAM,
                "help": help_text or f"Histogram metric {name}"
            }
        
        # Store as gauge for simplification
        self._metrics[name][label_key] = Metric(
            name=name,
            metric_type=MetricType.HISTOGRAM,
            value=value,
            labels=labels,
            help_text=help_text
        )
    
    def export(self) -> str:
        """
        Export metrics in Prometheus text format.
        
        Returns:
            Prometheus-formatted metrics text
        """
        lines = []
        
        for metric_name, metadata in self._metric_metadata.items():
            # HELP line
            lines.append(f"# HELP {metric_name} {metadata['help']}")
            
            # TYPE line
            lines.append(f"# TYPE {metric_name} {metadata['type'].value}")
            
            # Metric lines
            for label_key, metric in self._metrics[metric_name].items():
                if metric.labels:
                    label_str = ",".join(
                        f'{k}="{v}"' for k, v in metric.labels.items()
                    )
                    lines.append(f"{metric_name}{{{label_str}}} {metric.value}")
                else:
                    lines.append(f"{metric_name} {metric.value}")
            
            lines.append("")  # Blank line between metrics
        
        return "\n".join(lines)
    
    def get_metrics(self) -> Dict[str, List[Metric]]:
        """Get all metrics"""
        return {
            name: list(metrics.values())
            for name, metrics in self._metrics.items()
        }
    
    def _make_label_key(self, labels: Dict[str, str]) -> str:
        """Create unique key from labels"""
        if not labels:
            return "default"
        return ",".join(f"{k}={v}" for k, v in sorted(labels.items()))


class AlertManager:
    """
    Alert management system.
    
    Features:
    - Rule-based alerting
    - Threshold monitoring
    - Alert aggregation and deduplication
    - Alert routing and notifications
    
    Usage:
        alert_mgr = AlertManager()
        
        # Define alert rule
        alert_mgr.add_rule(
            name="high_error_rate",
            condition=lambda metrics: metrics.get("error_rate", 0) > 0.05,
            severity=AlertSeverity.ERROR,
            message="Error rate exceeds 5%"
        )
        
        # Check alerts
        alerts = alert_mgr.evaluate(current_metrics)
    """
    
    def __init__(self):
        self._rules: Dict[str, Dict[str, Any]] = {}
        self._active_alerts: Dict[str, Alert] = {}
        self._alert_history: List[Alert] = []
    
    def add_rule(
        self,
        name: str,
        condition: Callable[[Dict[str, Any]], bool],
        severity: AlertSeverity,
        message: str,
        labels: Optional[Dict[str, str]] = None
    ):
        """
        Add an alerting rule.
        
        Args:
            name: Rule name
            condition: Function that evaluates alert condition
            severity: Alert severity
            message: Alert message
            labels: Additional labels
        """
        self._rules[name] = {
            "condition": condition,
            "severity": severity,
            "message": message,
            "labels": labels or {}
        }
    
    def evaluate(
        self,
        metrics: Dict[str, Any]
    ) -> List[Alert]:
        """
        Evaluate alert rules against current metrics.
        
        Args:
            metrics: Current metrics to evaluate
            
        Returns:
            List of firing alerts
        """
        current_firing = set()
        
        for rule_name, rule in self._rules.items():
            try:
                should_fire = rule["condition"](metrics)
                
                if should_fire:
                    current_firing.add(rule_name)
                    
                    if rule_name not in self._active_alerts:
                        # New alert
                        alert = Alert(
                            alert_id=f"{rule_name}-{int(time.time())}",
                            name=rule_name,
                            severity=rule["severity"],
                            message=rule["message"],
                            labels=rule["labels"]
                        )
                        self._active_alerts[rule_name] = alert
                        self._alert_history.append(alert)
                else:
                    # Alert should resolve
                    if rule_name in self._active_alerts:
                        alert = self._active_alerts[rule_name]
                        alert.firing = False
                        alert.resolved_at = datetime.now()
                        del self._active_alerts[rule_name]
                        
            except Exception as e:
                # Log error but don't fail alerting
                pass
        
        return list(self._active_alerts.values())
    
    def get_active_alerts(self) -> List[Alert]:
        """Get currently firing alerts"""
        return list(self._active_alerts.values())
    
    def get_alert_history(
        self,
        hours: int = 24
    ) -> List[Alert]:
        """Get alert history"""
        cutoff = datetime.now() - timedelta(hours=hours)
        return [
            alert for alert in self._alert_history
            if alert.started_at > cutoff
        ]


class TraceCollector:
    """
    Distributed tracing collector.
    
    Features:
    - Trace and span collection
    - Parent-child span relationships
    - Trace visualization data
    - Performance analysis
    
    Usage:
        collector = TraceCollector()
        
        # Start trace
        trace_id = collector.start_trace("agent_request")
        
        # Add spans
        span_id = collector.start_span(
            trace_id=trace_id,
            operation_name="policy_check"
        )
        
        # End span
        collector.end_span(trace_id, span_id)
        
        # Get trace
        trace = collector.get_trace(trace_id)
    """
    
    def __init__(self):
        self._traces: Dict[str, Trace] = {}
        self._active_spans: Dict[str, Dict[str, Span]] = defaultdict(dict)
    
    def start_trace(
        self,
        operation_name: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Start a new trace.
        
        Args:
            operation_name: Name of the operation
            metadata: Additional metadata
            
        Returns:
            trace_id
        """
        import uuid
        trace_id = str(uuid.uuid4())
        
        trace = Trace(
            trace_id=trace_id,
            metadata=metadata or {}
        )
        
        self._traces[trace_id] = trace
        
        # Create root span
        self.start_span(
            trace_id=trace_id,
            operation_name=operation_name
        )
        
        return trace_id
    
    def start_span(
        self,
        trace_id: str,
        operation_name: str,
        parent_span_id: Optional[str] = None,
        tags: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Start a new span within a trace.
        
        Args:
            trace_id: Trace ID
            operation_name: Operation name
            parent_span_id: Parent span ID if nested
            tags: Span tags
            
        Returns:
            span_id
        """
        import uuid
        span_id = str(uuid.uuid4())
        
        span = Span(
            span_id=span_id,
            parent_span_id=parent_span_id,
            operation_name=operation_name,
            tags=tags or {}
        )
        
        self._active_spans[trace_id][span_id] = span
        
        return span_id
    
    def end_span(
        self,
        trace_id: str,
        span_id: str,
        tags: Optional[Dict[str, Any]] = None
    ):
        """
        End a span.
        
        Args:
            trace_id: Trace ID
            span_id: Span ID
            tags: Additional tags to add
        """
        if trace_id not in self._active_spans:
            return
        
        if span_id not in self._active_spans[trace_id]:
            return
        
        span = self._active_spans[trace_id][span_id]
        duration = (datetime.now() - span.started_at).total_seconds() * 1000
        span.duration_ms = duration
        
        if tags:
            span.tags.update(tags)
        
        # Move to trace
        if trace_id in self._traces:
            self._traces[trace_id].spans.append(span)
        
        # Remove from active
        del self._active_spans[trace_id][span_id]
    
    def end_trace(self, trace_id: str):
        """End a trace"""
        if trace_id not in self._traces:
            return
        
        trace = self._traces[trace_id]
        duration = (datetime.now() - trace.started_at).total_seconds() * 1000
        trace.duration_ms = duration
        
        # End any remaining active spans
        if trace_id in self._active_spans:
            for span_id in list(self._active_spans[trace_id].keys()):
                self.end_span(trace_id, span_id)
    
    def get_trace(self, trace_id: str) -> Optional[Trace]:
        """Get a trace by ID"""
        return self._traces.get(trace_id)
    
    def list_traces(
        self,
        limit: int = 100
    ) -> List[Trace]:
        """List recent traces"""
        traces = sorted(
            self._traces.values(),
            key=lambda t: t.started_at,
            reverse=True
        )
        return traces[:limit]
    
    def get_trace_visualization(
        self,
        trace_id: str
    ) -> Dict[str, Any]:
        """
        Get trace data formatted for visualization.
        
        Args:
            trace_id: Trace ID
            
        Returns:
            Visualization data with spans in hierarchical format
        """
        trace = self.get_trace(trace_id)
        if not trace:
            return {}
        
        # Build span hierarchy
        span_tree = self._build_span_tree(trace.spans)
        
        return {
            "trace_id": trace_id,
            "duration_ms": trace.duration_ms,
            "started_at": trace.started_at.isoformat(),
            "span_count": len(trace.spans),
            "span_tree": span_tree,
            "metadata": trace.metadata
        }
    
    def _build_span_tree(
        self,
        spans: List[Span]
    ) -> List[Dict[str, Any]]:
        """Build hierarchical span tree"""
        # Group spans by parent
        by_parent = defaultdict(list)
        for span in spans:
            by_parent[span.parent_span_id].append(span)
        
        # Build tree starting from root (parent_span_id = None)
        def build_node(span: Span) -> Dict[str, Any]:
            children = by_parent.get(span.span_id, [])
            return {
                "span_id": span.span_id,
                "operation_name": span.operation_name,
                "duration_ms": span.duration_ms,
                "tags": span.tags,
                "children": [build_node(child) for child in children]
            }
        
        return [build_node(span) for span in by_parent[None]]


class ObservabilityDashboard:
    """
    Central observability dashboard aggregating metrics, alerts, and traces.
    
    Features:
    - Real-time metrics display
    - Active alert monitoring
    - Trace visualization
    - System health overview
    
    Usage:
        dashboard = ObservabilityDashboard(
            prometheus=prometheus_exporter,
            alerts=alert_manager,
            traces=trace_collector
        )
        
        # Get dashboard data
        data = dashboard.get_dashboard_data()
    """
    
    def __init__(
        self,
        prometheus: PrometheusExporter,
        alerts: AlertManager,
        traces: TraceCollector
    ):
        self.prometheus = prometheus
        self.alerts = alerts
        self.traces = traces
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """
        Get comprehensive dashboard data.
        
        Returns:
            Dashboard data with metrics, alerts, traces
        """
        # Get key metrics
        metrics = self.prometheus.get_metrics()
        
        # Get active alerts
        active_alerts = self.alerts.get_active_alerts()
        
        # Get recent traces
        recent_traces = self.traces.list_traces(limit=10)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "metrics": {
                name: [
                    {
                        "value": m.value,
                        "labels": m.labels,
                        "timestamp": m.timestamp.isoformat()
                    }
                    for m in metric_list
                ]
                for name, metric_list in metrics.items()
            },
            "alerts": {
                "active_count": len(active_alerts),
                "alerts": [
                    {
                        "name": alert.name,
                        "severity": alert.severity.value,
                        "message": alert.message,
                        "started_at": alert.started_at.isoformat()
                    }
                    for alert in active_alerts
                ]
            },
            "traces": {
                "recent_count": len(recent_traces),
                "traces": [
                    {
                        "trace_id": trace.trace_id,
                        "duration_ms": trace.duration_ms,
                        "span_count": len(trace.spans),
                        "started_at": trace.started_at.isoformat()
                    }
                    for trace in recent_traces
                ]
            }
        }
    
    def get_health_status(self) -> Dict[str, Any]:
        """
        Get overall system health status.
        
        Returns:
            Health status with overall assessment
        """
        active_alerts = self.alerts.get_active_alerts()
        
        # Determine health based on alerts
        critical_count = sum(
            1 for a in active_alerts
            if a.severity == AlertSeverity.CRITICAL
        )
        error_count = sum(
            1 for a in active_alerts
            if a.severity == AlertSeverity.ERROR
        )
        
        if critical_count > 0:
            status = "critical"
        elif error_count > 0:
            status = "degraded"
        elif len(active_alerts) > 0:
            status = "warning"
        else:
            status = "healthy"
        
        return {
            "status": status,
            "active_alerts": len(active_alerts),
            "critical_alerts": critical_count,
            "error_alerts": error_count,
            "checked_at": datetime.now().isoformat()
        }


def create_observability_suite() -> Dict[str, Any]:
    """
    Create a complete observability suite.
    
    Returns:
        Dictionary with all observability components
    """
    prometheus = PrometheusExporter()
    alert_manager = AlertManager()
    trace_collector = TraceCollector()
    dashboard = ObservabilityDashboard(prometheus, alert_manager, trace_collector)
    
    return {
        "prometheus": prometheus,
        "alerts": alert_manager,
        "traces": trace_collector,
        "dashboard": dashboard
    }
