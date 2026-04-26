# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Observability and Monitoring Examples

This demonstrates production observability with Prometheus metrics,
alerting, distributed tracing, and dashboards.
"""

from agent_control_plane import (
    PrometheusExporter,
    AlertManager,
    TraceCollector,
    ObservabilityDashboard,
    MetricType,
    AlertSeverity,
    create_observability_suite
)
import time


def example_prometheus_metrics():
    """Example: Exporting Prometheus metrics"""
    print("=== Prometheus Metrics Example ===\n")
    
    exporter = PrometheusExporter()
    
    # Record various metrics
    exporter.increment_counter(
        "agent_requests_total",
        value=1,
        labels={"agent_id": "agent1", "status": "success"},
        help_text="Total number of agent requests"
    )
    
    exporter.increment_counter(
        "agent_requests_total",
        value=1,
        labels={"agent_id": "agent1", "status": "blocked"}
    )
    
    exporter.set_gauge(
        "agent_active_sessions",
        value=5,
        labels={"agent_id": "agent1"},
        help_text="Number of active agent sessions"
    )
    
    exporter.observe_histogram(
        "agent_request_duration_seconds",
        value=0.245,
        labels={"agent_id": "agent1"},
        help_text="Agent request duration"
    )
    
    # Export in Prometheus format
    print("Prometheus Metrics Export:")
    print("-" * 50)
    print(exporter.export())
    print("-" * 50)
    print()


def example_alerting():
    """Example: Rule-based alerting"""
    print("=== Alerting Example ===\n")
    
    alert_mgr = AlertManager()
    
    # Define alert rules
    alert_mgr.add_rule(
        name="high_error_rate",
        condition=lambda m: m.get("error_rate", 0) > 0.05,
        severity=AlertSeverity.ERROR,
        message="Error rate exceeds 5%",
        labels={"team": "platform"}
    )
    
    alert_mgr.add_rule(
        name="high_latency",
        condition=lambda m: m.get("avg_latency_ms", 0) > 1000,
        severity=AlertSeverity.WARNING,
        message="Average latency exceeds 1000ms"
    )
    
    alert_mgr.add_rule(
        name="system_overload",
        condition=lambda m: m.get("cpu_usage", 0) > 0.9,
        severity=AlertSeverity.CRITICAL,
        message="CPU usage above 90%"
    )
    
    # Simulate metrics
    test_scenarios = [
        {"name": "Normal", "error_rate": 0.02, "avg_latency_ms": 500, "cpu_usage": 0.6},
        {"name": "High Errors", "error_rate": 0.10, "avg_latency_ms": 600, "cpu_usage": 0.65},
        {"name": "Critical", "error_rate": 0.15, "avg_latency_ms": 1500, "cpu_usage": 0.95}
    ]
    
    for scenario in test_scenarios:
        print(f"Scenario: {scenario['name']}")
        print(f"  Metrics: error_rate={scenario['error_rate']:.2f}, "
              f"latency={scenario['avg_latency_ms']}ms, cpu={scenario['cpu_usage']:.2f}")
        
        alerts = alert_mgr.evaluate(scenario)
        
        if alerts:
            print(f"  🚨 {len(alerts)} alert(s) firing:")
            for alert in alerts:
                severity_icon = {
                    AlertSeverity.INFO: "ℹ️",
                    AlertSeverity.WARNING: "⚠️",
                    AlertSeverity.ERROR: "❌",
                    AlertSeverity.CRITICAL: "🔥"
                }
                print(f"     {severity_icon[alert.severity]} [{alert.severity.value}] {alert.message}")
        else:
            print(f"  ✅ No alerts")
        print()


def example_distributed_tracing():
    """Example: Distributed tracing"""
    print("=== Distributed Tracing Example ===\n")
    
    collector = TraceCollector()
    
    # Start a trace for a request
    trace_id = collector.start_trace(
        "agent_request",
        metadata={"user_id": "user123", "request_type": "tool_execution"}
    )
    
    print(f"Started trace: {trace_id}")
    
    # Simulate nested operations
    policy_span = collector.start_span(
        trace_id=trace_id,
        operation_name="policy_check",
        tags={"policy": "rate_limit"}
    )
    time.sleep(0.01)
    collector.end_span(trace_id, policy_span, tags={"result": "allowed"})
    
    execution_span = collector.start_span(
        trace_id=trace_id,
        operation_name="tool_execution",
        tags={"tool": "read_file"}
    )
    
    # Nested span
    validation_span = collector.start_span(
        trace_id=trace_id,
        operation_name="validate_input",
        parent_span_id=execution_span,
        tags={"validation_type": "schema"}
    )
    time.sleep(0.005)
    collector.end_span(trace_id, validation_span)
    
    time.sleep(0.015)
    collector.end_span(trace_id, execution_span, tags={"status": "success"})
    
    # End trace
    collector.end_trace(trace_id)
    
    # Get trace details
    trace = collector.get_trace(trace_id)
    print(f"\nTrace Details:")
    print(f"  Duration: {trace.duration_ms:.2f}ms")
    print(f"  Spans: {len(trace.spans)}")
    for span in trace.spans:
        indent = "    " if span.parent_span_id else "  "
        print(f"{indent}- {span.operation_name}: {span.duration_ms:.2f}ms")
    print()
    
    # Get visualization data
    viz = collector.get_trace_visualization(trace_id)
    print("Trace Visualization Data:")
    print(f"  Span tree depth: {len(viz['span_tree'])}")
    print()


def example_observability_dashboard():
    """Example: Observability dashboard"""
    print("=== Observability Dashboard Example ===\n")
    
    # Create components
    prometheus = PrometheusExporter()
    alert_mgr = AlertManager()
    trace_collector = TraceCollector()
    dashboard = ObservabilityDashboard(prometheus, alert_mgr, trace_collector)
    
    # Add some data
    prometheus.increment_counter("requests", value=100)
    prometheus.set_gauge("active_users", value=42)
    
    alert_mgr.add_rule(
        "test_alert",
        lambda m: False,
        AlertSeverity.INFO,
        "Test"
    )
    
    trace_collector.start_trace("sample_operation")
    
    # Get dashboard data
    data = dashboard.get_dashboard_data()
    
    print("Dashboard Overview:")
    print(f"  Timestamp: {data['timestamp']}")
    print(f"  Metrics: {len(data['metrics'])} metric types")
    print(f"  Active Alerts: {data['alerts']['active_count']}")
    print(f"  Recent Traces: {data['traces']['recent_count']}")
    print()
    
    # Get health status
    health = dashboard.get_health_status()
    
    status_icon = {
        "healthy": "🟢",
        "warning": "🟡",
        "degraded": "🟠",
        "critical": "🔴"
    }
    
    print(f"System Health: {status_icon.get(health['status'], '⚪')} {health['status']}")
    print(f"  Active Alerts: {health['active_alerts']}")
    print(f"  Critical: {health['critical_alerts']}")
    print(f"  Errors: {health['error_alerts']}")
    print()


def example_monitoring_workflow():
    """Example: Complete monitoring workflow"""
    print("=== Complete Monitoring Workflow ===\n")
    
    suite = create_observability_suite()
    
    prometheus = suite["prometheus"]
    alerts = suite["alerts"]
    traces = suite["traces"]
    dashboard = suite["dashboard"]
    
    print("Simulating agent request workflow...\n")
    
    # Start trace
    trace_id = traces.start_trace("agent_request")
    
    # Increment request counter
    prometheus.increment_counter(
        "agent_requests_total",
        labels={"status": "processing"}
    )
    
    # Update active sessions
    prometheus.set_gauge("agent_active_sessions", value=3)
    
    # Simulate processing
    span1 = traces.start_span(trace_id, "authentication")
    time.sleep(0.005)
    traces.end_span(trace_id, span1)
    
    span2 = traces.start_span(trace_id, "policy_check")
    time.sleep(0.008)
    traces.end_span(trace_id, span2)
    
    span3 = traces.start_span(trace_id, "execution")
    time.sleep(0.012)
    traces.end_span(trace_id, span3)
    
    # End trace
    traces.end_trace(trace_id)
    
    # Record duration
    trace = traces.get_trace(trace_id)
    prometheus.observe_histogram(
        "agent_request_duration_ms",
        value=trace.duration_ms
    )
    
    # Update counter
    prometheus.increment_counter(
        "agent_requests_total",
        labels={"status": "success"}
    )
    
    # Check alerts
    current_metrics = {
        "error_rate": 0.01,
        "avg_latency_ms": trace.duration_ms
    }
    
    alerts.add_rule(
        "high_latency",
        lambda m: m.get("avg_latency_ms", 0) > 50,
        AlertSeverity.WARNING,
        "High latency detected"
    )
    
    firing_alerts = alerts.evaluate(current_metrics)
    
    # Display results
    print("Workflow Results:")
    print(f"  ✅ Request processed")
    print(f"  ⏱️  Duration: {trace.duration_ms:.2f}ms")
    print(f"  📊 Metrics recorded: 3")
    print(f"  🔍 Spans traced: {len(trace.spans)}")
    print(f"  🚨 Alerts: {len(firing_alerts)}")
    
    if firing_alerts:
        for alert in firing_alerts:
            print(f"     - {alert.message}")
    
    print()
    
    # Get dashboard summary
    health = dashboard.get_health_status()
    print(f"System Health: {health['status']}")
    print()


def example_metrics_export_endpoint():
    """Example: Metrics export endpoint (for Prometheus scraping)"""
    print("=== Metrics Export Endpoint ===\n")
    
    exporter = PrometheusExporter()
    
    # Simulate real metrics
    exporter.increment_counter("http_requests_total", value=1250, 
                              labels={"method": "POST", "endpoint": "/api/agent"})
    exporter.increment_counter("http_requests_total", value=3200,
                              labels={"method": "GET", "endpoint": "/api/agent"})
    
    exporter.set_gauge("http_requests_in_flight", value=12)
    exporter.observe_histogram("http_request_duration_seconds", value=0.123)
    
    print("Metrics endpoint output (for Prometheus scraping):")
    print("=" * 60)
    export = exporter.export()
    print(export)
    print("=" * 60)
    print()
    print("Configuration for Prometheus:")
    print("  scrape_configs:")
    print("    - job_name: 'agent-control-plane'")
    print("      static_configs:")
    print("        - targets: ['localhost:9090']")
    print()


if __name__ == "__main__":
    print("Agent Control Plane - Observability & Monitoring Examples")
    print("=" * 70)
    print()
    
    example_prometheus_metrics()
    print("\n" + "=" * 70 + "\n")
    
    example_alerting()
    print("\n" + "=" * 70 + "\n")
    
    example_distributed_tracing()
    print("\n" + "=" * 70 + "\n")
    
    example_observability_dashboard()
    print("\n" + "=" * 70 + "\n")
    
    example_monitoring_workflow()
    print("\n" + "=" * 70 + "\n")
    
    example_metrics_export_endpoint()
