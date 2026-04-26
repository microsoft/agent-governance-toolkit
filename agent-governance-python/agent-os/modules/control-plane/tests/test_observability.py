# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Unit tests for Observability features
"""

import unittest
import time
from src.agent_control_plane.observability import (
    PrometheusExporter,
    AlertManager,
    TraceCollector,
    ObservabilityDashboard,
    MetricType,
    AlertSeverity,
    create_observability_suite
)


class TestPrometheusExporter(unittest.TestCase):
    """Test Prometheus metrics exporter"""
    
    def setUp(self):
        self.exporter = PrometheusExporter()
    
    def test_increment_counter(self):
        """Test incrementing counter metric"""
        self.exporter.increment_counter(
            "test_counter",
            value=1.0,
            labels={"service": "test"}
        )
        
        metrics = self.exporter.get_metrics()
        self.assertIn("test_counter", metrics)
    
    def test_set_gauge(self):
        """Test setting gauge metric"""
        self.exporter.set_gauge(
            "test_gauge",
            value=42.0,
            labels={"service": "test"}
        )
        
        metrics = self.exporter.get_metrics()
        self.assertIn("test_gauge", metrics)
        self.assertEqual(metrics["test_gauge"][0].value, 42.0)
    
    def test_observe_histogram(self):
        """Test observing histogram metric"""
        self.exporter.observe_histogram(
            "test_histogram",
            value=0.5,
            labels={"service": "test"}
        )
        
        metrics = self.exporter.get_metrics()
        self.assertIn("test_histogram", metrics)
    
    def test_export_prometheus_format(self):
        """Test exporting in Prometheus text format"""
        self.exporter.increment_counter("requests_total", labels={"status": "success"})
        self.exporter.set_gauge("active_connections", value=10)
        
        export = self.exporter.export()
        
        self.assertIn("# HELP", export)
        self.assertIn("# TYPE", export)
        self.assertIn("requests_total", export)
        self.assertIn("active_connections", export)
    
    def test_counter_accumulates(self):
        """Test that counter accumulates values"""
        self.exporter.increment_counter("test", value=1.0)
        self.exporter.increment_counter("test", value=2.0)
        
        metrics = self.exporter.get_metrics()
        self.assertEqual(metrics["test"][0].value, 3.0)
    
    def test_gauge_replaces(self):
        """Test that gauge replaces value"""
        self.exporter.set_gauge("test", value=10.0)
        self.exporter.set_gauge("test", value=20.0)
        
        metrics = self.exporter.get_metrics()
        self.assertEqual(metrics["test"][0].value, 20.0)


class TestAlertManager(unittest.TestCase):
    """Test alert management"""
    
    def setUp(self):
        self.alert_mgr = AlertManager()
    
    def test_add_rule(self):
        """Test adding alert rule"""
        self.alert_mgr.add_rule(
            name="test_alert",
            condition=lambda m: m.get("value", 0) > 10,
            severity=AlertSeverity.WARNING,
            message="Value exceeds threshold"
        )
        
        self.assertIn("test_alert", self.alert_mgr._rules)
    
    def test_evaluate_firing_alert(self):
        """Test evaluating alert that should fire"""
        self.alert_mgr.add_rule(
            name="high_error_rate",
            condition=lambda m: m.get("error_rate", 0) > 0.05,
            severity=AlertSeverity.ERROR,
            message="Error rate too high"
        )
        
        metrics = {"error_rate": 0.1}
        alerts = self.alert_mgr.evaluate(metrics)
        
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].name, "high_error_rate")
        self.assertTrue(alerts[0].firing)
    
    def test_evaluate_non_firing_alert(self):
        """Test evaluating alert that should not fire"""
        self.alert_mgr.add_rule(
            name="high_error_rate",
            condition=lambda m: m.get("error_rate", 0) > 0.05,
            severity=AlertSeverity.ERROR,
            message="Error rate too high"
        )
        
        metrics = {"error_rate": 0.01}
        alerts = self.alert_mgr.evaluate(metrics)
        
        self.assertEqual(len(alerts), 0)
    
    def test_alert_resolution(self):
        """Test alert resolution when condition clears"""
        self.alert_mgr.add_rule(
            name="test_alert",
            condition=lambda m: m.get("value", 0) > 10,
            severity=AlertSeverity.WARNING,
            message="Test"
        )
        
        # Fire alert
        self.alert_mgr.evaluate({"value": 15})
        self.assertEqual(len(self.alert_mgr.get_active_alerts()), 1)
        
        # Clear alert
        self.alert_mgr.evaluate({"value": 5})
        self.assertEqual(len(self.alert_mgr.get_active_alerts()), 0)
    
    def test_get_alert_history(self):
        """Test getting alert history"""
        self.alert_mgr.add_rule(
            name="test",
            condition=lambda m: m.get("value", 0) > 10,
            severity=AlertSeverity.INFO,
            message="Test"
        )
        
        self.alert_mgr.evaluate({"value": 15})
        
        history = self.alert_mgr.get_alert_history(hours=24)
        self.assertGreater(len(history), 0)


class TestTraceCollector(unittest.TestCase):
    """Test distributed tracing"""
    
    def setUp(self):
        self.collector = TraceCollector()
    
    def test_start_trace(self):
        """Test starting a trace"""
        trace_id = self.collector.start_trace("test_operation")
        
        self.assertIsNotNone(trace_id)
        self.assertIn(trace_id, self.collector._traces)
    
    def test_start_span(self):
        """Test starting a span"""
        trace_id = self.collector.start_trace("test")
        span_id = self.collector.start_span(
            trace_id=trace_id,
            operation_name="sub_operation"
        )
        
        self.assertIsNotNone(span_id)
    
    def test_end_span(self):
        """Test ending a span"""
        trace_id = self.collector.start_trace("test")
        span_id = self.collector.start_span(
            trace_id=trace_id,
            operation_name="sub_op"
        )
        
        time.sleep(0.01)  # Small delay
        self.collector.end_span(trace_id, span_id)
        
        trace = self.collector.get_trace(trace_id)
        self.assertGreater(len(trace.spans), 0)
        self.assertIsNotNone(trace.spans[0].duration_ms)
    
    def test_nested_spans(self):
        """Test nested span relationships"""
        trace_id = self.collector.start_trace("test")
        parent_span = self.collector.start_span(
            trace_id=trace_id,
            operation_name="parent"
        )
        child_span = self.collector.start_span(
            trace_id=trace_id,
            operation_name="child",
            parent_span_id=parent_span
        )
        
        self.collector.end_span(trace_id, child_span)
        self.collector.end_span(trace_id, parent_span)
        
        trace = self.collector.get_trace(trace_id)
        # Should have parent and child spans
        self.assertGreaterEqual(len(trace.spans), 2)
    
    def test_end_trace(self):
        """Test ending a trace"""
        trace_id = self.collector.start_trace("test")
        time.sleep(0.01)
        self.collector.end_trace(trace_id)
        
        trace = self.collector.get_trace(trace_id)
        self.assertIsNotNone(trace.duration_ms)
    
    def test_list_traces(self):
        """Test listing traces"""
        trace1 = self.collector.start_trace("op1")
        trace2 = self.collector.start_trace("op2")
        
        traces = self.collector.list_traces(limit=10)
        self.assertGreaterEqual(len(traces), 2)
    
    def test_trace_visualization(self):
        """Test getting trace visualization data"""
        trace_id = self.collector.start_trace("test")
        self.collector.end_trace(trace_id)
        
        viz = self.collector.get_trace_visualization(trace_id)
        
        self.assertIn("trace_id", viz)
        self.assertIn("span_tree", viz)
        self.assertIn("duration_ms", viz)


class TestObservabilityDashboard(unittest.TestCase):
    """Test observability dashboard"""
    
    def setUp(self):
        self.prometheus = PrometheusExporter()
        self.alerts = AlertManager()
        self.traces = TraceCollector()
        self.dashboard = ObservabilityDashboard(
            self.prometheus,
            self.alerts,
            self.traces
        )
    
    def test_get_dashboard_data(self):
        """Test getting dashboard data"""
        # Add some data
        self.prometheus.increment_counter("test", value=1)
        self.traces.start_trace("test_op")
        
        data = self.dashboard.get_dashboard_data()
        
        self.assertIn("metrics", data)
        self.assertIn("alerts", data)
        self.assertIn("traces", data)
        self.assertIn("timestamp", data)
    
    def test_get_health_status_healthy(self):
        """Test health status when system is healthy"""
        health = self.dashboard.get_health_status()
        
        self.assertEqual(health["status"], "healthy")
        self.assertEqual(health["active_alerts"], 0)
    
    def test_get_health_status_degraded(self):
        """Test health status when system is degraded"""
        # Add error alert
        self.alerts.add_rule(
            name="error",
            condition=lambda m: True,
            severity=AlertSeverity.ERROR,
            message="Error"
        )
        self.alerts.evaluate({})
        
        health = self.dashboard.get_health_status()
        
        self.assertEqual(health["status"], "degraded")
        self.assertGreater(health["error_alerts"], 0)
    
    def test_get_health_status_critical(self):
        """Test health status when system is critical"""
        # Add critical alert
        self.alerts.add_rule(
            name="critical",
            condition=lambda m: True,
            severity=AlertSeverity.CRITICAL,
            message="Critical"
        )
        self.alerts.evaluate({})
        
        health = self.dashboard.get_health_status()
        
        self.assertEqual(health["status"], "critical")
        self.assertGreater(health["critical_alerts"], 0)


class TestObservabilitySuite(unittest.TestCase):
    """Test observability suite creation"""
    
    def test_create_suite(self):
        """Test creating complete observability suite"""
        suite = create_observability_suite()
        
        self.assertIn("prometheus", suite)
        self.assertIn("alerts", suite)
        self.assertIn("traces", suite)
        self.assertIn("dashboard", suite)
        
        self.assertIsInstance(suite["prometheus"], PrometheusExporter)
        self.assertIsInstance(suite["alerts"], AlertManager)
        self.assertIsInstance(suite["traces"], TraceCollector)
        self.assertIsInstance(suite["dashboard"], ObservabilityDashboard)


if __name__ == '__main__':
    unittest.main()
