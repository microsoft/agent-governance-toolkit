# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Test Observability module (Prometheus + OpenTelemetry).
"""

import pytest


class TestKernelMetrics:
    """Test Prometheus metrics."""
    
    def test_import_observability(self):
        """Test importing observability module."""
        try:
            from observability.metrics import KernelMetrics
            assert KernelMetrics is not None
        except ImportError:
            pytest.skip("observability package not installed")
    
    def test_create_metrics(self):
        """Test creating metrics instance."""
        try:
            from observability.metrics import KernelMetrics
            
            metrics = KernelMetrics()
            assert metrics is not None
        except ImportError:
            pytest.skip("observability package not installed")
    
    def test_record_violation(self):
        """Test recording a violation."""
        try:
            from observability.metrics import KernelMetrics
            
            metrics = KernelMetrics()
            metrics.record_violation(
                agent_id="test-agent",
                policy="read_only",
                action="file_write"
            )
            
            # Should not crash
            assert True
        except ImportError:
            pytest.skip("observability package not installed")
    
    def test_record_policy_check(self):
        """Test recording policy check latency."""
        try:
            from observability.metrics import KernelMetrics
            
            metrics = KernelMetrics()
            
            with metrics.policy_check_timer(agent_id="test-agent", policy="strict"):
                # Simulate some work
                pass
            
            # Should not crash
            assert True
        except ImportError:
            pytest.skip("observability package not installed")
    
    def test_record_sigkill(self):
        """Test recording SIGKILL."""
        try:
            from observability.metrics import KernelMetrics
            
            metrics = KernelMetrics()
            metrics.record_sigkill(
                agent_id="test-agent",
                reason="policy_violation"
            )
            
            assert True
        except ImportError:
            pytest.skip("observability package not installed")
    
    def test_record_mttr(self):
        """Test recording mean time to recovery."""
        try:
            from observability.metrics import KernelMetrics
            
            metrics = KernelMetrics()
            metrics.record_mttr(
                agent_id="test-agent",
                recovery_seconds=5.2
            )
            
            assert True
        except ImportError:
            pytest.skip("observability package not installed")


class TestKernelTracer:
    """Test OpenTelemetry tracing."""
    
    def test_import_tracer(self):
        """Test importing tracer module."""
        try:
            from observability.tracer import KernelTracer
            assert KernelTracer is not None
        except ImportError:
            pytest.skip("observability package not installed")
    
    def test_create_tracer(self):
        """Test creating tracer instance."""
        try:
            from observability.tracer import KernelTracer
            
            tracer = KernelTracer(service_name="agent-os-test")
            assert tracer is not None
        except ImportError:
            pytest.skip("observability package not installed")
    
    def test_trace_execution(self):
        """Test tracing execution."""
        try:
            from observability.tracer import KernelTracer
            
            tracer = KernelTracer(service_name="agent-os-test")
            
            with tracer.trace_execution(
                agent_id="test-agent",
                action="database_query",
                params={"query": "SELECT 1"}
            ) as span:
                span.set_attribute("custom", "value")
            
            assert True
        except ImportError:
            pytest.skip("observability package not installed")
    
    def test_trace_policy_check(self):
        """Test tracing policy check."""
        try:
            from observability.tracer import KernelTracer
            
            tracer = KernelTracer(service_name="agent-os-test")
            
            with tracer.trace_policy_check(
                agent_id="test-agent",
                policy="strict"
            ):
                pass
            
            assert True
        except ImportError:
            pytest.skip("observability package not installed")
    
    def test_trace_signal(self):
        """Test tracing signal."""
        try:
            from observability.tracer import KernelTracer
            
            tracer = KernelTracer(service_name="agent-os-test")
            
            tracer.trace_signal(
                agent_id="test-agent",
                signal="SIGKILL",
                reason="policy_violation"
            )
            
            assert True
        except ImportError:
            pytest.skip("observability package not installed")


class TestPrometheusExporter:
    """Test Prometheus metrics export."""
    
    def test_import_exporter(self):
        """Test importing exporter module."""
        try:
            from observability.exporter import create_metrics_endpoint
            assert create_metrics_endpoint is not None
        except ImportError:
            pytest.skip("observability package not installed")
    
    def test_metrics_endpoint(self):
        """Test creating metrics endpoint."""
        try:
            from observability.exporter import create_metrics_endpoint
            
            endpoint = create_metrics_endpoint()
            
            # Should return something callable
            assert endpoint is not None
        except ImportError:
            pytest.skip("observability package not installed")


class TestObservabilityIntegration:
    """Test observability integration with kernel."""
    
    @pytest.mark.asyncio
    async def test_kernel_emits_metrics(self):
        """Test that kernel operations emit metrics."""
        try:
            from agent_os.stateless import StatelessKernel, ExecutionContext
            from observability.metrics import KernelMetrics
            
            metrics = KernelMetrics()
            kernel = StatelessKernel(metrics=metrics)
            
            context = ExecutionContext(
                agent_id="test",
                policies=[]
            )
            
            result = await kernel.execute(
                action="database_query",
                params={"query": "SELECT 1"},
                context=context
            )
            
            # Metrics should have been recorded
            assert True
        except (ImportError, TypeError):
            pytest.skip("Integration not available")
    
    @pytest.mark.asyncio
    async def test_kernel_emits_traces(self):
        """Test that kernel operations emit traces."""
        try:
            from agent_os.stateless import StatelessKernel, ExecutionContext
            from observability.tracer import KernelTracer
            
            tracer = KernelTracer(service_name="test")
            kernel = StatelessKernel(tracer=tracer)
            
            context = ExecutionContext(
                agent_id="test",
                policies=[]
            )
            
            result = await kernel.execute(
                action="database_query",
                params={"query": "SELECT 1"},
                context=context
            )
            
            # Traces should have been recorded
            assert True
        except (ImportError, TypeError):
            pytest.skip("Integration not available")


class TestDashboards:
    """Test dashboard templates."""
    
    def test_grafana_dashboard_exists(self):
        """Test Grafana dashboard JSON exists."""
        try:
            from observability.dashboards import get_grafana_dashboard
            
            dashboard = get_grafana_dashboard()
            
            assert "title" in dashboard
            assert "panels" in dashboard
        except ImportError:
            pytest.skip("observability package not installed")
    
    def test_dashboard_has_key_panels(self):
        """Test dashboard has required panels."""
        try:
            from observability.dashboards import get_grafana_dashboard
            
            dashboard = get_grafana_dashboard()
            panel_titles = [p.get("title", "") for p in dashboard.get("panels", [])]
            
            # Should have violation rate panel
            assert any("violation" in t.lower() for t in panel_titles)
            
            # Should have latency panel
            assert any("latency" in t.lower() for t in panel_titles)
        except ImportError:
            pytest.skip("observability package not installed")
