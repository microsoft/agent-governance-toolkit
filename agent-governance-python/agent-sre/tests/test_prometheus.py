# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Prometheus exporter."""


from agent_sre.integrations.prometheus import PrometheusExporter
from agent_sre.slo.indicators import TaskSuccessRate
from agent_sre.slo.objectives import SLO, ErrorBudget


class TestPrometheusExporter:
    def test_set_gauge(self):
        exp = PrometheusExporter()
        exp.set_gauge("my_gauge", 42.0)
        output = exp.render()
        assert "my_gauge 42.0" in output

    def test_inc_counter(self):
        exp = PrometheusExporter()
        exp.inc_counter("my_counter", 1.0)
        exp.inc_counter("my_counter", 2.0)
        output = exp.render()
        assert "my_counter 3.0" in output

    def test_render_format(self):
        exp = PrometheusExporter()
        exp.set_gauge("test_metric", 1.0, help_text="A test metric")
        output = exp.render()
        assert "# HELP test_metric A test metric" in output
        assert "# TYPE test_metric gauge" in output
        assert "test_metric 1.0" in output

    def test_labels(self):
        exp = PrometheusExporter()
        exp.set_gauge("labeled", 5.0, {"env": "prod", "app": "sre"})
        output = exp.render()
        assert 'app="sre"' in output
        assert 'env="prod"' in output

    def test_export_slo(self):
        slo = SLO(
            name="test-slo",
            indicators=[TaskSuccessRate(target=0.99)],
            error_budget=ErrorBudget(total=0.01),
        )
        exp = PrometheusExporter()
        exp.export_slo(slo, agent_id="agent-1")
        output = exp.render()
        assert "agent_sre_slo_status" in output
        assert "agent_sre_slo_budget_remaining" in output
        assert "agent_sre_slo_burn_rate" in output

    def test_clear(self):
        exp = PrometheusExporter()
        exp.set_gauge("g", 1.0)
        exp.inc_counter("c", 1.0)
        exp.clear()
        assert exp.render() == ""

    def test_stats(self):
        exp = PrometheusExporter()
        exp.set_gauge("g1", 1.0)
        exp.set_gauge("g2", 2.0)
        exp.inc_counter("c1", 1.0)
        stats = exp.get_stats()
        assert stats["gauges"] == 2
        assert stats["counters"] == 1

    def test_help_and_type(self):
        exp = PrometheusExporter()
        exp.set_gauge("cpu_usage", 0.75, help_text="CPU usage ratio")
        exp.inc_counter("requests_total", 100.0, help_text="Total requests")
        output = exp.render()
        assert "# HELP cpu_usage CPU usage ratio" in output
        assert "# TYPE cpu_usage gauge" in output
        assert "# HELP requests_total Total requests" in output
        assert "# TYPE requests_total counter" in output

    def test_multiple_label_sets(self):
        exp = PrometheusExporter()
        exp.set_gauge("http_requests", 10.0, {"method": "GET"})
        exp.set_gauge("http_requests", 5.0, {"method": "POST"})
        output = exp.render()
        assert 'method="GET"' in output
        assert 'method="POST"' in output
        stats = exp.get_stats()
        assert stats["gauges"] == 2
