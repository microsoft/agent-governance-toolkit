# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for A/B Testing Engine.

Covers: Experiment, Variant, MetricSummary, statistical analysis.
"""

import random

from agent_sre.experiments import (
    Experiment,
    ExperimentStatus,
    MetricSummary,
    SignificanceLevel,
    Variant,
)


class TestVariant:
    def test_basic(self):
        v = Variant(name="control")
        assert v.name == "control"
        assert v.weight == 0.5


class TestExperiment:
    def test_default_variants(self):
        exp = Experiment(name="test")
        assert len(exp.variants) == 2
        assert exp.variants[0].name == "control"
        assert exp.variants[1].name == "treatment"

    def test_lifecycle(self):
        exp = Experiment(name="test")
        assert exp.status == ExperimentStatus.DRAFT
        exp.start()
        assert exp.status == ExperimentStatus.RUNNING
        exp.stop()
        assert exp.status == ExperimentStatus.COMPLETED

    def test_abort(self):
        exp = Experiment(name="test")
        exp.start()
        exp.abort()
        assert exp.status == ExperimentStatus.ABORTED

    def test_assign_returns_variant(self):
        exp = Experiment(name="test")
        exp.start()
        result = exp.assign()
        assert result in ("control", "treatment")

    def test_assign_before_start(self):
        exp = Experiment(name="test")
        result = exp.assign()
        assert result == "control"  # Returns first variant

    def test_record(self):
        exp = Experiment(name="test")
        exp.record("control", "success_rate", 0.95)
        assert exp.sample_count == 1

    def test_analyze_no_data(self):
        exp = Experiment(name="test")
        results = exp.analyze()
        assert len(results) == 1  # One metric
        assert results[0].n_a == 0

    def test_analyze_equal_means(self):
        exp = Experiment(name="test")
        for _ in range(50):
            exp.record("control", "task_success_rate", 0.95)
            exp.record("treatment", "task_success_rate", 0.95)
        results = exp.analyze()
        assert results[0].significance == SignificanceLevel.NOT_SIGNIFICANT

    def test_analyze_different_means(self):
        random.seed(42)
        exp = Experiment(name="test")
        for _ in range(100):
            exp.record("control", "task_success_rate", random.gauss(0.85, 0.05))
            exp.record("treatment", "task_success_rate", random.gauss(0.95, 0.05))
        results = exp.analyze()
        assert results[0].significance in (
            SignificanceLevel.SIGNIFICANT,
            SignificanceLevel.HIGHLY_SIGNIFICANT,
        )
        assert results[0].winner == "treatment"

    def test_is_ready(self):
        exp = Experiment(name="test", min_samples=10)
        assert not exp.is_ready()
        for _ in range(10):
            exp.record("control", "task_success_rate", 0.9)
            exp.record("treatment", "task_success_rate", 0.9)
        assert exp.is_ready()

    def test_custom_variants(self):
        exp = Experiment(
            name="model-test",
            variants=[
                Variant("gpt-4", weight=0.3),
                Variant("gpt-3.5", weight=0.7),
            ],
            metrics=["latency", "accuracy"],
        )
        assert len(exp.metrics) == 2
        assert exp.variants[0].weight == 0.3

    def test_to_dict(self):
        exp = Experiment(name="test")
        exp.start()
        d = exp.to_dict()
        assert d["name"] == "test"
        assert d["status"] == "running"

    def test_multiple_metrics(self):
        exp = Experiment(
            name="test",
            metrics=["success_rate", "latency"],
        )
        for _ in range(50):
            exp.record("control", "success_rate", 0.9)
            exp.record("treatment", "success_rate", 0.95)
            exp.record("control", "latency", 500.0)
            exp.record("treatment", "latency", 450.0)

        results = exp.analyze()
        assert len(results) == 2
        assert results[0].metric_name == "success_rate"
        assert results[1].metric_name == "latency"

    def test_traffic_split(self):
        random.seed(42)
        exp = Experiment(
            name="test",
            variants=[Variant("a", weight=0.8), Variant("b", weight=0.2)],
        )
        exp.start()
        counts = {"a": 0, "b": 0}
        for _ in range(1000):
            v = exp.assign()
            counts[v] += 1

        # Should be roughly 80/20
        assert counts["a"] > 600
        assert counts["b"] > 100


class TestMetricSummary:
    def test_to_dict(self):
        ms = MetricSummary(
            metric_name="success",
            variant_a="control",
            variant_b="treatment",
            mean_a=0.85,
            mean_b=0.95,
            n_a=100,
            n_b=100,
            winner="treatment",
        )
        d = ms.to_dict()
        assert d["metric"] == "success"
        assert d["winner"] == "treatment"


class TestExperimentSLIIntegration:
    def test_experiment_feeds_slo(self):
        """A/B test results feed into SLO tracking."""
        from agent_sre.slo.indicators import TaskSuccessRate

        exp = Experiment(name="prompt-v2")
        exp.start()

        sli_control = TaskSuccessRate(target=0.90)
        sli_treatment = TaskSuccessRate(target=0.90)

        random.seed(42)
        for _ in range(50):
            variant = exp.assign()
            if variant == "control":
                success = random.random() < 0.85
                sli_control.record_task(success)
                exp.record("control", "task_success_rate", 1.0 if success else 0.0)
            else:
                success = random.random() < 0.95
                sli_treatment.record_task(success)
                exp.record("treatment", "task_success_rate", 1.0 if success else 0.0)

        results = exp.analyze()
        assert len(results) == 1
        # Both SLIs have data
        assert sli_control._total > 0
        assert sli_treatment._total > 0
