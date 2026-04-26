# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for W&B and MLflow exporters."""

import pytest

from agent_sre.integrations.mlflow.exporter import MLflowArtifact, MLflowExporter, MLflowRun
from agent_sre.integrations.wandb.exporter import WandBExporter, WandBRun

# ---------------------------------------------------------------------------
# W&B Exporter Tests
# ---------------------------------------------------------------------------

class TestWandBExporter:
    def test_offline_by_default(self):
        exporter = WandBExporter()
        assert exporter.is_offline is True

    def test_online_with_client(self):
        exporter = WandBExporter(client=object())
        assert exporter.is_offline is False

    def test_log_run(self):
        exporter = WandBExporter()
        run = exporter.log_run("test-run", {"accuracy": 0.95}, config={"lr": 0.01}, tags=["test"])
        assert isinstance(run, WandBRun)
        assert run.name == "test-run"
        assert run.metrics["accuracy"] == 0.95
        assert run.config["lr"] == 0.01
        assert "test" in run.tags

    def test_log_run_minimal(self):
        exporter = WandBExporter()
        run = exporter.log_run("simple", {"loss": 0.1})
        assert run.config == {}
        assert run.tags == []

    def test_runs_property(self):
        exporter = WandBExporter()
        exporter.log_run("r1", {"a": 1})
        exporter.log_run("r2", {"b": 2})
        assert len(exporter.runs) == 2
        assert exporter.runs[0].name == "r1"

    def test_log_cost_series(self):
        exporter = WandBExporter()
        run = exporter.log_cost_series("agent-1", [0.01, 0.02, 0.03])
        assert run.metrics["total_cost"] == pytest.approx(0.06)
        assert run.metrics["num_steps"] == 3
        assert run.metrics["avg_cost"] == pytest.approx(0.02)
        assert run.metrics["max_cost"] == pytest.approx(0.03)

    def test_log_cost_series_empty(self):
        exporter = WandBExporter()
        run = exporter.log_cost_series("agent-1", [])
        assert run.metrics["total_cost"] == 0.0
        assert run.metrics["avg_cost"] == 0.0

    def test_clear(self):
        exporter = WandBExporter()
        exporter.log_run("r1", {"a": 1})
        exporter.clear()
        assert len(exporter.runs) == 0

    def test_get_stats(self):
        exporter = WandBExporter(project="my-project")
        exporter.log_run("r1", {"a": 1})
        stats = exporter.get_stats()
        assert stats["project"] == "my-project"
        assert stats["total_runs"] == 1
        assert stats["is_offline"] is True

    def test_project_name(self):
        exporter = WandBExporter(project="custom")
        assert exporter.get_stats()["project"] == "custom"


# ---------------------------------------------------------------------------
# MLflow Exporter Tests
# ---------------------------------------------------------------------------

class TestMLflowExporter:
    def test_offline_by_default(self):
        exporter = MLflowExporter()
        assert exporter.is_offline is True

    def test_online_with_client(self):
        exporter = MLflowExporter(client=object())
        assert exporter.is_offline is False

    def test_log_run(self):
        exporter = MLflowExporter()
        run = exporter.log_run("test-run", {"f1": 0.88}, params={"epochs": "10"}, tags={"env": "test"})
        assert isinstance(run, MLflowRun)
        assert run.name == "test-run"
        assert run.metrics["f1"] == 0.88
        assert run.params["epochs"] == "10"
        assert run.tags["env"] == "test"

    def test_log_run_minimal(self):
        exporter = MLflowExporter()
        run = exporter.log_run("simple", {"loss": 0.1})
        assert run.params == {}
        assert run.tags == {}

    def test_runs_property(self):
        exporter = MLflowExporter()
        exporter.log_run("r1", {"a": 1})
        exporter.log_run("r2", {"b": 2})
        assert len(exporter.runs) == 2

    def test_log_artifact(self):
        exporter = MLflowExporter()
        artifact = exporter.log_artifact("run-1", "config.yaml", "key: value")
        assert isinstance(artifact, MLflowArtifact)
        assert artifact.run_name == "run-1"
        assert artifact.path == "config.yaml"
        assert artifact.content == "key: value"

    def test_artifacts_property(self):
        exporter = MLflowExporter()
        exporter.log_artifact("r1", "a.txt", "aaa")
        exporter.log_artifact("r1", "b.txt", "bbb")
        assert len(exporter.artifacts) == 2

    def test_clear(self):
        exporter = MLflowExporter()
        exporter.log_run("r1", {"a": 1})
        exporter.log_artifact("r1", "f.txt", "data")
        exporter.clear()
        assert len(exporter.runs) == 0
        assert len(exporter.artifacts) == 0

    def test_get_stats(self):
        exporter = MLflowExporter(experiment_name="my-exp")
        exporter.log_run("r1", {"a": 1})
        exporter.log_artifact("r1", "f.txt", "data")
        stats = exporter.get_stats()
        assert stats["experiment_name"] == "my-exp"
        assert stats["total_runs"] == 1
        assert stats["total_artifacts"] == 1
        assert stats["is_offline"] is True

    def test_experiment_name(self):
        exporter = MLflowExporter(experiment_name="custom")
        assert exporter.get_stats()["experiment_name"] == "custom"
