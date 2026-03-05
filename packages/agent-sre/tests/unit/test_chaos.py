# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for chaos engine — fault injection and resilience testing."""

import pytest

from agent_sre.chaos.engine import (
    AbortCondition,
    ChaosExperiment,
    ExperimentState,
    Fault,
    FaultType,
)


class TestFault:
    def test_tool_timeout(self) -> None:
        f = Fault.tool_timeout("web_search", delay_ms=5000)
        assert f.fault_type == FaultType.TIMEOUT_INJECTION
        assert f.target == "web_search"
        assert f.params["delay_ms"] == 5000

    def test_tool_error(self) -> None:
        f = Fault.tool_error("database", error="connection_refused", rate=0.5)
        assert f.rate == 0.5
        assert f.params["error"] == "connection_refused"

    def test_llm_latency(self) -> None:
        f = Fault.llm_latency("openai", p99_ms=10000)
        assert f.fault_type == FaultType.LATENCY_INJECTION
        assert f.target == "openai"

    def test_delegation_reject(self) -> None:
        with pytest.raises(NotImplementedError):
            Fault.delegation_reject("analyzer", rate=0.2)

    def test_network_partition(self) -> None:
        with pytest.raises(NotImplementedError):
            Fault.network_partition(["agent-a", "agent-b"])

    def test_cost_spike(self) -> None:
        with pytest.raises(NotImplementedError):
            Fault.cost_spike("expensive_tool", multiplier=20.0)

    def test_to_dict(self) -> None:
        f = Fault.tool_timeout("search", delay_ms=3000)
        d = f.to_dict()
        assert d["fault_type"] == "timeout_injection"
        assert d["target"] == "search"


class TestChaosExperiment:
    def test_creation(self) -> None:
        exp = ChaosExperiment(
            name="tool-resilience",
            target_agent="research-bot",
            faults=[Fault.tool_timeout("search", delay_ms=5000)],
            duration_seconds=1800,
        )
        assert exp.state == ExperimentState.PENDING
        assert len(exp.faults) == 1

    def test_start(self) -> None:
        exp = ChaosExperiment(
            name="test",
            target_agent="bot",
            faults=[Fault.tool_error("db")],
        )
        exp.start()
        assert exp.state == ExperimentState.RUNNING
        assert exp.started_at is not None

    def test_inject_fault(self) -> None:
        exp = ChaosExperiment(name="test", target_agent="bot", faults=[])
        exp.start()
        fault = Fault.tool_timeout("api")
        exp.inject_fault(fault, applied=True)
        assert len(exp.injection_events) == 1
        assert exp.injection_events[0].applied is True

    def test_abort(self) -> None:
        exp = ChaosExperiment(name="test", target_agent="bot", faults=[])
        exp.start()
        exp.abort(reason="quality too low")
        assert exp.state == ExperimentState.ABORTED
        assert exp.abort_reason == "quality too low"

    def test_check_abort(self) -> None:
        exp = ChaosExperiment(
            name="test",
            target_agent="bot",
            faults=[],
            abort_conditions=[
                AbortCondition(metric="success_rate", threshold=0.80, comparator="lte"),
            ],
        )
        exp.start()
        assert exp.check_abort({"success_rate": 0.90}) is False
        assert exp.check_abort({"success_rate": 0.75}) is True
        assert exp.state == ExperimentState.ABORTED

    def test_complete(self) -> None:
        exp = ChaosExperiment(name="test", target_agent="bot", faults=[])
        exp.start()
        exp.complete()
        assert exp.state == ExperimentState.COMPLETED
        assert exp.ended_at is not None

    def test_fault_impact_score(self) -> None:
        exp = ChaosExperiment(name="test", target_agent="bot", faults=[])
        exp.start()
        score = exp.calculate_resilience(
            baseline_success_rate=0.99,
            experiment_success_rate=0.95,
            recovery_time_ms=500,
            cost_increase_percent=10.0,
        )
        assert 0 < score.overall <= 100
        assert isinstance(score.passed, bool)

    def test_blast_radius_clamped(self) -> None:
        exp = ChaosExperiment(name="test", target_agent="bot", faults=[], blast_radius=1.5)
        assert exp.blast_radius == 1.0
        exp2 = ChaosExperiment(name="test", target_agent="bot", faults=[], blast_radius=-0.5)
        assert exp2.blast_radius == 0.0

    def test_to_dict(self) -> None:
        exp = ChaosExperiment(
            name="test",
            target_agent="bot",
            faults=[Fault.tool_timeout("api")],
        )
        exp.start()
        d = exp.to_dict()
        assert d["name"] == "test"
        assert d["state"] == "running"
        assert len(d["faults"]) == 1
