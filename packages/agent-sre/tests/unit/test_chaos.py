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
        f = Fault.delegation_reject("analyzer", rate=0.2)
        assert f.fault_type == FaultType.ERROR_INJECTION
        assert f.target == "analyzer"
        assert f.rate == 0.2
        assert f.params["error"] == "delegation_rejected"

    def test_network_partition(self) -> None:
        f = Fault.network_partition(["agent-a", "agent-b"])
        assert f.fault_type == FaultType.ERROR_INJECTION
        assert f.target == "agent-a"
        assert f.params["agents"] == ["agent-a", "agent-b"]

    def test_cost_spike(self) -> None:
        f = Fault.cost_spike("expensive_tool", multiplier=20.0)
        assert f.fault_type == FaultType.ERROR_INJECTION
        assert f.params["multiplier"] == 20.0

    def test_tool_wrong_schema(self) -> None:
        f = Fault.tool_wrong_schema("api_tool", rate=0.5)
        assert f.fault_type == FaultType.ERROR_INJECTION
        assert f.params["error"] == "schema_mismatch"

    def test_llm_degraded(self) -> None:
        f = Fault.llm_degraded("openai", quality=0.3)
        assert f.fault_type == FaultType.LATENCY_INJECTION
        assert f.params["quality"] == 0.3
        assert f.params["degraded"] is True

    def test_credential_expire(self) -> None:
        f = Fault.credential_expire("agent-x")
        assert f.fault_type == FaultType.ERROR_INJECTION
        assert f.params["error"] == "credential_expired"

    def test_deadlock_injection(self) -> None:
        f = Fault.deadlock_injection(["agent-a", "agent-b"], timeout_ms=15000)
        assert f.fault_type == FaultType.DEADLOCK_INJECTION
        assert f.target == "agent-a"
        assert f.params["agents"] == ["agent-a", "agent-b"]
        assert f.params["timeout_ms"] == 15000

    def test_contradictory_instruction(self) -> None:
        f = Fault.contradictory_instruction("bot", directive_a="expand", directive_b="summarize")
        assert f.fault_type == FaultType.CONTRADICTORY_INSTRUCTION
        assert f.target == "bot"
        assert f.params["directive_a"] == "expand"
        assert f.params["directive_b"] == "summarize"

    def test_trust_perturbation(self) -> None:
        f = Fault.trust_perturbation("agent-z", delta=-300.0)
        assert f.fault_type == FaultType.TRUST_PERTURBATION
        assert f.params["delta"] == -300.0

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


class TestBehavioralFaults:
    """Tests for behavioral fault injection (issue #88)."""

    def test_deadlock_experiment(self) -> None:
        exp = ChaosExperiment(
            name="deadlock-test",
            target_agent="agent-a",
            faults=[Fault.deadlock_injection(["agent-a", "agent-b"])],
            abort_conditions=[AbortCondition("task_success_rate", 0.3, "lte")],
        )
        exp.start()
        exp.inject_fault(exp.faults[0], applied=True)
        assert len(exp.injection_events) == 1
        assert exp.injection_events[0].fault_type == FaultType.DEADLOCK_INJECTION

    def test_contradictory_instruction_experiment(self) -> None:
        exp = ChaosExperiment(
            name="contradiction-test",
            target_agent="bot",
            faults=[Fault.contradictory_instruction("bot", "expand", "summarize")],
        )
        exp.start()
        exp.inject_fault(exp.faults[0], applied=True)
        assert exp.injection_events[0].fault_type == FaultType.CONTRADICTORY_INSTRUCTION

    def test_trust_perturbation_experiment(self) -> None:
        exp = ChaosExperiment(
            name="trust-test",
            target_agent="agent-z",
            faults=[Fault.trust_perturbation("agent-z", delta=-200.0)],
            abort_conditions=[AbortCondition("bypass_rate", 0.2, "gte")],
        )
        exp.start()
        exp.inject_fault(exp.faults[0], applied=True)
        assert exp.injection_events[0].fault_type == FaultType.TRUST_PERTURBATION
        # Trust drop should trigger abort if bypass rate exceeds threshold
        assert exp.check_abort({"bypass_rate": 0.5}) is True
        assert exp.state == ExperimentState.ABORTED

    def test_deadlock_with_timeout_detection(self) -> None:
        """Deadlock should be detectable via timeout abort condition."""
        exp = ChaosExperiment(
            name="deadlock-timeout",
            target_agent="agent-a",
            faults=[Fault.deadlock_injection(["agent-a", "agent-b"], timeout_ms=5000)],
            abort_conditions=[AbortCondition("task_success_rate", 0.0, "lte")],
            duration_seconds=10,
        )
        exp.start()
        exp.inject_fault(exp.faults[0], applied=True)
        # When task_success_rate hits 0, should abort
        assert exp.check_abort({"task_success_rate": 0.0}) is True

    def test_enterprise_faults_create_valid_experiments(self) -> None:
        """All enterprise faults should create valid Fault objects."""
        faults = [
            Fault.delegation_reject("analyzer"),
            Fault.llm_degraded("openai"),
            Fault.tool_wrong_schema("api"),
            Fault.credential_expire("bot"),
            Fault.network_partition(["a", "b"]),
            Fault.cost_spike("expensive"),
        ]
        exp = ChaosExperiment(
            name="enterprise-combo",
            target_agent="bot",
            faults=faults,
        )
        assert len(exp.faults) == 6
        for f in exp.faults:
            d = f.to_dict()
            assert "fault_type" in d
            assert "target" in d

    def test_behavioral_fault_types_in_enum(self) -> None:
        """Verify the 3 new behavioral fault types exist."""
        assert FaultType.DEADLOCK_INJECTION.value == "deadlock_injection"
        assert FaultType.CONTRADICTORY_INSTRUCTION.value == "contradictory_instruction"
        assert FaultType.TRUST_PERTURBATION.value == "trust_perturbation"


class TestChaosLibraryBehavioral:
    """Tests for behavioral experiment templates in the library."""

    def test_library_has_behavioral_templates(self) -> None:
        from agent_sre.chaos.library import ChaosLibrary
        lib = ChaosLibrary()
        agent_templates = lib.list_templates(category="agent")
        assert len(agent_templates) >= 3
        ids = [t.template_id for t in agent_templates]
        assert "deadlock-injection" in ids
        assert "contradictory-instruction" in ids
        assert "trust-perturbation" in ids

    def test_library_has_enterprise_templates(self) -> None:
        from agent_sre.chaos.library import ChaosLibrary
        lib = ChaosLibrary()
        ids = [t.template_id for t in lib.list_templates()]
        assert "delegation-reject" in ids
        assert "credential-expiry" in ids

    def test_instantiate_deadlock_template(self) -> None:
        from agent_sre.chaos.library import ChaosLibrary
        lib = ChaosLibrary()
        exp = lib.instantiate("deadlock-injection", "my-agent")
        assert exp is not None
        assert exp.target_agent == "my-agent"
        assert len(exp.faults) == 1
        assert exp.faults[0].fault_type == FaultType.DEADLOCK_INJECTION

    def test_instantiate_trust_perturbation_template(self) -> None:
        from agent_sre.chaos.library import ChaosLibrary
        lib = ChaosLibrary()
        exp = lib.instantiate("trust-perturbation", "agent-x")
        assert exp is not None
        assert exp.faults[0].fault_type == FaultType.TRUST_PERTURBATION

    def test_total_template_count(self) -> None:
        from agent_sre.chaos.library import ChaosLibrary
        lib = ChaosLibrary()
        # 3 basic + 3 adversarial + 3 behavioral + 2 enterprise = 11
        assert len(lib.list_templates()) == 11

    def test_categories_include_agent(self) -> None:
        from agent_sre.chaos.library import ChaosLibrary
        lib = ChaosLibrary()
        cats = lib.categories()
        assert "agent" in cats
