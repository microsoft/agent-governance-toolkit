# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for runbook reference — models, executor, registry, and YAML loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_sre.incidents.detector import Incident, IncidentSeverity, Signal, SignalType
from agent_sre.incidents.runbook import (
    ExecutionStatus,
    Runbook,
    RunbookExecution,
    RunbookStep,
    StepResult,
    StepStatus,
)
from agent_sre.incidents.runbook_executor import RunbookExecutor
from agent_sre.incidents.runbook_registry import RunbookRegistry, load_runbooks_from_yaml

BUILTIN_DIR = Path(__file__).resolve().parent.parent / "src" / "agent_sre" / "incidents" / "runbooks"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_incident(
    signal_type: SignalType = SignalType.SLO_BREACH,
    severity: IncidentSeverity = IncidentSeverity.P2,
) -> Incident:
    signal = Signal(signal_type=signal_type, source="agent-1", message="test signal")
    return Incident(title="Test incident", severity=severity, signals=[signal], agent_id="agent-1")


def _ok_action(incident: Incident) -> str:
    return f"ok:{incident.agent_id}"


def _fail_action(incident: Incident) -> str:
    raise RuntimeError("step failed")


def _rollback_action(incident: Incident) -> str:
    return "rolled back"


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------

class TestRunbookModels:
    def test_step_to_dict_callable(self) -> None:
        step = RunbookStep(name="s1", action=_ok_action, timeout_seconds=60)
        d = step.to_dict()
        assert d["name"] == "s1"
        assert d["timeout_seconds"] == 60
        assert d["has_rollback"] is False

    def test_step_to_dict_string(self) -> None:
        step = RunbookStep(name="s1", action="echo hello", rollback_action="echo undo")
        d = step.to_dict()
        assert d["action"] == "echo hello"
        assert d["has_rollback"] is True

    def test_runbook_to_dict(self) -> None:
        rb = Runbook(
            id="rb-1",
            name="Test Runbook",
            description="desc",
            trigger_conditions=[{"type": "slo_breach", "severity": "p1"}],
            steps=[RunbookStep(name="s1", action="cmd")],
            labels={"team": "sre"},
        )
        d = rb.to_dict()
        assert d["id"] == "rb-1"
        assert d["name"] == "Test Runbook"
        assert len(d["steps"]) == 1
        assert d["labels"]["team"] == "sre"

    def test_step_result_to_dict(self) -> None:
        sr = StepResult(step_name="s1", status=StepStatus.SUCCESS, output="done")
        sr.started_at = 100.0
        sr.completed_at = 105.0
        d = sr.to_dict()
        assert d["status"] == "success"
        assert d["duration_seconds"] == 5.0

    def test_execution_to_dict(self) -> None:
        ex = RunbookExecution(runbook_id="rb-1", incident_id="inc-1")
        ex.started_at = 100.0
        ex.completed_at = 110.0
        ex.status = ExecutionStatus.COMPLETED
        d = ex.to_dict()
        assert d["status"] == "completed"
        assert d["duration_seconds"] == 10.0


# ---------------------------------------------------------------------------
# Executor tests
# ---------------------------------------------------------------------------

class TestRunbookExecutor:
    def test_runs_steps_in_order(self) -> None:
        rb = Runbook(
            id="rb-order",
            name="Order Test",
            steps=[
                RunbookStep(name="step-a", action=_ok_action),
                RunbookStep(name="step-b", action=_ok_action),
            ],
        )
        executor = RunbookExecutor()
        execution = executor.execute(rb, _make_incident())
        assert execution.status == ExecutionStatus.COMPLETED
        assert len(execution.step_results) == 2
        assert execution.step_results[0].step_name == "step-a"
        assert execution.step_results[1].step_name == "step-b"
        assert all(r.status == StepStatus.SUCCESS for r in execution.step_results)

    def test_string_actions(self) -> None:
        rb = Runbook(
            id="rb-str",
            name="String Action",
            steps=[RunbookStep(name="cmd", action="echo hello")],
        )
        executor = RunbookExecutor()
        execution = executor.execute(rb, _make_incident())
        assert execution.status == ExecutionStatus.COMPLETED
        assert "[command]" in execution.step_results[0].output

    def test_step_failure_marks_failed(self) -> None:
        rb = Runbook(
            id="rb-fail",
            name="Failure Test",
            steps=[
                RunbookStep(name="ok", action=_ok_action),
                RunbookStep(name="boom", action=_fail_action),
            ],
        )
        executor = RunbookExecutor()
        execution = executor.execute(rb, _make_incident())
        assert execution.status == ExecutionStatus.FAILED
        failed_step = [r for r in execution.step_results if r.status == StepStatus.FAILED]
        assert len(failed_step) == 1
        assert "step failed" in failed_step[0].error

    def test_rollback_on_failure(self) -> None:
        rb = Runbook(
            id="rb-rollback",
            name="Rollback Test",
            steps=[
                RunbookStep(name="ok", action=_ok_action, rollback_action=_rollback_action),
                RunbookStep(name="boom", action=_fail_action),
            ],
        )
        executor = RunbookExecutor()
        execution = executor.execute(rb, _make_incident())
        # When rollback actions exist and run, status is ROLLED_BACK
        assert execution.status in (ExecutionStatus.FAILED, ExecutionStatus.ROLLED_BACK)
        # Should have step results including rolled-back ones
        assert len(execution.step_results) >= 2

    def test_approval_callback_approved(self) -> None:
        rb = Runbook(
            id="rb-approve",
            name="Approval Test",
            steps=[
                RunbookStep(name="gate", action=_ok_action, requires_approval=True),
            ],
        )
        executor = RunbookExecutor()
        execution = executor.execute(rb, _make_incident(), approve_callback=lambda s, i: True)
        assert execution.status == ExecutionStatus.COMPLETED
        assert execution.step_results[0].status == StepStatus.SUCCESS

    def test_approval_callback_denied(self) -> None:
        rb = Runbook(
            id="rb-deny",
            name="Deny Test",
            steps=[
                RunbookStep(name="gate", action=_ok_action, requires_approval=True),
            ],
        )
        executor = RunbookExecutor()
        execution = executor.execute(rb, _make_incident(), approve_callback=lambda s, i: False)
        assert execution.status == ExecutionStatus.COMPLETED
        assert execution.step_results[0].status == StepStatus.SKIPPED

    def test_no_callback_pauses_with_waiting(self) -> None:
        rb = Runbook(
            id="rb-wait",
            name="Wait Test",
            steps=[
                RunbookStep(name="gate", action=_ok_action, requires_approval=True),
            ],
        )
        executor = RunbookExecutor()
        execution = executor.execute(rb, _make_incident())
        assert execution.status == ExecutionStatus.WAITING_APPROVAL
        assert execution.step_results[0].status == StepStatus.WAITING_APPROVAL

    def test_timing_recorded(self) -> None:
        rb = Runbook(
            id="rb-time",
            name="Timing Test",
            steps=[RunbookStep(name="s1", action=_ok_action)],
        )
        executor = RunbookExecutor()
        execution = executor.execute(rb, _make_incident())
        assert execution.started_at is not None
        assert execution.completed_at is not None
        assert execution.step_results[0].started_at is not None
        assert execution.step_results[0].completed_at is not None

    def test_event_log_audit_trail(self) -> None:
        rb = Runbook(
            id="rb-audit",
            name="Audit Test",
            steps=[RunbookStep(name="s1", action=_ok_action)],
        )
        executor = RunbookExecutor()
        execution = executor.execute(rb, _make_incident())
        assert execution.status == ExecutionStatus.COMPLETED
        # Event log should have entries for start + step events + completion
        assert len(executor._event_log) > 0


# ---------------------------------------------------------------------------
# Registry tests
# ---------------------------------------------------------------------------

class TestRunbookRegistry:
    def test_register_and_get(self) -> None:
        registry = RunbookRegistry()
        rb = Runbook(id="rb-1", name="Test")
        registry.register(rb)
        assert registry.get("rb-1") is rb
        assert registry.get("nonexistent") is None

    def test_list_all(self) -> None:
        registry = RunbookRegistry()
        registry.register(Runbook(id="a", name="A"))
        registry.register(Runbook(id="b", name="B"))
        assert len(registry.list_all()) == 2

    def test_match_by_signal_type(self) -> None:
        registry = RunbookRegistry()
        rb = Runbook(
            id="slo-rb",
            name="SLO Runbook",
            trigger_conditions=[{"type": "slo_breach"}],
        )
        registry.register(rb)

        incident = _make_incident(signal_type=SignalType.SLO_BREACH)
        matched = registry.match(incident)
        assert len(matched) == 1
        assert matched[0].id == "slo-rb"

    def test_match_by_severity(self) -> None:
        registry = RunbookRegistry()
        rb = Runbook(
            id="p1-rb",
            name="P1 Runbook",
            trigger_conditions=[{"severity": "p1"}],
        )
        registry.register(rb)

        p1_incident = _make_incident(severity=IncidentSeverity.P1)
        assert len(registry.match(p1_incident)) == 1

        p3_incident = _make_incident(severity=IncidentSeverity.P3)
        assert len(registry.match(p3_incident)) == 0

    def test_no_match(self) -> None:
        registry = RunbookRegistry()
        rb = Runbook(
            id="cost-rb",
            name="Cost Runbook",
            trigger_conditions=[{"type": "cost_anomaly"}],
        )
        registry.register(rb)

        incident = _make_incident(signal_type=SignalType.POLICY_VIOLATION)
        assert len(registry.match(incident)) == 0


# ---------------------------------------------------------------------------
# YAML loading tests
# ---------------------------------------------------------------------------

class TestYamlLoading:
    def test_load_runbooks_from_yaml(self, tmp_path: Path) -> None:
        yaml_content = """
runbooks:
  - id: test-rb
    name: Test Runbook
    description: A test runbook
    trigger_conditions:
      - type: slo_breach
        severity: p1
    labels:
      team: sre
    steps:
      - name: Step One
        action: "echo one"
        timeout_seconds: 30
        requires_approval: false
      - name: Step Two
        action: "echo two"
        requires_approval: true
        rollback_action: "echo undo"
"""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(yaml_content)

        runbooks = load_runbooks_from_yaml(yaml_file)
        assert len(runbooks) == 1
        rb = runbooks[0]
        assert rb.id == "test-rb"
        assert rb.name == "Test Runbook"
        assert len(rb.steps) == 2
        assert rb.steps[0].timeout_seconds == 30
        assert rb.steps[1].requires_approval is True
        assert rb.steps[1].rollback_action == "echo undo"
        assert rb.trigger_conditions[0]["type"] == "slo_breach"
        assert rb.labels["team"] == "sre"


# ---------------------------------------------------------------------------
# Built-in runbook validation
# ---------------------------------------------------------------------------

class TestBuiltinRunbooks:
    def test_all_builtin_runbooks_load(self) -> None:
        yaml_files = list(BUILTIN_DIR.glob("*.yaml"))
        assert len(yaml_files) == 4, f"Expected 4 built-in runbooks, found {len(yaml_files)}"

        for yaml_file in yaml_files:
            runbooks = load_runbooks_from_yaml(yaml_file)
            assert len(runbooks) >= 1, f"No runbooks loaded from {yaml_file.name}"
            rb = runbooks[0]
            assert rb.id, f"Runbook in {yaml_file.name} missing id"
            assert rb.name, f"Runbook in {yaml_file.name} missing name"
            assert len(rb.steps) > 0, f"Runbook in {yaml_file.name} has no steps"
            assert len(rb.trigger_conditions) > 0, (
                f"Runbook in {yaml_file.name} has no trigger conditions"
            )

    def test_builtin_runbooks_register_and_match(self) -> None:
        registry = RunbookRegistry()
        for yaml_file in BUILTIN_DIR.glob("*.yaml"):
            for rb in load_runbooks_from_yaml(yaml_file):
                registry.register(rb)

        assert len(registry.list_all()) == 4

        # SLO breach incident should match rollback-version
        incident = _make_incident(
            signal_type=SignalType.SLO_BREACH, severity=IncidentSeverity.P1
        )
        matched = registry.match(incident)
        matched_ids = {m.id for m in matched}
        assert "rollback-version" in matched_ids

    def test_restart_agent_runbook_structure(self) -> None:
        runbooks = load_runbooks_from_yaml(BUILTIN_DIR / "restart_agent.yaml")
        rb = runbooks[0]
        assert rb.id == "restart-agent"
        step_names = [s.name for s in rb.steps]
        assert "Check agent health" in step_names
        assert "Restart agent" in step_names
        # Restart step should require approval
        restart_step = next(s for s in rb.steps if s.name == "Restart agent")
        assert restart_step.requires_approval is True
        assert restart_step.rollback_action is not None
