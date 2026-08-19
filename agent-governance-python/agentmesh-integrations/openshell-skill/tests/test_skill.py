# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import agent_control_specification as acs
import pytest

from openshell_agentmesh import GovernanceSkill, ShellPolicyViolation, governed_shell
from openshell_agentmesh.cli import main as cli_main


_NATIVE_MANIFEST = """agent_control_specification_version: 0.3.0-alpha-agt
metadata:
  name: openshell_adapter_scenarios
extends: []
policies:
  shell_policy:
    type: custom
    adapter: openshell_adapter_scenarios
intervention_points:
  pre_tool_call:
    policy_target: $.tool_call.args
    policy_target_kind: tool_args
    tool_name_from: $.tool_call.name
    policy:
      id: shell_policy
tools:
  shell.execute:
    clearance: restricted
"""


def result(
    decision: acs.Decision,
    *,
    reason: str = "test",
    transformed: Any = None,
) -> acs.InterventionPointResult:
    transform = (
        acs.Transform(path="$", value=transformed)
        if decision is acs.Decision.TRANSFORM
        else None
    )
    return acs.InterventionPointResult(
        verdict=acs.Verdict(decision=decision, reason=reason, transform=transform),
        transformed_policy_target=transformed,
        transformed_policy_target_applied=decision is acs.Decision.TRANSFORM,
    )


class FakeControl:
    def __init__(
        self, outcomes: list[acs.InterventionPointResult] | None = None
    ) -> None:
        self.outcomes = list(outcomes or [result(acs.Decision.ALLOW)])
        self.requests: list[tuple[Any, dict[str, Any], Any]] = []

    async def evaluate_intervention_point(
        self, point: Any, snapshot: dict[str, Any], mode: Any
    ):
        self.requests.append((point, snapshot, mode))
        return self.outcomes.pop(0) if len(self.outcomes) > 1 else self.outcomes[0]

    async def enforce(self, point: Any, outcome: Any, mode: Any) -> None:
        raise RuntimeError("approval unavailable")


class BrokenControl:
    async def evaluate_intervention_point(
        self, point: Any, snapshot: dict[str, Any], mode: Any
    ):
        raise RuntimeError("backend unavailable")


class ScriptedNativePolicy:
    def __init__(self, verdict: dict[str, Any]) -> None:
        self.verdict = verdict
        self.invocations: list[dict[str, Any]] = []

    def evaluate(self, invocation: Any) -> dict[str, Any]:
        self.invocations.append(dict(invocation))
        return self.verdict


@pytest.mark.skipif(
    getattr(acs, "_IS_OPEN_SHELL_TEST_STUB", False),
    reason="native ACS extension is unavailable",
)
def test_native_acs_manifest_allows_and_denies_shell_actions() -> None:
    allow_policy = ScriptedNativePolicy({"decision": "allow"})
    allow_skill = GovernanceSkill(
        acs.AgentControl.from_native(_NATIVE_MANIFEST, policy_dispatcher=allow_policy)
    )
    command, outcome = allow_skill.authorize_shell_command(["git", "status"], api="test")
    assert command == ["git", "status"]
    assert outcome.verdict.decision is acs.Decision.ALLOW
    assert allow_policy.invocations[0]["input"]["tool"]["name"] == "shell.execute"

    deny_policy = ScriptedNativePolicy({"decision": "deny", "reason": "blocked-native"})
    deny_skill = GovernanceSkill(
        acs.AgentControl.from_native(_NATIVE_MANIFEST, policy_dispatcher=deny_policy)
    )
    with pytest.raises(ShellPolicyViolation, match="blocked-native"):
        deny_skill.authorize_shell_command(["danger"], api="test")


def test_builds_canonical_pre_tool_call_snapshot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("OPENSHELL_SANDBOX_ID", "sandbox-42")
    monkeypatch.setenv("OPENSHELL_COMPUTE_DRIVER", "gvisor")
    control = FakeControl()
    skill = GovernanceSkill(
        control, agent_id="did:agt:test", context={"tenant": "alpha"}
    )

    command, outcome = skill.authorize_shell_command(
        ["git", "status"],
        api="subprocess.run",
        cwd=tmp_path,
        context={"task": "review"},
    )

    assert command == ["git", "status"]
    assert outcome.verdict.decision is acs.Decision.ALLOW
    point, snapshot, _ = control.requests[0]
    assert point.value == "pre_tool_call"
    assert snapshot["tool_call"]["name"] == "shell.execute"
    args = snapshot["tool_call"]["args"]
    assert args == {
        "executable": "git",
        "argv": ["git", "status"],
        "command": "git status",
        "shell": False,
        "api": "subprocess.run",
        "cwd": str(tmp_path),
        "sandbox_id": "sandbox-42",
        "compute_driver": "gvisor",
        "context": {"tenant": "alpha", "task": "review"},
    }
    assert snapshot["envelope"]["agent"]["id"] == "did:agt:test"
    assert snapshot["envelope"]["session"]["id"] == "sandbox-42"


@pytest.mark.parametrize(
    ("decision", "effective_decision"),
    [
        (acs.Decision.DENY, acs.Decision.DENY),
        (acs.Decision.ESCALATE, acs.Decision.DENY),
    ],
)
def test_non_permitting_verdicts_raise(
    decision: acs.Decision, effective_decision: acs.Decision
) -> None:
    skill = GovernanceSkill(FakeControl([result(decision, reason="blocked")]))
    with pytest.raises(ShellPolicyViolation, match="blocked") as caught:
        skill.authorize_shell_command(["danger"], api="test")
    assert caught.value.result.verdict.decision is effective_decision


@pytest.mark.parametrize("decision", [acs.Decision.ALLOW, acs.Decision.WARN])
def test_permitting_verdicts_preserve_command(decision: acs.Decision) -> None:
    original = ("python", "-V")
    command, _ = GovernanceSkill(
        FakeControl([result(decision)])
    ).authorize_shell_command(original, api="test")
    assert command is original


def test_transform_replaces_argv_and_preserves_sequence_type() -> None:
    target = {"argv": ["python", "-V"], "command": "python -V"}
    skill = GovernanceSkill(
        FakeControl([result(acs.Decision.TRANSFORM, transformed=target)])
    )
    command, _ = skill.authorize_shell_command(("unsafe",), api="test")
    assert command == ("python", "-V")


def test_shell_transform_requires_command_string() -> None:
    target = {"argv": ["echo", "safe"]}
    skill = GovernanceSkill(
        FakeControl([result(acs.Decision.TRANSFORM, transformed=target)])
    )
    with pytest.raises(PermissionError, match="string command"):
        skill.authorize_shell_command("unsafe", api="test", shell=True)


@pytest.mark.parametrize("target", [None, [], {}, {"argv": []}, {"argv": [1]}])
def test_invalid_transform_fails_closed(target: Any) -> None:
    skill = GovernanceSkill(
        FakeControl([result(acs.Decision.TRANSFORM, transformed=target)])
    )
    with pytest.raises(
        PermissionError, match="invalid command transform|non-empty string argv"
    ):
        skill.authorize_shell_command(["unsafe"], api="test")


def test_evaluator_exception_fails_closed() -> None:
    with pytest.raises(PermissionError, match="failed closed") as caught:
        GovernanceSkill(BrokenControl()).authorize_shell_command(
            ["echo", "x"], api="test"
        )
    assert isinstance(caught.value.__cause__, RuntimeError)


def test_governed_subprocess_executes_allowed_command() -> None:
    skill = GovernanceSkill(FakeControl())
    with governed_shell(skill, {"operation": "version-check"}):
        completed = subprocess.run(
            [sys.executable, "-c", "print('governed')"],
            check=True,
            capture_output=True,
            text=True,
        )
    assert completed.stdout.strip() == "governed"
    args = skill.session.control.requests[0][1]["tool_call"]["args"]
    assert args["context"] == {"operation": "version-check"}


def test_governed_subprocess_does_not_execute_denied_command(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    skill = GovernanceSkill(FakeControl([result(acs.Decision.DENY)]))
    with governed_shell(skill):
        with pytest.raises(ShellPolicyViolation):
            subprocess.run(
                [sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"]
            )
    assert not marker.exists()


def test_transform_is_applied_before_subprocess_execution() -> None:
    target = {
        "argv": [sys.executable, "-c", "print('safe')"],
        "command": f"{sys.executable} -c \"print('safe')\"",
    }
    skill = GovernanceSkill(
        FakeControl([result(acs.Decision.TRANSFORM, transformed=target)])
    )
    with governed_shell(skill):
        completed = subprocess.run(
            [sys.executable, "-c", "print('unsafe')"],
            capture_output=True,
            text=True,
            check=True,
        )
    assert completed.stdout.strip() == "safe"


def test_transform_of_string_command_executes_as_argv() -> None:
    target = {
        "argv": [sys.executable, "-c", "print('safe-string')"],
        "command": f"{sys.executable} -c \"print('safe-string')\"",
    }
    skill = GovernanceSkill(
        FakeControl([result(acs.Decision.TRANSFORM, transformed=target)])
    )
    with governed_shell(skill):
        completed = subprocess.run("unsafe", capture_output=True, text=True, check=True)
    assert completed.stdout.strip() == "safe-string"


def test_keyword_args_form_is_intercepted() -> None:
    skill = GovernanceSkill(FakeControl())
    with governed_shell(skill):
        subprocess.run(args=[sys.executable, "-c", "pass"], check=True)
    assert (
        skill.session.control.requests[0][1]["tool_call"]["args"]["api"]
        == "subprocess.run"
    )


def test_nested_context_uses_innermost_skill() -> None:
    outer = GovernanceSkill(FakeControl())
    inner = GovernanceSkill(FakeControl())
    with governed_shell(outer):
        with governed_shell(inner):
            subprocess.run([sys.executable, "-c", "pass"], check=True)
        subprocess.run([sys.executable, "-c", "pass"], check=True)
    assert len(inner.session.control.requests) == 1
    assert len(outer.session.control.requests) == 1


def test_interception_is_restored_after_context() -> None:
    original_run = subprocess.run
    original_popen = subprocess.Popen
    with governed_shell(GovernanceSkill(FakeControl())):
        assert subprocess.run is not original_run
        assert subprocess.Popen is not original_popen
    assert subprocess.run is original_run
    assert subprocess.Popen is original_popen


def test_interception_is_restored_when_body_raises() -> None:
    original_run = subprocess.run
    try:
        with governed_shell(GovernanceSkill(FakeControl())):
            raise RuntimeError("body failed")
    except RuntimeError as exc:
        assert str(exc) == "body failed"
    else:
        pytest.fail("governed body did not raise")
    assert subprocess.run is original_run


def test_direct_popen_is_governed() -> None:
    skill = GovernanceSkill(FakeControl())
    with governed_shell(skill):
        process = subprocess.Popen(
            [sys.executable, "-c", "pass"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert process.wait(timeout=10) == 0
    assert (
        skill.session.control.requests[0][1]["tool_call"]["args"]["api"]
        == "subprocess.Popen"
    )


def test_os_system_and_popen_are_governed(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, Any]] = []
    monkeypatch.setattr(
        os, "system", lambda command: calls.append(("system", command)) or 0
    )
    monkeypatch.setattr(
        os,
        "popen",
        lambda command, mode="r", buffering=-1: calls.append(("popen", command)),
    )
    skill = GovernanceSkill(FakeControl())
    with governed_shell(skill):
        assert os.system("echo safe") == 0
        os.popen("echo safe")
    assert calls == [("system", "echo safe"), ("popen", "echo safe")]
    apis = [
        request[1]["tool_call"]["args"]["api"]
        for request in skill.session.control.requests
    ]
    assert apis == ["os.system", "os.popen"]


def test_deactivate_without_activation_is_safe() -> None:
    GovernanceSkill(FakeControl()).deactivate()


def test_contextvars_isolate_concurrent_agents() -> None:
    barrier = threading.Barrier(2)
    controls = [FakeControl(), FakeControl()]

    def worker(index: int) -> None:
        with governed_shell(GovernanceSkill(controls[index]), {"worker": index}):
            barrier.wait()
            subprocess.run([sys.executable, "-c", "pass"], check=True)

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
        assert not thread.is_alive()
    for index, control in enumerate(controls):
        args = control.requests[0][1]["tool_call"]["args"]
        assert args["context"]["worker"] == index


def test_sync_interception_works_inside_running_event_loop() -> None:
    skill = GovernanceSkill(FakeControl())

    async def exercise() -> None:
        with governed_shell(skill):
            subprocess.run([sys.executable, "-c", "pass"], check=True)

    asyncio.run(exercise())
    assert len(skill.session.control.requests) == 1


def test_pathlike_and_bytes_arguments_are_normalized(tmp_path: Path) -> None:
    skill = GovernanceSkill(FakeControl())
    skill.authorize_shell_command((tmp_path / "tool", b"value"), api="test")
    args = skill.session.control.requests[0][1]["tool_call"]["args"]
    assert args["argv"] == [str(tmp_path / "tool"), "value"]


def test_cli_reports_allow(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    skill = GovernanceSkill(FakeControl())
    monkeypatch.setattr(
        GovernanceSkill, "from_manifest", classmethod(lambda cls, path, **kw: skill)
    )
    assert cli_main(["--manifest", "policy.yaml", "echo", "hello"]) == 0
    assert '"decision": "allow"' in capsys.readouterr().out


def test_cli_reports_deny(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    skill = GovernanceSkill(FakeControl([result(acs.Decision.DENY, reason="no")]))
    monkeypatch.setattr(
        GovernanceSkill, "from_manifest", classmethod(lambda cls, path, **kw: skill)
    )
    assert cli_main(["--manifest", "policy.yaml", "danger"]) == 1
    assert '"decision": "deny"' in capsys.readouterr().out
