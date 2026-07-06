# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Regression tests for the "fail closed and honor inputs" hardening of
agent_control_plane. Each test corresponds to one defect and asserts the
documented repro flips from broken to correct.

Covers:
  #1 kernel fail-open when no policy engine
  #2 KernelMetrics.to_dict returns the int type object for agent_crashes
  #3 policy_checks (and policy_violations) double-increment per syscall
  #4 dict-shaped requests bypass the capability validator
  #5 strict_mode config flag is ignored
  #6 validate_action ignores its parameters (skips validators)
  #7 alignment validator that raises is treated as compliant
  #8 get_audit_log(0) returns the whole log instead of zero entries
"""

import types

import pytest

from agent_control_plane.kernel_space import (
    KernelSpace,
    KernelMetrics,
    SyscallRequest,
    SyscallType,
)
from agent_control_plane.agent_kernel import ActionType
from agent_control_plane.mute_agent import (
    MuteAgentValidator,
    MuteAgentConfig,
    AgentCapability,
)
from agent_control_plane.governance_layer import (
    GovernanceLayer,
    AlignmentPrinciple,
)


class _AllowAllPolicy:
    """Minimal policy engine that never reports a violation."""

    def check_violation(self, agent_role, tool_name, args):
        return None


def _reject_etc_passwd(request):
    """Capability validator: reject reads of /etc/passwd."""
    return request.parameters.get("path") != "/etc/passwd"


def _file_read_config(strict_mode=True):
    cap = AgentCapability(
        name="file_read",
        description="Read allowed files",
        action_types=[ActionType.FILE_READ],
        parameter_schema={},
        validator=_reject_etc_passwd,
    )
    return MuteAgentConfig(
        agent_id="a1",
        capabilities=[cap],
        strict_mode=strict_mode,
    )


# --------------------------------------------------------------------------- #
# kernel_space.py
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_defect1_kernel_fails_closed_without_policy_engine():
    """#1 A kernel with no policy engine denies external syscalls by default."""
    kernel = KernelSpace()  # policy_engine=None, permissive=False
    ctx = kernel.create_agent_context("agent")
    req = SyscallRequest(
        syscall=SyscallType.SYS_EXEC,
        args={"tool": "rm_rf_root", "target": "/"},
    )

    allowed, error = await kernel._check_policy(req, ctx)
    assert allowed is False
    assert error is not None

    # Full syscall path returns a clean denial, not a panic/exception.
    result = await kernel.syscall(req, ctx)
    assert result.success is False
    assert result.error_code == -2


@pytest.mark.asyncio
async def test_defect1_self_scoped_syscalls_allowed_without_engine():
    """#1 Fail-closed is scoped: a no-engine kernel still allows self-scoped
    syscalls (own VFS, lifecycle) while denying external ones (tool execution),
    so an agent can use its own memory and exit cleanly and is not left
    registered."""
    kernel = KernelSpace()  # no engine, non-permissive
    ctx = kernel.create_agent_context("agent")

    # Own-VFS write then read: allowed.
    w = await kernel.syscall(
        SyscallRequest(syscall=SyscallType.SYS_WRITE,
                       args={"path": "/mem/working/n.txt", "data": "hi"}), ctx)
    assert w.success is True
    r = await kernel.syscall(
        SyscallRequest(syscall=SyscallType.SYS_READ,
                       args={"path": "/mem/working/n.txt"}), ctx)
    assert r.success is True

    # SYS_EXEC (external tool execution) stays denied.
    x = await kernel.syscall(
        SyscallRequest(syscall=SyscallType.SYS_EXEC,
                       args={"tool": "rm_rf_root", "target": "/"}), ctx)
    assert x.success is False

    # SYS_EXIT is honored and removes the agent (no leak).
    e = await kernel.syscall(
        SyscallRequest(syscall=SyscallType.SYS_EXIT, args={"code": 0}), ctx)
    assert e.success is True
    assert "agent" not in kernel._agents


@pytest.mark.asyncio
async def test_defect1_permissive_opt_in_allows_without_engine():
    """#1 permissive=True restores the legacy allow-all behavior explicitly."""
    kernel = KernelSpace(permissive=True)
    ctx = kernel.create_agent_context("agent")
    req = SyscallRequest(
        syscall=SyscallType.SYS_EXEC,
        args={"tool": "rm_rf_root", "target": "/"},
    )

    allowed, error = await kernel._check_policy(req, ctx)
    assert allowed is True
    assert error is None


@pytest.mark.asyncio
async def test_defect1_sys_checkpolicy_advisory_fails_closed():
    """#1 The SYS_CHECKPOLICY advisory reports allowed=False when no engine."""
    kernel = KernelSpace()  # non-permissive
    ctx = kernel.create_agent_context("agent")
    req = SyscallRequest(
        syscall=SyscallType.SYS_CHECKPOLICY,
        args={"action": "file_read", "target": "/etc/passwd"},
    )

    result = await kernel.syscall(req, ctx)
    assert result.success is True  # the query itself succeeds
    assert result.return_value["allowed"] is False


def test_defect2_agent_crashes_is_a_count_not_the_int_type():
    """#2 to_dict serializes the agent_crashes count, not the builtin int type."""
    d = KernelMetrics().to_dict()
    assert d["agent_crashes"] == 0
    assert d["agent_crashes"] is not int


@pytest.mark.asyncio
async def test_defect3_policy_checks_increment_once_per_syscall():
    """#3 One enforced syscall advances policy_checks by exactly 1."""
    kernel = KernelSpace(policy_engine=_AllowAllPolicy())
    ctx = kernel.create_agent_context("agent")
    before = kernel.metrics.policy_checks

    await kernel.syscall(SyscallRequest(syscall=SyscallType.SYS_GETPOLICY, args={}), ctx)

    assert kernel.metrics.policy_checks - before == 1


# --------------------------------------------------------------------------- #
# mute_agent.py
# --------------------------------------------------------------------------- #

def test_defect4_dict_request_runs_capability_validator():
    """#4 A dict-shaped request is validated, not silently approved."""
    validator = MuteAgentValidator(_file_read_config())

    dangerous = validator.validate_request(
        {"action_type": ActionType.FILE_READ, "request_id": "d1",
         "parameters": {"path": "/etc/passwd"}}
    )
    assert dangerous.is_valid is False

    # Parity: the equivalent object-shaped request is rejected identically.
    obj = types.SimpleNamespace(
        action_type=ActionType.FILE_READ, request_id="o1",
        parameters={"path": "/etc/passwd"},
    )
    assert validator.validate_request(obj).is_valid is False

    # A safe dict path is still approved.
    safe = validator.validate_request(
        {"action_type": ActionType.FILE_READ, "request_id": "d2",
         "parameters": {"path": "/tmp/ok.txt"}}
    )
    assert safe.is_valid is True


def test_defect4_string_action_type_is_coerced():
    """#4 A string action_type is coerced and still validated."""
    validator = MuteAgentValidator(_file_read_config())
    result = validator.validate_request(
        {"action_type": "file_read", "request_id": "s1",
         "parameters": {"path": "/etc/passwd"}}
    )
    assert result.is_valid is False


def test_defect5_strict_mode_false_allows_out_of_capability():
    """#5 strict_mode=False lets well-formed out-of-capability actions through."""
    non_strict = MuteAgentValidator(_file_read_config(strict_mode=False))
    ok, reason = non_strict.validate_action(ActionType.CODE_EXECUTION, {})
    assert ok is True
    assert reason is None

    # strict_mode=True still rejects the same action.
    strict = MuteAgentValidator(_file_read_config(strict_mode=True))
    ok2, _ = strict.validate_action(ActionType.CODE_EXECUTION, {})
    assert ok2 is False


def test_defect5_malformed_action_type_rejected_in_both_modes():
    """#5 A missing/unknown action_type fails closed regardless of strict_mode."""
    non_strict = MuteAgentValidator(_file_read_config(strict_mode=False))
    ok, _ = non_strict.validate_action("not_a_real_action", {})
    assert ok is False


def test_defect6_validate_action_runs_parameter_validator():
    """#6 validate_action invokes the capability validator on its parameters."""
    validator = MuteAgentValidator(_file_read_config())

    ok, reason = validator.validate_action(ActionType.FILE_READ, {"path": "/etc/passwd"})
    assert ok is False
    assert reason is not None

    ok2, reason2 = validator.validate_action(ActionType.FILE_READ, {"path": "/tmp/ok.txt"})
    assert ok2 is True
    assert reason2 is None


def test_defect6_validator_that_raises_fails_closed():
    """#6/#4 A validator that raises is treated as rejection, not approval."""
    def boom(request):
        raise ValueError("boom")

    cap = AgentCapability(
        name="file_read", description="", action_types=[ActionType.FILE_READ],
        parameter_schema={}, validator=boom,
    )
    validator = MuteAgentValidator(
        MuteAgentConfig(agent_id="a1", capabilities=[cap])
    )
    ok, _ = validator.validate_action(ActionType.FILE_READ, {"path": "/tmp/ok.txt"})
    assert ok is False


# --------------------------------------------------------------------------- #
# governance_layer.py
# --------------------------------------------------------------------------- #

def test_defect7_raising_alignment_validator_is_not_compliant():
    """#7 An alignment validator that raises produces a violation, not aligned."""
    gov = GovernanceLayer()

    def raising_validator(ctx):
        raise ValueError("validator blew up")

    gov.add_alignment_rule(
        principle=AlignmentPrinciple.HARM_PREVENTION,
        description="must not X",
        validator=raising_validator,
    )

    result = gov.check_alignment({"anything": True})
    assert result["aligned"] is False
    assert len(result["violations"]) >= 1
    assert any(v.get("type") == "validator_error" for v in result["violations"])


def test_defect8_get_audit_log_zero_returns_empty():
    """#8 get_audit_log(0) returns zero entries; None returns the whole log."""
    gov = GovernanceLayer()
    gov.request_human_review("r1", "reason 1", {})
    gov.request_human_review("r2", "reason 2", {})

    assert len(gov.get_audit_log(None)) == 2
    assert gov.get_audit_log(0) == []
    assert len(gov.get_audit_log(1)) == 1

    with pytest.raises(ValueError):
        gov.get_audit_log(-1)
