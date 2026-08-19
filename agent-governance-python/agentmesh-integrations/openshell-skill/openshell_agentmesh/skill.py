# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Fail-closed shell interception for OpenShell-hosted Python agents."""

from __future__ import annotations

import contextvars
import os
import shlex
import subprocess
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping

from agent_control_specification import (
    AgentControl,
    Decision,
    EnforcementMode,
    HostSession,
)
from agent_control_specification import InterventionPointResult


class ShellPolicyViolation(PermissionError):
    """Raised before execution when ACS does not permit a shell command."""

    def __init__(self, result: InterventionPointResult) -> None:
        self.result = result
        reason = (
            result.verdict.message
            or result.verdict.reason
            or result.verdict.decision.value
        )
        super().__init__(f"OpenShell command blocked by policy: {reason}")


class GovernanceSkill:
    """Bind an ACS host session to Python process-creation APIs."""

    def __init__(
        self,
        control: Any,
        *,
        agent_id: str | None = None,
        session_id: str | None = None,
        mode: EnforcementMode | str = EnforcementMode.ENFORCE,
        context: Mapping[str, Any] | None = None,
    ) -> None:
        resolved_agent_id = agent_id or os.getenv("AGT_AGENT_ID") or "openshell-agent"
        resolved_session_id = (
            session_id
            or os.getenv("OPENSHELL_SANDBOX_ID")
            or os.getenv("SANDBOX_ID")
            or "openshell-session"
        )
        self.session = HostSession(
            control,
            agent_id=resolved_agent_id,
            session_id=resolved_session_id,
            mode=mode,
        )
        self.context = dict(context or {})

    @classmethod
    def from_manifest(
        cls, manifest_path: str | os.PathLike[str], **kwargs: Any
    ) -> "GovernanceSkill":
        """Load an ACS manifest and create an OpenShell governance skill."""
        return cls(AgentControl.from_path(os.fspath(manifest_path)), **kwargs)

    def authorize_shell_command(
        self,
        command: Any,
        *,
        api: str,
        shell: bool = False,
        cwd: Any = None,
        context: Mapping[str, Any] | None = None,
    ) -> tuple[Any, InterventionPointResult]:
        args = _command_args(command, shell=shell)
        command_context = dict(self.context)
        command_context.update(context or {})
        target: dict[str, Any] = {
            "executable": Path(args[0]).name if args else "",
            "argv": args,
            "command": _command_text(command),
            "shell": shell,
            "api": api,
            "cwd": os.fspath(cwd) if cwd is not None else os.getcwd(),
            "sandbox_id": os.getenv("OPENSHELL_SANDBOX_ID") or os.getenv("SANDBOX_ID"),
            "compute_driver": os.getenv("OPENSHELL_COMPUTE_DRIVER"),
            "context": command_context,
        }
        try:
            result = self.session.pre_tool_call(
                tool_name="shell.execute", args=target, call_id=uuid.uuid4().hex
            )
        except Exception as exc:
            raise PermissionError("OpenShell policy evaluation failed closed") from exc

        if not result.verdict.decision.permits:
            raise ShellPolicyViolation(result)
        if result.verdict.decision is Decision.TRANSFORM:
            transformed = result.transformed_policy_target
            if not isinstance(transformed, Mapping):
                raise PermissionError(
                    "OpenShell policy returned an invalid command transform"
                )
            return _transformed_command(command, transformed, shell=shell), result
        return command, result

    def activate(self, context: Mapping[str, Any] | None = None) -> "GovernanceSkill":
        _activate_shell_interception(self, context)
        return self

    def deactivate(self) -> None:
        _deactivate_shell_interception(self)


@contextmanager
def governed_shell(
    skill: GovernanceSkill, context: Mapping[str, Any] | None = None
) -> Iterator[GovernanceSkill]:
    """Govern process creation in the current async or thread context."""
    skill.activate(context=context)
    try:
        yield skill
    finally:
        skill.deactivate()


_SHELL_PATCH_LOCK = threading.RLock()
_SHELL_PATCH_LOCAL = threading.local()
_SHELL_ORIGINALS: dict[str, Any] = {}
_PATCH_USERS = 0
_ACTIVE_SHELL_SKILLS: contextvars.ContextVar[
    tuple[tuple[GovernanceSkill, dict[str, Any]], ...]
] = contextvars.ContextVar("openshell_active_governance", default=())


def _activate_shell_interception(
    skill: GovernanceSkill, context: Mapping[str, Any] | None
) -> None:
    global _PATCH_USERS
    with _SHELL_PATCH_LOCK:
        if not _SHELL_ORIGINALS:
            _SHELL_ORIGINALS.update(
                {
                    "subprocess.run": subprocess.run,
                    "subprocess.Popen": subprocess.Popen,
                    "os.system": os.system,
                    "os.popen": os.popen,
                }
            )
            subprocess.run = _governed_subprocess_run
            subprocess.Popen = _governed_subprocess_popen
            os.system = _governed_os_system
            os.popen = _governed_os_popen
        _PATCH_USERS += 1
    _ACTIVE_SHELL_SKILLS.set(
        (*_ACTIVE_SHELL_SKILLS.get(), (skill, dict(context or {})))
    )


def _deactivate_shell_interception(skill: GovernanceSkill) -> None:
    global _PATCH_USERS
    stack = list(_ACTIVE_SHELL_SKILLS.get())
    for index in range(len(stack) - 1, -1, -1):
        if stack[index][0] is skill:
            del stack[index]
            _ACTIVE_SHELL_SKILLS.set(tuple(stack))
            with _SHELL_PATCH_LOCK:
                _PATCH_USERS = max(0, _PATCH_USERS - 1)
                if _PATCH_USERS == 0 and _SHELL_ORIGINALS:
                    subprocess.run = _SHELL_ORIGINALS.pop("subprocess.run")
                    subprocess.Popen = _SHELL_ORIGINALS.pop("subprocess.Popen")
                    os.system = _SHELL_ORIGINALS.pop("os.system")
                    os.popen = _SHELL_ORIGINALS.pop("os.popen")
            return


def _authorize_active_shell(
    command: Any, *, api: str, shell: bool = False, cwd: Any = None
) -> Any:
    if getattr(_SHELL_PATCH_LOCAL, "bypass", False):
        return command
    stack = _ACTIVE_SHELL_SKILLS.get()
    if not stack:
        return command
    skill, context = stack[-1]
    transformed, _ = skill.authorize_shell_command(
        command, api=api, shell=shell, cwd=cwd, context=context
    )
    return transformed


def _with_popen_bypass(callable_obj: Any, *args: Any, **kwargs: Any) -> Any:
    previous = getattr(_SHELL_PATCH_LOCAL, "bypass", False)
    _SHELL_PATCH_LOCAL.bypass = True
    try:
        return callable_obj(*args, **kwargs)
    finally:
        _SHELL_PATCH_LOCAL.bypass = previous


def _governed_subprocess_run(*popenargs: Any, **kwargs: Any) -> Any:
    command = popenargs[0] if popenargs else kwargs.get("args")
    command = _authorize_active_shell(
        command,
        api="subprocess.run",
        shell=bool(kwargs.get("shell", False)),
        cwd=kwargs.get("cwd"),
    )
    if popenargs:
        popenargs = (command, *popenargs[1:])
    else:
        kwargs["args"] = command
    return _with_popen_bypass(_SHELL_ORIGINALS["subprocess.run"], *popenargs, **kwargs)


def _governed_subprocess_popen(*popenargs: Any, **kwargs: Any) -> Any:
    if getattr(_SHELL_PATCH_LOCAL, "bypass", False):
        return _SHELL_ORIGINALS["subprocess.Popen"](*popenargs, **kwargs)
    command = popenargs[0] if popenargs else kwargs.get("args")
    command = _authorize_active_shell(
        command,
        api="subprocess.Popen",
        shell=bool(kwargs.get("shell", False)),
        cwd=kwargs.get("cwd"),
    )
    if popenargs:
        popenargs = (command, *popenargs[1:])
    else:
        kwargs["args"] = command
    return _SHELL_ORIGINALS["subprocess.Popen"](*popenargs, **kwargs)


def _governed_os_system(command: Any) -> int:
    transformed = _authorize_active_shell(command, api="os.system", shell=True)
    return _SHELL_ORIGINALS["os.system"](transformed)


def _governed_os_popen(command: Any, mode: str = "r", buffering: int = -1) -> Any:
    transformed = _authorize_active_shell(command, api="os.popen", shell=True)
    return _SHELL_ORIGINALS["os.popen"](transformed, mode, buffering)


def _command_args(command: Any, *, shell: bool) -> list[str]:
    if command is None:
        return []
    if isinstance(command, (list, tuple)):
        return [_stringify_arg(arg) for arg in command]
    text = _stringify_arg(command)
    if shell:
        return [text]
    try:
        return shlex.split(text, posix=os.name != "nt")
    except ValueError:
        return [text]


def _command_text(command: Any) -> str:
    if isinstance(command, (list, tuple)):
        return shlex.join([_stringify_arg(arg) for arg in command])
    return _stringify_arg(command)


def _stringify_arg(arg: Any) -> str:
    if isinstance(arg, bytes):
        return os.fsdecode(arg)
    if isinstance(arg, os.PathLike):
        value = os.fspath(arg)
        return os.fsdecode(value) if isinstance(value, bytes) else value
    return str(arg)


def _transformed_command(
    original: Any, transformed: Mapping[str, Any], *, shell: bool
) -> Any:
    argv = transformed.get("argv")
    command = transformed.get("command")
    if shell:
        if not isinstance(command, str):
            raise PermissionError(
                "OpenShell shell transform must provide a string command"
            )
        return command
    if (
        not isinstance(argv, list)
        or not argv
        or not all(isinstance(v, str) for v in argv)
    ):
        raise PermissionError(
            "OpenShell command transform must provide a non-empty string argv"
        )
    if isinstance(original, tuple):
        return tuple(argv)
    return argv
