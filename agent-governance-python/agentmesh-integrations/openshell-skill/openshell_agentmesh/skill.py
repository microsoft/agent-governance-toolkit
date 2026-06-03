# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Governance skill for OpenShell sandboxed agents."""

from __future__ import annotations
from contextlib import contextmanager
import json
import os
import re
import shlex
import subprocess
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional
import yaml

@dataclass
class PolicyDecision:
    allowed: bool
    action: str
    reason: str
    policy_name: Optional[str] = None
    trust_score: float = 0.0


class ShellPolicyViolation(PermissionError):
    """Raised when shell interception blocks a command before execution."""

    def __init__(self, decision: PolicyDecision) -> None:
        self.decision = decision
        super().__init__(decision.reason)

@dataclass
class _PolicyRule:
    name: str
    field: str
    operator: str
    value: Any
    action: str
    priority: int = 0
    message: str = ""

class GovernanceSkill:
    def __init__(
        self,
        policy_dir: Optional[Path] = None,
        trust_threshold: float = 0.5,
        audit_path: Optional[Path] = None,
    ) -> None:
        self._rules: list[_PolicyRule] = []
        self._trust_scores: dict[str, float] = {}
        self._audit_log: list[dict] = []
        self._trust_threshold = trust_threshold
        self._audit_path = Path(audit_path) if audit_path else None
        if policy_dir:
            self.load_policies(policy_dir)

    def load_policies(self, policy_dir: Path) -> int:
        policy_dir = Path(policy_dir)
        if not policy_dir.is_dir():
            raise FileNotFoundError(f"Policy directory not found: {policy_dir}")
        self._rules.clear()
        for yaml_file in sorted(policy_dir.glob("*.yaml")):
            with open(yaml_file, encoding="utf-8") as f:
                doc = yaml.safe_load(f)
            if not doc:
                continue
            for rd in doc.get("rules", []):
                cond = rd.get("condition", {})
                self._rules.append(_PolicyRule(name=rd.get("name", yaml_file.stem), field=cond.get("field", "action"), operator=cond.get("operator", "equals"), value=cond.get("value", ""), action=rd.get("action", "deny"), priority=rd.get("priority", 0), message=rd.get("message", "")))
        self._rules.sort(key=lambda r: r.priority, reverse=True)
        return len(self._rules)

    def check_policy(self, action: str, context: Optional[dict] = None) -> PolicyDecision:
        context = context or {}
        agent_did = context.get("agent_did", "unknown")
        trust = self.get_trust_score(agent_did)
        if trust < self._trust_threshold:
            reason = f"Trust score {trust:.2f} below threshold {self._trust_threshold:.2f}"
            decision = PolicyDecision(allowed=False, action=action, reason=reason, trust_score=trust)
            self.log_action(action, "deny", agent_did, context)
            return decision
        for rule in self._rules:
            target = action if rule.field == "action" else context.get(rule.field, "")
            if self._match(rule.operator, target, rule.value):
                allowed = rule.action == "allow"
                reason = rule.message or (("Allowed" if allowed else "Denied") + " by rule: " + rule.name)
                decision = PolicyDecision(allowed=allowed, action=action, reason=reason, policy_name=rule.name, trust_score=trust)
                self.log_action(action, "allow" if allowed else "deny", agent_did, context)
                return decision
        decision = PolicyDecision(allowed=False, action=action, reason="No matching rule - default deny", trust_score=trust)
        self.log_action(action, "deny", agent_did, context)
        return decision

    def authorize_shell_command(
        self,
        command: Any,
        *,
        api: str,
        shell: bool = False,
        context: Optional[dict] = None,
    ) -> PolicyDecision:
        action, shell_context = _shell_action_and_context(
            command,
            api=api,
            shell=shell,
            context=context,
        )
        decision = self.check_policy(action, shell_context)
        if not decision.allowed:
            raise ShellPolicyViolation(decision)
        return decision

    def activate(self, context: Optional[dict] = None) -> "GovernanceSkill":
        """Enable opt-in shell interception for this process."""

        _activate_shell_interception(self, context)
        return self

    def deactivate(self) -> None:
        """Disable this skill's shell interception activation."""

        _deactivate_shell_interception(self)

    def get_trust_score(self, agent_did: str) -> float:
        return self._trust_scores.get(agent_did, 1.0)

    def adjust_trust(self, agent_did: str, delta: float) -> float:
        current = self.get_trust_score(agent_did)
        new_score = max(0.0, min(1.0, current + delta))
        self._trust_scores[agent_did] = new_score
        return new_score

    def log_action(self, action: str, decision: str, agent_did: str = "unknown", context: Optional[dict] = None) -> dict:
        entry = {"timestamp": datetime.now(timezone.utc).isoformat(), "action": action, "decision": decision, "agent_did": agent_did, "trust_score": self.get_trust_score(agent_did), "context": context or {}}
        self._audit_log.append(entry)
        if self._audit_path:
            self._audit_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._audit_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str, sort_keys=True) + "\n")
        return entry

    def get_audit_log(self, limit: int = 50) -> list[dict]:
        return self._audit_log[-limit:]

    @staticmethod
    def _match(operator: str, target: str, value: Any) -> bool:
        if operator == "equals": return target == value
        if operator == "starts_with": return target.startswith(str(value))
        if operator == "contains": return str(value) in target
        if operator == "matches": return bool(re.search(str(value), target))
        if operator == "in": return target in (value if isinstance(value, list) else [value])
        return False


@contextmanager
def governed_shell(skill: GovernanceSkill, context: Optional[dict] = None) -> Iterator[GovernanceSkill]:
    """Temporarily route Python shell APIs through an OpenShell governance skill."""

    skill.activate(context=context)
    try:
        yield skill
    finally:
        skill.deactivate()


_SHELL_PATCH_LOCK = threading.RLock()
_SHELL_PATCH_LOCAL = threading.local()
_SHELL_ORIGINALS: dict[str, Any] = {}
_ACTIVE_SHELL_SKILLS: list[tuple[GovernanceSkill, dict[str, Any]]] = []


def _activate_shell_interception(skill: GovernanceSkill, context: Optional[dict]) -> None:
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
        _ACTIVE_SHELL_SKILLS.append((skill, dict(context or {})))


def _deactivate_shell_interception(skill: GovernanceSkill) -> None:
    with _SHELL_PATCH_LOCK:
        for index in range(len(_ACTIVE_SHELL_SKILLS) - 1, -1, -1):
            if _ACTIVE_SHELL_SKILLS[index][0] is skill:
                del _ACTIVE_SHELL_SKILLS[index]
                break

        if not _ACTIVE_SHELL_SKILLS and _SHELL_ORIGINALS:
            subprocess.run = _SHELL_ORIGINALS.pop("subprocess.run")
            subprocess.Popen = _SHELL_ORIGINALS.pop("subprocess.Popen")
            os.system = _SHELL_ORIGINALS.pop("os.system")
            os.popen = _SHELL_ORIGINALS.pop("os.popen")


def _current_shell_skill() -> Optional[tuple[GovernanceSkill, dict[str, Any]]]:
    with _SHELL_PATCH_LOCK:
        if not _ACTIVE_SHELL_SKILLS:
            return None
        skill, context = _ACTIVE_SHELL_SKILLS[-1]
        return skill, dict(context)


def _authorize_active_shell(command: Any, *, api: str, shell: bool = False) -> None:
    if getattr(_SHELL_PATCH_LOCAL, "bypass", False):
        return
    active = _current_shell_skill()
    if not active:
        return
    skill, context = active
    skill.authorize_shell_command(command, api=api, shell=shell, context=context)


def _with_popen_bypass(callable_obj, *args, **kwargs):
    previous = getattr(_SHELL_PATCH_LOCAL, "bypass", False)
    _SHELL_PATCH_LOCAL.bypass = True
    try:
        return callable_obj(*args, **kwargs)
    finally:
        _SHELL_PATCH_LOCAL.bypass = previous


def _governed_subprocess_run(*popenargs, **kwargs):
    command = popenargs[0] if popenargs else kwargs.get("args")
    _authorize_active_shell(command, api="subprocess.run", shell=bool(kwargs.get("shell", False)))
    return _with_popen_bypass(_SHELL_ORIGINALS["subprocess.run"], *popenargs, **kwargs)


def _governed_subprocess_popen(*popenargs, **kwargs):
    if getattr(_SHELL_PATCH_LOCAL, "bypass", False):
        return _SHELL_ORIGINALS["subprocess.Popen"](*popenargs, **kwargs)
    command = popenargs[0] if popenargs else kwargs.get("args")
    _authorize_active_shell(command, api="subprocess.Popen", shell=bool(kwargs.get("shell", False)))
    return _SHELL_ORIGINALS["subprocess.Popen"](*popenargs, **kwargs)


def _governed_os_system(command):
    _authorize_active_shell(command, api="os.system", shell=True)
    return _SHELL_ORIGINALS["os.system"](command)


def _governed_os_popen(command, mode="r", buffering=-1):
    _authorize_active_shell(command, api="os.popen", shell=True)
    return _SHELL_ORIGINALS["os.popen"](command, mode, buffering)


def _shell_action_and_context(
    command: Any,
    *,
    api: str,
    shell: bool,
    context: Optional[dict],
) -> tuple[str, dict[str, Any]]:
    args = _command_args(command)
    binary = Path(args[0]).name if args else ""
    command_text = _command_text(command)
    shell_context = dict(context or {})
    shell_context.update(
        {
            "shell_api": api,
            "shell_binary": binary,
            "shell_command": command_text,
            "shell_args": args,
            "shell": shell,
        }
    )
    return f"shell:{binary}", shell_context


def _command_args(command: Any) -> list[str]:
    if command is None:
        return []
    if isinstance(command, (list, tuple)):
        return [_stringify_arg(arg) for arg in command]
    text = _stringify_arg(command)
    try:
        return shlex.split(text)
    except ValueError:
        return [text]


def _command_text(command: Any) -> str:
    if isinstance(command, (list, tuple)):
        return " ".join(shlex.quote(_stringify_arg(arg)) for arg in command)
    return _stringify_arg(command)


def _stringify_arg(arg: Any) -> str:
    if isinstance(arg, bytes):
        return os.fsdecode(arg)
    if isinstance(arg, os.PathLike):
        path = os.fspath(arg)
        return os.fsdecode(path) if isinstance(path, bytes) else path
    return str(arg)
