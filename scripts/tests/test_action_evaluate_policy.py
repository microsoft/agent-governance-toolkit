# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for action/evaluate_policy.py using stand-in runtime modules."""

from __future__ import annotations

import enum
import importlib.util
import json
import sys
import types
from dataclasses import dataclass
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "action" / "evaluate_policy.py"


def _load():
    spec = importlib.util.spec_from_file_location("evaluate_policy", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Decision(enum.Enum):
    ALLOW = "allow"
    DENY = "deny"

    @property
    def permits(self) -> bool:
        return self is _Decision.ALLOW


@dataclass
class _Verdict:
    decision: _Decision
    reason: str | None = None
    message: str | None = None


@dataclass
class _Result:
    verdict: _Verdict


def _acs_module(decision: _Decision, seen: list) -> types.ModuleType:
    class AgentControl:
        @classmethod
        def from_path(cls, path):
            seen.append(path)
            return cls()

        async def evaluate_intervention_point(self, point, snapshot):
            seen.append((point, snapshot))
            return _Result(_Verdict(decision, "tool_denied" if decision is _Decision.DENY else None, "msg"))

    module = types.ModuleType("agent_control_specification")
    module.AgentControl = AgentControl
    return module


@pytest.mark.parametrize("decision,code", [(_Decision.ALLOW, 0), (_Decision.DENY, 1)])
def test_acs_runtime_used_when_available(monkeypatch, capsys, decision, code):
    seen: list = []
    monkeypatch.setitem(sys.modules, "agent_control_specification", _acs_module(decision, seen))
    monkeypatch.setenv("AGT_POLICY", "manifest.yaml")
    monkeypatch.setenv("AGT_IP", "pre_tool_call")
    monkeypatch.setenv("AGT_CONTEXT", json.dumps({"tool": {"name": "shell"}}))
    assert _load().main() == code
    out = json.loads(capsys.readouterr().out)
    assert out["runtime"] == "agent_control_specification"
    assert out["verdict"] == decision.value
    assert seen == ["manifest.yaml", ("pre_tool_call", {"tool": {"name": "shell"}})]


def test_legacy_wrapper_used_for_older_toolkits(monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "agent_control_specification", None)

    class _Legacy:
        verdict, reason_code, message = "deny", "policy:blocked", "blocked"

        def is_allowed(self):
            return False

    class AgtRuntime:
        def __init__(self, path):
            self.path = path

        def evaluate(self, point, snapshot):
            return _Legacy()

    agt = types.ModuleType("agt")
    policies = types.ModuleType("agt.policies")
    policies.AgtRuntime = AgtRuntime
    monkeypatch.setitem(sys.modules, "agt", agt)
    monkeypatch.setitem(sys.modules, "agt.policies", policies)
    monkeypatch.setenv("AGT_POLICY", "manifest.yaml")
    monkeypatch.delenv("AGT_CONTEXT", raising=False)
    assert _load().main() == 1
    assert json.loads(capsys.readouterr().out)["runtime"] == "agt.policies"


def test_invalid_context_fails_closed(monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "agent_control_specification", _acs_module(_Decision.ALLOW, []))
    monkeypatch.setenv("AGT_POLICY", "manifest.yaml")
    monkeypatch.setenv("AGT_CONTEXT", "[1, 2]")
    assert _load().main() == 1
    assert json.loads(capsys.readouterr().out)["verdict"] == "error"
