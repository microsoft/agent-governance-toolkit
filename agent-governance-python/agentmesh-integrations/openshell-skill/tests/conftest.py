# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""A minimal ACS contract stub for local adapter unit tests.

CI uses the real native ACS extension. Developers who cannot build that
extension locally may explicitly opt into this contract stub by setting
``OPENSHELL_TEST_STUB_ACS=1``; the native integration test is then skipped.
"""

from __future__ import annotations

import asyncio
import importlib
import os
import sys
import threading
import types
from dataclasses import dataclass
from enum import Enum
from typing import Any


try:
    importlib.import_module("agent_control_specification")

    _USE_STUB = False
except ImportError:
    if os.getenv("OPENSHELL_TEST_STUB_ACS") != "1":
        raise
    _USE_STUB = True


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    WARN = "warn"
    ESCALATE = "escalate"
    TRANSFORM = "transform"

    @property
    def permits(self) -> bool:
        return self in {Decision.ALLOW, Decision.WARN, Decision.TRANSFORM}


class EnforcementMode(str, Enum):
    ENFORCE = "enforce"
    EVALUATE_ONLY = "evaluate_only"


class InterventionPoint(str, Enum):
    PRE_TOOL_CALL = "pre_tool_call"


@dataclass(frozen=True)
class Transform:
    path: str
    value: Any


@dataclass(frozen=True)
class Verdict:
    decision: Decision
    reason: str | None = None
    message: str | None = None
    transform: Transform | None = None


@dataclass(frozen=True)
class InterventionPointResult:
    verdict: Verdict
    transformed_policy_target: Any = None
    transformed_policy_target_applied: bool = False


class AgentControl:
    @classmethod
    def from_path(cls, path: str) -> "AgentControl":
        raise RuntimeError("native ACS is not available in the unit-test stub")


class HostSession:
    def __init__(
        self,
        control: Any,
        *,
        agent_id: str,
        session_id: str,
        mode: EnforcementMode | str,
    ) -> None:
        self.control = control
        self.agent_id = agent_id
        self.session_id = session_id
        self.mode = EnforcementMode(mode)

    def pre_tool_call(
        self, *, tool_name: str, args: Any, call_id: str
    ) -> InterventionPointResult:
        snapshot = {
            "tool_call": {"name": tool_name, "args": args, "id": call_id},
            "envelope": {
                "agent": {"id": self.agent_id},
                "session": {"id": self.session_id},
                "intervention_point": "pre_tool_call",
            },
        }
        result = _run_sync(
            self.control.evaluate_intervention_point(
                InterventionPoint.PRE_TOOL_CALL, snapshot, self.mode
            )
        )
        if (
            self.mode is EnforcementMode.ENFORCE
            and result.verdict.decision is Decision.ESCALATE
        ):
            try:
                _run_sync(
                    self.control.enforce(
                        InterventionPoint.PRE_TOOL_CALL, result, self.mode
                    )
                )
            except Exception:
                return InterventionPointResult(
                    verdict=Verdict(
                        decision=Decision.DENY,
                        reason=result.verdict.reason,
                        message=result.verdict.message,
                    )
                )
            return InterventionPointResult(
                verdict=Verdict(
                    decision=Decision.ALLOW,
                    reason=result.verdict.reason,
                    message=result.verdict.message,
                )
            )
        return result


def _run_sync(coroutine: Any) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)
    outcome: dict[str, Any] = {}

    def run() -> None:
        try:
            outcome["value"] = asyncio.run(coroutine)
        except Exception as exc:
            outcome["error"] = exc

    thread = threading.Thread(target=run)
    thread.start()
    thread.join()
    if "error" in outcome:
        raise outcome["error"]
    return outcome["value"]


module = types.ModuleType("agent_control_specification")
module._IS_OPEN_SHELL_TEST_STUB = True  # type: ignore[attr-defined]
for name, value in {
    "AgentControl": AgentControl,
    "Decision": Decision,
    "EnforcementMode": EnforcementMode,
    "HostSession": HostSession,
    "InterventionPointResult": InterventionPointResult,
    "Transform": Transform,
    "Verdict": Verdict,
}.items():
    setattr(module, name, value)
if _USE_STUB:
    sys.modules["agent_control_specification"] = module
