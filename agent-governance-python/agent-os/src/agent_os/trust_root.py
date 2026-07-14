# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Deterministic trust authority for supervisor hierarchies."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_os.integrations._native_adapter_runtime import NativeAdapterRuntime
from agent_os.integrations.base import AdapterExecutionState


@dataclass
class TrustDecision:
    """Result of a deterministic trust-authority evaluation."""

    allowed: bool
    reason: str
    authority: str
    deterministic: bool = True


class TrustRoot:
    """Final, non-agent authority backed by the native ACS runtime."""

    def __init__(self, runtime: Any, max_escalation_depth: int = 3) -> None:
        self._runtime = NativeAdapterRuntime(runtime)
        self.max_escalation_depth = max_escalation_depth
        self._context = AdapterExecutionState(
            agent_id="trust-root",
            session_id="trust-root-session",
        )

    def validate_action(self, action: dict[str, Any]) -> TrustDecision:
        """Evaluate an action at the native pre-tool intervention point."""
        tool = str(action.get("tool", ""))
        arguments = action.get("arguments", {})
        if not isinstance(arguments, dict):
            arguments = {"value": arguments}
        result = self._runtime.evaluate_pre_tool_call(
            self._context,
            tool_name=tool,
            args=arguments,
            call_id=f"trust-{self._context.call_count + 1}",
        )
        if result.allowed:
            self._context.call_count += 1
        return TrustDecision(
            allowed=result.allowed,
            reason=result.reason or result.verdict,
            authority="native-runtime",
        )

    def validate_supervisor(self, supervisor_config: dict[str, Any]) -> bool:
        """Verify that a supervisor declaration meets root requirements."""
        level = supervisor_config.get("level")
        is_agent = supervisor_config.get("is_agent", True)
        if level is None or not supervisor_config.get("name"):
            return False
        return not (level == 0 and is_agent)

    def is_deterministic(self) -> bool:
        """The authority delegates only to the deterministic ACS runtime."""
        return True
