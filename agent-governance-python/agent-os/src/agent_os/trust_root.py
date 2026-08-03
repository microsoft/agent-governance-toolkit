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
        # TrustDecision carries no replacement, so a transform cannot be
        # honoured here. Reporting it as allowed would let the caller run the
        # original action while the policy believed it was rewritten, and this
        # is the final authority, so it fails closed instead.
        if result.transform is not None:
            return TrustDecision(
                allowed=False,
                reason=(
                    "runtime returned a transform the trust root cannot apply "
                    f"({result.reason or result.verdict})"
                ),
                authority="native-runtime",
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

        # The level must be a real integer before it can be compared against the
        # root. ``"0" == 0`` is False in Python, so a string level skipped the
        # determinism check below entirely rather than failing it. ``bool`` is a
        # subclass of ``int`` and ``False == 0``, so it is excluded explicitly
        # instead of being read as the root level.
        if isinstance(level, bool) or not isinstance(level, int):
            return False

        # Level 0 is the root; higher levels are closer to workers. A negative
        # level would sit *above* the deterministic root, which is the one place
        # in the hierarchy that must not be occupied by an agent.
        if level < 0:
            return False

        # Root level must be deterministic — not an LLM agent
        if level == 0 and is_agent:
            return False

        return True

    def is_deterministic(self) -> bool:
        """The authority delegates only to the deterministic ACS runtime."""
        return True
