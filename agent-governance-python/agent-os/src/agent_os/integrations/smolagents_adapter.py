# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
HuggingFace smolagents Integration for Agent-OS
================================================

Provides kernel-level governance for smolagents agent workflows.

Every decision is routed through the supplied native runtime. Transform
verdicts rewrite tool arguments and observations before smolagents consumes
them.

Features:
- Native step-callback integration
- Policy evaluation routed through the ACS runtime
- Transform-verdict rewriting of tool arguments and tool results
- Escalate-verdict approval routing via the configured resolver
- Full audit trail of tool calls and agent runs
- Works without smolagents installed (graceful import handling)
- Compatible with CodeAgent and ToolCallingAgent

Example:
    >>> from agent_os.integrations.smolagents_adapter import SmolagentsKernel
    >>>
    >>> kernel = SmolagentsKernel(runtime=runtime)
    >>> from smolagents import CodeAgent, HfApiModel
    >>> agent = CodeAgent(
    ...     tools=[my_tool],
    ...     model=HfApiModel(),
    ...     step_callbacks=[kernel.as_step_callback()],
    ... )
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Callable

from ._native_adapter_runtime import (
    AdapterResult,
    AdapterRuntime,
)
from ..exceptions import PolicyViolationError
from .base import BaseIntegration, AdapterExecutionState, get_adapter_runtime

logger = logging.getLogger(__name__)

# Graceful import of smolagents
try:
    import smolagents as _smolagents  # noqa: F401

    _HAS_SMOLAGENTS = True
except ImportError:
    _HAS_SMOLAGENTS = False


def _check_smolagents_available() -> None:
    """Raise a helpful error when the ``smolagents`` package is missing."""
    if not _HAS_SMOLAGENTS:
        raise ImportError(
            "The 'smolagents' package is required for live smolagents agent wrapping. "
            "Install it with: pip install smolagents"
        )


@dataclass
class AuditEvent:
    """Single audit trail entry."""

    timestamp: float
    event_type: str
    agent_name: str
    details: dict[str, Any]


class SmolagentsKernel(BaseIntegration):
    """
    Governance kernel for HuggingFace smolagents.

    Extends BaseIntegration and intercepts tool calls on smolagents
    CodeAgent and ToolCallingAgent instances by wrapping each tool's
    ``forward`` method with governance checks.

    Supports human approval workflows for sensitive tools and
    token/call budget tracking.
    """

    def __init__(
        self,
        on_violation: Callable[[PolicyViolationError], None] | None = None,
        *,
        runtime: Any,
    ):
        super().__init__(runtime=runtime)
        self.on_violation = on_violation or self._default_violation_handler
        self._tool_call_count = 0
        self._agent_call_count = 0
        self._start_time = time.time()
        self._audit_log: list[AuditEvent] = []
        self._violations: list[PolicyViolationError] = []
        self._bridge: AdapterRuntime = get_adapter_runtime(runtime)

    @property
    def bridge(self) -> AdapterRuntime:
        """Return the v5 :class:`AdapterRuntime` for this kernel."""
        return self._bridge

    def evaluate_input(
        self, ctx: AdapterExecutionState, input_data: Any
    ) -> AdapterResult:
        """Public access to the AGT ``input`` intervention point evaluation."""
        return self._bridge.evaluate_input(ctx, body=self._to_body(input_data))

    def evaluate_pre_tool_call(
        self,
        ctx: AdapterExecutionState,
        *,
        tool_name: str,
        args: Any,
        call_id: str = "call-1",
    ) -> AdapterResult:
        """AGT ``pre_tool_call`` evaluation for a smolagents tool invocation."""
        normalised: dict[str, Any]
        if isinstance(args, dict):
            normalised = args
        elif isinstance(args, str):
            normalised = {"arguments": args}
        else:
            normalised = {"value": args}
        return self._bridge.evaluate_pre_tool_call(
            ctx, tool_name=tool_name, args=normalised, call_id=call_id
        )

    def evaluate_output(
        self, ctx: AdapterExecutionState, output_data: Any
    ) -> AdapterResult:
        """AGT ``output`` intervention point evaluation for tool results."""
        return self._bridge.evaluate_output(ctx, content=self._to_body(output_data))

    @staticmethod
    def _to_body(data: Any) -> Any:
        """Normalise a smolagents payload to a JSON-serialisable body.

        smolagents tool args may be dicts or strings; tool results may
        also be dictionaries, so the adapter stringifies other payloads.
        """
        if isinstance(data, (str, dict)):
            return data
        if hasattr(data, "content"):
            return str(getattr(data, "content"))
        return str(data)

    def _get_or_create_context(self, agent_name: str) -> AdapterExecutionState:
        """Return (and lazily create) the :class:`AdapterExecutionState` for ``agent_name``.

        Smolagents identifies agents only by name, so the adapter maintains
        one state per agent name.
        """
        ctx = self.contexts.get(agent_name)
        if ctx is None:
            ctx = AdapterExecutionState(
                agent_id=agent_name,
                session_id=f"smol-{agent_name}-{int(time.time())}",
            )
            self.contexts[agent_name] = ctx
        return ctx

    # ------------------------------------------------------------------
    # BaseIntegration abstract methods
    # ------------------------------------------------------------------

    def as_step_callback(self) -> "GovernanceStepCallback":
        """Create a governance callback for smolagents' native ``step_callbacks``.

        Returns a ``GovernanceStepCallback`` that can be passed directly to
        a smolagents agent's ``step_callbacks`` list::

            kernel = SmolagentsKernel(runtime=runtime)
            callback = kernel.as_step_callback()

            agent = CodeAgent(
                tools=[...],
                model=model,
                step_callbacks=[callback],
            )

        This is the **recommended** integration pattern for smolagents,
        as it uses the framework's native callback system instead of
        monkey-patching tool ``forward`` methods.

        Returns:
            A ``GovernanceStepCallback`` instance.
        """
        return GovernanceStepCallback(self)

    def _default_violation_handler(self, error: PolicyViolationError) -> None:
        """Default handler called when a policy violation occurs.

        Logs the violation as an error. Override by passing a custom
        on_violation callback to the kernel constructor.

        Args:
            error: The PolicyViolationError that was raised.
        """
        logger.error(f"Policy violation: {error}")

    def _record(self, event_type: str, agent_name: str, details: dict[str, Any]) -> None:
        """Append an audit event to the internal audit log.

        Records the event only when log_all_calls is enabled.

        Args:
            event_type: Short string label for the event.
            agent_name: ID or name of the agent generating the event.
            details: Arbitrary dict of additional context.
        """
        self._audit_log.append(
                AuditEvent(
                    timestamp=time.time(),
                    event_type=event_type,
                    agent_name=agent_name,
                    details=details,
                )
            )

    def reset(self) -> None:
        """Reset lifecycle counters for a new execution."""
        self._tool_call_count = 0
        self._agent_call_count = 0
        self._start_time = time.time()

    def get_audit_log(self) -> list[AuditEvent]:
        """Return the full audit trail."""
        return list(self._audit_log)

    def get_violations(self) -> list[PolicyViolationError]:
        """Return all collected violations."""
        return list(self._violations)

    def get_stats(self) -> dict[str, Any]:
        """Return native runtime and lifecycle statistics."""
        return {
            "tool_calls": self._tool_call_count,
            "agent_calls": self._agent_call_count,
            "violations": len(self._violations),
            "audit_events": len(self._audit_log),
        }

    def health_check(self) -> dict[str, Any]:
        """Return adapter health status."""
        elapsed = time.time() - self._start_time
        has_violations = len(self._violations) > 0
        return {
            "status": "degraded" if has_violations else "healthy",
            "backend": "smolagents",
            "smolagents_available": _HAS_SMOLAGENTS,
            "violations": len(self._violations),
            "uptime_seconds": round(elapsed, 2),
        }


# ═══════════════════════════════════════════════════════════════════
# Native Hook: GovernanceStepCallback
# ═══════════════════════════════════════════════════════════════════
#
# smolagents provides ``step_callbacks`` — a list of callables
# invoked after each agent step with (step, agent) signature.
# GovernanceStepCallback implements this protocol.
#
# Usage:
#     kernel = SmolagentsKernel(runtime=runtime)
#     agent = CodeAgent(
#         tools=[...], model=model,
#         step_callbacks=[kernel.as_step_callback()],
#     )
# ═══════════════════════════════════════════════════════════════════


class GovernanceStepCallback:
    """Governance callback for smolagents' native ``step_callbacks`` system.

    Implements the smolagents step-callback protocol
    (``__call__(step, agent)``) and inspects each completed step for
    governance violations.

    The callback evaluates tool calls and observations through the native
    runtime and records an audit trail for every step.

    Example::

        kernel = SmolagentsKernel(runtime=runtime)
        callback = kernel.as_step_callback()

        agent = CodeAgent(
            tools=[web_search_tool],
            model=model,
            step_callbacks=[callback],
        )
    """

    def __init__(self, kernel: SmolagentsKernel) -> None:
        self._kernel = kernel
        self._step_count: int = 0

    @property
    def kernel(self) -> SmolagentsKernel:
        """Return the governing kernel."""
        return self._kernel

    @property
    def step_count(self) -> int:
        """Return the number of steps processed."""
        return self._step_count

    def __call__(self, step: Any, agent: Any) -> None:
        """Step-callback protocol implementation for smolagents.

        Called by the smolagents runtime after each agent step completes.
        Inspects the step for tool calls and validates them against the
        governance policy via the AGT 5.0 ``pre_tool_call`` intervention
        point. Observations are validated via the AGT ``output``
        intervention point so transform/deny/escalate verdicts flow
        through the same engine.

        Args:
            step: A ``smolagents.MemoryStep`` (or similar) containing
                step details such as ``tool_calls`` or ``action``.
            agent: The smolagents agent instance.

        Raises:
            PolicyViolationError: If the step violates governance policy.
        """
        self._step_count += 1
        agent_name = getattr(agent, "name", None) or str(id(agent))
        ctx = self._kernel._get_or_create_context(agent_name)

        # Extract tool calls from the step
        tool_calls = getattr(step, "tool_calls", None) or []
        action = getattr(step, "action", None)
        observation = getattr(step, "observation", None)

        # If the step has an action with a tool call
        if action and hasattr(action, "tool_name"):
            tool_calls = [action]

        for tc in tool_calls:
            tool_name = getattr(tc, "tool_name", None) or getattr(tc, "name", str(tc))
            tool_args = getattr(tc, "tool_arguments", None) or getattr(tc, "arguments", {})

            # ─── AGT pre_tool_call evaluation ───────────────────────
            self._kernel._tool_call_count += 1
            ctx.call_count = max(0, self._kernel._tool_call_count - 1)
            bridge_result = self._kernel.evaluate_pre_tool_call(
                ctx,
                tool_name=tool_name,
                args=tool_args if isinstance(tool_args, (dict, str)) else {"value": tool_args},
                call_id=f"{agent_name}:{tool_name}:{self._step_count}",
            )
            if bridge_result.transform is not None and isinstance(
                bridge_result.transform.value, dict
            ):
                # Rewrite the tool-call args in place per AGT-DELTA D1.1
                # so the subsequent smolagents executor sees the
                # sanitised payload.
                try:
                    if hasattr(tc, "tool_arguments"):
                        tc.tool_arguments = bridge_result.transform.value
                    elif hasattr(tc, "arguments"):
                        tc.arguments = bridge_result.transform.value
                except Exception:  # noqa: BLE001 — best-effort rewrite
                    pass
            if not bridge_result.allowed:
                self._kernel._record(
                    "tool_blocked", agent_name,
                    {"tool": tool_name, "reason": bridge_result.reason},
                )
                error = bridge_result.to_policy_violation(PolicyViolationError)
                self._kernel._violations.append(error)
                self._kernel.on_violation(error)
                raise error

            # Mirror the post-increment count into ctx so the next
            # intervention point's ``builder_for`` sees it. Do NOT call
            # ``record_post_execute`` here — that would double-count
            # against the AGT budget rule.
            ctx.call_count = self._kernel._tool_call_count

            # Audit
            self._kernel._record(
                "tool_executed", agent_name,
                {"tool": tool_name, "step": self._step_count},
            )

        # Scan observation via the AGT ``output`` intervention point.
        if observation:
            bridge_result = self._kernel.evaluate_output(ctx, observation)
            if bridge_result.transform is not None:
                try:
                    step.observation = bridge_result.transform.value
                except Exception:  # noqa: BLE001 — best-effort rewrite
                    pass
            elif not bridge_result.allowed:
                self._kernel._record(
                    "observation_blocked", agent_name,
                    {"reason": bridge_result.reason, "step": self._step_count},
                )
                error = bridge_result.to_policy_violation(PolicyViolationError)
                self._kernel._violations.append(error)
                self._kernel.on_violation(error)
                raise error

    def __repr__(self) -> str:
        return f"GovernanceStepCallback(steps={self._step_count})"


__all__ = [
    "SmolagentsKernel",
    "PolicyViolationError",
    "AuditEvent",
    "GovernanceStepCallback",
    "_HAS_SMOLAGENTS",
    "_check_smolagents_available",
]
