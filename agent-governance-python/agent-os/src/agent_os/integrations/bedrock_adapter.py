# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""AWS Bedrock Agent integration backed by a required native ACS runtime.

Inputs and streamed action-group calls are mediated before Bedrock receives or
exposes them. Host-owned PII protection, rate limiting, and audit remain local.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterator

from ._native_adapter_runtime import (
    AdapterResult,
    AdapterRuntime,
)
from .base import (
    get_adapter_runtime,
    PII_PATTERNS,
    BaseIntegration,
    AdapterExecutionState,
    GovernanceEventType,
    PolicyViolationError,
)
from .rate_limiter import RateLimiter

logger = logging.getLogger("agent_os.bedrock")


try:
    import boto3 as _boto3  # noqa: F401
    _HAS_BOTO3 = True
except ImportError:
    _HAS_BOTO3 = False

# Back-compat alias for the shared ``PII_PATTERNS`` constant (issue #2635).
# Existing consumers can keep importing ``bedrock_adapter._PII_RE`` — the
# pre-refactor name for Bedrock's PII regex list — and continue to get the
# same tuple of compiled regexes, now sourced from a single point of truth
# in :mod:`agent_os.integrations.base`.
_PII_RE = PII_PATTERNS


def _check_boto3() -> None:
    if not _HAS_BOTO3:
        raise ImportError(
            "The 'boto3' package is required for BedrockKernel. "
            "Install it with: pip install boto3"
        )


def _scan_pii(text: str) -> list[str]:
    return [p.pattern for p in _PII_RE if p.search(text)]


@dataclass
class BedrockContext(AdapterExecutionState):
    """Execution context for a Bedrock Agent session.

    Attributes:
        agent_arn: Full ARN of the Bedrock agent (used as trust identity).
        invocation_ids: Recorded invocation IDs for audit.
        action_groups_invoked: Names of action groups triggered in the session.
        blocked_events: Count of action-group events blocked by policy.
    """

    agent_arn: str = ""
    invocation_ids: list[str] = field(default_factory=list)
    action_groups_invoked: list[str] = field(default_factory=list)
    blocked_events: int = 0


class BedrockKernel(BaseIntegration):
    """Govern Bedrock Agent input and action-group calls with ACS."""

    def __init__(
        self,
        rate_limit_per_minute: int = 0,
        *,
        runtime: Any,
    ) -> None:
        """Initialise host rate limiting and the required native runtime."""
        super().__init__(runtime=runtime)
        self._rate_limiter: RateLimiter | None = (
            RateLimiter(max_calls=rate_limit_per_minute, time_window=60.0)
            if rate_limit_per_minute > 0
            else None
        )
        self._start_time = time.monotonic()
        self._last_error: str | None = None
        self._bridge: AdapterRuntime = get_adapter_runtime(runtime)

    @property
    def bridge(self) -> AdapterRuntime:
        """Return the v5 :class:`AdapterRuntime` for this kernel."""
        return self._bridge

    def evaluate_input(
        self, ctx: AdapterExecutionState, input_data: Any
    ) -> AdapterResult:
        """Public access to the AGT ``input`` intervention point evaluation."""
        body = input_data if isinstance(input_data, (str, dict)) else str(input_data)
        return self._bridge.evaluate_input(ctx, body=body)

    def evaluate_pre_tool_call(
        self,
        ctx: AdapterExecutionState,
        *,
        tool_name: str,
        args: dict[str, Any],
        call_id: str = "call-1",
    ) -> AdapterResult:
        """AGT ``pre_tool_call`` evaluation for a Bedrock action-group event."""
        return self._bridge.evaluate_pre_tool_call(
            ctx, tool_name=tool_name, args=args, call_id=call_id
        )


    def wrap(self, client: Any) -> "GovernedBedrockClient":
        """Wrap a Bedrock Agent Runtime client with governance.

        Args:
            client: A ``boto3`` ``bedrock-agent-runtime`` client.

        Returns:
            A :class:`GovernedBedrockClient` that enforces policy.
        """
        _check_boto3()
        ctx = BedrockContext(
            agent_id=f"bedrock-{id(client)}",
            session_id=f"bdr-{int(time.time())}",
        )
        self.contexts[ctx.agent_id] = ctx
        return GovernedBedrockClient(client=client, kernel=self, ctx=ctx)

    def unwrap(self, governed_agent: Any) -> Any:
        if isinstance(governed_agent, GovernedBedrockClient):
            return governed_agent._client
        return governed_agent


    def _check_rate_limit(self, agent_arn: str) -> None:
        if self._rate_limiter is None:
            return
        status = self._rate_limiter.check(agent_arn)
        if not status.allowed:
            raise PolicyViolationError(
                f"Rate limit exceeded for agent ARN '{agent_arn}': "
                f"retry after {status.wait_seconds:.1f}s"
            )

    def _check_input(self, ctx: BedrockContext, input_text: str) -> None:
        """Apply host-side PII protection after runtime evaluation."""
        pii = _scan_pii(input_text)
        if pii:
            self.emit(GovernanceEventType.TOOL_CALL_BLOCKED, {
                "agent_id": ctx.agent_id, "reason": f"PII detected: {pii[0]}",
                "timestamp": datetime.now().isoformat(),
            })
            raise PolicyViolationError(
                f"Input blocked — PII detected (pattern: {pii[0]})"
            )

    def health_check(self) -> dict[str, Any]:
        uptime = time.monotonic() - self._start_time
        return {
            "status": "degraded" if self._last_error else "healthy",
            "backend": "aws-bedrock",
            "last_error": self._last_error,
            "uptime_seconds": round(uptime, 2),
            "active_sessions": len(self.contexts),
        }


class _GovernedEventStream:
    """Wraps Bedrock's streaming EventStream and enforces governance on events.

    Bedrock streams chunks via an ``EventStream``.  This proxy iterates the
    stream and intercepts ``returnControl`` / ``actionGroupInvocation`` events
    to apply tool allow/block-list checks before passing them downstream.
    """

    def __init__(
        self,
        stream: Any,
        kernel: BedrockKernel,
        ctx: BedrockContext,
    ) -> None:
        self._stream = stream
        self._kernel = kernel
        self._ctx = ctx

    def __iter__(self) -> Iterator[dict[str, Any]]:
        for event in self._stream:
            # Intercept returnControl events carrying action-group invocations
            rc = event.get("returnControl") or event.get("chunk", {}).get("returnControl")
            if rc:
                for inv in rc.get("invocationInputs", []):
                    ag = inv.get("actionGroupInvocationInput", {})
                    tool_name = ag.get("actionGroupName") or ag.get("function", "")
                    if tool_name:
                        # Evaluate every action group through ACS before
                        # Bedrock exposes it to the host.
                        tool_args = ag.get("parameters") or {}
                        if not isinstance(tool_args, dict):
                            tool_args = {"value": tool_args}
                        bridge_result = self._kernel.evaluate_pre_tool_call(
                            self._ctx,
                            tool_name=tool_name,
                            args=tool_args,
                            call_id=str(self._ctx.call_count + 1),
                        )
                        if bridge_result.transform is not None and isinstance(
                            bridge_result.transform.value, dict
                        ):
                            # Rewrite the action-group parameters in
                            # place per AGT-DELTA D1.1 so the
                            # downstream Bedrock consumer sees the
                            # AGT-redacted payload.
                            try:
                                ag["parameters"] = bridge_result.transform.value
                            except Exception:  # noqa: BLE001 — best-effort rewrite
                                pass
                        if not bridge_result.allowed:
                            self._ctx.blocked_events += 1
                            logger.warning(
                                "Bedrock action blocked by AGT | tool=%s agent=%s",
                                tool_name, self._ctx.agent_id,
                            )
                            self._kernel.emit(GovernanceEventType.TOOL_CALL_BLOCKED, {
                                "agent_id": self._ctx.agent_id,
                                "tool_name": tool_name,
                                "reason": bridge_result.reason,
                                "timestamp": datetime.now().isoformat(),
                            })
                            raise bridge_result.to_policy_violation(PolicyViolationError)
                        self._ctx.action_groups_invoked.append(tool_name)
                        self._ctx.call_count += 1
                        self._ctx.tool_calls.append({
                            "name": tool_name,
                            "timestamp": datetime.now().isoformat(),
                        })
                        logger.info(
                            "Bedrock action allowed | tool=%s agent=%s",
                            tool_name, self._ctx.agent_id,
                        )
            yield event

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


class GovernedBedrockClient:
    """Bedrock Agent Runtime client wrapped with Agent OS governance.

    Drop-in proxy for a ``boto3`` ``bedrock-agent-runtime`` client.
    All ``invoke_agent`` calls are governed; all other attributes are
    transparently proxied to the underlying client.

    Example::

        governed = kernel.wrap(boto3.client("bedrock-agent-runtime"))
        response = governed.invoke_agent(
            agentId="ABCDEF",
            agentAliasId="ALIAS1",
            sessionId="s-123",
            inputText="List all orders",
        )
        for event in response["completion"]:
            ...  # events already filtered by governance
    """

    def __init__(
        self,
        client: Any,
        kernel: BedrockKernel,
        ctx: BedrockContext,
    ) -> None:
        self._client = client
        self._kernel = kernel
        self._ctx = ctx

    def invoke_agent(self, **kwargs: Any) -> dict[str, Any]:
        """Mediate a Bedrock call and return its governed event stream."""
        agent_id_param = kwargs.get("agentId", "")
        agent_alias = kwargs.get("agentAliasId", "")
        region = getattr(getattr(self._client, "meta", None), "region_name", "")
        agent_arn = f"arn:aws:bedrock:{region}::agent/{agent_id_param}/{agent_alias}"
        self._ctx.agent_arn = agent_arn

        # 1. Rate limit
        self._kernel._check_rate_limit(agent_arn)

        # 2. Native runtime input evaluation, followed by host-side PII checks.
        input_text = kwargs.get("inputText", "")
        if input_text:
            result = self._kernel.evaluate_input(self._ctx, input_text)
            if result.transform is not None and isinstance(result.transform.value, str):
                input_text = result.transform.value
                kwargs["inputText"] = input_text
            if not result.allowed:
                self._kernel.emit(GovernanceEventType.POLICY_VIOLATION, {
                    "agent_id": self._ctx.agent_id,
                    "agent_arn": agent_arn,
                    "reason": result.reason,
                    "timestamp": datetime.now().isoformat(),
                })
                raise result.to_policy_violation(PolicyViolationError)
            self._kernel._check_input(self._ctx, input_text)

        # Audit log
        logger.info(
            "Bedrock invoke_agent | arn=%s session=%s",
            agent_arn, kwargs.get("sessionId", ""),
        )
        self._kernel.emit(GovernanceEventType.POLICY_CHECK, {
            "agent_id": self._ctx.agent_id,
            "agent_arn": agent_arn,
            "timestamp": datetime.now().isoformat(),
        })

        # 5. Execute
        try:
            response = self._client.invoke_agent(**kwargs)
        except Exception as exc:
            self._kernel._last_error = str(exc)
            raise

        invocation_id = response.get("ResponseMetadata", {}).get("RequestId", f"req-{int(time.time())}")
        self._ctx.invocation_ids.append(invocation_id)

        # Wrap the completion stream with governance
        if "completion" in response:
            response = dict(response)
            response["completion"] = _GovernedEventStream(
                response["completion"], self._kernel, self._ctx
            )

        self._kernel.post_execute(self._ctx, response)
        return response

    def get_context(self) -> BedrockContext:
        """Return the session execution context."""
        return self._ctx

    def get_audit_summary(self) -> dict[str, Any]:
        """Return a structured audit summary for this session."""
        return {
            "agent_arn": self._ctx.agent_arn,
            "invocation_ids": self._ctx.invocation_ids,
            "action_groups_invoked": self._ctx.action_groups_invoked,
            "tool_call_count": self._ctx.call_count,
            "blocked_events": self._ctx.blocked_events,
            "session_id": self._ctx.session_id,
        }

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)

    def __repr__(self) -> str:
        return (
            f"GovernedBedrockClient(agent_arn={self._ctx.agent_arn!r}, "
            f"calls={self._ctx.call_count})"
        )
