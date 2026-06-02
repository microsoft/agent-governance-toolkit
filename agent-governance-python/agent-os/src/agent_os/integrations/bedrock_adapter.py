# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AWS Bedrock Agent Governance Adapter

Wraps the Bedrock Agent Runtime client with Agent OS governance: blocked
pattern scanning on inputs, tool allow/block-list enforcement on streaming
action-group events, rate limiting per agent ARN, and a full audit trail.

Backend (AGT 5.0): every policy decision is routed through
:class:`agt.policies.runtime.AgtRuntime` (the ACS-backed v5 engine).
The v4 :class:`~agent_os.integrations.base.GovernancePolicy` is
translated to an AGT manifest via
:func:`agt.policies.bridge.governance_to_acs_manifest` at adapter init
time, an :class:`AgtRuntime` is memoised per policy, and a
:class:`agt.policies.snapshot.SnapshotBuilder` mirrors the v4
``ExecutionContext`` budgets between intervention points. The legacy
``invoke_agent`` surface (including ``PolicyViolationError`` raising
on policy denial) is preserved so v4 callers keep working.
``transform`` verdicts (AGT-DELTA D1.1) rewrite the outbound
``inputText`` before the boto3 client sees it; ``escalate`` verdicts
route through the configured approval resolver per AGT-DELTA D1.4.

Usage::

    from agent_os.integrations import BedrockKernel
    from agent_os.integrations.base import GovernancePolicy
    import boto3

    kernel = BedrockKernel(
        policy=GovernancePolicy(
            blocked_patterns=["DROP TABLE", "rm -rf"],
            allowed_tools=["query_database", "summarize"],
            max_tool_calls=20,
        )
    )

    governed = kernel.wrap(boto3.client("bedrock-agent-runtime", region_name="us-east-1"))
    response = governed.invoke_agent(
        agentId="ABCDEF1234",
        agentAliasId="ALIAS1",
        sessionId="session-xyz",
        inputText="Summarize last quarter sales",
    )

Cedar/OPA policy evaluation is inherited from BaseIntegration::

    kernel = BedrockKernel.from_cedar("policies/bedrock.cedar")
    governed = kernel.wrap(client)

Features:
- Graceful boto3 import (no hard dependency)
- AGT 5.0 ACS runtime evaluation of inputText (input) and action-group
  events (pre_tool_call) via AdapterRuntimeBridge
- Transform-verdict rewriting of outbound inputText
- Escalate-verdict approval routing via the configured resolver
- Blocked-pattern scanning on inputText before invocation
- Tool allow/block-list enforced on action-group invocation events in stream
- max_tool_calls limit enforced per session
- Rate limiting per agent ARN via RateLimiter
- Agent ARN mapped to AGT trust identity for audit
- Full audit trail via GovernanceEventType events
- health_check() endpoint
- wrap() / unwrap() round-trip
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Iterator, Optional

from ._v5_runtime_bridge import (
    AdapterRuntimeBridge,
    BridgeResult,
    get_runtime_bridge,
)
from .base import (
    PII_PATTERNS,
    BaseIntegration,
    ExecutionContext,
    GovernanceEventType,
    GovernancePolicy,
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
class BedrockContext(ExecutionContext):
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
    """AWS Bedrock Agent governance adapter.

    Wraps a ``boto3`` Bedrock Agent Runtime client and enforces governance
    on every ``invoke_agent`` call.

    Args:
        policy: Governance policy.  Uses default when ``None``.
        blocked_tools: Additional tool/action-group names to block regardless
            of ``policy.allowed_tools``.
        rate_limit_per_minute: Max ``invoke_agent`` calls per agent ARN per
            minute.  ``0`` disables rate limiting.
        evaluator: Optional ``PolicyEvaluator`` for Cedar/OPA evaluation.

    Example::

        kernel = BedrockKernel(
            policy=GovernancePolicy(allowed_tools=["summarize"]),
            blocked_tools=["delete_s3_bucket"],
            rate_limit_per_minute=60,
        )
        governed = kernel.wrap(boto3.client("bedrock-agent-runtime"))
    """

    def __init__(
        self,
        policy: GovernancePolicy | None = None,
        blocked_tools: list[str] | None = None,
        rate_limit_per_minute: int = 0,
        evaluator: Any = None,
        *,
        approval_resolver: Optional[Callable[..., Any]] = None,
        enable_agt_pii_routing: bool = False,
        _runtime: Optional[Any] = None,
        _runtime_factory: Optional[Callable[..., Any]] = None,
    ) -> None:
        """Initialise the Bedrock governance kernel.

        Args:
            policy: Governance policy.  Uses default when ``None``.
                The policy is translated to an AGT manifest and an
                :class:`agt.policies.runtime.AgtRuntime` is constructed
                over it at init time.
            blocked_tools: Additional tool/action-group names to block
                regardless of ``policy.allowed_tools``.
            rate_limit_per_minute: Max ``invoke_agent`` calls per agent
                ARN per minute. ``0`` disables rate limiting.
            evaluator: Optional ``PolicyEvaluator`` for legacy Cedar/OPA
                policy evaluation. Retained for backward compatibility;
                the primary decision path now runs through the AGT 5.0
                runtime.
            approval_resolver: Optional callable invoked when the AGT
                engine returns an ``escalate`` verdict. Signature
                matches :data:`agt.policies.runtime.ApprovalCallback`.
                When ``None`` an escalate verdict fails closed to
                ``deny``.
            enable_agt_pii_routing: When ``True`` the AGT input
                intervention point runs BEFORE the host-side
                ``_check_input`` PII / blocked-pattern scan, so an
                AGT D1.1 transform on PII (or an AGT deny / escalate)
                takes precedence and is given a chance to redact the
                outbound text. When ``False`` (the v4 default) the
                host scan still fires first and any PII match raises
                a :class:`PolicyViolationError` before the bridge
                runs. Hosts opt in to the AGT routing once they have
                migrated their PII handling into the manifest.

                .. deprecated::
                    The ``False`` default is preserved for v4
                    back-compatibility and is the documented exception
                    to the AGT D1.1 "AGT runs first" ordering called
                    out in ``policy-engine/spec/SPECIFICATION.md``
                    §14. v6 will flip the default to ``True`` so
                    every adapter routes through the bridge first.
                    Existing hosts SHOULD set this to ``True`` ahead
                    of v6 and migrate their PII patterns into the AGT
                    manifest (typically via the stock
                    ``data.agt.patterns`` library plus a
                    ``transform`` verdict).
            _runtime: Test seam — inject a pre-built :class:`AgtRuntime`
                so scenario tests can wire a scripted policy dispatcher
                without OPA on PATH. Not part of the public surface.
            _runtime_factory: Test seam — override the runtime factory
                used by the bridge cache. Not part of the public surface.
        """
        super().__init__(policy, evaluator=evaluator)
        self._blocked_tools: set[str] = set(blocked_tools or [])
        self._rate_limiter: RateLimiter | None = (
            RateLimiter(max_calls=rate_limit_per_minute, time_window=60.0)
            if rate_limit_per_minute > 0
            else None
        )
        self._start_time = time.monotonic()
        self._last_error: str | None = None
        self._approval_resolver = approval_resolver
        self._enable_agt_pii_routing = bool(enable_agt_pii_routing)
        self._bridge: AdapterRuntimeBridge = get_runtime_bridge(
            self.policy,
            approval_resolver=approval_resolver,
            runtime=_runtime,
            runtime_factory=_runtime_factory,
        )

    @property
    def enable_agt_pii_routing(self) -> bool:
        """Whether AGT runs first on the input intervention point."""
        return self._enable_agt_pii_routing

    @property
    def bridge(self) -> AdapterRuntimeBridge:
        """Return the v5 :class:`AdapterRuntimeBridge` for this kernel."""
        return self._bridge

    def evaluate_input(
        self, ctx: ExecutionContext, input_data: Any
    ) -> BridgeResult:
        """Public access to the AGT ``input`` intervention point evaluation."""
        body = input_data if isinstance(input_data, (str, dict)) else str(input_data)
        return self._bridge.evaluate_input(ctx, body=body)

    def evaluate_pre_tool_call(
        self,
        ctx: ExecutionContext,
        *,
        tool_name: str,
        args: dict[str, Any],
        call_id: str = "call-1",
    ) -> BridgeResult:
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
            policy=self.policy,
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
        """Block on pattern matches and PII in input."""
        matched = self.policy.matches_pattern(input_text)
        if matched:
            self.emit(GovernanceEventType.TOOL_CALL_BLOCKED, {
                "agent_id": ctx.agent_id, "reason": f"blocked pattern: {matched[0]}",
                "timestamp": datetime.now().isoformat(),
            })
            raise PolicyViolationError(
                f"Input blocked by policy — matched pattern: {matched[0]!r}"
            )
        pii = _scan_pii(input_text)
        if pii:
            self.emit(GovernanceEventType.TOOL_CALL_BLOCKED, {
                "agent_id": ctx.agent_id, "reason": f"PII detected: {pii[0]}",
                "timestamp": datetime.now().isoformat(),
            })
            raise PolicyViolationError(
                f"Input blocked — PII detected (pattern: {pii[0]})"
            )

    def _check_tool(self, ctx: BedrockContext, tool_name: str) -> None:
        """Enforce tool allow/block-list and call-count limit."""
        if tool_name in self._blocked_tools:
            ctx.blocked_events += 1
            raise PolicyViolationError(
                f"Action group '{tool_name}' is explicitly blocked by policy"
            )
        if self.policy.allowed_tools and tool_name not in self.policy.allowed_tools:
            ctx.blocked_events += 1
            raise PolicyViolationError(
                f"Action group '{tool_name}' is not in the allowed_tools list"
            )
        if ctx.call_count >= self.policy.max_tool_calls:
            raise PolicyViolationError(
                f"Tool call limit reached: {ctx.call_count} >= {self.policy.max_tool_calls}"
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
                        # 1. Host-side allow/block-list + count guard
                        # (preserves the v4 PolicyViolationError types
                        # the existing tests check for).
                        try:
                            self._kernel._check_tool(self._ctx, tool_name)
                        except PolicyViolationError:
                            logger.warning(
                                "Bedrock action blocked | tool=%s agent=%s",
                                tool_name, self._ctx.agent_id,
                            )
                            self._kernel.emit(GovernanceEventType.TOOL_CALL_BLOCKED, {
                                "agent_id": self._ctx.agent_id,
                                "tool_name": tool_name,
                                "timestamp": datetime.now().isoformat(),
                            })
                            raise
                        # 2. AGT pre_tool_call intervention point.
                        # ``ctx.call_count`` is the pre-increment value
                        # going in so the bridge's host-side budget
                        # check mirrors the v4 ``>=`` contract.
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
                            raise PolicyViolationError.from_check_result(
                                bridge_result.check_result
                            )
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
        """Govern a Bedrock ``invoke_agent`` call.

        Enforces:
        1. Rate limiting per agent ARN.
        2. Blocked-pattern and PII scanning on ``inputText``.
        3. AGT 5.0 ACS runtime evaluation at the ``input`` intervention
           point via :class:`AdapterRuntimeBridge`. A ``deny`` verdict
           raises :class:`PolicyViolationError.from_check_result(...)`;
           a ``transform`` verdict (AGT-DELTA D1.1) rewrites
           ``inputText`` before the boto3 client sees it; an
           ``escalate`` verdict that the configured approval resolver
           refuses fails closed to a deny.
        4. Legacy Cedar/OPA gate (kept for backward compatibility).
        5. Tool allow/block-list and call-count on streaming action
           events (also routed through AGT ``pre_tool_call``).

        Args:
            **kwargs: Forwarded to ``client.invoke_agent()``.

        Returns:
            The Bedrock response dict with ``completion`` replaced by a
            governed :class:`_GovernedEventStream`.

        Raises:
            PolicyViolationError: On any governance violation.
        """
        agent_id_param = kwargs.get("agentId", "")
        agent_alias = kwargs.get("agentAliasId", "")
        region = getattr(getattr(self._client, "meta", None), "region_name", "")
        agent_arn = f"arn:aws:bedrock:{region}::agent/{agent_id_param}/{agent_alias}"
        self._ctx.agent_arn = agent_arn

        # 1. Rate limit
        self._kernel._check_rate_limit(agent_arn)

        # 2. Input governance. Per AGT-DELTA D1.1 a transform verdict
        # on the input intervention point rewrites the outbound text
        # before it reaches Bedrock. When ``enable_agt_pii_routing`` is
        # set on the kernel the AGT bridge runs FIRST so a manifest-
        # defined PII transform can redact the text; the host-side
        # ``_check_input`` PII scan then runs against the (possibly
        # redacted) text and only raises when the AGT path allowed
        # without rewriting. When the flag is off (the v4 default) the
        # host scan still fires first to preserve the historical
        # PolicyViolationError shape.
        input_text = kwargs.get("inputText", "")
        if self._kernel.enable_agt_pii_routing and input_text:
            bridge_result = self._kernel.evaluate_input(self._ctx, input_text)
            if bridge_result.transform is not None and isinstance(
                bridge_result.transform.value, str
            ):
                input_text = bridge_result.transform.value
                kwargs["inputText"] = input_text
            if not bridge_result.allowed:
                self._kernel.emit(GovernanceEventType.POLICY_VIOLATION, {
                    "agent_id": self._ctx.agent_id,
                    "agent_arn": agent_arn,
                    "reason": bridge_result.reason,
                    "timestamp": datetime.now().isoformat(),
                })
                raise PolicyViolationError.from_check_result(
                    bridge_result.check_result
                )
            # The bridge approved or transformed; fall through to the
            # host-side PII scan against the effective text.
            self._kernel._check_input(self._ctx, input_text)
        else:
            self._kernel._check_input(self._ctx, input_text)

            # 3. AGT input intervention point (legacy ordering)
            if input_text:
                bridge_result = self._kernel.evaluate_input(self._ctx, input_text)
                if bridge_result.transform is not None and isinstance(
                    bridge_result.transform.value, str
                ):
                    # Rewrite the outbound inputText per AGT-DELTA D1.1 so
                    # the Bedrock client sees the AGT-redacted payload.
                    input_text = bridge_result.transform.value
                    kwargs["inputText"] = input_text
                if not bridge_result.allowed:
                    self._kernel.emit(GovernanceEventType.POLICY_VIOLATION, {
                        "agent_id": self._ctx.agent_id,
                        "agent_arn": agent_arn,
                        "reason": bridge_result.reason,
                        "timestamp": datetime.now().isoformat(),
                    })
                    raise PolicyViolationError.from_check_result(
                        bridge_result.check_result
                    )

        # 4. Cedar/OPA gate (legacy)
        cedar_ctx = self._kernel._build_cedar_context(
            agent_id=agent_arn,
            action_type="invoke_agent",
            tool_name="",
            tool_args={"inputText": input_text},
        )
        allowed, reason = self._kernel._evaluate_policy(cedar_ctx)
        if not allowed:
            raise PolicyViolationError(f"Cedar/OPA policy denied invocation: {reason}")

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
