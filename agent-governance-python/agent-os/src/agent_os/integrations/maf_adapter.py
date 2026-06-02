# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Microsoft Agent Framework (MAF) Governance Adapter

Bridges the Agent OS governance toolkit into MAF's native middleware system.
Four composable middleware layers enforce policy, capability guards, audit
trails, and rogue-agent detection at every level of the agent stack:

- GovernancePolicyMiddleware (AgentMiddleware): Declarative policy enforcement
- CapabilityGuardMiddleware (FunctionMiddleware): Tool allow/deny lists
- AuditTrailMiddleware (AgentMiddleware): Tamper-proof audit logging
- RogueDetectionMiddleware (FunctionMiddleware): Behavioral anomaly detection

Each middleware works independently and can be composed in any combination.

Usage::

    from agent_framework import Agent
    from agent_os.integrations.maf_adapter import create_governance_middleware

    middleware = create_governance_middleware(
        policy_directory="policies/",
        allowed_tools=["web_search", "file_read"],
        enable_rogue_detection=True,
    )

    agent = Agent(
        name="researcher",
        instructions="You are a research assistant.",
        middleware=middleware,
    )
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

from ._v5_runtime_bridge import (
    AdapterRuntimeBridge,
    BridgeResult,
    get_runtime_bridge,
)
from ..exceptions import PolicyViolationError as _CanonicalPolicyViolationError
from .base import BaseIntegration, ExecutionContext, GovernancePolicy

# Optional v4 PolicyEvaluator (legacy back-compat path). When the
# package is missing, GovernancePolicyMiddleware can still be
# constructed via the v5 kernel path.
try:
    from agent_os.policies import PolicyDecision, PolicyEvaluator
except ImportError:  # pragma: no cover - depends on workspace layout
    PolicyDecision = None  # type: ignore[assignment,misc]
    PolicyEvaluator = None  # type: ignore[assignment,misc]

# Optional agentmesh AuditLog. The MAF middleware adapter has shipped
# with agentmesh.governance.AuditLog as the audit sink; we keep using
# it when available but allow the module to import on systems where
# agentmesh is not installed (e.g. the v5 scenario tests).
try:
    from agentmesh.governance import AuditEntry, AuditLog
except ImportError:  # pragma: no cover - depends on workspace layout
    AuditEntry = None  # type: ignore[assignment,misc]
    AuditLog = None  # type: ignore[assignment,misc]

# rogue_detector symbols may not be available in older agent-sre releases
try:
    from agent_sre.anomaly import RiskLevel, RogueAgentDetector, RogueDetectorConfig
except ImportError:
    RiskLevel = None  # type: ignore[assignment,misc]
    RogueAgentDetector = None  # type: ignore[assignment,misc]
    RogueDetectorConfig = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)


class PolicyViolationError(_CanonicalPolicyViolationError):
    """Raised when a MAF agent invocation violates governance policy.

    Subclass of :class:`agent_os.exceptions.PolicyViolationError` so the
    canonical ``from_check_result`` constructor is available while
    preserving the legacy
    ``agent_os.integrations.maf_adapter.PolicyViolationError`` import
    path for v4 callers.
    """

    pass

# ---------------------------------------------------------------------------
# Conditional MAF imports — fall back to local stubs when agent_framework
# is not installed so the module remains importable for testing / linting.
# ---------------------------------------------------------------------------
try:
    from agent_framework import (
        AgentContext,
        AgentMiddleware,
        AgentResponse,
        FunctionInvocationContext,
        FunctionMiddleware,
        Message,
        MiddlewareTermination,
    )
except ImportError:  # pragma: no cover
    logger.debug(
        "agent_framework is not installed; MAF middleware classes will use "
        "protocol-only base stubs."
    )

    class AgentMiddleware:  # type: ignore[no-redef]
        """Stub base class when agent_framework is absent."""

    class FunctionMiddleware:  # type: ignore[no-redef]
        """Stub base class when agent_framework is absent."""

    class AgentContext:  # type: ignore[no-redef]
        """Stub for type hints."""

    class FunctionInvocationContext:  # type: ignore[no-redef]
        """Stub for type hints."""

    class AgentResponse:  # type: ignore[no-redef]
        def __init__(self, *, messages: list[Any] | None = None) -> None:
            self.messages = messages or []

    class Message:  # type: ignore[no-redef]
        def __init__(self, role: str, contents: list[str] | None = None) -> None:
            self.role = role
            self.contents = contents or []

        @property
        def text(self) -> str:
            return str(self.contents[0]) if self.contents else ""

    class MiddlewareTermination(Exception):  # type: ignore[no-redef]
        """Local fallback when agent_framework is not installed."""


# ═══════════════════════════════════════════════════════════════════════════
# 0. MAFKernel (AGT 5.0 v5 entrypoint)
# ═══════════════════════════════════════════════════════════════════════════


class MAFKernel(BaseIntegration):
    """Microsoft Agent Framework adapter for Agent OS (AGT 5.0).

    Builds an :class:`AdapterRuntimeBridge` over the v4
    :class:`GovernancePolicy` so MAF middleware classes can route every
    intervention point evaluation through the ACS-backed
    :class:`agt.policies.runtime.AgtRuntime`. The kernel exposes:

    - :meth:`bridge` — the underlying AdapterRuntimeBridge.
    - :meth:`evaluate_input` — AGT ``input`` intervention point eval.
    - :meth:`evaluate_pre_tool_call` — AGT ``pre_tool_call`` eval.
    - :meth:`as_policy_middleware` — convenience factory returning a
      :class:`GovernancePolicyMiddleware` wired to this kernel.
    - :meth:`as_capability_guard` — convenience factory returning a
      :class:`CapabilityGuardMiddleware` wired to this kernel.

    The legacy :class:`GovernancePolicyMiddleware` /
    :class:`CapabilityGuardMiddleware` constructors that took
    a :class:`PolicyEvaluator` / tool-name lists still work; passing a
    kernel switches them onto the v5 path.
    """

    def __init__(
        self,
        policy: Optional[GovernancePolicy] = None,
        *,
        approval_resolver: Optional[Callable[..., Any]] = None,
        _runtime: Optional[Any] = None,
        _runtime_factory: Optional[Callable[..., Any]] = None,
    ) -> None:
        """Initialise the MAF governance kernel.

        Args:
            policy: Governance policy to enforce. When ``None`` the
                default :class:`GovernancePolicy` is used. The policy
                is translated to an AGT manifest and an
                :class:`agt.policies.runtime.AgtRuntime` is constructed
                over it at init time.
            approval_resolver: Optional callable invoked when the AGT
                engine returns an ``escalate`` verdict. Signature
                matches :data:`agt.policies.runtime.ApprovalCallback`.
                When ``None`` an escalate verdict fails closed to
                ``deny``.
            _runtime: Test seam — inject a pre-built
                :class:`AgtRuntime` so scenario tests can wire a
                scripted policy dispatcher without OPA on PATH. Not
                part of the public surface.
            _runtime_factory: Test seam — override the runtime factory
                used by the bridge cache. Not part of the public
                surface.
        """
        super().__init__(policy)
        self._approval_resolver = approval_resolver
        self._start_time = time.monotonic()
        self._last_error: Optional[str] = None
        self._bridge: AdapterRuntimeBridge = get_runtime_bridge(
            self.policy,
            approval_resolver=approval_resolver,
            runtime=_runtime,
            runtime_factory=_runtime_factory,
        )

    @property
    def bridge(self) -> AdapterRuntimeBridge:
        """Return the v5 :class:`AdapterRuntimeBridge` for this kernel."""
        return self._bridge

    def evaluate_input(
        self, ctx: ExecutionContext, input_data: Any
    ) -> BridgeResult:
        """Public access to the AGT ``input`` intervention point evaluation."""
        body: Any
        if isinstance(input_data, (str, dict)):
            body = input_data
        elif hasattr(input_data, "content"):
            body = str(getattr(input_data, "content"))
        else:
            body = str(input_data)
        return self._bridge.evaluate_input(ctx, body=body)

    def evaluate_pre_tool_call(
        self,
        ctx: ExecutionContext,
        *,
        tool_name: str,
        args: dict[str, Any],
        call_id: str = "call-1",
    ) -> BridgeResult:
        """AGT ``pre_tool_call`` evaluation for a MAF function invocation."""
        return self._bridge.evaluate_pre_tool_call(
            ctx, tool_name=tool_name, args=args, call_id=call_id
        )

    def unwrap(self, agent: Any) -> Any:
        """No-op unwrap — MAFKernel emits middleware, not wrappers."""
        return agent

    def wrap(self, agent: Any) -> Any:
        """No-op wrap — MAFKernel surfaces governance via middleware.

        MAF integrations are composed by passing the middleware list
        returned from :meth:`as_policy_middleware` /
        :meth:`as_capability_guard` (or
        :func:`create_governance_middleware`) to
        ``Agent(middleware=...)``. The wrap()/unwrap() pair satisfies
        the :class:`BaseIntegration` abstract surface but does not
        proxy the agent.
        """
        return agent

    def as_policy_middleware(
        self,
        *,
        audit_log: Any | None = None,
        agent_id: str = "maf-agent",
    ) -> GovernancePolicyMiddleware:
        """Return a :class:`GovernancePolicyMiddleware` backed by this kernel.

        The returned middleware evaluates every agent invocation at
        the AGT ``input`` intervention point via the runtime bridge.
        """
        return GovernancePolicyMiddleware(
            kernel=self,
            audit_log=audit_log,
            agent_id=agent_id,
        )

    def as_capability_guard(
        self,
        *,
        audit_log: Any | None = None,
        agent_id: str = "maf-agent",
    ) -> CapabilityGuardMiddleware:
        """Return a :class:`CapabilityGuardMiddleware` backed by this kernel.

        The returned middleware evaluates every tool invocation at the
        AGT ``pre_tool_call`` intervention point via the runtime bridge.
        """
        return CapabilityGuardMiddleware(
            kernel=self,
            audit_log=audit_log,
            agent_id=agent_id,
        )

    def health_check(self) -> dict[str, Any]:
        """Return adapter health status."""
        uptime = time.monotonic() - self._start_time
        status = "degraded" if self._last_error else "healthy"
        return {
            "status": status,
            "backend": "maf",
            "backend_connected": True,
            "last_error": self._last_error,
            "uptime_seconds": round(uptime, 2),
        }


# ═══════════════════════════════════════════════════════════════════════════
# 1. GovernancePolicyMiddleware
# ═══════════════════════════════════════════════════════════════════════════


class GovernancePolicyMiddleware(AgentMiddleware):
    """AgentMiddleware that evaluates declarative governance policies.

    Two construction paths are supported:

    1. **Legacy v4** — pass an :class:`agent_os.policies.PolicyEvaluator`
       loaded with policy documents. The middleware runs the evaluator's
       v4 :class:`PolicyDecision` and surfaces deny outcomes as
       :class:`MiddlewareTermination`. The ``governance_decision`` key
       attached to the context metadata stays a v4 :class:`PolicyDecision`
       for back-compat.
    2. **AGT 5.0** — pass an :class:`MAFKernel`. The middleware routes
       every agent invocation through the kernel's AGT
       :class:`AdapterRuntimeBridge` at the ``input`` intervention
       point. ``transform`` verdicts (AGT-DELTA D1.1) rewrite the
       most recent user message content before the agent runs;
       ``deny`` verdicts raise :class:`MiddlewareTermination` with the
       canonical AGT reason in the body; ``escalate`` verdicts route
       through the kernel's configured approval resolver per AGT-DELTA
       D1.4 and surface as allow (resolver approved) or deny (resolver
       refused / not wired). The ``governance_decision`` metadata key
       carries the v5 :class:`BridgeResult` on this path so downstream
       middleware can introspect it.

    Args:
        evaluator: Legacy v4 :class:`PolicyEvaluator`. Mutually
            exclusive with ``kernel``.
        kernel: v5 :class:`MAFKernel`. Mutually exclusive with
            ``evaluator``.
        audit_log: Optional :class:`AuditLog` for recording decisions.
        agent_id: Agent identifier used when constructing the
            :class:`ExecutionContext` for the v5 path.
    """

    def __init__(
        self,
        evaluator: Any | None = None,
        audit_log: Any | None = None,
        *,
        kernel: MAFKernel | None = None,
        agent_id: str = "maf-agent",
    ) -> None:
        if evaluator is None and kernel is None:
            raise TypeError(
                "GovernancePolicyMiddleware requires either an evaluator "
                "(legacy v4) or a kernel (AGT 5.0). Pass exactly one."
            )
        if evaluator is not None and kernel is not None:
            raise TypeError(
                "GovernancePolicyMiddleware accepts an evaluator OR a "
                "kernel, not both."
            )
        self.evaluator = evaluator
        self.kernel = kernel
        self.audit_log = audit_log
        self._agent_id = agent_id
        # Lazily build a per-instance ExecutionContext for the v5 path
        # so the bridge SnapshotBuilder can mirror call counts.
        self._v5_ctx: ExecutionContext | None = None

    def _ensure_v5_context(self) -> ExecutionContext:
        """Build the v5 :class:`ExecutionContext` on first need."""
        assert self.kernel is not None
        if self._v5_ctx is None:
            self._v5_ctx = ExecutionContext(
                agent_id=self._agent_id,
                session_id=f"maf-mw-{int(time.time())}",
                policy=self.kernel.policy,
            )
        return self._v5_ctx

    async def process(
        self,
        context: AgentContext,
        call_next: Callable[[], Awaitable[None]],
    ) -> None:
        """Evaluate governance policy before agent execution."""
        if self.kernel is not None:
            await self._process_v5(context, call_next)
        else:
            await self._process_v4(context, call_next)

    async def _process_v4(
        self,
        context: AgentContext,
        call_next: Callable[[], Awaitable[None]],
    ) -> None:
        """Legacy v4 PolicyEvaluator-backed processing."""
        agent_name = getattr(context.agent, "name", "unknown")

        # Extract the last user message text (handle empty conversations).
        last_message_text = ""
        messages: list[Any] = getattr(context, "messages", None) or []
        if messages:
            last_msg = messages[-1]
            # Message.text is the MAF accessor; fall back to str()
            last_message_text = (
                getattr(last_msg, "text", None) or str(last_msg)
            )

        # Build context dict for the policy evaluator.
        eval_context: dict[str, Any] = {
            "agent": agent_name,
            "message": last_message_text,
            "timestamp": time.time(),
            "stream": getattr(context, "stream", False),
            "message_count": len(messages),
        }

        decision = self.evaluator.evaluate(eval_context)

        # Persist the decision in the MAF metadata for downstream middleware.
        metadata: dict[str, Any] = getattr(context, "metadata", {})
        metadata["governance_decision"] = decision

        if not decision.allowed:
            logger.info(
                "Policy DENY for agent '%s': %s (rule=%s)",
                agent_name,
                decision.reason,
                decision.matched_rule,
            )

            # Set a user-visible response explaining the denial.
            context.result = AgentResponse(
                messages=[
                    Message(
                        "assistant",
                        [f"⛔ Policy violation: {decision.reason}"],
                    )
                ]
            )

            if self.audit_log:
                self.audit_log.log(
                    event_type="policy_violation",
                    agent_did=agent_name,
                    action="deny",
                    data={
                        "reason": decision.reason,
                        "matched_rule": decision.matched_rule,
                        "message_preview": last_message_text[:200],
                    },
                    outcome="denied",
                    policy_decision=decision.action,
                )

            raise MiddlewareTermination(decision.reason)

        # Policy allowed — log and continue the pipeline.
        logger.debug(
            "Policy ALLOW for agent '%s' (rule=%s)",
            agent_name,
            decision.matched_rule,
        )

        if self.audit_log:
            self.audit_log.log(
                event_type="policy_evaluation",
                agent_did=agent_name,
                action="allow",
                data={
                    "matched_rule": decision.matched_rule,
                    "message_preview": last_message_text[:200],
                },
                outcome="success",
                policy_decision=decision.action,
            )

        await call_next()

    async def _process_v5(
        self,
        context: AgentContext,
        call_next: Callable[[], Awaitable[None]],
    ) -> None:
        """AGT 5.0 AdapterRuntimeBridge-backed processing."""
        assert self.kernel is not None
        agent_name = getattr(context.agent, "name", "unknown")

        # Extract the last user message text (handle empty conversations).
        last_message_text = ""
        last_msg = None
        messages: list[Any] = getattr(context, "messages", None) or []
        if messages:
            last_msg = messages[-1]
            last_message_text = (
                getattr(last_msg, "text", None) or str(last_msg)
            )

        ctx = self._ensure_v5_context()
        bridge_result = self.kernel.evaluate_input(ctx, last_message_text)

        metadata: dict[str, Any] = getattr(context, "metadata", {})
        metadata["governance_decision"] = bridge_result

        if not bridge_result.allowed:
            reason = bridge_result.reason or "policy_violation"
            logger.info(
                "Policy DENY (AGT input) for agent '%s': %s",
                agent_name,
                reason,
            )

            # Set a user-visible response explaining the denial.
            context.result = AgentResponse(
                messages=[
                    Message(
                        "assistant",
                        [f"⛔ Policy violation: {reason}"],
                    )
                ]
            )

            if self.audit_log:
                self.audit_log.log(
                    event_type="policy_violation",
                    agent_did=agent_name,
                    action="deny",
                    data={
                        "reason": reason,
                        "message_preview": last_message_text[:200],
                    },
                    outcome="denied",
                    policy_decision="deny",
                )

            raise MiddlewareTermination(reason)

        # AGT-DELTA D1.1: rewrite the last message body when the engine
        # returned a transform verdict so the agent's downstream tools
        # see the AGT-sanitised text.
        if (
            bridge_result.transform is not None
            and isinstance(bridge_result.transform.value, str)
            and last_msg is not None
        ):
            try:
                if hasattr(last_msg, "text"):
                    last_msg.text = bridge_result.transform.value
                if hasattr(last_msg, "contents") and isinstance(
                    getattr(last_msg, "contents"), list
                ):
                    last_msg.contents = [bridge_result.transform.value]
            except Exception:  # noqa: BLE001 — best-effort rewrite
                pass

        logger.debug(
            "Policy ALLOW (AGT input) for agent '%s'", agent_name
        )

        if self.audit_log:
            self.audit_log.log(
                event_type="policy_evaluation",
                agent_did=agent_name,
                action="allow",
                data={
                    "message_preview": last_message_text[:200],
                },
                outcome="success",
                policy_decision="allow",
            )

        await call_next()


# ═══════════════════════════════════════════════════════════════════════════
# 2. CapabilityGuardMiddleware
# ═══════════════════════════════════════════════════════════════════════════


class CapabilityGuardMiddleware(FunctionMiddleware):
    """FunctionMiddleware that enforces tool allow/deny lists.

    Two construction paths are supported:

    1. **Legacy v4** — pass ``allowed_tools`` and/or ``denied_tools``
       lists. Each tool invocation is checked against those explicit
       lists; the deny list takes precedence. If a tool is not
       permitted, the function result is set to an error string and
       :class:`MiddlewareTermination` is raised.
    2. **AGT 5.0** — pass an :class:`MAFKernel`. The middleware routes
       every tool invocation through the kernel's AGT
       :class:`AdapterRuntimeBridge` at the ``pre_tool_call``
       intervention point. ``transform`` verdicts (AGT-DELTA D1.1)
       rewrite ``context.arguments`` before the next filter runs;
       ``deny`` verdicts raise :class:`MiddlewareTermination` with the
       canonical AGT reason; ``escalate`` verdicts route through the
       kernel's configured approval resolver per AGT-DELTA D1.4.

    Args:
        allowed_tools: Legacy v4 whitelist of permitted tool names.
        denied_tools: Legacy v4 blacklist of forbidden tool names.
        audit_log: Optional :class:`AuditLog` for recording invocations.
        kernel: v5 :class:`MAFKernel`. When provided, the v5 path
            replaces the legacy allow/deny lists.
        agent_id: Agent identifier used when constructing the v5
            :class:`ExecutionContext`.
    """

    def __init__(
        self,
        allowed_tools: list[str] | None = None,
        denied_tools: list[str] | None = None,
        audit_log: Any | None = None,
        *,
        kernel: MAFKernel | None = None,
        agent_id: str = "maf-agent",
    ) -> None:
        self.allowed_tools = allowed_tools
        self.denied_tools = denied_tools
        self.audit_log = audit_log
        self.kernel = kernel
        self._agent_id = agent_id
        self._v5_ctx: ExecutionContext | None = None

    def _ensure_v5_context(self) -> ExecutionContext:
        """Build the v5 :class:`ExecutionContext` on first need."""
        assert self.kernel is not None
        if self._v5_ctx is None:
            self._v5_ctx = ExecutionContext(
                agent_id=self._agent_id,
                session_id=f"maf-cap-{int(time.time())}",
                policy=self.kernel.policy,
            )
        return self._v5_ctx

    def _is_denied(self, tool_name: str) -> bool:
        """Return ``True`` if *tool_name* should be blocked (v4 path)."""
        # Explicit deny list takes precedence.
        if self.denied_tools and tool_name in self.denied_tools:
            return True
        # If an allow list is set, anything not in it is denied.
        if self.allowed_tools is not None and tool_name not in self.allowed_tools:
            return True
        return False

    async def process(
        self,
        context: FunctionInvocationContext,
        call_next: Callable[[], Awaitable[None]],
    ) -> None:
        """Guard tool invocations against capability policy."""
        if self.kernel is not None:
            await self._process_v5(context, call_next)
        else:
            await self._process_v4(context, call_next)

    async def _process_v4(
        self,
        context: FunctionInvocationContext,
        call_next: Callable[[], Awaitable[None]],
    ) -> None:
        """Legacy v4 allow/deny-list processing."""
        func_name = getattr(
            getattr(context, "function", None), "name", "unknown"
        )

        if self._is_denied(func_name):
            logger.info("Capability DENY: tool '%s' blocked by policy", func_name)

            context.result = (
                f"⛔ Tool '{func_name}' is not permitted by governance policy"
            )

            if self.audit_log:
                self.audit_log.log(
                    event_type="tool_blocked",
                    agent_did="capability-guard",
                    action="deny",
                    resource=func_name,
                    data={"tool": func_name},
                    outcome="denied",
                )

            raise MiddlewareTermination(
                f"Tool '{func_name}' is not permitted by governance policy"
            )

        # Tool is allowed — log start, execute, log completion.
        if self.audit_log:
            self.audit_log.log(
                event_type="tool_invocation",
                agent_did="capability-guard",
                action="start",
                resource=func_name,
                data={"tool": func_name},
                outcome="success",
            )

        logger.debug("Capability ALLOW: invoking tool '%s'", func_name)

        await call_next()

        # Log completion with a truncated result summary.
        result_summary = str(getattr(context, "result", ""))[:500]
        if self.audit_log:
            self.audit_log.log(
                event_type="tool_invocation",
                agent_did="capability-guard",
                action="complete",
                resource=func_name,
                data={
                    "tool": func_name,
                    "result_preview": result_summary,
                },
                outcome="success",
            )

    async def _process_v5(
        self,
        context: FunctionInvocationContext,
        call_next: Callable[[], Awaitable[None]],
    ) -> None:
        """AGT 5.0 AdapterRuntimeBridge-backed processing."""
        assert self.kernel is not None
        func_name = getattr(
            getattr(context, "function", None), "name", "unknown"
        )

        # Build the args dict from the MAF FunctionInvocationContext.
        raw_args = getattr(context, "arguments", None)
        if isinstance(raw_args, dict):
            args_dict = dict(raw_args)
        elif raw_args is None:
            args_dict = {}
        else:
            args_dict = {"_value": raw_args}

        ctx = self._ensure_v5_context()
        bridge_result = self.kernel.evaluate_pre_tool_call(
            ctx,
            tool_name=func_name,
            args=args_dict,
            call_id=f"maf-cap-{ctx.call_count + 1}",
        )

        if not bridge_result.allowed:
            reason = bridge_result.reason or "tool_blocked"
            logger.info(
                "Capability DENY (AGT pre_tool_call): tool '%s' blocked: %s",
                func_name,
                reason,
            )

            context.result = (
                f"⛔ Tool '{func_name}' is not permitted by governance policy"
            )

            if self.audit_log:
                self.audit_log.log(
                    event_type="tool_blocked",
                    agent_did="capability-guard",
                    action="deny",
                    resource=func_name,
                    data={"tool": func_name, "reason": reason},
                    outcome="denied",
                )

            raise MiddlewareTermination(
                f"Tool '{func_name}' is not permitted by governance policy"
            )

        # AGT-DELTA D1.1: rewrite the outbound arguments when the
        # engine returned a transform verdict so the next filter sees
        # the AGT-sanitised payload.
        if bridge_result.transform is not None and isinstance(
            bridge_result.transform.value, dict
        ):
            try:
                context.arguments = bridge_result.transform.value
            except Exception:  # noqa: BLE001 — best-effort rewrite
                pass

        if self.audit_log:
            self.audit_log.log(
                event_type="tool_invocation",
                agent_did="capability-guard",
                action="start",
                resource=func_name,
                data={"tool": func_name},
                outcome="success",
            )

        logger.debug(
            "Capability ALLOW (AGT pre_tool_call): invoking tool '%s'",
            func_name,
        )

        await call_next()

        ctx.call_count += 1

        # Log completion with a truncated result summary.
        result_summary = str(getattr(context, "result", ""))[:500]
        if self.audit_log:
            self.audit_log.log(
                event_type="tool_invocation",
                agent_did="capability-guard",
                action="complete",
                resource=func_name,
                data={
                    "tool": func_name,
                    "result_preview": result_summary,
                },
                outcome="success",
            )


# ═══════════════════════════════════════════════════════════════════════════
# 3. AuditTrailMiddleware
# ═══════════════════════════════════════════════════════════════════════════


class AuditTrailMiddleware(AgentMiddleware):
    """AgentMiddleware that records tamper-proof audit entries.

    Wraps every agent invocation with pre- and post-execution audit
    entries, capturing timing information and the execution outcome.
    The resulting :class:`AuditEntry` ID is stored in
    ``context.metadata["audit_entry_id"]`` for downstream correlation.

    Args:
        audit_log: :class:`AuditLog` instance for recording entries.
        agent_did: Optional decentralised identifier for the agent.
            Defaults to the MAF agent name when not provided.
    """

    def __init__(
        self,
        audit_log: Any,
        agent_did: str | None = None,
    ) -> None:
        self.audit_log = audit_log
        self.agent_did = agent_did

    async def process(
        self,
        context: AgentContext,
        call_next: Callable[[], Awaitable[None]],
    ) -> None:
        """Record pre/post execution audit entries with timing."""
        agent_name = getattr(context.agent, "name", "unknown")
        did = self.agent_did or agent_name

        messages: list[Any] = getattr(context, "messages", None) or []
        metadata: dict[str, Any] = getattr(context, "metadata", {})

        # Pre-execution audit entry.
        start_entry = self.audit_log.log(
            event_type="agent_invocation",
            agent_did=did,
            action="start",
            data={
                "agent_name": agent_name,
                "message_count": len(messages),
                "stream": getattr(context, "stream", False),
            },
            outcome="success",
        )

        # Store the entry ID for downstream middleware / callers.
        metadata["audit_entry_id"] = start_entry.entry_id

        start_time = time.time()
        outcome = "success"
        error_detail: str | None = None

        try:
            await call_next()
        except Exception as exc:
            outcome = "error"
            error_detail = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            elapsed = time.time() - start_time

            # Post-execution audit entry.
            self.audit_log.log(
                event_type="agent_invocation",
                agent_did=did,
                action="complete",
                data={
                    "agent_name": agent_name,
                    "elapsed_seconds": round(elapsed, 4),
                    "start_entry_id": start_entry.entry_id,
                    **({"error": error_detail} if error_detail else {}),
                },
                outcome=outcome,
            )

            logger.debug(
                "Audit: agent '%s' completed in %.3fs (outcome=%s)",
                agent_name,
                elapsed,
                outcome,
            )


# ═══════════════════════════════════════════════════════════════════════════
# 4. RogueDetectionMiddleware
# ═══════════════════════════════════════════════════════════════════════════


class RogueDetectionMiddleware(FunctionMiddleware):
    """FunctionMiddleware that detects rogue agent behaviour.

    Feeds every tool invocation into a
    :class:`~agent_sre.anomaly.RogueAgentDetector` and checks the
    resulting risk assessment.  High-risk agents are blocked with a
    ``MiddlewareTermination``; medium-risk invocations proceed with a
    warning logged to the audit trail.

    Args:
        detector: Pre-configured :class:`RogueAgentDetector`.
        agent_id: Identifier for the agent being monitored.
        capability_profile: Optional dict mapping ``"allowed_tools"``
            to a list of expected tool names.  Registered with the
            detector on construction.
        audit_log: Optional :class:`AuditLog` for recording detections.
    """

    def __init__(
        self,
        detector: Any,
        agent_id: str,
        capability_profile: dict[str, Any] | None = None,
        audit_log: Any | None = None,
    ) -> None:
        self.detector = detector
        self.agent_id = agent_id
        self.audit_log = audit_log

        # Register the expected capability profile if provided.
        if capability_profile and "allowed_tools" in capability_profile:
            self.detector.register_capability_profile(
                agent_id,
                capability_profile["allowed_tools"],
            )

    async def process(
        self,
        context: FunctionInvocationContext,
        call_next: Callable[[], Awaitable[None]],
    ) -> None:
        """Assess rogue risk before allowing tool execution."""
        func_name = getattr(
            getattr(context, "function", None), "name", "unknown"
        )
        now = time.time()

        # Feed the observation into the detector's analyzers.
        self.detector.record_action(
            agent_id=self.agent_id,
            action=func_name,
            tool_name=func_name,
            timestamp=now,
        )

        # Produce a composite risk assessment.
        assessment = self.detector.assess(self.agent_id, timestamp=now)

        if assessment.quarantine_recommended:
            logger.warning(
                "Rogue QUARANTINE for agent '%s': risk=%s score=%.2f",
                self.agent_id,
                assessment.risk_level.value,
                assessment.composite_score,
            )

            context.result = (
                f"⛔ Agent '{self.agent_id}' has been quarantined due to "
                f"anomalous behaviour (risk={assessment.risk_level.value}, "
                f"score={assessment.composite_score:.2f})"
            )

            if self.audit_log:
                self.audit_log.log(
                    event_type="rogue_detection",
                    agent_did=self.agent_id,
                    action="quarantine",
                    resource=func_name,
                    data=assessment.to_dict(),
                    outcome="denied",
                )

            raise MiddlewareTermination(
                f"Agent '{self.agent_id}' quarantined: "
                f"risk={assessment.risk_level.value}"
            )

        # Log a warning for MEDIUM or above but allow execution.
        if assessment.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH):
            logger.warning(
                "Rogue WARNING for agent '%s': risk=%s score=%.2f "
                "(tool=%s)",
                self.agent_id,
                assessment.risk_level.value,
                assessment.composite_score,
                func_name,
            )

            if self.audit_log:
                self.audit_log.log(
                    event_type="rogue_detection",
                    agent_did=self.agent_id,
                    action="warning",
                    resource=func_name,
                    data=assessment.to_dict(),
                    outcome="success",
                )

        await call_next()


# ═══════════════════════════════════════════════════════════════════════════
# Convenience factory
# ═══════════════════════════════════════════════════════════════════════════


def create_governance_middleware(
    policy_directory: str | Path | None = None,
    allowed_tools: list[str] | None = None,
    denied_tools: list[str] | None = None,
    agent_id: str = "default-agent",
    enable_rogue_detection: bool = True,
    audit_log: Any | None = None,
    *,
    policy: GovernancePolicy | None = None,
    approval_resolver: Optional[Callable[..., Any]] = None,
    _runtime: Optional[Any] = None,
    _runtime_factory: Optional[Callable[..., Any]] = None,
) -> list:
    """Create a complete governance middleware stack for a MAF agent.

    Assembles and returns an ordered list of middleware instances ready
    to pass directly to a MAF ``Agent(middleware=...)`` constructor.

    The stack is built bottom-up:

    1. :class:`AuditTrailMiddleware` (if *audit_log* provided)
    2. :class:`GovernancePolicyMiddleware` (if *policy_directory* or
       *policy* provided)
    3. :class:`CapabilityGuardMiddleware` (if allow/deny lists or
       *policy* provided)
    4. :class:`RogueDetectionMiddleware` (if *enable_rogue_detection*)

    Args:
        policy_directory: Path to a directory of YAML policy files.
            When provided, a :class:`PolicyEvaluator` is created and
            loaded with all ``*.yaml`` / ``*.yml`` files found. Builds
            the legacy v4 :class:`GovernancePolicyMiddleware`.
        allowed_tools: Whitelist of permitted tool names (legacy v4
            :class:`CapabilityGuardMiddleware` path).
        denied_tools: Blacklist of forbidden tool names (legacy v4
            :class:`CapabilityGuardMiddleware` path).
        agent_id: Identifier for the agent (used by audit and rogue
            detection).
        enable_rogue_detection: Whether to include the
            :class:`RogueDetectionMiddleware`.
        audit_log: Shared :class:`AuditLog` instance.  When ``None``,
            a fresh in-memory log is created if any auditing middleware
            is needed.
        policy: AGT 5.0 :class:`GovernancePolicy`. When provided, an
            :class:`MAFKernel` is built and the v5 routing replaces the
            legacy paths for :class:`GovernancePolicyMiddleware` and
            :class:`CapabilityGuardMiddleware`. Mutually exclusive with
            ``policy_directory`` for policy enforcement.
        approval_resolver: Optional callable invoked when the AGT
            engine returns an ``escalate`` verdict (only used when
            ``policy`` is provided).
        _runtime: Test seam — inject a pre-built :class:`AgtRuntime`
            for scenario tests. Not part of the public surface.
        _runtime_factory: Test seam — override the runtime factory.
            Not part of the public surface.

    Returns:
        List of middleware instances in recommended execution order.

    Example::

        from agent_framework import Agent
        from agent_os.integrations.maf_adapter import create_governance_middleware
        from agent_os.integrations.base import GovernancePolicy

        # AGT 5.0 path
        stack = create_governance_middleware(
            policy=GovernancePolicy(blocked_patterns=["password"]),
            allowed_tools=["search", "read_file"],
            agent_id="my-researcher",
        )
        agent = Agent(name="researcher", middleware=stack)
    """
    stack: list[Any] = []

    # Build an MAFKernel when an AGT 5.0 policy is supplied.
    kernel: MAFKernel | None = None
    if policy is not None:
        kernel = MAFKernel(
            policy,
            approval_resolver=approval_resolver,
            _runtime=_runtime,
            _runtime_factory=_runtime_factory,
        )

    # Determine whether we need an audit log for any layer.
    needs_audit = (
        audit_log is not None
        or policy_directory is not None
        or kernel is not None
        or allowed_tools is not None
        or denied_tools is not None
        or enable_rogue_detection
    )
    if needs_audit and audit_log is None and AuditLog is not None:
        audit_log = AuditLog()

    # 1. Audit trail (outermost — captures everything).
    if audit_log is not None:
        stack.append(AuditTrailMiddleware(audit_log=audit_log, agent_did=agent_id))

    # 2. Governance policy enforcement.
    if kernel is not None:
        stack.append(
            GovernancePolicyMiddleware(
                kernel=kernel,
                audit_log=audit_log,
                agent_id=agent_id,
            )
        )
    elif policy_directory is not None:
        if PolicyEvaluator is None:
            raise ImportError(
                "agent_os.policies.PolicyEvaluator is required for the "
                "legacy v4 policy_directory path. Pass a `policy=` "
                "GovernancePolicy to use the AGT 5.0 v5 path instead."
            )
        evaluator = PolicyEvaluator()
        evaluator.load_policies(policy_directory)
        stack.append(
            GovernancePolicyMiddleware(evaluator=evaluator, audit_log=audit_log)
        )

    # 3. Capability guard.
    if kernel is not None:
        stack.append(
            CapabilityGuardMiddleware(
                allowed_tools=allowed_tools,
                denied_tools=denied_tools,
                audit_log=audit_log,
                kernel=kernel,
                agent_id=agent_id,
            )
        )
    elif allowed_tools is not None or denied_tools is not None:
        stack.append(
            CapabilityGuardMiddleware(
                allowed_tools=allowed_tools,
                denied_tools=denied_tools,
                audit_log=audit_log,
            )
        )

    # 4. Rogue detection (innermost — closest to actual tool execution).
    if enable_rogue_detection and RogueAgentDetector is not None:
        detector = RogueAgentDetector(config=RogueDetectorConfig())
        capability_profile: dict[str, Any] | None = None
        if allowed_tools:
            capability_profile = {"allowed_tools": allowed_tools}
        stack.append(
            RogueDetectionMiddleware(
                detector=detector,
                agent_id=agent_id,
                capability_profile=capability_profile,
                audit_log=audit_log,
            )
        )

    return stack
