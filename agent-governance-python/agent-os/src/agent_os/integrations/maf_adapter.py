# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Microsoft Agent Framework (MAF) Governance Adapter

Bridges the Agent OS governance toolkit into MAF's native middleware system.
Four composable middleware layers enforce policy, capability guards, audit
trails, and rogue-agent detection at every level of the agent stack:

- RuntimeGovernanceMiddleware (AgentMiddleware): Declarative policy enforcement
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
from typing import Any, Awaitable, Callable, Optional

from ._native_adapter_runtime import (
    AdapterResult,
    AdapterRuntime,
)
from ..exceptions import PolicyViolationError  # noqa: F401
from .base import BaseIntegration, AdapterExecutionState, get_adapter_runtime

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
    """Microsoft Agent Framework adapter backed by a native ACS runtime."""

    def __init__(
        self,
        *,
        runtime: Any,
    ) -> None:
        """Initialise the kernel with the required native runtime."""
        super().__init__(runtime=runtime)
        self._start_time = time.monotonic()
        self._last_error: Optional[str] = None
        self._bridge: AdapterRuntime = get_adapter_runtime(runtime)

    @property
    def bridge(self) -> AdapterRuntime:
        """Return the v5 :class:`AdapterRuntime` for this kernel."""
        return self._bridge

    def evaluate_input(
        self, ctx: AdapterExecutionState, input_data: Any
    ) -> AdapterResult:
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
        ctx: AdapterExecutionState,
        *,
        tool_name: str,
        args: dict[str, Any],
        call_id: str = "call-1",
    ) -> AdapterResult:
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
        returned from :meth:`as_runtime_middleware` /
        :meth:`as_capability_guard` (or
        :func:`create_governance_middleware`) to
        ``Agent(middleware=...)``. The wrap()/unwrap() pair satisfies
        the :class:`BaseIntegration` abstract surface but does not
        proxy the agent.
        """
        return agent

    def as_runtime_middleware(
        self,
        *,
        audit_log: Any | None = None,
        agent_id: str = "maf-agent",
    ) -> RuntimeGovernanceMiddleware:
        """Return a :class:`RuntimeGovernanceMiddleware` backed by this kernel.

        The returned middleware evaluates every agent invocation at
        the AGT ``input`` intervention point via the runtime bridge.
        """
        return RuntimeGovernanceMiddleware(
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
# 1. RuntimeGovernanceMiddleware
# ═══════════════════════════════════════════════════════════════════════════


class RuntimeGovernanceMiddleware(AgentMiddleware):
    """Mediate every MAF agent invocation through a native runtime."""

    def __init__(
        self,
        *,
        kernel: MAFKernel,
        audit_log: Any | None = None,
        agent_id: str = "maf-agent",
    ) -> None:
        self.kernel = kernel
        self.audit_log = audit_log
        self._agent_id = agent_id
        self._v5_ctx: AdapterExecutionState | None = None

    def _ensure_v5_context(self) -> AdapterExecutionState:
        """Build the v5 :class:`AdapterExecutionState` on first need."""
        assert self.kernel is not None
        if self._v5_ctx is None:
            self._v5_ctx = AdapterExecutionState(
                agent_id=self._agent_id,
                session_id=f"maf-mw-{int(time.time())}",
            )
        return self._v5_ctx

    async def process(
        self,
        context: AgentContext,
        call_next: Callable[[], Awaitable[None]],
    ) -> None:
        """Evaluate the native runtime before agent execution."""
        await self._process_v5(context, call_next)

    async def _process_v5(
        self,
        context: AgentContext,
        call_next: Callable[[], Awaitable[None]],
    ) -> None:
        """AGT 5.0 AdapterRuntime-backed processing."""
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
            and isinstance(bridge_result.transformed_value, str)
            and last_msg is not None
        ):
            try:
                if hasattr(last_msg, "text"):
                    last_msg.text = bridge_result.transformed_value
                if hasattr(last_msg, "contents") and isinstance(
                    getattr(last_msg, "contents"), list
                ):
                    last_msg.contents = [bridge_result.transformed_value]
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
    """Mediate every MAF function call through a native runtime."""

    def __init__(
        self,
        *,
        kernel: MAFKernel,
        audit_log: Any | None = None,
        agent_id: str = "maf-agent",
    ) -> None:
        self.audit_log = audit_log
        self.kernel = kernel
        self._agent_id = agent_id
        self._v5_ctx: AdapterExecutionState | None = None

    def _ensure_v5_context(self) -> AdapterExecutionState:
        """Build the v5 :class:`AdapterExecutionState` on first need."""
        assert self.kernel is not None
        if self._v5_ctx is None:
            self._v5_ctx = AdapterExecutionState(
                agent_id=self._agent_id,
                session_id=f"maf-cap-{int(time.time())}",
            )
        return self._v5_ctx

    async def process(
        self,
        context: FunctionInvocationContext,
        call_next: Callable[[], Awaitable[None]],
    ) -> None:
        """Evaluate the native runtime before function invocation."""
        await self._process_v5(context, call_next)

    async def _process_v5(
        self,
        context: FunctionInvocationContext,
        call_next: Callable[[], Awaitable[None]],
    ) -> None:
        """AGT 5.0 AdapterRuntime-backed processing."""
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
            bridge_result.transformed_value, dict
        ):
            try:
                context.arguments = bridge_result.transformed_value
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
    *,
    runtime: Any,
    agent_id: str = "default-agent",
    enable_rogue_detection: bool = True,
    audit_log: Any | None = None,
) -> list[Any]:
    """Create the native runtime middleware stack for a MAF agent."""
    kernel = MAFKernel(runtime=runtime)
    if audit_log is None and AuditLog is not None:
        audit_log = AuditLog()

    stack: list[Any] = []
    if audit_log is not None:
        stack.append(AuditTrailMiddleware(audit_log=audit_log, agent_did=agent_id))
    stack.extend([
        RuntimeGovernanceMiddleware(
            kernel=kernel, audit_log=audit_log, agent_id=agent_id
        ),
        CapabilityGuardMiddleware(
            kernel=kernel, audit_log=audit_log, agent_id=agent_id
        ),
    ])
    if enable_rogue_detection and RogueAgentDetector is not None:
        stack.append(
            RogueDetectionMiddleware(
                detector=RogueAgentDetector(config=RogueDetectorConfig()),
                agent_id=agent_id,
                audit_log=audit_log,
            )
        )
    return stack
