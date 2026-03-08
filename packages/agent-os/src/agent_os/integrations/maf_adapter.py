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
from typing import Any, Awaitable, Callable

from agent_os.policies import PolicyDecision, PolicyEvaluator
from agentmesh.governance import AuditEntry, AuditLog
from agent_sre.anomaly import RiskLevel, RogueAgentDetector, RogueDetectorConfig

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
        def __init__(self, role: str, content: list[str] | None = None) -> None:
            self.role = role
            self.content = content or []

        @property
        def text(self) -> str:
            return self.content[0] if self.content else ""

    class MiddlewareTermination(Exception):  # type: ignore[no-redef]
        """Local fallback when agent_framework is not installed."""


# ═══════════════════════════════════════════════════════════════════════════
# 1. GovernancePolicyMiddleware
# ═══════════════════════════════════════════════════════════════════════════


class GovernancePolicyMiddleware(AgentMiddleware):
    """AgentMiddleware that evaluates declarative governance policies.

    Intercepts every agent invocation, builds a context dict from the
    incoming messages and agent metadata, and evaluates it against loaded
    :class:`~agent_os.policies.PolicyEvaluator` rules.  Denied requests
    are short-circuited with an ``AgentResponse`` explaining the
    violation and a ``MiddlewareTermination`` is raised.

    Args:
        evaluator: Pre-configured :class:`PolicyEvaluator` with loaded
            policy documents.
        audit_log: Optional :class:`AuditLog` for recording decisions.
    """

    def __init__(
        self,
        evaluator: PolicyEvaluator,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.evaluator = evaluator
        self.audit_log = audit_log

    async def process(
        self,
        context: AgentContext,
        call_next: Callable[[], Awaitable[None]],
    ) -> None:
        """Evaluate governance policy before agent execution."""
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

        decision: PolicyDecision = self.evaluator.evaluate(eval_context)

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


# ═══════════════════════════════════════════════════════════════════════════
# 2. CapabilityGuardMiddleware
# ═══════════════════════════════════════════════════════════════════════════


class CapabilityGuardMiddleware(FunctionMiddleware):
    """FunctionMiddleware that enforces tool allow/deny lists.

    Each tool invocation is checked against explicit ``allowed_tools``
    and ``denied_tools`` lists.  If a tool is not permitted, the
    function result is set to an error string and
    ``MiddlewareTermination`` is raised.

    When both ``allowed_tools`` and ``denied_tools`` are provided,
    ``denied_tools`` takes precedence (a tool in both lists is denied).

    Args:
        allowed_tools: Whitelist of permitted tool names.  If ``None``,
            all tools are allowed unless explicitly denied.
        denied_tools: Blacklist of forbidden tool names.
        audit_log: Optional :class:`AuditLog` for recording tool
            invocations.
    """

    def __init__(
        self,
        allowed_tools: list[str] | None = None,
        denied_tools: list[str] | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.allowed_tools = allowed_tools
        self.denied_tools = denied_tools
        self.audit_log = audit_log

    def _is_denied(self, tool_name: str) -> bool:
        """Return ``True`` if *tool_name* should be blocked."""
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
        audit_log: AuditLog,
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
        start_entry: AuditEntry = self.audit_log.log(
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
        detector: RogueAgentDetector,
        agent_id: str,
        capability_profile: dict[str, Any] | None = None,
        audit_log: AuditLog | None = None,
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
    audit_log: AuditLog | None = None,
) -> list:
    """Create a complete governance middleware stack for a MAF agent.

    Assembles and returns an ordered list of middleware instances ready
    to pass directly to a MAF ``Agent(middleware=...)`` constructor.

    The stack is built bottom-up:

    1. :class:`AuditTrailMiddleware` (if *audit_log* provided)
    2. :class:`GovernancePolicyMiddleware` (if *policy_directory* provided)
    3. :class:`CapabilityGuardMiddleware` (if allow/deny lists provided)
    4. :class:`RogueDetectionMiddleware` (if *enable_rogue_detection*)

    Args:
        policy_directory: Path to a directory of YAML policy files.
            When provided, a :class:`PolicyEvaluator` is created and
            loaded with all ``*.yaml`` / ``*.yml`` files found.
        allowed_tools: Whitelist of permitted tool names.
        denied_tools: Blacklist of forbidden tool names.
        agent_id: Identifier for the agent (used by audit and rogue
            detection).
        enable_rogue_detection: Whether to include the
            :class:`RogueDetectionMiddleware`.
        audit_log: Shared :class:`AuditLog` instance.  When ``None``,
            a fresh in-memory log is created if any auditing middleware
            is needed.

    Returns:
        List of middleware instances in recommended execution order.

    Example::

        from agent_framework import Agent
        from agent_os.integrations.maf_adapter import create_governance_middleware

        stack = create_governance_middleware(
            policy_directory="policies/",
            allowed_tools=["search", "read_file"],
            agent_id="my-researcher",
        )
        agent = Agent(name="researcher", middleware=stack)
    """
    stack: list[Any] = []

    # Determine whether we need an audit log for any layer.
    needs_audit = (
        audit_log is not None
        or policy_directory is not None
        or allowed_tools is not None
        or denied_tools is not None
        or enable_rogue_detection
    )
    if needs_audit and audit_log is None:
        audit_log = AuditLog()

    # 1. Audit trail (outermost — captures everything).
    if audit_log is not None:
        stack.append(AuditTrailMiddleware(audit_log=audit_log, agent_did=agent_id))

    # 2. Governance policy enforcement.
    if policy_directory is not None:
        evaluator = PolicyEvaluator()
        evaluator.load_policies(policy_directory)
        stack.append(
            GovernancePolicyMiddleware(evaluator=evaluator, audit_log=audit_log)
        )

    # 3. Capability guard.
    if allowed_tools is not None or denied_tools is not None:
        stack.append(
            CapabilityGuardMiddleware(
                allowed_tools=allowed_tools,
                denied_tools=denied_tools,
                audit_log=audit_log,
            )
        )

    # 4. Rogue detection (innermost — closest to actual tool execution).
    if enable_rogue_detection:
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
