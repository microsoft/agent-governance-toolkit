# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
HuggingFace smolagents Integration for Agent-OS
================================================

Provides kernel-level governance for smolagents agent workflows.

Backend (AGT 5.0): every policy decision is routed through
:class:`agt.policies.runtime.AgtRuntime` (the ACS-backed v5 engine).
The v4 :class:`~agent_os.integrations.base.GovernancePolicy` derived
from :class:`PolicyConfig` is translated to an AGT manifest via
:func:`agt.policies.bridge.governance_to_acs_manifest` at adapter init
time, an :class:`AgtRuntime` is memoised per policy, and a
:class:`agt.policies.snapshot.SnapshotBuilder` mirrors the v4
``ExecutionContext`` budgets between intervention points. The legacy
``before_tool_call`` / ``after_tool_call`` tuple-shaped API is preserved
so v4 callers keep working. ``transform`` verdicts (AGT-DELTA D1.1)
rewrite the outbound tool arguments and tool result before smolagents
sees them; ``escalate`` verdicts route through the configured approval
resolver per AGT-DELTA D1.4.

Features:
- Extends BaseIntegration with wrap/unwrap for smolagents agents
- Policy evaluation routed through the AGT 5.0 ACS engine
- Transform-verdict rewriting of tool arguments and tool results
- Escalate-verdict approval routing via the configured resolver
- Tool allow/block lists
- Content filtering with blocked patterns
- Human approval workflow for sensitive tools
- Token/call budget tracking
- Full audit trail of tool calls and agent runs
- Works without smolagents installed (graceful import handling)
- Compatible with CodeAgent and ToolCallingAgent

Example:
    >>> from agent_os.integrations.smolagents_adapter import SmolagentsKernel
    >>>
    >>> kernel = SmolagentsKernel(
    ...     max_tool_calls=10,
    ...     blocked_tools=["exec_code", "shell"],
    ...     blocked_patterns=["DROP TABLE", "rm -rf"],
    ...     require_human_approval=True,
    ...     sensitive_tools=["delete_file", "send_email"],
    ... )
    >>>
    >>> # Wrap an existing agent
    >>> from smolagents import CodeAgent, HfApiModel
    >>> agent = CodeAgent(tools=[my_tool], model=HfApiModel())
    >>> governed = kernel.wrap(agent)
    >>> result = governed.run("Summarize this document")
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ._v5_runtime_bridge import (
    AdapterRuntimeBridge,
    BridgeResult,
    get_runtime_bridge,
)
from ..exceptions import PolicyViolationError as _CanonicalPolicyViolationError
from .base import BaseIntegration, ExecutionContext, GovernancePolicy

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
class PolicyConfig:
    """Policy configuration for smolagents governance."""

    max_tool_calls: int = 50
    max_agent_calls: int = 20
    timeout_seconds: int = 300

    allowed_tools: list[str] = field(default_factory=list)
    blocked_tools: list[str] = field(default_factory=list)

    blocked_patterns: list[str] = field(default_factory=list)

    log_all_calls: bool = True

    require_human_approval: bool = False
    sensitive_tools: list[str] = field(default_factory=list)

    max_budget: float | None = None


class PolicyViolationError(_CanonicalPolicyViolationError):
    """Raised when a governance policy is violated.

    Subclass of :class:`agent_os.exceptions.PolicyViolationError` so the
    canonical ``from_check_result`` constructor is available while
    preserving the legacy ``smolagents_adapter.PolicyViolationError``
    signature (``policy_name`` / ``description`` / ``severity``) for v4
    callers.
    """

    def __init__(
        self,
        policy_name: str = "governance",
        description: str = "",
        severity: str = "high",
    ):
        self.policy_name = policy_name
        self.description = description
        self.severity = severity
        super().__init__(f"Policy violation ({policy_name}): {description}")


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
        policy: PolicyConfig | None = None,
        on_violation: Callable[[PolicyViolationError], None] | None = None,
        *,
        evaluator: Any = None,
        # Convenience kwargs (create PolicyConfig automatically)
        max_tool_calls: int = 50,
        max_agent_calls: int = 20,
        timeout_seconds: int = 300,
        allowed_tools: list[str] | None = None,
        blocked_tools: list[str] | None = None,
        blocked_patterns: list[str] | None = None,
        require_human_approval: bool = False,
        sensitive_tools: list[str] | None = None,
        max_budget: float | None = None,
        approval_resolver: Optional[Callable[..., Any]] = None,
        _runtime: Optional[Any] = None,
        _runtime_factory: Optional[Callable[..., Any]] = None,
    ):
        """Initialise the smolagents governance kernel.

        Args:
            policy: Smolagents-specific :class:`PolicyConfig`. When
                ``None`` a config is constructed from the convenience
                kwargs.
            on_violation: Optional callback invoked on policy
                violations. Defaults to logging the error.
            evaluator: Optional ``PolicyEvaluator`` for legacy Cedar/OPA
                policy evaluation. Retained for backward compatibility;
                the primary decision path now runs through the AGT 5.0
                runtime.
            max_tool_calls, max_agent_calls, timeout_seconds,
            allowed_tools, blocked_tools, blocked_patterns,
            require_human_approval, sensitive_tools, max_budget:
                Convenience kwargs used to construct a ``PolicyConfig``
                when ``policy`` is ``None``.
            approval_resolver: Optional callable invoked when the AGT
                engine returns an ``escalate`` verdict. Signature matches
                :data:`agt.policies.runtime.ApprovalCallback`. When
                ``None`` an escalate verdict fails closed to ``deny``.
            _runtime: Test seam — inject a pre-built :class:`AgtRuntime`
                so scenario tests can wire a scripted policy dispatcher
                without OPA on PATH. Not part of the public surface.
            _runtime_factory: Test seam — override the runtime factory
                used by the bridge cache. Not part of the public surface.
        """
        if policy is not None:
            self._sm_config = policy
        else:
            self._sm_config = PolicyConfig(
                max_tool_calls=max_tool_calls,
                max_agent_calls=max_agent_calls,
                timeout_seconds=timeout_seconds,
                allowed_tools=allowed_tools or [],
                blocked_tools=blocked_tools or [],
                blocked_patterns=blocked_patterns or [],
                require_human_approval=require_human_approval,
                sensitive_tools=sensitive_tools or [],
                max_budget=max_budget,
            )

        # Initialize BaseIntegration with a GovernancePolicy mapped from PolicyConfig.
        # ``require_human_approval`` is intentionally NOT mapped — smolagents
        # has its own per-tool ``sensitive_tools`` gate which the AGT
        # ``require_human_approval`` field cannot represent. The smolagents
        # approval workflow stays host-side; the AGT runtime governs the
        # other policy fields.
        governance_policy = GovernancePolicy(
            max_tool_calls=self._sm_config.max_tool_calls,
            timeout_seconds=self._sm_config.timeout_seconds,
            allowed_tools=list(self._sm_config.allowed_tools),
            blocked_patterns=list(self._sm_config.blocked_patterns),
            log_all_calls=self._sm_config.log_all_calls,
        )
        super().__init__(policy=governance_policy, evaluator=evaluator)

        self.on_violation = on_violation or self._default_violation_handler

        # Counters
        self._tool_call_count: int = 0
        self._agent_call_count: int = 0
        self._start_time: float = time.time()
        self._budget_spent: float = 0.0

        # Audit trail
        self._audit_log: list[AuditEvent] = []

        # Violations collected
        self._violations: list[PolicyViolationError] = []

        # Human approval tracking
        self._pending_approvals: dict[str, dict[str, Any]] = {}
        self._approved_calls: dict[str, bool] = {}

        # Wrapped agents registry and original forward methods
        self._wrapped_agents: dict[str, Any] = {}
        self._original_forwards: dict[str, Callable[..., Any]] = {}

        # AGT 5.0 bridge — routes every intervention point through the
        # ACS-backed runtime per AGT-DELTA D1.1/D1.4.
        self._approval_resolver = approval_resolver
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
        return self._bridge.evaluate_input(ctx, body=self._to_body(input_data))

    def evaluate_pre_tool_call(
        self,
        ctx: ExecutionContext,
        *,
        tool_name: str,
        args: Any,
        call_id: str = "call-1",
    ) -> BridgeResult:
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
        self, ctx: ExecutionContext, output_data: Any
    ) -> BridgeResult:
        """AGT ``output`` intervention point evaluation for tool results."""
        return self._bridge.evaluate_output(ctx, content=self._to_body(output_data))

    @staticmethod
    def _to_body(data: Any) -> Any:
        """Normalise a smolagents payload to a JSON-serialisable body.

        smolagents tool args may be dicts or strings; tool results may
        also be dicts. The AGT manifest bridge pattern-matches a string
        ``policy_target.value``, so the adapter stringifies non-string
        payloads before forwarding so the v4 contract still holds.
        """
        if isinstance(data, (str, dict)):
            return data
        if hasattr(data, "content"):
            return str(getattr(data, "content"))
        return str(data)

    def _get_or_create_context(self, agent_name: str) -> ExecutionContext:
        """Return (and lazily create) the :class:`ExecutionContext` for ``agent_name``.

        The bridge requires a v4 :class:`ExecutionContext` to derive the
        per-session :class:`SnapshotBuilder`. Smolagents identifies agents
        only by name, so we maintain one ``ExecutionContext`` per agent
        name inside the inherited ``self.contexts`` dict.
        """
        ctx = self.contexts.get(agent_name)
        if ctx is None:
            ctx = ExecutionContext(
                agent_id=agent_name,
                session_id=f"smol-{agent_name}-{int(time.time())}",
                policy=self.policy,
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

            kernel = SmolagentsKernel(policy=config)
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

    def wrap(self, agent: Any) -> Any:
        """Wrap a smolagents agent with governance.

        .. deprecated::
            Use :meth:`as_step_callback` with ``step_callbacks=`` instead
            for a non-invasive integration.

        Intercepts each tool's ``forward`` method so that every tool call
        passes through policy checks before execution.  The agent's
        ``toolbox`` (dict of tool-name → Tool) is iterated and each tool
        is wrapped in-place.

        Works without smolagents installed (for testing with mocks).
        """
        import warnings
        warnings.warn(
            "SmolagentsKernel.wrap() is deprecated. Use as_step_callback() "
            "with agent = Agent(step_callbacks=[kernel.as_step_callback()]) "
            "for a non-invasive integration.",
            DeprecationWarning,
            stacklevel=2,
        )
        agent_name = getattr(agent, "name", None) or str(id(agent))

        # smolagents stores tools in agent.toolbox (dict-like or has .tools)
        tools = self._get_tools(agent)
        for tool_name, tool_obj in tools.items():
            self._wrap_tool(tool_obj, tool_name, agent_name)

        self._wrapped_agents[agent_name] = agent
        self._record("agent_wrapped", agent_name, {"agent_type": type(agent).__name__})
        logger.info("Wrapped smolagents agent '%s' with governance kernel", agent_name)
        return agent

    def unwrap(self, governed_agent: Any) -> Any:
        """Remove governance wrapper and restore original tool forwards."""
        agent_name = getattr(governed_agent, "name", None) or str(id(governed_agent))

        tools = self._get_tools(governed_agent)
        for tool_name, tool_obj in tools.items():
            key = f"{agent_name}:{tool_name}"
            if key in self._original_forwards:
                tool_obj.forward = self._original_forwards.pop(key)

        self._wrapped_agents.pop(agent_name, None)
        return governed_agent

    # ------------------------------------------------------------------
    # Tool wrapping
    # ------------------------------------------------------------------

    @staticmethod
    def _get_tools(agent: Any) -> dict[str, Any]:
        """Extract the tool dict from a smolagents agent.

        smolagents agents expose tools via ``agent.toolbox`` which may be
        a ``Toolbox`` object (with a ``.tools`` dict) or a plain dict.
        Falls back to an empty dict when no toolbox is found.
        """
        toolbox = getattr(agent, "toolbox", None)
        if toolbox is None:
            return {}
        # Toolbox object has a .tools dict
        if hasattr(toolbox, "tools"):
            return toolbox.tools
        # Plain dict
        if isinstance(toolbox, dict):
            return toolbox
        return {}

    def _wrap_tool(self, tool: Any, tool_name: str, agent_name: str) -> None:
        """Replace ``tool.forward`` with a governed version."""
        original_forward = tool.forward
        key = f"{agent_name}:{tool_name}"
        self._original_forwards[key] = original_forward

        kernel = self

        def governed_forward(*args: Any, **kwargs: Any) -> Any:
            """Governed wrapper around a smolagents tool's forward method.

            Intercepts the tool invocation, validates the call against
            the active policy, updates call counters and the audit log,
            then delegates to the original forward implementation.

            Args:
                *args: Positional arguments forwarded to the original tool.
                **kwargs: Keyword arguments forwarded to the original tool.

            Returns:
                The result from the original tool's forward method.

            Raises:
                PolicyViolationError: If the call violates the active policy.
            """
            # Pre-execution governance check
            result = kernel.before_tool_call(
                tool_name=tool_name,
                tool_args=kwargs or (args[0] if args else {}),
                agent_name=agent_name,
            )
            if result is not None:
                raise PolicyViolationError(
                    result.get("policy", "governance"),
                    result.get("error", "Tool call blocked by policy"),
                )

            # Execute original tool
            output = original_forward(*args, **kwargs)

            # Post-execution governance check
            filtered = kernel.after_tool_call(
                tool_name=tool_name,
                tool_result=output,
                agent_name=agent_name,
            )
            return filtered

        tool.forward = governed_forward

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

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
        if self._sm_config.log_all_calls:
            self._audit_log.append(
                AuditEvent(
                    timestamp=time.time(),
                    event_type=event_type,
                    agent_name=agent_name,
                    details=details,
                )
            )

    def _check_tool_allowed(self, tool_name: str) -> tuple[bool, str]:
        """Check whether a tool is permitted by the active policy.

        Args:
            tool_name: Name of the tool to check.

        Returns:
            Tuple of (allowed: bool, reason: str).
        """
        if tool_name in self._sm_config.blocked_tools:
            return False, f"Tool '{tool_name}' is blocked by policy"
        if self._sm_config.allowed_tools and tool_name not in self._sm_config.allowed_tools:
            return False, f"Tool '{tool_name}' not in allowed list"
        return True, ""

    def _check_content(self, content: str) -> tuple[bool, str]:
        """Scan a string for policy-blocked patterns.

        Args:
            content: The text to scan.

        Returns:
            Tuple of (allowed: bool, reason: str).
        """
        content_lower = content.lower()
        for pattern in self._sm_config.blocked_patterns:
            if pattern.lower() in content_lower:
                return False, f"Content matches blocked pattern: '{pattern}'"
        return True, ""

    def _check_timeout(self) -> tuple[bool, str]:
        """Check whether the kernel has exceeded its configured timeout.

        Returns:
            Tuple of (within_limit: bool, reason: str).
        """
        elapsed = time.time() - self._start_time
        if elapsed > self._sm_config.timeout_seconds:
            return False, f"Execution timeout ({elapsed:.0f}s > {self._sm_config.timeout_seconds}s)"
        return True, ""

    def _check_budget(self, cost: float = 1.0) -> tuple[bool, str]:
        """Check whether a tool call would exceed the configured cost budget.

        Args:
            cost: Cost units to add for this call (default 1.0).

        Returns:
            Tuple of (within_budget: bool, reason: str).
        """
        if self._sm_config.max_budget is not None:
            if self._budget_spent + cost > self._sm_config.max_budget:
                return False, (
                    f"Budget exceeded: spent {self._budget_spent} + {cost} "
                    f"> limit {self._sm_config.max_budget}"
                )
        return True, ""

    def _needs_approval(self, tool_name: str) -> bool:
        """Check if a tool call requires human approval."""
        if not self._sm_config.require_human_approval:
            return False
        if self._sm_config.sensitive_tools:
            return tool_name in self._sm_config.sensitive_tools
        return True

    def _raise_violation(self, policy_name: str, description: str) -> PolicyViolationError:
        """Create, record, and surface a PolicyViolationError.

        Appends the error to the violations list and calls on_violation.

        Args:
            policy_name: Short identifier for the violated policy rule.
            description: Human-readable description of the violation.

        Returns:
            The constructed PolicyViolationError (caller may raise it).
        """
        error = PolicyViolationError(policy_name, description)
        self._violations.append(error)
        self.on_violation(error)
        return error

    # ------------------------------------------------------------------
    # Tool-call governance hooks
    # ------------------------------------------------------------------

    def before_tool_call(
        self,
        tool_name: str = "unknown",
        tool_args: Any = None,
        agent_name: str = "unknown",
        cost: float = 1.0,
    ) -> dict[str, Any] | None:
        """
        Pre-execution governance check for a tool call.

        Returns None to allow execution, or a dict with error info to block it.

        Order preserves the v4 contract: host-side guards
        (timeout / count / budget / tool-allowed / sensitive-tool
        approval / content-pattern) run first; only when they all pass
        does the AGT ``pre_tool_call`` intervention point fire through
        the :class:`AdapterRuntimeBridge`. A ``deny`` verdict surfaces
        as a blocking dict; a ``transform`` verdict (AGT-DELTA D1.1)
        rewrites ``tool_args`` in place; an ``escalate`` verdict that
        the configured approval resolver refuses is surfaced as a deny.
        """
        if tool_args is None:
            tool_args = {}

        self._record("before_tool", agent_name, {"tool": tool_name, "args": tool_args})

        # Check timeout
        ok, reason = self._check_timeout()
        if not ok:
            error = self._raise_violation("timeout", reason)
            return {"error": str(error), "policy": "timeout"}

        # Check tool count (v4 contract uses ``>`` — increment first
        # then test).
        self._tool_call_count += 1
        if self._tool_call_count > self._sm_config.max_tool_calls:
            error = self._raise_violation(
                "tool_limit",
                f"Tool call count ({self._tool_call_count}) exceeds limit ({self._sm_config.max_tool_calls})",
            )
            return {"error": str(error), "policy": "tool_limit"}

        # Check budget
        ok, reason = self._check_budget(cost)
        if not ok:
            error = self._raise_violation("budget_exceeded", reason)
            return {"error": str(error), "policy": "budget_exceeded"}

        # Check tool allowed (blocked_tools list is smolagents-specific
        # and not represented in the v4 GovernancePolicy; keep the host
        # guard so the v4 contract still holds for blocked_tools).
        ok, reason = self._check_tool_allowed(tool_name)
        if not ok:
            error = self._raise_violation("tool_filter", reason)
            return {"error": str(error), "policy": "tool_filter"}

        # Human approval check (host-side — smolagents has a per-tool
        # ``sensitive_tools`` concept that the v4 ``require_human_approval``
        # AGT field cannot represent; gate before the AGT eval so the
        # adapter still returns the v4 approval shape).
        if self._needs_approval(tool_name):
            call_id = f"{agent_name}:{tool_name}:{self._tool_call_count}"
            if call_id not in self._approved_calls:
                self._pending_approvals[call_id] = {
                    "tool_name": tool_name,
                    "tool_args": tool_args,
                    "agent_name": agent_name,
                    "timestamp": time.time(),
                }
                self._record("approval_required", agent_name, {
                    "tool": tool_name, "call_id": call_id,
                })
                error = self._raise_violation(
                    "human_approval_required",
                    f"Tool '{tool_name}' requires human approval (call_id={call_id})",
                )
                return {
                    "error": str(error),
                    "call_id": call_id,
                    "needs_approval": True,
                    "policy": "human_approval_required",
                }

        # Host-side defensive content check on argument *values*. The
        # AGT manifest bridge only pattern-matches a string
        # ``policy_target.value``, so keep the host-side scan for dict
        # values to preserve the v4 behavioural contract (mirrors the
        # crewai/autogen adapters).
        if isinstance(tool_args, dict):
            for value in tool_args.values():
                if isinstance(value, str):
                    ok, reason = self._check_content(value)
                    if not ok:
                        error = self._raise_violation("content_filter", reason)
                        return {"error": str(error), "policy": "content_filter"}
        elif isinstance(tool_args, str):
            ok, reason = self._check_content(tool_args)
            if not ok:
                error = self._raise_violation("content_filter", reason)
                return {"error": str(error), "policy": "content_filter"}

        # ─── AGT pre_tool_call evaluation ────────────────────────────
        # Pass the pre-increment ``ctx.call_count`` so the bridge's
        # ``max_tool_calls`` host-side guard mirrors the v4 ``>``
        # contract (the host counter above has already advanced).
        ctx = self._get_or_create_context(agent_name)
        ctx.call_count = max(0, self._tool_call_count - 1)
        bridge_result = self.evaluate_pre_tool_call(
            ctx,
            tool_name=tool_name,
            args=tool_args,
            call_id=f"{agent_name}:{tool_name}:{self._tool_call_count}",
        )
        if bridge_result.transform is not None and isinstance(
            bridge_result.transform.value, dict
        ):
            # Mutate the caller's dict in place so the smolagents tool
            # receives the AGT-redacted arguments per AGT-DELTA D1.1.
            if isinstance(tool_args, dict):
                tool_args.clear()
                tool_args.update(bridge_result.transform.value)
        if not bridge_result.allowed:
            reason_text = (
                bridge_result.check_result.public_message
                or bridge_result.reason
                or "Tool call blocked by AGT policy"
            )
            error = self._raise_violation("agt_pre_tool_call", reason_text)
            return {
                "error": str(error),
                "policy": "agt_pre_tool_call",
                "verdict": bridge_result.verdict,
            }

        # Track budget spend. The next intervention point will see the
        # updated ``ctx.call_count`` via ``builder_for`` (which mirrors
        # ``ctx.call_count`` into the snapshot builder), so we do NOT
        # call ``record_post_execute`` here — that would double-count
        # against the AGT ``max_tool_calls`` rule which fires on
        # ``tool_call_count >= max``.
        self._budget_spent += cost
        ctx.call_count = self._tool_call_count

        return None  # Allow execution

    def after_tool_call(
        self,
        tool_name: str = "unknown",
        tool_result: Any = None,
        agent_name: str = "unknown",
    ) -> Any:
        """
        Post-execution governance check for a tool call.

        Inspects tool output for blocked patterns via the AGT ``output``
        intervention point. ``deny`` verdicts surface as a redacted
        sentinel; ``transform`` verdicts rewrite ``tool_result`` per
        AGT-DELTA D1.1.
        """
        self._record("after_tool", agent_name, {
            "tool": tool_name,
            "result_type": type(tool_result).__name__,
        })

        # ─── AGT output intervention point ───────────────────────────
        ctx = self._get_or_create_context(agent_name)
        if isinstance(tool_result, (str, dict)):
            bridge_result = self.evaluate_output(ctx, tool_result)
            if bridge_result.transform is not None:
                # Replace the tool result with the AGT-redacted payload
                # per AGT-DELTA D1.1. Preserve the original type when
                # the transform value type matches.
                tool_result = bridge_result.transform.value
            elif not bridge_result.allowed:
                detail = (
                    bridge_result.check_result.public_message
                    or bridge_result.reason
                    or "Tool output blocked by AGT policy"
                )
                reason_text = f"{detail} (in tool observation)"
                self._raise_violation("agt_output", reason_text)
                if isinstance(tool_result, dict):
                    return {"error": reason_text}
                return f"[BLOCKED] {reason_text}"

        # Host-side fallback content scan for legacy callers that
        # didn't match the AGT pattern policy (mirrors the previous
        # behaviour for non-pattern-driven kernels).
        if isinstance(tool_result, str):
            ok, reason = self._check_content(tool_result)
            if not ok:
                self._raise_violation("output_filter", reason)
                return f"[BLOCKED] {reason}"

        if isinstance(tool_result, dict):
            for value in tool_result.values():
                if isinstance(value, str):
                    ok, reason = self._check_content(value)
                    if not ok:
                        self._raise_violation("output_filter", reason)
                        return {"error": reason}

        return tool_result

    # ------------------------------------------------------------------
    # Human Approval API
    # ------------------------------------------------------------------

    def approve(self, call_id: str) -> bool:
        """Approve a pending tool call by its call_id."""
        if call_id in self._pending_approvals:
            self._approved_calls[call_id] = True
            info = self._pending_approvals.pop(call_id)
            self._record("approval_granted", info.get("agent_name", "unknown"), {
                "call_id": call_id, "tool": info.get("tool_name"),
            })
            return True
        return False

    def deny(self, call_id: str) -> bool:
        """Deny a pending tool call by its call_id."""
        if call_id in self._pending_approvals:
            info = self._pending_approvals.pop(call_id)
            self._record("approval_denied", info.get("agent_name", "unknown"), {
                "call_id": call_id, "tool": info.get("tool_name"),
            })
            return True
        return False

    def get_pending_approvals(self) -> dict[str, dict[str, Any]]:
        """Return all pending approval requests."""
        return dict(self._pending_approvals)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def reset(self) -> None:
        """Reset counters and start time (for new execution runs)."""
        self._tool_call_count = 0
        self._agent_call_count = 0
        self._start_time = time.time()
        self._budget_spent = 0.0

    def get_audit_log(self) -> list[AuditEvent]:
        """Return the full audit trail."""
        return list(self._audit_log)

    def get_violations(self) -> list[PolicyViolationError]:
        """Return all collected violations."""
        return list(self._violations)

    def get_stats(self) -> dict[str, Any]:
        """Get governance statistics."""
        return {
            "tool_calls": self._tool_call_count,
            "agent_calls": self._agent_call_count,
            "violations": len(self._violations),
            "audit_events": len(self._audit_log),
            "elapsed_seconds": round(time.time() - self._start_time, 2),
            "budget_spent": self._budget_spent,
            "budget_limit": self._sm_config.max_budget,
            "pending_approvals": len(self._pending_approvals),
            "policy": {
                "max_tool_calls": self._sm_config.max_tool_calls,
                "max_agent_calls": self._sm_config.max_agent_calls,
                "blocked_tools": self._sm_config.blocked_tools,
                "allowed_tools": self._sm_config.allowed_tools,
                "require_human_approval": self._sm_config.require_human_approval,
                "sensitive_tools": self._sm_config.sensitive_tools,
            },
        }

    def health_check(self) -> dict[str, Any]:
        """Return adapter health status."""
        elapsed = time.time() - self._start_time
        has_violations = len(self._violations) > 0
        return {
            "status": "degraded" if has_violations else "healthy",
            "backend": "smolagents",
            "smolagents_available": _HAS_SMOLAGENTS,
            "wrapped_agents": len(self._wrapped_agents),
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
#     kernel = SmolagentsKernel(policy=config)
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

    The callback:
    - Validates tool names in ``step.tool_calls`` against ``allowed_tools``
      and ``blocked_tools``
    - Scans tool arguments and observations for ``blocked_patterns``
    - Enforces ``max_tool_calls`` limits
    - Records an audit trail for every step

    Example::

        kernel = SmolagentsKernel(
            allowed_tools=["web_search"],
            blocked_patterns=["DROP TABLE"],
        )
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
        config = self._kernel._sm_config
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

            # Blocked tools (host-side guard; blocked_tools is
            # smolagents-specific and not encoded in GovernancePolicy).
            if tool_name in config.blocked_tools:
                self._kernel._record(
                    "tool_blocked", agent_name,
                    {"tool": tool_name, "reason": "blocked_tool"},
                )
                raise PolicyViolationError(
                    "blocked_tool",
                    f"Tool '{tool_name}' is explicitly blocked",
                )

            # ─── AGT pre_tool_call evaluation ───────────────────────
            self._kernel._tool_call_count += 1
            # Pass the pre-increment count to the bridge so the AGT
            # ``max_tool_calls`` rule (``>=``) lines up with the v4
            # ``>`` contract used by the host-side guard below.
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
                raise PolicyViolationError(
                    "agt_pre_tool_call",
                    bridge_result.check_result.public_message
                    or bridge_result.reason
                    or f"Tool '{tool_name}' denied by AGT policy",
                )

            # Check call count (v4 contract uses ``>``)
            if self._kernel._tool_call_count > config.max_tool_calls:
                raise PolicyViolationError(
                    "max_tool_calls_exceeded",
                    f"Tool call limit exceeded: "
                    f"{self._kernel._tool_call_count} > {config.max_tool_calls}",
                )

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
                detail = (
                    bridge_result.check_result.public_message
                    or bridge_result.reason
                    or "Step observation blocked by AGT policy"
                )
                raise PolicyViolationError(
                    "agt_output",
                    f"{detail} (in tool observation)",
                )

    def __repr__(self) -> str:
        return f"GovernanceStepCallback(steps={self._step_count})"


__all__ = [
    "SmolagentsKernel",
    "PolicyConfig",
    "PolicyViolationError",
    "AuditEvent",
    "GovernanceStepCallback",
    "_HAS_SMOLAGENTS",
    "_check_smolagents_available",
]
