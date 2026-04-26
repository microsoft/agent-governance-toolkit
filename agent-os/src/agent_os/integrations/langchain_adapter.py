# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
LangChain Integration

Wraps LangChain agents/chains with Agent OS governance.

Usage:
    from agent_os.integrations import LangChainKernel

    kernel = LangChainKernel()
    governed_chain = kernel.wrap(my_langchain_chain)

    # Now all invocations go through Agent OS
    result = governed_chain.invoke({"input": "..."})
"""

import asyncio
import functools
import logging
import re
import time
from datetime import datetime
from typing import Any, Optional

from .base import BaseIntegration, GovernancePolicy

logger = logging.getLogger("agent_os.langchain")

# Patterns used to detect potential PII / secrets in memory writes
_PII_PATTERNS = [
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),           # SSN
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),  # email
    re.compile(r"\b(?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S+", re.IGNORECASE),
]


class LangChainKernel(BaseIntegration):
    """
    LangChain adapter for Agent OS.

    Supports:
    - Chains (invoke, ainvoke)
    - Agents (run, arun)
    - Runnables (invoke, batch, stream)
    - Deep hooks: tool registry interception, memory write validation,
      and sub-agent spawn detection (when ``deep_hooks_enabled`` is True).
    """

    def __init__(
        self,
        policy: Optional[GovernancePolicy] = None,
        timeout_seconds: float = 300.0,
        deep_hooks_enabled: bool = True,
    ):
        """Initialise the LangChain governance kernel.

        Args:
            policy: Governance policy to enforce. When ``None`` the default
                ``GovernancePolicy`` is used.
            timeout_seconds: Default timeout in seconds for async operations
                (default 300).
            deep_hooks_enabled: When ``True`` (default), the kernel will
                apply deep integration hooks — tool registry interception,
                memory write validation, and sub-agent spawn detection —
                during :meth:`wrap`.
        """
        super().__init__(policy)
        self.timeout_seconds = timeout_seconds
        self.deep_hooks_enabled = deep_hooks_enabled
        self._wrapped_agents: dict[int, Any] = {}  # id(wrapped) -> original
        self._start_time = time.monotonic()
        self._last_error: Optional[str] = None
        self._tool_invocations: list[dict[str, Any]] = []
        self._memory_audit_log: list[dict[str, Any]] = []
        self._delegation_chains: list[dict[str, Any]] = []

    # ── Deep Integration Hooks ────────────────────────────────────

    def _intercept_tool_registry(self, agent: Any, ctx: Any) -> None:
        """Intercept the agent's tool registry to apply per-tool governance.

        After the agent is wrapped this method inspects its ``tools``
        attribute.  Each tool's ``_run`` and ``_arun`` methods are replaced
        with governed wrappers that:

        * Check the tool name against ``blocked_patterns`` in the active
          policy before every invocation.
        * Track each invocation (tool name, arguments, timestamp) in
          :attr:`_tool_invocations`.
        * Respect the ``allowed_tools`` allowlist when configured.

        Args:
            agent: The underlying LangChain agent / runnable.
            ctx: The :class:`ExecutionContext` for governance checks.
        """
        tools = getattr(agent, "tools", None)
        if not tools:
            return

        for tool in tools:
            if getattr(tool, "_deep_governed", False):
                continue
            tool_name = getattr(tool, "name", type(tool).__name__)
            self._wrap_tool_method(tool, tool_name, "_run", ctx)
            self._wrap_tool_method(tool, tool_name, "_arun", ctx, is_async=True)
            tool._deep_governed = True
            logger.debug("Deep-governed tool registered: %s", tool_name)

    def _wrap_tool_method(
        self,
        tool: Any,
        tool_name: str,
        method_name: str,
        ctx: Any,
        is_async: bool = False,
    ) -> None:
        """Replace a single tool method with a governed wrapper.

        Args:
            tool: The LangChain tool object.
            tool_name: Human-readable tool name for logging/audit.
            method_name: The attribute to patch (``"_run"`` or ``"_arun"``).
            ctx: Execution context.
            is_async: Whether the target method is a coroutine.
        """
        original_method = getattr(tool, method_name, None)
        if original_method is None:
            return

        kernel = self

        if is_async:
            @functools.wraps(original_method)
            async def governed_async(*args: Any, **kwargs: Any) -> Any:
                kernel._check_tool_policy(tool_name, args, kwargs, ctx)
                kernel._record_tool_invocation(tool_name, args, kwargs)
                return await original_method(*args, **kwargs)

            setattr(tool, method_name, governed_async)
        else:
            @functools.wraps(original_method)
            def governed_sync(*args: Any, **kwargs: Any) -> Any:
                kernel._check_tool_policy(tool_name, args, kwargs, ctx)
                kernel._record_tool_invocation(tool_name, args, kwargs)
                return original_method(*args, **kwargs)

            setattr(tool, method_name, governed_sync)

    def _check_tool_policy(
        self, tool_name: str, args: Any, kwargs: Any, ctx: Any
    ) -> None:
        """Validate a tool call against the active governance policy.

        Raises :class:`PolicyViolationError` if the tool is not allowed or
        if its arguments match a blocked pattern.
        """
        # Allowed-tools check
        if self.policy.allowed_tools and tool_name not in self.policy.allowed_tools:
            raise PolicyViolationError(
                f"Tool '{tool_name}' not in allowed list: {self.policy.allowed_tools}"
            )

        # Blocked-patterns check on arguments
        args_str = str(args) + str(kwargs)
        matched = self.policy.matches_pattern(args_str)
        if matched:
            raise PolicyViolationError(
                f"Blocked pattern '{matched[0]}' detected in tool '{tool_name}' arguments"
            )

        # Blocked-patterns check on tool name itself
        name_matched = self.policy.matches_pattern(tool_name)
        if name_matched:
            raise PolicyViolationError(
                f"Tool '{tool_name}' matches blocked pattern '{name_matched[0]}'"
            )

    def _record_tool_invocation(
        self, tool_name: str, args: Any, kwargs: Any
    ) -> None:
        """Append a tool invocation record to the audit log."""
        record = {
            "tool_name": tool_name,
            "args": str(args),
            "kwargs": str(kwargs),
            "timestamp": datetime.now().isoformat(),
        }
        self._tool_invocations.append(record)
        if self.policy.log_all_calls:
            logger.info("Tool invocation: %s", record)

    # ── Memory Write Interception ─────────────────────────────────

    def _intercept_memory(self, agent: Any, ctx: Any) -> None:
        """Intercept memory writes on the wrapped agent.

        If the underlying object exposes a ``memory`` attribute with a
        ``save_context`` method, that method is replaced with a governed
        wrapper that:

        * Validates the data being written against PII / secret patterns.
        * Checks data against ``blocked_patterns`` in the active policy.
        * Logs every memory write to :attr:`_memory_audit_log`.

        Args:
            agent: The underlying LangChain agent / chain.
            ctx: The :class:`ExecutionContext` for governance checks.
        """
        memory = getattr(agent, "memory", None)
        if memory is None:
            return

        save_context = getattr(memory, "save_context", None)
        if save_context is None or getattr(memory, "_deep_governed", False):
            return

        kernel = self

        @functools.wraps(save_context)
        def governed_save_context(inputs: Any, outputs: Any) -> Any:
            """Governed wrapper around ``memory.save_context``."""
            kernel._validate_memory_write(inputs, outputs, ctx)
            result = save_context(inputs, outputs)
            kernel._memory_audit_log.append({
                "action": "save_context",
                "inputs_summary": str(inputs)[:200],
                "outputs_summary": str(outputs)[:200],
                "timestamp": datetime.now().isoformat(),
                "agent_id": ctx.agent_id,
            })
            logger.debug(
                "Memory write recorded for agent=%s", ctx.agent_id
            )
            return result

        memory.save_context = governed_save_context
        memory._deep_governed = True

    def _validate_memory_write(
        self, inputs: Any, outputs: Any, ctx: Any
    ) -> None:
        """Check memory content for PII, secrets, and blocked patterns.

        Raises :class:`PolicyViolationError` if the content being written
        to memory matches any PII pattern or blocked policy pattern.

        Args:
            inputs: The input dict being stored.
            outputs: The output dict being stored.
            ctx: Execution context.
        """
        combined = str(inputs) + str(outputs)

        # PII / secrets detection
        for pattern in _PII_PATTERNS:
            if pattern.search(combined):
                raise PolicyViolationError(
                    f"Memory write blocked: sensitive data detected "
                    f"(pattern: {pattern.pattern})"
                )

        # Policy blocked-patterns check
        matched = self.policy.matches_pattern(combined)
        if matched:
            raise PolicyViolationError(
                f"Memory write blocked: blocked pattern '{matched[0]}' detected"
            )

    # ── Sub-agent Spawn Detection ─────────────────────────────────

    def _detect_agent_spawning(self, agent: Any, ctx: Any) -> None:
        """Wrap ``invoke`` calls to detect and govern sub-agent delegation.

        Monitors the agent's ``invoke`` method (if present on the original
        object) for delegation patterns.  Each invocation increments a
        depth counter and is checked against the policy's
        ``max_tool_calls`` as a proxy for maximum delegation depth.

        Delegation chains are recorded in :attr:`_delegation_chains`.

        Args:
            agent: The underlying LangChain agent / runnable.
            ctx: The :class:`ExecutionContext` for governance checks.
        """
        original_invoke = getattr(agent, "invoke", None)
        if original_invoke is None or getattr(agent, "_spawn_governed", False):
            return

        kernel = self
        max_depth = self.policy.max_tool_calls  # reuse as delegation depth cap

        @functools.wraps(original_invoke)
        def governed_invoke(input_data: Any, **kwargs: Any) -> Any:
            # Track delegation depth via ctx metadata
            depth = len(kernel._delegation_chains) + 1
            if depth > max_depth:
                raise PolicyViolationError(
                    f"Max delegation depth ({max_depth}) exceeded at depth {depth}"
                )

            chain_record = {
                "parent_agent": ctx.agent_id,
                "depth": depth,
                "input_summary": str(input_data)[:200],
                "timestamp": datetime.now().isoformat(),
            }
            kernel._delegation_chains.append(chain_record)
            logger.info(
                "Sub-agent delegation detected: agent=%s depth=%d",
                ctx.agent_id, depth,
            )

            return original_invoke(input_data, **kwargs)

        agent.invoke = governed_invoke
        agent._spawn_governed = True

    # ── wrap / unwrap ─────────────────────────────────────────────

    def wrap(self, agent: Any) -> Any:
        """Wrap a LangChain chain, agent, or runnable with governance.

        Creates a proxy object that intercepts all execution methods
        (``invoke``, ``ainvoke``, ``run``, ``batch``, ``stream``) and
        applies pre-/post-execution policy checks.

        When :attr:`deep_hooks_enabled` is ``True`` (the default) the
        following additional hooks are applied:

        * **Tool registry interception** — each tool's ``_run`` / ``_arun``
          is wrapped with governance checks.
        * **Memory write interception** — ``memory.save_context`` is
          validated for PII and blocked patterns.
        * **Sub-agent spawn detection** — ``invoke`` calls are monitored
          for delegation depth.

        The wrapping strategy uses a dynamically created inner class so that
        attribute access for non-execution methods (e.g. ``name``,
        ``verbose``) is transparently forwarded to the original object.

        Args:
            agent: Any LangChain-compatible object that exposes ``invoke``,
                ``run``, ``batch``, or ``stream`` methods.

        Returns:
            A ``GovernedLangChainAgent`` proxy whose execution calls are
            subject to governance.

        Raises:
            PolicyViolationError: Raised at execution time if input or
                output violates the active policy.

        Example:
            >>> kernel = LangChainKernel(policy=GovernancePolicy(
            ...     blocked_patterns=["DROP TABLE"]
            ... ))
            >>> governed = kernel.wrap(my_chain)
            >>> result = governed.invoke({"input": "safe query"})
        """
        # Get agent ID from the object
        agent_id = getattr(agent, 'name', None) or f"langchain-{id(agent)}"
        ctx = self.create_context(agent_id)

        # Store original
        self._wrapped_agents[id(agent)] = agent

        # Apply deep hooks before creating the wrapper class
        if self.deep_hooks_enabled:
            try:
                self._intercept_tool_registry(agent, ctx)
            except Exception as exc:
                logger.warning("Tool registry interception failed: %s", exc)
            try:
                self._intercept_memory(agent, ctx)
            except Exception as exc:
                logger.warning("Memory interception failed: %s", exc)
            try:
                self._detect_agent_spawning(agent, ctx)
            except Exception as exc:
                logger.warning("Agent spawn detection setup failed: %s", exc)

        # Create wrapper class
        original = agent
        kernel = self

        class GovernedLangChainAgent:
            """LangChain agent wrapped with Agent OS governance"""

            def __init__(self):
                self._original = original
                self._ctx = ctx
                self._kernel = kernel

            def invoke(self, input_data: Any, **kwargs) -> Any:
                """Governed synchronous invocation.

                Args:
                    input_data: Input to pass to the chain/agent.
                    **kwargs: Extra arguments forwarded to the original
                        ``invoke`` call.

                Returns:
                    The result from the underlying chain/agent.

                Raises:
                    PolicyViolationError: If the input or output violates
                        governance policy.
                """
                logger.debug("invoke called with input=%r kwargs=%r", input_data, kwargs)
                # Pre-check
                allowed, reason = self._kernel.pre_execute(self._ctx, input_data)
                if not allowed:
                    logger.info("Policy DENY on invoke: %s", reason)
                    raise PolicyViolationError(reason)
                logger.info("Policy ALLOW on invoke")

                # Execute
                try:
                    result = self._original.invoke(input_data, **kwargs)
                except Exception as exc:
                    logger.error("invoke failed: %s", exc)
                    self._kernel._last_error = str(exc)
                    raise

                # Post-check
                valid, reason = self._kernel.post_execute(self._ctx, result)
                if not valid:
                    logger.info("Policy DENY on invoke result: %s", reason)
                    raise PolicyViolationError(reason)

                return result

            async def ainvoke(self, input_data: Any, **kwargs) -> Any:
                """Governed asynchronous invocation.

                Async counterpart of :meth:`invoke` — applies identical
                pre-/post-execution policy checks with timeout support.

                Args:
                    input_data: Input to pass to the chain/agent.
                    **kwargs: Extra arguments forwarded to the original
                        ``ainvoke`` call.

                Returns:
                    The result from the underlying chain/agent.

                Raises:
                    PolicyViolationError: If the input or output violates
                        governance policy.
                    asyncio.TimeoutError: If the operation exceeds the timeout.
                """
                logger.debug("ainvoke called with input=%r kwargs=%r", input_data, kwargs)
                allowed, reason = self._kernel.pre_execute(self._ctx, input_data)
                if not allowed:
                    logger.info("Policy DENY on ainvoke: %s", reason)
                    raise PolicyViolationError(reason)
                logger.info("Policy ALLOW on ainvoke")

                try:
                    result = await asyncio.wait_for(
                        self._original.ainvoke(input_data, **kwargs),
                        timeout=self._kernel.timeout_seconds,
                    )
                except asyncio.TimeoutError:
                    logger.warning(
                        "ainvoke timed out after %ss", self._kernel.timeout_seconds
                    )
                    self._kernel._last_error = "timeout"
                    raise
                except Exception as exc:
                    logger.error("ainvoke failed: %s", exc)
                    self._kernel._last_error = str(exc)
                    raise

                valid, reason = self._kernel.post_execute(self._ctx, result)
                if not valid:
                    logger.info("Policy DENY on ainvoke result: %s", reason)
                    raise PolicyViolationError(reason)

                return result

            def run(self, *args, **kwargs) -> Any:
                """Governed run for legacy LangChain agents.

                Args:
                    *args: Positional arguments; the first is treated as
                        the input for policy checking.
                    **kwargs: Keyword arguments forwarded to the original
                        ``run`` call.

                Returns:
                    The result from the underlying agent.

                Raises:
                    PolicyViolationError: If the input or output violates
                        governance policy.
                """
                input_data = args[0] if args else kwargs
                logger.debug("run called with input=%r", input_data)
                allowed, reason = self._kernel.pre_execute(self._ctx, input_data)
                if not allowed:
                    logger.info("Policy DENY on run: %s", reason)
                    raise PolicyViolationError(reason)
                logger.info("Policy ALLOW on run")

                try:
                    result = self._original.run(*args, **kwargs)
                except Exception as exc:
                    logger.error("run failed: %s", exc)
                    self._kernel._last_error = str(exc)
                    raise

                valid, reason = self._kernel.post_execute(self._ctx, result)
                if not valid:
                    logger.info("Policy DENY on run result: %s", reason)
                    raise PolicyViolationError(reason)

                return result

            def batch(self, inputs: list, **kwargs) -> list:
                """Governed batch execution.

                Each input in the batch is individually checked against
                the governance policy before the batch is submitted.

                Args:
                    inputs: List of inputs to process.
                    **kwargs: Extra arguments forwarded to the original
                        ``batch`` call.

                Returns:
                    List of results from the underlying chain/agent.

                Raises:
                    PolicyViolationError: If any input or output in the
                        batch violates governance policy.
                """
                logger.debug("batch called with %d inputs", len(inputs))
                for inp in inputs:
                    allowed, reason = self._kernel.pre_execute(self._ctx, inp)
                    if not allowed:
                        logger.info("Policy DENY on batch input: %s", reason)
                        raise PolicyViolationError(reason)
                logger.info("Policy ALLOW on batch (%d inputs)", len(inputs))

                try:
                    results = self._original.batch(inputs, **kwargs)
                except Exception as exc:
                    logger.error("batch failed: %s", exc)
                    self._kernel._last_error = str(exc)
                    raise

                for result in results:
                    valid, reason = self._kernel.post_execute(self._ctx, result)
                    if not valid:
                        logger.info("Policy DENY on batch result: %s", reason)
                        raise PolicyViolationError(reason)

                return results

            def stream(self, input_data: Any, **kwargs):
                """Governed streaming execution.

                The input is policy-checked before streaming begins.
                Individual chunks are yielded as-is; a post-execution
                check runs after the stream is fully consumed.

                Args:
                    input_data: Input to pass to the chain/agent.
                    **kwargs: Extra arguments forwarded to the original
                        ``stream`` call.

                Yields:
                    Chunks from the underlying stream.

                Raises:
                    PolicyViolationError: If the input violates governance
                        policy.
                """
                logger.debug("stream called with input=%r", input_data)
                allowed, reason = self._kernel.pre_execute(self._ctx, input_data)
                if not allowed:
                    logger.info("Policy DENY on stream: %s", reason)
                    raise PolicyViolationError(reason)
                logger.info("Policy ALLOW on stream")

                yield from self._original.stream(input_data, **kwargs)

                self._kernel.post_execute(self._ctx, None)

            # Passthrough for non-execution methods
            def __getattr__(self, name):
                return getattr(self._original, name)

        return GovernedLangChainAgent()

    def unwrap(self, governed_agent: Any) -> Any:
        """Retrieve the original unwrapped LangChain object.

        Args:
            governed_agent: A governed wrapper returned by :meth:`wrap`.

        Returns:
            The original LangChain chain, agent, or runnable.
        """
        return governed_agent._original

    def health_check(self) -> dict[str, Any]:
        """Return adapter health status.

        Returns:
            A dict with ``status``, ``backend``, ``last_error``, and
            ``uptime_seconds`` keys.
        """
        uptime = time.monotonic() - self._start_time
        status = "degraded" if self._last_error else "healthy"
        return {
            "status": status,
            "backend": "langchain",
            "backend_connected": True,
            "last_error": self._last_error,
            "uptime_seconds": round(uptime, 2),
        }


class PolicyViolationError(Exception):
    """Raised when a LangChain agent/chain violates governance policy."""

    pass


# Convenience function
def wrap(
    agent: Any,
    policy: Optional[GovernancePolicy] = None,
    timeout_seconds: float = 300.0,
) -> Any:
    """Convenience wrapper for LangChain agents and chains.

    Args:
        agent: Any LangChain-compatible object.
        policy: Optional governance policy (uses defaults when ``None``).
        timeout_seconds: Default timeout in seconds (default 300).

    Returns:
        A governed proxy around *agent*.

    Example:
        >>> from agent_os.integrations.langchain_adapter import wrap
        >>> governed = wrap(my_chain, policy=GovernancePolicy(max_tokens=5000))
        >>> result = governed.invoke({"input": "hello"})
    """
    return LangChainKernel(policy, timeout_seconds=timeout_seconds).wrap(agent)
