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
import logging
import time
from typing import Any, Optional

from .base import BaseIntegration, GovernancePolicy

logger = logging.getLogger("agent_os.langchain")


class LangChainKernel(BaseIntegration):
    """
    LangChain adapter for Agent OS.

    Supports:
    - Chains (invoke, ainvoke)
    - Agents (run, arun)
    - Runnables (invoke, batch, stream)
    """

    def __init__(
        self,
        policy: Optional[GovernancePolicy] = None,
        timeout_seconds: float = 300.0,
    ):
        """Initialise the LangChain governance kernel.

        Args:
            policy: Governance policy to enforce. When ``None`` the default
                ``GovernancePolicy`` is used.
            timeout_seconds: Default timeout in seconds for async operations
                (default 300).
        """
        super().__init__(policy)
        self.timeout_seconds = timeout_seconds
        self._wrapped_agents: dict[int, Any] = {}  # id(wrapped) -> original
        self._start_time = time.monotonic()
        self._last_error: Optional[str] = None

    def wrap(self, agent: Any) -> Any:
        """Wrap a LangChain chain, agent, or runnable with governance.

        Creates a proxy object that intercepts all execution methods
        (``invoke``, ``ainvoke``, ``run``, ``batch``, ``stream``) and
        applies pre-/post-execution policy checks.

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
