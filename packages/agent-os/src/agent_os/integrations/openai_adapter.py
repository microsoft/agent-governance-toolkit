# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
OpenAI Assistants Integration

Wraps OpenAI Assistants API with Agent OS governance.

Usage:
    from agent_os.integrations import OpenAIKernel
    from openai import OpenAI

    client = OpenAI()
    kernel = OpenAIKernel(policy="strict")

    # Create assistant as normal
    assistant = client.beta.assistants.create(
        name="Trading Bot",
        instructions="You analyze market data",
        model="gpt-4-turbo"
    )

    # Wrap for governance
    governed_assistant = kernel.wrap(assistant, client)

    # All runs are now governed!
    thread = governed_assistant.create_thread()
    governed_assistant.add_message(thread.id, "Analyze AAPL")
    run = governed_assistant.run(thread.id)  # Governed execution

Features:
- Pre-execution policy checks
- Tool call interception and validation
- Real-time run monitoring
- SIGKILL support (cancel run on violation)
- Full audit trail
"""

import json
import logging
import random
import time
from collections.abc import Generator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional

from .base import BaseIntegration, ExecutionContext, GovernancePolicy

logger = logging.getLogger("agent_os.openai")


@dataclass
class AssistantContext(ExecutionContext):
    """Extended execution context for OpenAI Assistants.

    Tracks assistant-specific state including thread IDs, run IDs,
    function call history, and cumulative token usage for governance
    enforcement.

    Attributes:
        assistant_id: The OpenAI assistant identifier.
        thread_ids: List of thread IDs created during this session.
        run_ids: List of run IDs executed during this session.
        function_calls: History of function/tool calls made by the assistant.
        prompt_tokens: Cumulative prompt tokens consumed across all runs.
        completion_tokens: Cumulative completion tokens consumed across all runs.
    """

    assistant_id: str = ""
    thread_ids: list[str] = field(default_factory=list)
    run_ids: list[str] = field(default_factory=list)
    function_calls: list[dict] = field(default_factory=list)

    # Token tracking
    prompt_tokens: int = 0
    completion_tokens: int = 0


# Transient error base classes for retry detection
_TRANSIENT_ERROR_NAMES = ("RateLimitError", "APIConnectionError", "Timeout", "APITimeoutError")


def _is_transient(exc: Exception) -> bool:
    """Return True if the exception is a transient OpenAI error."""
    return type(exc).__name__ in _TRANSIENT_ERROR_NAMES


def retry_with_backoff(
    fn: Callable[..., Any],
    *args: Any,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    **kwargs: Any,
) -> Any:
    """Call *fn* with exponential backoff + jitter on transient errors.

    Args:
        fn: Callable to invoke.
        max_retries: Number of retry attempts after the initial call.
        base_delay: Base delay in seconds for backoff calculation.
        max_delay: Upper bound for the computed delay.

    Returns:
        The return value of *fn*.

    Raises:
        The last caught exception if all retries are exhausted.
    """
    last_exc: Optional[Exception] = None
    for attempt in range(max_retries + 1):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            if not _is_transient(exc) or attempt == max_retries:
                raise
            last_exc = exc
            delay = min(base_delay * (2 ** attempt) + random.uniform(0, 1), max_delay)  # noqa: S311 — non-cryptographic use for request jitter
            logger.warning(
                "Retry %d/%d for %s after %s (delay=%.2fs)",
                attempt + 1,
                max_retries,
                fn.__name__ if hasattr(fn, "__name__") else str(fn),
                type(exc).__name__,
                delay,
            )
            time.sleep(delay)
    raise last_exc  # type: ignore[misc]


class OpenAIKernel(BaseIntegration):
    """
    OpenAI Assistants adapter for Agent OS.

    Provides governance for:
    - Assistant creation/modification
    - Thread management
    - Run execution
    - Tool/function calls
    - File operations

    Example:
        kernel = OpenAIKernel(policy=GovernancePolicy(
            max_tokens=10000,
            allowed_tools=["code_interpreter", "retrieval"],
            blocked_patterns=["password", "api_key", "secret"]
        ))

        governed = kernel.wrap(assistant, client)
        result = governed.run(thread_id)
    """

    def __init__(
        self,
        policy: Optional[GovernancePolicy] = None,
        max_retries: int = 3,
        timeout_seconds: float = 300.0,
    ):
        """Initialise the OpenAI governance kernel.

        Args:
            policy: Governance policy to enforce. When ``None`` the default
                ``GovernancePolicy`` is used.
            max_retries: Maximum number of retry attempts for transient
                OpenAI errors (default 3).
            timeout_seconds: Default timeout in seconds for operations
                (default 300).
        """
        super().__init__(policy)
        self.max_retries = max_retries
        self.timeout_seconds = timeout_seconds
        self._wrapped_assistants: dict[str, Any] = {}  # assistant_id -> original
        self._clients: dict[str, Any] = {}  # assistant_id -> client
        self._cancelled_runs: set[str] = set()
        self._start_time = time.monotonic()
        self._last_error: Optional[str] = None

    def wrap(self, agent: Any, client: Any = None) -> "GovernedAssistant":
        """Wrap an OpenAI Assistant with governance.

        This is the primary wrapping method, consistent with all other
        adapters.  OpenAI Assistants require both an assistant object
        **and** a client, so ``client`` must be provided.

        Args:
            agent: OpenAI Assistant object.
            client: OpenAI client instance (required).

        Returns:
            GovernedAssistant with full governance.

        Raises:
            TypeError: If *client* is not provided.
        """
        if client is None:
            raise TypeError(
                "OpenAIKernel.wrap() requires a 'client' argument: "
                "kernel.wrap(assistant, client)"
            )
        assistant_id = agent.id
        ctx = AssistantContext(
            agent_id=assistant_id,
            session_id=f"oai-{int(time.time())}",
            policy=self.policy,
            assistant_id=assistant_id
        )
        self.contexts[assistant_id] = ctx
        self._wrapped_assistants[assistant_id] = agent
        self._clients[assistant_id] = client

        return GovernedAssistant(
            assistant=agent,
            client=client,
            kernel=self,
            ctx=ctx
        )

    def wrap_assistant(self, assistant: Any, client: Any) -> "GovernedAssistant":
        """Wrap an OpenAI Assistant with governance.

        .. deprecated::
            Use :meth:`wrap` instead::

                governed = kernel.wrap(assistant, client)

        Args:
            assistant: OpenAI Assistant object.
            client: OpenAI client instance.

        Returns:
            GovernedAssistant with full governance.
        """
        import warnings
        warnings.warn(
            "wrap_assistant() is deprecated, use wrap(assistant, client) instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.wrap(assistant, client)

    def unwrap(self, governed_agent: Any) -> Any:
        """Retrieve the original unwrapped assistant.

        Args:
            governed_agent: A ``GovernedAssistant`` or any object.

        Returns:
            The original OpenAI assistant object if *governed_agent* is a
            ``GovernedAssistant``; otherwise returns *governed_agent* as-is.
        """
        if isinstance(governed_agent, GovernedAssistant):
            return governed_agent._assistant
        return governed_agent

    def cancel_run(self, thread_id: str, run_id: str, client: Any):
        """Cancel a run (SIGKILL equivalent).

        Immediately marks the run as cancelled locally and issues a cancel
        request to the OpenAI API.  If the API call fails (e.g. the run
        has already completed), the error is silently ignored.

        Args:
            thread_id: The thread the run belongs to.
            run_id: The run to cancel.
            client: OpenAI client used to issue the cancellation.
        """
        self._cancelled_runs.add(run_id)
        try:
            client.beta.threads.runs.cancel(
                thread_id=thread_id,
                run_id=run_id
            )
        except Exception:  # noqa: BLE001 — best-effort cancel, run may already be complete
            logger.warning("Run cancel failed (may already be complete): thread=%s run=%s", thread_id, run_id, exc_info=True)

    def is_cancelled(self, run_id: str) -> bool:
        """Check whether a run has been cancelled via :meth:`cancel_run`.

        Args:
            run_id: The run identifier to check.

        Returns:
            ``True`` if the run was previously cancelled.
        """
        return run_id in self._cancelled_runs

    def health_check(self) -> dict[str, Any]:
        """Return adapter health status.

        Returns:
            A dict with ``status``, ``backend``, ``last_error``, and
            ``uptime_seconds`` keys.
        """
        uptime = time.monotonic() - self._start_time
        has_clients = bool(self._clients)
        if self._last_error:
            status = "degraded"
        elif not has_clients:
            status = "healthy"
        else:
            status = "healthy"
        return {
            "status": status,
            "backend": "openai",
            "backend_connected": has_clients,
            "last_error": self._last_error,
            "uptime_seconds": round(uptime, 2),
        }


class GovernedAssistant:
    """
    OpenAI Assistant wrapped with Agent OS governance.

    All API calls are intercepted for policy enforcement.
    """

    def __init__(
        self,
        assistant: Any,
        client: Any,
        kernel: OpenAIKernel,
        ctx: AssistantContext
    ):
        self._assistant = assistant
        self._client = client
        self._kernel = kernel
        self._ctx = ctx
        self._tool_registry: dict[str, Callable] = {}

    def register_tool(self, name: str, func: Callable) -> None:
        """Register a tool function for automatic execution."""
        self._tool_registry[name] = func

    @property
    def id(self) -> str:
        """Assistant ID"""
        return self._assistant.id

    @property
    def name(self) -> str:
        """Assistant name"""
        return self._assistant.name

    # =========================================================================
    # Thread Management
    # =========================================================================

    def create_thread(self, **kwargs) -> Any:
        """Create a new conversation thread.

        The thread ID is automatically recorded in the execution context
        for audit purposes.

        Args:
            **kwargs: Forwarded to ``client.beta.threads.create()``.

        Returns:
            The newly created OpenAI thread object.
        """
        thread = self._client.beta.threads.create(**kwargs)
        self._ctx.thread_ids.append(thread.id)
        return thread

    def get_thread(self, thread_id: str) -> Any:
        """Retrieve an existing thread by ID.

        Args:
            thread_id: The thread to retrieve.

        Returns:
            The OpenAI thread object.
        """
        return self._client.beta.threads.retrieve(thread_id)

    def delete_thread(self, thread_id: str) -> bool:
        """Delete a thread and remove it from the execution context.

        Args:
            thread_id: The thread to delete.

        Returns:
            ``True`` if the thread was successfully deleted.
        """
        result = self._client.beta.threads.delete(thread_id)
        if thread_id in self._ctx.thread_ids:
            self._ctx.thread_ids.remove(thread_id)
        return result.deleted

    # =========================================================================
    # Message Management
    # =========================================================================

    def add_message(
        self,
        thread_id: str,
        content: str,
        role: str = "user",
        **kwargs
    ) -> Any:
        """Add a message to a thread with pre-execution policy checks.

        The message content is validated against ``blocked_patterns`` before
        being sent to the OpenAI API.

        Args:
            thread_id: Target thread.
            content: Message text.
            role: Message role (default ``"user"``).
            **kwargs: Additional parameters forwarded to the API.

        Returns:
            The created OpenAI message object.

        Raises:
            PolicyViolationError: If the content matches a blocked pattern.
        """
        # Pre-check: blocked patterns
        allowed, reason = self._kernel.pre_execute(self._ctx, content)
        if not allowed:
            raise PolicyViolationError(f"Message blocked: {reason}")

        message = self._client.beta.threads.messages.create(
            thread_id=thread_id,
            role=role,
            content=content,
            **kwargs
        )
        return message

    def list_messages(self, thread_id: str, **kwargs) -> list:
        """List messages in a thread.

        Args:
            thread_id: The thread whose messages to list.
            **kwargs: Additional parameters (e.g. ``limit``, ``order``).

        Returns:
            A list of message objects in the thread.
        """
        return self._client.beta.threads.messages.list(
            thread_id=thread_id,
            **kwargs
        )

    # =========================================================================
    # Run Execution (Core Governance)
    # =========================================================================

    def run(
        self,
        thread_id: str,
        instructions: Optional[str] = None,
        tools: Optional[list] = None,
        poll_interval: float = 1.0,
        **kwargs
    ) -> Any:
        """
        Execute a governed run.

        This is the primary method for executing the assistant.
        All tool calls and outputs are validated against policy.

        Args:
            thread_id: Thread to run on
            instructions: Optional override instructions
            tools: Optional tools to enable
            poll_interval: How often to check run status
            **kwargs: Additional run parameters

        Returns:
            Completed run object

        Raises:
            PolicyViolationError: If policy is violated
            RunCancelledException: If run was SIGKILL'd
        """
        # Pre-check
        if instructions:
            allowed, reason = self._kernel.pre_execute(self._ctx, instructions)
            if not allowed:
                raise PolicyViolationError(f"Instructions blocked: {reason}")

        # Validate tools against policy
        if tools:
            self._validate_tools(tools)

        # Create run
        run_kwargs = {
            "thread_id": thread_id,
            "assistant_id": self._assistant.id,
            **kwargs
        }
        if instructions:
            run_kwargs["instructions"] = instructions
        if tools:
            run_kwargs["tools"] = tools

        run = self._client.beta.threads.runs.create(**run_kwargs)
        self._ctx.run_ids.append(run.id)

        # Poll until complete (with governance checks)
        return self._poll_run(thread_id, run.id, poll_interval)

    def run_stream(
        self,
        thread_id: str,
        instructions: Optional[str] = None,
        **kwargs
    ) -> Generator:
        """
        Stream a governed run.

        Yields events as they arrive, with real-time policy checks.
        """
        # Pre-check
        if instructions:
            allowed, reason = self._kernel.pre_execute(self._ctx, instructions)
            if not allowed:
                raise PolicyViolationError(f"Instructions blocked: {reason}")

        # Create streaming run
        with self._client.beta.threads.runs.stream(
            thread_id=thread_id,
            assistant_id=self._assistant.id,
            instructions=instructions,
            **kwargs
        ) as stream:
            for event in stream:
                # Check for cancellation
                if hasattr(event, 'data') and hasattr(event.data, 'id'):
                    if self._kernel.is_cancelled(event.data.id):
                        raise RunCancelledException("Run was cancelled (SIGKILL)")

                # Yield event
                yield event

    def _poll_run(
        self,
        thread_id: str,
        run_id: str,
        poll_interval: float
    ) -> Any:
        """
        Poll run status with governance checks.
        """
        while True:
            # Check for SIGKILL
            if self._kernel.is_cancelled(run_id):
                raise RunCancelledException("Run was cancelled (SIGKILL)")

            run = self._client.beta.threads.runs.retrieve(
                thread_id=thread_id,
                run_id=run_id
            )

            # Update token counts
            if hasattr(run, 'usage') and run.usage:
                self._ctx.prompt_tokens += run.usage.prompt_tokens or 0
                self._ctx.completion_tokens += run.usage.completion_tokens or 0

                # Check token limit
                total = self._ctx.prompt_tokens + self._ctx.completion_tokens
                if total > self._kernel.policy.max_tokens:
                    self._kernel.cancel_run(thread_id, run_id, self._client)
                    raise PolicyViolationError(
                        f"Token limit exceeded: {total} > {self._kernel.policy.max_tokens}"
                    )

            # Handle different statuses
            if run.status == "completed":
                self._kernel.post_execute(self._ctx, run)
                return run

            elif run.status == "requires_action":
                # Tool calls need approval
                run = self._handle_tool_calls(thread_id, run)

            elif run.status in ["failed", "cancelled", "expired"]:
                return run

            elif run.status in ["queued", "in_progress"]:
                time.sleep(poll_interval)

            else:
                # Unknown status
                time.sleep(poll_interval)

    def _handle_tool_calls(self, thread_id: str, run: Any) -> Any:
        """
        Handle tool calls with policy validation.
        """
        tool_calls = run.required_action.submit_tool_outputs.tool_calls
        tool_outputs = []

        for tool_call in tool_calls:
            # Record tool call
            call_info = {
                "id": tool_call.id,
                "type": tool_call.type,
                "function": tool_call.function.name if hasattr(tool_call, 'function') else None,
                "arguments": tool_call.function.arguments if hasattr(tool_call, 'function') else None,
                "timestamp": datetime.now().isoformat()
            }
            self._ctx.function_calls.append(call_info)
            self._ctx.tool_calls.append(call_info)

            # Check tool call count
            if len(self._ctx.tool_calls) > self._kernel.policy.max_tool_calls:
                self._kernel.cancel_run(thread_id, run.id, self._client)
                raise PolicyViolationError(
                    f"Tool call limit exceeded: {len(self._ctx.tool_calls)} > {self._kernel.policy.max_tool_calls}"
                )

            # Validate function name
            if hasattr(tool_call, 'function'):
                func_name = tool_call.function.name
                if self._kernel.policy.allowed_tools:
                    if func_name not in self._kernel.policy.allowed_tools:
                        self._kernel.cancel_run(thread_id, run.id, self._client)
                        raise PolicyViolationError(
                            f"Tool not allowed: {func_name}"
                        )

            # Check human approval requirement
            if self._kernel.policy.require_human_approval:
                tool_outputs.append({
                    "tool_call_id": tool_call.id,
                    "output": json.dumps({
                        "status": "requires_approval",
                        "function": func_name if hasattr(tool_call, 'function') else "unknown",
                        "message": "Tool execution requires human approval per governance policy"
                    })
                })
                continue

            # Execute via tool registry if available
            output = None
            if hasattr(self, '_tool_registry') and self._tool_registry:
                func_name_exec = tool_call.function.name if hasattr(tool_call, 'function') else None
                if func_name_exec and func_name_exec in self._tool_registry:
                    try:
                        args = json.loads(tool_call.function.arguments) if hasattr(tool_call, 'function') else {}
                        result = self._tool_registry[func_name_exec](**args)
                        output = json.dumps(result) if not isinstance(result, str) else result
                    except Exception as e:
                        logger.warning("Tool execution failed for %s", func_name_exec, exc_info=True)
                        output = json.dumps({"status": "error", "message": str(e)})

            if output is None:
                output = json.dumps({
                    "status": "no_executor",
                    "function": tool_call.function.name if hasattr(tool_call, 'function') else "unknown",
                    "message": "No tool executor registered for this function"
                })

            tool_outputs.append({
                "tool_call_id": tool_call.id,
                "output": output
            })

        # Submit outputs
        return self._client.beta.threads.runs.submit_tool_outputs(
            thread_id=thread_id,
            run_id=run.id,
            tool_outputs=tool_outputs
        )

    def _validate_tools(self, tools: list):
        """Validate tools against policy"""
        if not self._kernel.policy.allowed_tools:
            return  # No restrictions

        for tool in tools:
            tool_type = tool.get("type") if isinstance(tool, dict) else getattr(tool, "type", None)
            if tool_type and tool_type not in self._kernel.policy.allowed_tools:
                raise PolicyViolationError(f"Tool type not allowed: {tool_type}")

    # =========================================================================
    # Signal Handling
    # =========================================================================

    def sigkill(self, thread_id: str, run_id: str):
        """Send SIGKILL to a running assistant — immediately cancels the run.

        This is the primary mechanism for forcibly stopping a governed
        assistant that has violated policy or needs emergency termination.

        Args:
            thread_id: Thread containing the run.
            run_id: The run to kill.

        Example:
            >>> governed.sigkill(thread_id="thread_abc", run_id="run_xyz")
        """
        self._kernel.cancel_run(thread_id, run_id, self._client)

    def sigstop(self, thread_id: str, run_id: str):
        """Send SIGSTOP to a running assistant.

        .. note::

            The OpenAI Assistants API does not support pausing a run, so
            this behaves identically to :meth:`sigkill` (cancels the run).

        Args:
            thread_id: Thread containing the run.
            run_id: The run to stop.
        """
        self._kernel.cancel_run(thread_id, run_id, self._client)

    # =========================================================================
    # Utility
    # =========================================================================

    def get_context(self) -> AssistantContext:
        """Return the execution context containing the full audit trail.

        Returns:
            The ``AssistantContext`` for this governed assistant, including
            thread IDs, run IDs, function call history, and token usage.
        """
        return self._ctx

    def get_token_usage(self) -> dict:
        """Return cumulative token usage statistics.

        Returns:
            A dict with keys ``prompt_tokens``, ``completion_tokens``,
            ``total_tokens``, and ``limit``.

        Example:
            >>> governed.get_token_usage()
            {'prompt_tokens': 120, 'completion_tokens': 80, 'total_tokens': 200, 'limit': 10000}
        """
        return {
            "prompt_tokens": self._ctx.prompt_tokens,
            "completion_tokens": self._ctx.completion_tokens,
            "total_tokens": self._ctx.prompt_tokens + self._ctx.completion_tokens,
            "limit": self._kernel.policy.max_tokens
        }

    def __getattr__(self, name):
        """Proxy attribute access to the underlying OpenAI assistant.

        Allows transparent access to assistant properties (e.g. ``model``,
        ``instructions``) that are not explicitly overridden by this wrapper.
        """
        return getattr(self._assistant, name)


class PolicyViolationError(Exception):
    """Raised when an assistant action violates governance policy.

    Contains a human-readable reason describing which policy was violated.
    """

    pass


class RunCancelledException(Exception):
    """Raised when a run is forcibly cancelled via SIGKILL.

    Indicates that ``cancel_run`` (or ``sigkill``) was invoked, either
    directly or automatically by the governance layer (e.g. token limit
    exceeded, disallowed tool call).
    """

    pass


# ============================================================================
# Convenience Functions
# ============================================================================

def wrap(
    assistant: Any,
    client: Any,
    policy: Optional[GovernancePolicy] = None,
    max_retries: int = 3,
    timeout_seconds: float = 300.0,
) -> GovernedAssistant:
    """Quick wrapper for OpenAI Assistants.

    Example::

        from agent_os.integrations.openai_adapter import wrap

        governed = wrap(my_assistant, openai_client)
        result = governed.run(thread_id)
    """
    return OpenAIKernel(
        policy, max_retries=max_retries, timeout_seconds=timeout_seconds
    ).wrap(assistant, client)


def wrap_assistant(
    assistant: Any,
    client: Any,
    policy: Optional[GovernancePolicy] = None,
    max_retries: int = 3,
    timeout_seconds: float = 300.0,
) -> GovernedAssistant:
    """Quick wrapper for OpenAI Assistants.

    .. deprecated::
        Use :func:`wrap` instead.
    """
    import warnings
    warnings.warn(
        "wrap_assistant() is deprecated, use wrap() instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    return wrap(assistant, client, policy=policy, max_retries=max_retries,
                timeout_seconds=timeout_seconds)
