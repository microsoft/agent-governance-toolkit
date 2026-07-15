# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Semantic Kernel integration backed by a required native ACS runtime.

Function arguments, prompts, and outputs are mediated before Semantic Kernel
executes or returns them.
"""

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from .base import (
    AdapterExecutionState,
    BaseIntegration,
    GovernanceEventType,
    get_adapter_runtime,
)
from ._native_adapter_runtime import (
    AdapterResult,
    AdapterRuntime,
)
from ..exceptions import PolicyViolationError


@dataclass
class SKContext(AdapterExecutionState):
    """Extended execution context for Semantic Kernel.

    Tracks kernel-specific state including loaded plugins, function
    invocation history, memory operations, and cumulative token usage.

    Attributes:
        kernel_id: Unique identifier for this kernel instance.
        plugins_loaded: Names of plugins added through the governed wrapper.
        functions_invoked: Audit log of every function invocation.
        memory_operations: Audit log of memory save/search operations.
        prompt_tokens: Cumulative prompt tokens consumed.
        completion_tokens: Cumulative completion tokens consumed.
    """

    kernel_id: str = ""
    plugins_loaded: list[str] = field(default_factory=list)
    functions_invoked: list[dict] = field(default_factory=list)
    memory_operations: list[dict] = field(default_factory=list)

    # Token tracking
    prompt_tokens: int = 0
    completion_tokens: int = 0


class SemanticKernelWrapper(BaseIntegration):
    """Govern Semantic Kernel functions, plugins, memory, and planners."""

    def __init__(
        self,
        kernel: Any = None,
        timeout_seconds: float = 300.0,
        *,
        runtime: Any,
    ):
        """Initialise host timeout settings and the required native runtime."""
        super().__init__(runtime=runtime)
        self._kernel = kernel
        self._stopped = False
        self._killed = False
        self._contexts: dict[str, SKContext] = {}
        self.timeout_seconds = timeout_seconds
        self._start_time = time.monotonic()
        self._last_error: Optional[str] = None
        self._bridge: AdapterRuntime = get_adapter_runtime(runtime)

    @property
    def bridge(self) -> AdapterRuntime:
        """Return the v5 :class:`AdapterRuntime` for this wrapper."""
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
        """AGT ``pre_tool_call`` evaluation for a Semantic Kernel function call."""
        return self._bridge.evaluate_pre_tool_call(
            ctx, tool_name=tool_name, args=args, call_id=call_id
        )

    def as_filter(self) -> "GovernanceFunctionFilter":
        """Create a governance filter for Semantic Kernel's native filter system.

        Returns a ``GovernanceFunctionFilter`` that can be registered with::

            kernel.add_filter("auto_function_invocation", wrapper.as_filter())
            kernel.add_filter("function_invocation", wrapper.as_filter())

        This is the **recommended** integration pattern for Semantic Kernel
        as it uses the framework's native ``add_filter()`` API instead of
        proxying the kernel object.

        Returns:
            A ``GovernanceFunctionFilter`` instance.
        """
        return GovernanceFunctionFilter(self)

    def wrap(self, kernel: Any) -> "GovernedSemanticKernel":
        """Wrap a Semantic Kernel with governance.

        .. deprecated::
            Use :meth:`as_filter` with ``kernel.add_filter()`` instead
            for a non-invasive integration.

        Args:
            kernel: Semantic Kernel instance

        Returns:
            GovernedSemanticKernel with full governance
        """
        import warnings
        warnings.warn(
            "SemanticKernelWrapper.wrap() is deprecated. Use as_filter() with "
            "kernel.add_filter('auto_function_invocation', wrapper.as_filter()) "
            "for a non-invasive integration.",
            DeprecationWarning,
            stacklevel=2,
        )
        kernel_id = f"sk-{id(kernel)}"
        ctx = SKContext(
            agent_id=kernel_id,
            session_id=f"sk-{int(datetime.now().timestamp())}",
            kernel_id=kernel_id
        )
        self._contexts[kernel_id] = ctx

        return GovernedSemanticKernel(
            kernel=kernel,
            wrapper=self,
            ctx=ctx
        )

    def unwrap(self, governed_kernel: Any) -> Any:
        """Retrieve the original unwrapped Semantic Kernel instance.

        Args:
            governed_kernel: A ``GovernedSemanticKernel`` or any object.

        Returns:
            The original ``Kernel`` if *governed_kernel* is a
            ``GovernedSemanticKernel``; otherwise returns the input as-is.
        """
        if isinstance(governed_kernel, GovernedSemanticKernel):
            return governed_kernel._kernel
        return governed_kernel

    def signal_stop(self, kernel_id: str):
        """SIGSTOP — pause all function invocations.

        While stopped, calls to :meth:`GovernedSemanticKernel.invoke`
        will block (``await asyncio.sleep``) until :meth:`signal_continue`
        is called.

        Args:
            kernel_id: Identifier of the kernel to pause.
        """
        self._stopped = True

    def signal_continue(self, kernel_id: str):
        """SIGCONT — resume execution after a previous SIGSTOP.

        Args:
            kernel_id: Identifier of the kernel to resume.
        """
        self._stopped = False

    def signal_kill(self, kernel_id: str):
        """SIGKILL — terminate all kernel operations immediately.

        Once killed, any in-flight or future invocations will raise
        ``ExecutionKilledError``.

        Args:
            kernel_id: Identifier of the kernel to kill.
        """
        self._killed = True

    def is_stopped(self) -> bool:
        """Return whether the wrapper is in a stopped (SIGSTOP) state."""
        return self._stopped

    def is_killed(self) -> bool:
        """Return whether the wrapper has received SIGKILL."""
        return self._killed

    def health_check(self) -> dict[str, Any]:
        """Return adapter health status.

        Returns:
            A dict with ``status``, ``backend``, ``last_error``, and
            ``uptime_seconds`` keys.
        """
        uptime = time.monotonic() - self._start_time
        if self._killed:
            status = "unhealthy"
        elif self._last_error:
            status = "degraded"
        else:
            status = "healthy"
        return {
            "status": status,
            "backend": "semantic_kernel",
            "backend_connected": self._kernel is not None,
            "last_error": self._last_error,
            "uptime_seconds": round(uptime, 2),
        }


class GovernedSemanticKernel:
    """
    Semantic Kernel wrapped with Agent OS governance.

    Intercepts all function calls, plugin operations, and memory access.
    """

    def __init__(
        self,
        kernel: Any,
        wrapper: SemanticKernelWrapper,
        ctx: SKContext
    ):
        self._kernel = kernel
        self._wrapper = wrapper
        self._ctx = ctx

    # =========================================================================
    # Function Invocation (Core Governance)
    # =========================================================================

    async def invoke(
        self,
        plugin_name: Optional[str] = None,
        function_name: Optional[str] = None,
        function: Optional[Any] = None,
        **kwargs
    ) -> Any:
        """
        Governed function invocation.

        Args:
            plugin_name: Name of the plugin
            function_name: Name of the function
            function: Direct function reference (alternative)
            **kwargs: Arguments to pass to function

        Returns:
            Function result

        Raises:
            PolicyViolationError: If policy is violated
            ExecutionStoppedError: If SIGSTOP received
            ExecutionKilledError: If SIGKILL received
        """
        # Check signals
        if self._wrapper.is_killed():
            raise ExecutionKilledError("Kernel received SIGKILL")

        while self._wrapper.is_stopped():
            await asyncio.sleep(0.1)
            if self._wrapper.is_killed():
                raise ExecutionKilledError("Kernel received SIGKILL")

        # Build function identifier
        if function:
            function_name_value = getattr(function, "name", str(function))
            function_plugin = getattr(function, "plugin_name", None)
            func_id = (
                f"{function_plugin}.{function_name_value}"
                if function_plugin
                else function_name_value
            )
        else:
            func_id = f"{plugin_name}.{function_name}"

        # Record invocation
        invocation = {
            "function": func_id,
            "arguments": str(kwargs)[:500],  # Truncate for audit
            "timestamp": datetime.now().isoformat()
        }
        self._ctx.functions_invoked.append(invocation)

        # Route the function invocation through the native runtime.
        self._ctx.tool_calls.append(invocation)
        current_call_count = len(self._ctx.tool_calls)
        self._ctx.call_count = max(0, current_call_count - 1)
        try:
            bridge_result = self._wrapper.evaluate_pre_tool_call(
                self._ctx,
                tool_name=func_id,
                args=dict(kwargs),
                call_id=f"sk-call-{current_call_count}",
            )
        finally:
            self._ctx.call_count = current_call_count
        if not bridge_result.allowed:
            raise bridge_result.to_policy_violation(PolicyViolationError)
        if bridge_result.transform is not None and isinstance(
            bridge_result.transform.value, dict
        ):
            kwargs = dict(bridge_result.transform.value)

        # Execute
        try:
            if function:
                result = await self._kernel.invoke(function, **kwargs)
            elif plugin_name and function_name:
                result = await self._kernel.invoke(
                    self._kernel.plugins[plugin_name][function_name],
                    **kwargs
                )
            else:
                raise ValueError("Must provide either function or plugin_name+function_name")

            # AGT output intervention point evaluation on the function
            # result. AGT-DELTA D1.1: a transform verdict rewrites the
            # value the caller sees, mirroring the GovernanceFunctionFilter
            # path (semantic_kernel_adapter.py:1161-1167) and the
            # llamaindex_adapter post hook (llamaindex_adapter.py:187-203).
            post_result = self._wrapper.bridge.evaluate_output(
                self._ctx, content=str(result)
            )
            if not post_result.allowed:
                raise post_result.to_policy_violation(PolicyViolationError)
            if post_result.transform is not None and isinstance(
                post_result.transform.value, str
            ):
                if hasattr(result, "value"):
                    try:
                        result.value = post_result.transform.value
                        return result
                    except Exception:  # noqa: BLE001 — best-effort rewrite
                        pass
                return post_result.transform.value

            return result

        except Exception as e:
            if "SIGKILL" in str(e) or self._wrapper.is_killed():
                raise ExecutionKilledError("Kernel received SIGKILL") from e
            raise

    def invoke_sync(
        self,
        plugin_name: Optional[str] = None,
        function_name: Optional[str] = None,
        function: Optional[Any] = None,
        **kwargs
    ) -> Any:
        """Synchronous wrapper around :meth:`invoke`.

        Runs the async ``invoke`` in a new event loop via
        ``asyncio.run()``.  Useful for scripts or environments that are
        not already running an async loop.

        Args:
            plugin_name: Name of the plugin containing the function.
            function_name: Name of the function within the plugin.
            function: Direct function reference (alternative to
                *plugin_name* + *function_name*).
            **kwargs: Arguments forwarded to the kernel function.

        Returns:
            The function result.

        Raises:
            PolicyViolationError: If the invocation violates policy.
            ExecutionKilledError: If SIGKILL has been received.
        """
        return asyncio.run(self.invoke(
            plugin_name=plugin_name,
            function_name=function_name,
            function=function,
            **kwargs
        ))

    # =========================================================================
    # Plugin Management
    # =========================================================================

    def add_plugin(
        self,
        plugin: Any,
        plugin_name: str,
        **kwargs
    ) -> Any:
        """Register a plugin with the kernel, tracking it for governance.

        The plugin name is recorded in the execution context for audit
        purposes.  Plugin functions remain subject to
        ``allowed_tools`` policy checks when invoked.

        Args:
            plugin: The plugin object to register.
            plugin_name: Human-readable name for the plugin.
            **kwargs: Extra arguments forwarded to the kernel's
                ``add_plugin`` method.

        Returns:
            The result from the underlying ``kernel.add_plugin()`` call.
        """
        # Record plugin
        self._ctx.plugins_loaded.append(plugin_name)

        # Add to kernel
        return self._kernel.add_plugin(plugin, plugin_name, **kwargs)

    def import_plugin_from_openai(
        self,
        plugin_name: str,
        openai_function: dict,
        **kwargs
    ) -> Any:
        """Import an OpenAI function definition as a Semantic Kernel plugin.

        Args:
            plugin_name: Name to register the plugin under.
            openai_function: OpenAI-format function definition dict.
            **kwargs: Extra arguments forwarded to the kernel.

        Returns:
            The result from the underlying import call.
        """
        self._ctx.plugins_loaded.append(f"openai:{plugin_name}")
        return self._kernel.import_plugin_from_openai(
            plugin_name,
            openai_function,
            **kwargs
        )

    @property
    def plugins(self) -> dict:
        """Access loaded plugins"""
        return self._kernel.plugins

    # =========================================================================
    # Memory Operations (Governed)
    # =========================================================================

    async def memory_save(
        self,
        collection: str,
        text: str,
        id: Optional[str] = None,
        **kwargs
    ) -> Any:
        """Save information to kernel memory with governance checks.

        The text content is validated at the AGT ``input`` intervention
        point before being persisted. A ``transform`` verdict (AGT-DELTA
        D1.1) rewrites the text before the memory backend sees it. The
        operation is recorded in the audit trail.

        Args:
            collection: Memory collection name.
            text: Text content to save.
            id: Optional identifier for the memory entry.
            **kwargs: Extra arguments forwarded to the memory backend.

        Returns:
            The result from the memory backend, or ``None`` if no memory
            backend is configured.

        Raises:
            PolicyViolationError: If the text violates a blocked pattern.
            ExecutionKilledError: If SIGKILL has been received.
        """
        # Check signals
        if self._wrapper.is_killed():
            raise ExecutionKilledError("Kernel received SIGKILL")

        # AGT input intervention point check on the memory body
        bridge_result = self._wrapper.evaluate_input(self._ctx, text)
        if not bridge_result.allowed:
            raise _prefixed_violation("Memory save blocked", bridge_result)
        if bridge_result.transform is not None and isinstance(
            bridge_result.transform.value, str
        ):
            text = bridge_result.transform.value

        # Record operation
        self._ctx.memory_operations.append({
            "operation": "save",
            "collection": collection,
            "id": id,
            "timestamp": datetime.now().isoformat()
        })

        # Execute
        if hasattr(self._kernel, 'memory') and self._kernel.memory:
            return await self._kernel.memory.save_information(
                collection=collection,
                text=text,
                id=id,
                **kwargs
            )
        return None

    async def memory_search(
        self,
        collection: str,
        query: str,
        limit: int = 5,
        **kwargs
    ) -> list:
        """Search kernel memory with governance logging.

        The search operation is recorded in the audit trail (query text
        is truncated to 100 characters in the log).

        Args:
            collection: Memory collection to search.
            query: Search query string.
            limit: Maximum number of results to return (default 5).
            **kwargs: Extra arguments forwarded to the memory backend.

        Returns:
            A list of search results, or an empty list if no memory
            backend is configured.

        Raises:
            ExecutionKilledError: If SIGKILL has been received.
        """
        # Check signals
        if self._wrapper.is_killed():
            raise ExecutionKilledError("Kernel received SIGKILL")

        # Record operation
        self._ctx.memory_operations.append({
            "operation": "search",
            "collection": collection,
            "query": query[:100],  # Truncate for audit
            "timestamp": datetime.now().isoformat()
        })

        # Execute
        if hasattr(self._kernel, 'memory') and self._kernel.memory:
            return await self._kernel.memory.search(
                collection=collection,
                query=query,
                limit=limit,
                **kwargs
            )
        return []

    # =========================================================================
    # Chat Completion (Governed)
    # =========================================================================

    async def invoke_prompt(
        self,
        prompt: str,
        **kwargs
    ) -> Any:
        """
        Invoke a prompt with governance.

        This is for direct chat/completion calls. The prompt is
        evaluated at the AGT ``input`` intervention point. ``transform``
        verdicts (AGT-DELTA D1.1) rewrite the prompt before Semantic
        Kernel sees it.
        """
        # Check signals
        if self._wrapper.is_killed():
            raise ExecutionKilledError("Kernel received SIGKILL")

        # AGT input intervention point check on the prompt
        bridge_result = self._wrapper.evaluate_input(self._ctx, prompt)
        if not bridge_result.allowed:
            raise _prefixed_violation("Prompt blocked", bridge_result)
        if bridge_result.transform is not None and isinstance(
            bridge_result.transform.value, str
        ):
            prompt = bridge_result.transform.value

        # Record
        self._ctx.functions_invoked.append({
            "function": "prompt",
            "arguments": prompt[:500],
            "timestamp": datetime.now().isoformat()
        })

        # Get chat service and invoke
        # This works with SK's chat completion service pattern
        result = await self._kernel.invoke_prompt(prompt, **kwargs)

        # AGT output intervention point evaluation on the result.
        # AGT-DELTA D1.1: a transform verdict rewrites the value the
        # caller sees.
        post_result = self._wrapper.bridge.evaluate_output(
            self._ctx, content=str(result)
        )
        if not post_result.allowed:
            raise post_result.to_policy_violation(PolicyViolationError)
        if post_result.transform is not None and isinstance(
            post_result.transform.value, str
        ):
            if hasattr(result, "value"):
                try:
                    result.value = post_result.transform.value
                    return result
                except Exception:  # noqa: BLE001 — best-effort rewrite
                    pass
            return post_result.transform.value

        return result

    # =========================================================================
    # Planner (Governed)
    # =========================================================================

    async def create_plan(
        self,
        goal: str,
        planner: Optional[Any] = None,
        **kwargs
    ) -> Any:
        """Create a governed execution plan.

        Each step in the generated plan is validated against
        ``allowed_tools`` before execution is permitted.

        Args:
            goal: Natural language description of the goal.
            planner: Optional planner instance; defaults to
                ``SequentialPlanner`` if not provided.
            **kwargs: Extra arguments forwarded to the planner.

        Returns:
            A ``GovernedPlan`` that validates steps on invocation.

        Raises:
            PolicyViolationError: If the goal text violates policy.
            ExecutionKilledError: If SIGKILL has been received.
        """
        # Check signals
        if self._wrapper.is_killed():
            raise ExecutionKilledError("Kernel received SIGKILL")

        # AGT input intervention point check on the planner goal
        bridge_result = self._wrapper.evaluate_input(self._ctx, goal)
        if not bridge_result.allowed:
            raise bridge_result.to_policy_violation(PolicyViolationError)
        if bridge_result.transform is not None and isinstance(
            bridge_result.transform.value, str
        ):
            goal = bridge_result.transform.value

        # Create plan
        if planner:
            plan = await planner.create_plan(goal, **kwargs)
        else:
            # Use default sequential planner if available
            try:
                from semantic_kernel.planners import SequentialPlanner
            except ImportError:
                raise ImportError(
                    "semantic-kernel is required for planning. "
                    "Install it with: pip install semantic-kernel"
                )
            planner = SequentialPlanner(self._kernel)
            plan = await planner.create_plan(goal, **kwargs)

        return GovernedPlan(plan, self._wrapper, self._ctx)

    # =========================================================================
    # Signal Handling
    # =========================================================================

    def sigkill(self):
        """Send SIGKILL — terminate all kernel operations immediately."""
        self._wrapper.signal_kill(self._ctx.kernel_id)

    def sigstop(self):
        """Send SIGSTOP — pause all kernel operations."""
        self._wrapper.signal_stop(self._ctx.kernel_id)

    def sigcont(self):
        """Send SIGCONT — resume kernel operations after SIGSTOP."""
        self._wrapper.signal_continue(self._ctx.kernel_id)

    # =========================================================================
    # Utility
    # =========================================================================

    def get_context(self) -> SKContext:
        """Return the execution context containing the full audit trail.

        Returns:
            The ``SKContext`` for this governed kernel.
        """
        return self._ctx

    def get_audit_log(self) -> dict:
        """Return a structured audit log of all kernel activity.

        Returns:
            A dict with keys ``kernel_id``, ``session_id``,
            ``plugins_loaded``, ``functions_invoked``,
            ``memory_operations``, ``call_count``, and ``checkpoints``.
        """
        return {
            "kernel_id": self._ctx.kernel_id,
            "session_id": self._ctx.session_id,
            "plugins_loaded": self._ctx.plugins_loaded,
            "functions_invoked": self._ctx.functions_invoked,
            "memory_operations": self._ctx.memory_operations,
            "call_count": self._ctx.call_count,
            "checkpoints": self._ctx.checkpoints
        }

    def __getattr__(self, name):
        """Proxy attribute access to the underlying Semantic Kernel instance."""
        return getattr(self._kernel, name)


class GovernedPlan:
    """A Semantic Kernel plan wrapped with step-level governance.

    Each step in the plan is validated against the ``allowed_tools``
    policy constraint before execution begins.
    """

    def __init__(
        self,
        plan: Any,
        wrapper: SemanticKernelWrapper,
        ctx: SKContext
    ):
        """Initialise a governed plan wrapper.

        Args:
            plan: The original Semantic Kernel plan object.
            wrapper: Parent governance wrapper for signal/policy access.
            ctx: Execution context for audit logging.
        """
        self._plan = plan
        self._wrapper = wrapper
        self._ctx = ctx

    async def invoke(self, **kwargs) -> Any:
        """Execute the plan with step-by-step governance validation.

        Before execution, each step is checked against ``allowed_tools``.
        Execution is aborted if SIGKILL has been received.

        Args:
            **kwargs: Arguments forwarded to the plan's ``invoke`` method.

        Returns:
            The plan execution result.

        Raises:
            PolicyViolationError: If a plan step is not in ``allowed_tools``.
            ExecutionKilledError: If SIGKILL has been received.
        """
        # Check signals before starting
        if self._wrapper.is_killed():
            raise ExecutionKilledError("Kernel received SIGKILL")

        # Validate plan steps through the native tool intervention.
        if hasattr(self._plan, '_steps'):
            for step in self._plan._steps:
                step_name = getattr(step, 'name', str(step))
                result = self._wrapper.evaluate_pre_tool_call(
                    self._ctx,
                    tool_name=step_name,
                    args=dict(kwargs),
                    call_id=f"sk-plan-{self._ctx.call_count + 1}",
                )
                if not result.allowed:
                    raise result.to_policy_violation(PolicyViolationError)

        # Execute with signal checks
        result = await self._plan.invoke(**kwargs)

        return result

    def __getattr__(self, name):
        return getattr(self._plan, name)


def _prefixed_violation(
    prefix: str, adapter_result: AdapterResult
) -> PolicyViolationError:
    """Add stable host context while preserving the native evaluation."""
    base = adapter_result.to_policy_violation(PolicyViolationError)
    exc = PolicyViolationError(f"{prefix}: {base}", details=base.details)
    exc.evaluation_result = getattr(base, "evaluation_result", None)
    return exc


class ExecutionStoppedError(Exception):
    """Raised when execution is blocked by SIGSTOP."""

    pass


class ExecutionKilledError(Exception):
    """Raised when execution is terminated by SIGKILL."""

    pass


# ============================================================================
# Convenience Functions
# ============================================================================

def wrap_kernel(
    kernel: Any,
    timeout_seconds: float = 300.0,
    *,
    runtime: Any,
) -> GovernedSemanticKernel:
    """Quick wrapper for Semantic Kernel.

    .. deprecated::
        Use ``SemanticKernelWrapper.as_filter()`` with
        ``kernel.add_filter()`` instead.

    Example:
        from agent_os.integrations.semantic_kernel_adapter import wrap_kernel

        governed = wrap_kernel(my_kernel)
        result = await governed.invoke("plugin", "function")
    """
    import warnings
    warnings.warn(
        "wrap_kernel() is deprecated. Use SemanticKernelWrapper(runtime=...).as_filter() "
        "with kernel.add_filter('auto_function_invocation', ...) instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    wrapper = SemanticKernelWrapper(
        timeout_seconds=timeout_seconds,
        runtime=runtime,
    )
    # Suppress the deprecation from wrap() since we already emitted one
    import contextlib
    with contextlib.suppress(Exception), warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return wrapper.wrap(kernel)


# ═══════════════════════════════════════════════════════════════════
# Native Hook: GovernanceFunctionFilter
# ═══════════════════════════════════════════════════════════════════
#
# Semantic Kernel provides kernel.add_filter() for registering
# function invocation and auto-function-invocation filters.
# GovernanceFunctionFilter implements the filter protocol:
#
#     async def __call__(self, context, next):
#         ...
#         await next(context)
#         ...
#
# Usage:
#     wrapper = SemanticKernelWrapper(policy=policy)
#     sk_kernel.add_filter("auto_function_invocation", wrapper.as_filter())
#     sk_kernel.add_filter("function_invocation", wrapper.as_filter())
# ═══════════════════════════════════════════════════════════════════


class GovernanceFunctionFilter:
    """Governance filter for Semantic Kernel's native ``add_filter()`` system.

    The filter mediates function arguments and results through ACS.
    """

    def __init__(self, wrapper: SemanticKernelWrapper) -> None:
        self._wrapper = wrapper
        self._ctx = SKContext(
            agent_id="sk-filter",
            session_id=f"sk-filter-{int(datetime.now().timestamp())}",
            kernel_id="sk-filter",
        )
        wrapper._contexts["sk-filter"] = self._ctx

    @property
    def wrapper(self) -> SemanticKernelWrapper:
        """Return the parent ``SemanticKernelWrapper``."""
        return self._wrapper

    @property
    def context(self) -> SKContext:
        """Return the execution context."""
        return self._ctx

    async def __call__(self, context: Any, next: Any) -> None:
        """Filter protocol implementation for Semantic Kernel.

        Called by the SK runtime before/after each function invocation.
        Routes the call through the AGT 5.0 ACS engine at the
        ``pre_tool_call`` intervention point. ``transform`` verdicts
        (AGT-DELTA D1.1) rewrite ``context.arguments`` before the
        function executes; ``escalate`` verdicts route through the
        configured approval resolver per AGT-DELTA D1.4.

        Args:
            context: SK's ``FunctionInvocationContext`` or
                ``AutoFunctionInvocationContext``.
            next: Async callable to continue the filter chain or execute
                the function.

        Raises:
            PolicyViolationError: If the function violates governance policy.
        """
        # Extract function identity
        func = getattr(context, "function", None)
        func_name = getattr(func, "name", None) or "unknown"
        plugin_name = getattr(func, "plugin_name", None) or ""
        full_name = f"{plugin_name}.{func_name}" if plugin_name else func_name
        trusted_skill_sources = self._wrapper.trusted_sources(
            self._wrapper.trusted_skill_metadata_source(
                skill_name=plugin_name or getattr(func, "skill_name", None),
                skill_origin=getattr(func, "skill_origin", None),
            )
        )
        skill_fields = self._wrapper.build_skill_audit_fields(
            trusted_sources=trusted_skill_sources,
            default_origin="semantic_kernel_plugin",
            context_before=getattr(context, "arguments", None),
        )

        self._wrapper.emit_skill_audit_event(
            GovernanceEventType.POLICY_CHECK,
            agent_id=self._ctx.agent_id,
            action="semantic_kernel.function_invocation",
            trusted_sources=trusted_skill_sources,
            default_origin="semantic_kernel_plugin",
            context_before=getattr(context, "arguments", None),
            function_name=full_name,
        )

        # Record invocation
        self._ctx.functions_invoked.append({
            "function": full_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **skill_fields,
        })

        args = getattr(context, "arguments", None)
        args_dict: dict[str, Any]
        if isinstance(args, dict):
            args_dict = dict(args)
        elif args is None:
            args_dict = {}
        else:
            args_dict = {"_value": args}
        bridge_result = self._wrapper.evaluate_pre_tool_call(
            self._ctx,
            tool_name=full_name,
            args=args_dict,
            call_id=f"sk-filter-{self._ctx.call_count + 1}",
        )
        if not bridge_result.allowed:
            raise bridge_result.to_policy_violation(PolicyViolationError)
        if bridge_result.transform is not None and isinstance(
            bridge_result.transform.value, dict
        ):
            try:
                context.arguments = bridge_result.transform.value
            except Exception:  # noqa: BLE001 — best-effort rewrite
                pass

        # Proceed with execution
        await next(context)

        # AGT output intervention point evaluation on the function result.
        result = getattr(context, "result", None)
        if result is not None:
            post_result = self._wrapper.bridge.evaluate_output(
                self._ctx, content=str(result)
            )
            if not post_result.allowed:
                raise post_result.to_policy_violation(PolicyViolationError)
            if post_result.transform is not None and isinstance(
                post_result.transform.value, str
            ):
                try:
                    context.result = post_result.transform.value
                except Exception:  # noqa: BLE001 — best-effort rewrite
                    pass

        # Advance the host counter so the next snapshot sees this invocation.
        self._ctx.call_count += 1

    def __repr__(self) -> str:
        return "GovernanceFunctionFilter(wrapper=SemanticKernelWrapper)"
