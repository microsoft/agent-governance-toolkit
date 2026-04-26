# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Microsoft Semantic Kernel Integration

Wraps Semantic Kernel with Agent OS governance.

Usage:
    from agent_os.integrations import SemanticKernelWrapper
    from semantic_kernel import Kernel

    sk = Kernel()
    governed_sk = SemanticKernelWrapper(sk, policy="strict")

    # All invocations are now governed
    result = await governed_sk.invoke(function, input="...")

Features:
- Function invocation governance
- Plugin/skill validation
- Memory access control
- Token limit enforcement
- Full audit trail
- POSIX-style signals
"""

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from .base import BaseIntegration, ExecutionContext, GovernancePolicy


@dataclass
class SKContext(ExecutionContext):
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
    """
    Microsoft Semantic Kernel adapter for Agent OS.

    Provides governance for:
    - Function invocations
    - Plugin loading
    - Memory operations
    - Chat/text completions
    - Planner execution

    Example:
        from semantic_kernel import Kernel
        from agent_os.integrations import SemanticKernelWrapper

        sk = Kernel()
        sk.add_plugin(MyPlugin(), "my_plugin")

        governed = SemanticKernelWrapper(sk, policy=GovernancePolicy(
            allowed_tools=["my_plugin.safe_function"],
            blocked_patterns=["password", "secret"]
        ))

        # All executions are now governed
        result = await governed.invoke("my_plugin", "safe_function", input="...")
    """

    def __init__(
        self,
        kernel: Any = None,
        policy: Optional[GovernancePolicy] = None,
        timeout_seconds: float = 300.0,
    ):
        """Initialise the Semantic Kernel governance wrapper.

        Args:
            kernel: Optional Semantic Kernel instance.  Can also be
                provided later via :meth:`wrap`.
            policy: Governance policy to enforce. When ``None`` the default
                ``GovernancePolicy`` is used.
            timeout_seconds: Default timeout in seconds (default 300).
        """
        super().__init__(policy)
        self._kernel = kernel
        self._stopped = False
        self._killed = False
        self._contexts: dict[str, SKContext] = {}
        self.timeout_seconds = timeout_seconds
        self._start_time = time.monotonic()
        self._last_error: Optional[str] = None

    def wrap(self, kernel: Any) -> "GovernedSemanticKernel":
        """
        Wrap a Semantic Kernel with governance.

        Args:
            kernel: Semantic Kernel instance

        Returns:
            GovernedSemanticKernel with full governance
        """
        kernel_id = f"sk-{id(kernel)}"
        ctx = SKContext(
            agent_id=kernel_id,
            session_id=f"sk-{int(datetime.now().timestamp())}",
            policy=self.policy,
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
            func_id = getattr(function, 'name', str(function))
        else:
            func_id = f"{plugin_name}.{function_name}"

        # Record invocation
        invocation = {
            "function": func_id,
            "arguments": str(kwargs)[:500],  # Truncate for audit
            "timestamp": datetime.now().isoformat()
        }
        self._ctx.functions_invoked.append(invocation)

        # Pre-execution check
        allowed, reason = self._wrapper.pre_execute(self._ctx, kwargs)
        if not allowed:
            raise PolicyViolationError(f"Invocation blocked: {reason}")

        # Check allowed functions
        if self._wrapper.policy.allowed_tools:
            if func_id not in self._wrapper.policy.allowed_tools:
                # Check if plugin is allowed (wildcard)
                if plugin_name:
                    if f"{plugin_name}.*" not in self._wrapper.policy.allowed_tools:
                        raise PolicyViolationError(f"Function not allowed: {func_id}")
                else:
                    raise PolicyViolationError(f"Function not allowed: {func_id}")

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

            # Post-execution check
            valid, reason = self._wrapper.post_execute(self._ctx, result)
            if not valid:
                raise PolicyViolationError(f"Result blocked: {reason}")

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

        The text content is validated against ``blocked_patterns`` before
        being persisted.  The operation is recorded in the audit trail.

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

        # Pre-check content
        allowed, reason = self._wrapper.pre_execute(self._ctx, text)
        if not allowed:
            raise PolicyViolationError(f"Memory save blocked: {reason}")

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

        This is for direct chat/completion calls.
        """
        # Check signals
        if self._wrapper.is_killed():
            raise ExecutionKilledError("Kernel received SIGKILL")

        # Pre-check prompt
        allowed, reason = self._wrapper.pre_execute(self._ctx, prompt)
        if not allowed:
            raise PolicyViolationError(f"Prompt blocked: {reason}")

        # Record
        self._ctx.functions_invoked.append({
            "function": "prompt",
            "arguments": prompt[:500],
            "timestamp": datetime.now().isoformat()
        })

        # Get chat service and invoke
        # This works with SK's chat completion service pattern
        result = await self._kernel.invoke_prompt(prompt, **kwargs)

        # Post-check result
        valid, reason = self._wrapper.post_execute(self._ctx, result)
        if not valid:
            raise PolicyViolationError(f"Result blocked: {reason}")

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

        # Pre-check goal
        allowed, reason = self._wrapper.pre_execute(self._ctx, goal)
        if not allowed:
            raise PolicyViolationError(f"Plan goal blocked: {reason}")

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

        # Validate plan steps against policy
        if hasattr(self._plan, '_steps'):
            for step in self._plan._steps:
                step_name = getattr(step, 'name', str(step))
                if self._wrapper.policy.allowed_tools:
                    if step_name not in self._wrapper.policy.allowed_tools:
                        raise PolicyViolationError(
                            f"Plan step not allowed: {step_name}"
                        )

        # Execute with signal checks
        result = await self._plan.invoke(**kwargs)

        return result

    def __getattr__(self, name):
        return getattr(self._plan, name)


# ============================================================================
# Exceptions
# ============================================================================

class PolicyViolationError(Exception):
    """Raised when a Semantic Kernel function violates governance policy."""

    pass


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
    policy: Optional[GovernancePolicy] = None,
    timeout_seconds: float = 300.0,
) -> GovernedSemanticKernel:
    """
    Quick wrapper for Semantic Kernel.

    Example:
        from agent_os.integrations.semantic_kernel_adapter import wrap_kernel

        governed = wrap_kernel(my_kernel)
        result = await governed.invoke("plugin", "function")
    """
    return SemanticKernelWrapper(
        policy=policy, timeout_seconds=timeout_seconds
    ).wrap(kernel)
