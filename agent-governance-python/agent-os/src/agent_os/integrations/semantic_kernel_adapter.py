# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Microsoft Semantic Kernel Integration

Wraps Semantic Kernel with Agent OS governance.

Backend (AGT 5.0): every policy decision is routed through
:class:`agt.policies.runtime.AgtRuntime` (the ACS-backed v5 engine).
The v4 :class:`~agent_os.integrations.base.GovernancePolicy` is
translated to an AGT manifest via
:func:`agt.policies.bridge.governance_to_acs_manifest` at adapter init
time, an :class:`AgtRuntime` is memoised per policy, and a
:class:`agt.policies.snapshot.SnapshotBuilder` mirrors the v4
``ExecutionContext`` budgets between intervention points. The legacy
``pre_execute`` / ``post_execute`` tuple API is preserved so v4 callers
keep working. ``transform`` verdicts (AGT-DELTA D1.1) rewrite the
outbound function arguments or prompt content before Semantic Kernel
sees them; ``escalate`` verdicts route through the configured approval
resolver per AGT-DELTA D1.4.

Usage:
    from agent_os.integrations import SemanticKernelWrapper
    from semantic_kernel import Kernel

    sk = Kernel()
    governed_sk = SemanticKernelWrapper(sk, policy="strict")

    # All invocations are now governed
    result = await governed_sk.invoke(function, input="...")

Features:
- Function invocation governance via the AGT 5.0 ACS runtime
- Plugin/skill validation at the AGT pre_tool_call hook
- Transform-verdict rewriting of arguments and prompts
- Escalate-verdict approval routing via the configured resolver
- Memory access control
- Token limit enforcement
- Full audit trail with AGT bisected input/enforced identities
- POSIX-style signals
"""

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional

from ._v5_runtime_bridge import (
    AdapterRuntimeBridge,
    BridgeResult,
    get_runtime_bridge,
)
from ..exceptions import PolicyViolationError as _CanonicalPolicyViolationError
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
        evaluator: Any = None,
        *,
        approval_resolver: Optional[Callable[..., Any]] = None,
        _runtime: Optional[Any] = None,
        _runtime_factory: Optional[Callable[..., Any]] = None,
    ):
        """Initialise the Semantic Kernel governance wrapper.

        Args:
            kernel: Optional Semantic Kernel instance.  Can also be
                provided later via :meth:`wrap`.
            policy: Governance policy to enforce. When ``None`` the default
                ``GovernancePolicy`` is used. The policy is translated to
                an AGT manifest and an :class:`agt.policies.runtime.AgtRuntime`
                is constructed over it at init time.
            timeout_seconds: Default timeout in seconds (default 300).
            evaluator: Optional ``PolicyEvaluator`` for legacy Cedar/OPA
                policy evaluation. Retained for backward compatibility;
                the primary decision path now runs through the AGT 5.0
                runtime.
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
        super().__init__(policy, evaluator=evaluator)
        self._kernel = kernel
        self._stopped = False
        self._killed = False
        self._contexts: dict[str, SKContext] = {}
        self.timeout_seconds = timeout_seconds
        self._start_time = time.monotonic()
        self._last_error: Optional[str] = None
        self._approval_resolver = approval_resolver
        self._bridge: AdapterRuntimeBridge = get_runtime_bridge(
            self.policy,
            approval_resolver=approval_resolver,
            runtime=_runtime,
            runtime_factory=_runtime_factory,
        )

    @property
    def bridge(self) -> AdapterRuntimeBridge:
        """Return the v5 :class:`AdapterRuntimeBridge` for this wrapper."""
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

        # Host-side allowlist guard FIRST (wildcard-aware). The AGT
        # manifest bridge emits no tools catalog when allowed_tools is
        # empty and cannot encode SK's plugin-wildcard entries like
        # ``MyPlugin.*``, so the host check must run before the engine
        # pre_tool_call check to (a) surface the v4 friendly "Function
        # not allowed" message and (b) honour wildcard allows that the
        # engine tool catalog would otherwise deny.
        allowlist_matched_via_wildcard = False
        if self._wrapper.policy.allowed_tools:
            if func_id not in self._wrapper.policy.allowed_tools:
                wildcard = f"{plugin_name}.*" if plugin_name else None
                if wildcard and wildcard in self._wrapper.policy.allowed_tools:
                    allowlist_matched_via_wildcard = True
                else:
                    raise PolicyViolationError(f"Function not allowed: {func_id}")

        # AGT pre_tool_call evaluation: route the function invocation
        # through the v5 ACS engine so transform / escalate / deny
        # verdicts (AGT-DELTA D1.1 / D1.4) all apply uniformly. Skipped
        # when the host guard accepted the call via a plugin wildcard,
        # because the bridge tool catalog cannot encode ``MyPlugin.*``
        # and would deny a v4-allowed call.
        self._ctx.tool_calls.append(invocation)
        self._ctx.call_count = len(self._ctx.tool_calls)
        if not allowlist_matched_via_wildcard:
            bridge_result = self._wrapper.evaluate_pre_tool_call(
                self._ctx,
                tool_name=func_id,
                args=dict(kwargs),
                call_id=f"sk-call-{self._ctx.call_count}",
            )
            if not bridge_result.allowed:
                raise PolicyViolationError.from_check_result(
                    bridge_result.check_result
                )
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
                raise PolicyViolationError.from_check_result(
                    post_result.check_result
                )
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
            raise _prefixed_violation("Memory save blocked", bridge_result.check_result)
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
            raise _prefixed_violation("Prompt blocked", bridge_result.check_result)
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
            raise PolicyViolationError.from_check_result(
                post_result.check_result
            )
        # v4 host post_execute hook (overridable) — honour host-side output
        # blocks the AGT output intervention point does not encode.
        valid, message = self._wrapper.post_execute(self._ctx, str(result))
        if not valid:
            raise PolicyViolationError(f"Result blocked: {message}")
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
            raise PolicyViolationError.from_check_result(
                bridge_result.check_result
            )
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

class PolicyViolationError(_CanonicalPolicyViolationError):
    """Raised when a Semantic Kernel function violates governance policy.

    Subclass of :class:`agent_os.exceptions.PolicyViolationError` so the
    canonical ``from_check_result`` constructor is available while
    preserving the legacy ``agent_os.integrations.semantic_kernel_adapter.PolicyViolationError``
    import path for v4 callers.
    """

    pass


def _prefixed_violation(prefix: str, check_result: Any) -> PolicyViolationError:
    """Build a host-friendly :class:`PolicyViolationError` for an SK surface.

    Surfaces the v4-style ``"<prefix>: <detail>"`` message that hosts match
    on (e.g. ``"Prompt blocked"``) while preserving the structured
    ``check_result`` and details so callers can still switch on
    ``e.check_result.category`` per the AGT host-integration contract.
    """
    base = PolicyViolationError.from_check_result(check_result)
    exc = PolicyViolationError(f"{prefix}: {base}", details=base.details)
    exc.check_result = check_result
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
    policy: Optional[GovernancePolicy] = None,
    timeout_seconds: float = 300.0,
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
        "wrap_kernel() is deprecated. Use SemanticKernelWrapper(policy=...).as_filter() "
        "with kernel.add_filter('auto_function_invocation', ...) instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    wrapper = SemanticKernelWrapper(policy=policy, timeout_seconds=timeout_seconds)
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

    Implements the SK filter protocol (``async __call__(context, next)``)
    and intercepts function invocations for policy enforcement.

    The filter:
    - Validates function names against ``allowed_tools``
    - Scans function arguments for ``blocked_patterns``
    - Enforces ``max_tool_calls`` limits
    - Runs Cedar/OPA ``pre_execute`` checks
    - Runs ``post_execute`` drift detection on results

    Example::

        wrapper = SemanticKernelWrapper(policy=GovernancePolicy(
            allowed_tools=["MyPlugin.safe_func"],
            blocked_patterns=["DROP TABLE"],
        ))
        governance_filter = wrapper.as_filter()

        sk_kernel.add_filter("auto_function_invocation", governance_filter)
        sk_kernel.add_filter("function_invocation", governance_filter)
    """

    def __init__(self, wrapper: SemanticKernelWrapper) -> None:
        self._wrapper = wrapper
        self._ctx = SKContext(
            agent_id="sk-filter",
            session_id=f"sk-filter-{int(datetime.now().timestamp())}",
            policy=wrapper.policy,
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

        # Record invocation
        self._ctx.functions_invoked.append({
            "function": full_name,
            "timestamp": datetime.now().isoformat(),
        })

        # Check allowed_tools (host-side allowlist guard — the AGT
        # manifest bridge does not encode SK's plugin-wildcard pattern
        # ``MyPlugin.*``).
        allowlist_matched_via_wildcard = False
        if self._wrapper.policy.allowed_tools:
            if full_name not in self._wrapper.policy.allowed_tools:
                wildcard = f"{plugin_name}.*" if plugin_name else None
                if wildcard and wildcard in self._wrapper.policy.allowed_tools:
                    allowlist_matched_via_wildcard = True
                else:
                    raise PolicyViolationError(
                        f"Function not allowed: {full_name}"
                    )

        # Check blocked patterns in arguments (host-side defensive scan
        # because the AGT manifest bridge only pattern-matches the
        # input intervention point's policy_target).
        args = getattr(context, "arguments", None)
        if args:
            args_str = str(args)
            for pattern in self._wrapper.policy.blocked_patterns:
                pat = pattern if isinstance(pattern, str) else pattern[0]
                if pat.lower() in args_str.lower():
                    raise PolicyViolationError(
                        f"Blocked pattern '{pat}' in arguments for {full_name}"
                    )

        # Check call count (post_execute_check also increments call_count,
        # so we check against the current value before post_execute runs).
        # This mirrors the v4 PolicyInterceptor max_tool_calls branch and
        # holds even when the AGT manifest bridge does not bind
        # pre_tool_call for the active policy.
        if self._ctx.call_count >= self._wrapper.policy.max_tool_calls:
            raise PolicyViolationError(
                f"Tool call limit exceeded: "
                f"{self._ctx.call_count} >= {self._wrapper.policy.max_tool_calls}"
            )

        # AGT pre_tool_call intervention point evaluation.
        # Wildcard-allowed function names cannot be encoded in the AGT
        # manifest tool catalog, so when the host-side guard accepted
        # the call via a plugin wildcard (``MyPlugin.*``) we skip the
        # bridge tool-catalog check and rely on the v4-equivalent host
        # checks above.
        if not allowlist_matched_via_wildcard:
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
                raise PolicyViolationError.from_check_result(
                    bridge_result.check_result
                )
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
                raise PolicyViolationError.from_check_result(
                    post_result.check_result
                )
            if post_result.transform is not None and isinstance(
                post_result.transform.value, str
            ):
                try:
                    context.result = post_result.transform.value
                except Exception:  # noqa: BLE001 — best-effort rewrite
                    pass

        # Advance the per-context call counter so subsequent invocations
        # see the running budget. The v4 base.post_execute_check did
        # this implicitly; the v5 path now does it explicitly.
        self._ctx.call_count += 1

    def __repr__(self) -> str:
        return "GovernanceFunctionFilter(wrapper=SemanticKernelWrapper)"

