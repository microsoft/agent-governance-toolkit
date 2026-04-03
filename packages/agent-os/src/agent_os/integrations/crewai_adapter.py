# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
CrewAI Integration

Wraps CrewAI crews and agents with Agent OS governance.

Usage:
    from agent_os.integrations import CrewAIKernel

    kernel = CrewAIKernel()
    governed_crew = kernel.wrap(my_crew)

    # Now all crew executions go through Agent OS
    result = governed_crew.kickoff()
"""

import functools
import logging
import re
from datetime import datetime
from typing import Any, Optional

logger = logging.getLogger(__name__)

from .base import (
    BaseIntegration,
    GovernancePolicy,
    PolicyInterceptor,
    PolicyViolationError,
    ToolCallRequest,
)

logger = logging.getLogger(__name__)

# Patterns used to detect potential PII / secrets in memory writes
_PII_PATTERNS = [
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),           # SSN
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),  # email
    re.compile(r"\b(?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S+", re.IGNORECASE),
]


class CrewAIKernel(BaseIntegration):
    """
    CrewAI adapter for Agent OS.

    Supports:
    - Crew (kickoff, kickoff_async)
    - Individual agents within crews
    - Task execution monitoring
    - Individual tool call interception (allowed_tools, blocked_patterns)
    - Deep hooks: step-by-step task execution, memory interception,
      and sub-agent delegation detection (when ``deep_hooks_enabled`` is True).
    """

    def __init__(self, policy: Optional[GovernancePolicy] = None, deep_hooks_enabled: bool = True):
        super().__init__(policy)
        self.deep_hooks_enabled = deep_hooks_enabled
        self._wrapped_crews: dict[int, Any] = {}
        self._step_log: list[dict[str, Any]] = []
        self._memory_audit_log: list[dict[str, Any]] = []
        self._delegation_log: list[dict[str, Any]] = []
        logger.debug("CrewAIKernel initialized with policy=%s deep_hooks_enabled=%s", policy, deep_hooks_enabled)

    def wrap(self, crew: Any) -> Any:
        """
        Wrap a CrewAI crew with governance.

        Intercepts:
        - kickoff() / kickoff_async()
        - Individual agent executions
        - Individual tool calls within agents
        - Task completions
        """
        crew_id = getattr(crew, 'id', None) or f"crew-{id(crew)}"
        crew_name = getattr(crew, 'name', crew_id)
        ctx = self.create_context(crew_id)
        logger.info("Wrapping crew with governance: crew_name=%s, crew_id=%s", crew_name, crew_id)

        self._wrapped_crews[id(crew)] = crew

        original = crew
        kernel = self

        class GovernedCrewAICrew:
            """CrewAI crew wrapped with Agent OS governance"""

            def __init__(self):
                self._original = original
                self._ctx = ctx
                self._kernel = kernel
                self._crew_name = crew_name

            def kickoff(self, inputs: dict = None) -> Any:
                """Governed kickoff"""
                logger.info("Crew execution started: crew_name=%s", self._crew_name)
                allowed, reason = self._kernel.pre_execute(self._ctx, inputs)
                if not allowed:
                    logger.warning("Crew execution blocked by policy: crew_name=%s, reason=%s", self._crew_name, reason)
                    raise PolicyViolationError(reason)

                # Wrap individual agents and their tools
                if hasattr(self._original, 'agents'):
                    for agent in self._original.agents:
                        self._wrap_agent(agent)

                result = self._original.kickoff(inputs)

                valid, reason = self._kernel.post_execute(self._ctx, result)
                if not valid:
                    logger.warning("Crew post-execution validation failed: crew_name=%s, reason=%s", self._crew_name, reason)
                    raise PolicyViolationError(reason)

                logger.info("Crew execution completed: crew_name=%s", self._crew_name)
                return result

            async def kickoff_async(self, inputs: dict = None) -> Any:
                """Governed async kickoff"""
                logger.info("Async crew execution started: crew_name=%s", self._crew_name)
                allowed, reason = self._kernel.pre_execute(self._ctx, inputs)
                if not allowed:
                    logger.warning("Async crew execution blocked by policy: crew_name=%s, reason=%s", self._crew_name, reason)
                    raise PolicyViolationError(reason)

                # Wrap individual agents and their tools
                if hasattr(self._original, 'agents'):
                    for agent in self._original.agents:
                        self._wrap_agent(agent)

                result = await self._original.kickoff_async(inputs)

                valid, reason = self._kernel.post_execute(self._ctx, result)
                if not valid:
                    logger.warning("Async crew post-execution validation failed: crew_name=%s, reason=%s", self._crew_name, reason)
                    raise PolicyViolationError(reason)

                logger.info("Async crew execution completed: crew_name=%s", self._crew_name)
                return result

            def _wrap_tool(self, tool, agent_name: str):
                """Wrap a CrewAI tool's _run method with governance interception."""
                interceptor = PolicyInterceptor(self._kernel.policy, self._ctx)
                original_run = getattr(tool, '_run', None)
                if not original_run or getattr(tool, '_governed', False):
                    return

                tool_name = getattr(tool, 'name', type(tool).__name__)
                ctx = self._ctx
                crew_name = self._crew_name

                def governed_run(*args, **kwargs):
                    """Governed wrapper around a CrewAI tool's run method.

                    Intercepts the tool call, runs pre-execution policy checks,
                    records the invocation in the audit log, and delegates
                    to the original _run implementation.

                    Args:
                        *args: Positional arguments forwarded to the original tool.
                        **kwargs: Keyword arguments forwarded to the original tool.

                    Returns:
                        The result from the original tool's run method.

                    Raises:
                        PolicyViolationError: If the tool call violates the active policy.
                    """
                    request = ToolCallRequest(
                        tool_name=tool_name,
                        arguments=kwargs if kwargs else {"args": args},
                        agent_id=agent_name,
                    )
                    result = interceptor.intercept(request)
                    if not result.allowed:
                        logger.warning(
                            "Tool call blocked: crew=%s, agent=%s, tool=%s, reason=%s",
                            crew_name, agent_name, tool_name, result.reason,
                        )
                        raise PolicyViolationError(
                            f"Tool '{tool_name}' blocked: {result.reason}"
                        )
                    ctx.call_count += 1
                    logger.info(
                        "Tool call allowed: crew=%s, agent=%s, tool=%s",
                        crew_name, agent_name, tool_name,
                    )
                    return original_run(*args, **kwargs)

                tool._run = governed_run
                tool._governed = True

            def _wrap_agent(self, agent):
                """Add governance hooks to individual agent and its tools.

                When ``deep_hooks_enabled`` is ``True`` on the kernel, this
                also applies step-level execution interception, memory write
                validation, and delegation detection.
                """
                agent_name = getattr(agent, 'name', str(id(agent)))
                logger.debug("Wrapping individual agent: crew_name=%s, agent=%s", self._crew_name, agent_name)

                # Wrap individual tools for per-call interception
                agent_tools = getattr(agent, 'tools', None) or []
                for tool in agent_tools:
                    self._wrap_tool(tool, agent_name)

                original_execute = getattr(agent, 'execute_task', None)
                if original_execute:
                    crew_name = self._crew_name

                    def governed_execute(task, *args, **kwargs):
                        """Governed wrapper around a CrewAI agent's task execution.

                        Intercepts each task execution call, applies pre-execution
                        policy checks, and delegates to the original execute method.

                        Args:
                            task: The CrewAI Task object to execute.
                            *args: Additional positional arguments.
                            **kwargs: Additional keyword arguments.

                        Returns:
                            The task execution result from the underlying agent.

                        Raises:
                            PolicyViolationError: If the execution violates the active policy.
                        """
                        task_id = getattr(task, 'id', None) or str(id(task))
                        logger.info("Agent task execution started: crew_name=%s, task_id=%s", crew_name, task_id)
                        if self._kernel.policy.require_human_approval:
                            raise PolicyViolationError(
                                f"Task '{task_id}' requires human approval per governance policy"
                            )
                        allowed, reason = self._kernel.pre_execute(self._ctx, task)
                        if not allowed:
                            raise PolicyViolationError(f"Task blocked: {reason}")

                        result = original_execute(task, *args, **kwargs)
                        valid, drift_reason = self._kernel.post_execute(self._ctx, result)
                        if not valid:
                            logger.warning("Post-execute violation: crew_name=%s, task_id=%s, reason=%s", crew_name, task_id, drift_reason)
                        logger.info("Agent task execution completed: crew_name=%s, task_id=%s", crew_name, task_id)
                        return result
                    agent.execute_task = governed_execute

                # Deep hooks at agent level
                if self._kernel.deep_hooks_enabled:
                    self._kernel._intercept_task_steps(agent, agent_name, self._crew_name)
                    self._kernel._intercept_crew_memory(agent, self._ctx, agent_name)
                    self._kernel._detect_crew_delegation(agent, self._ctx, agent_name)

            def __getattr__(self, name):
                return getattr(self._original, name)

        return GovernedCrewAICrew()

    def unwrap(self, governed_crew: Any) -> Any:
        """Get original crew from wrapped version"""
        logger.debug("Unwrapping governed crew")
        return governed_crew._original

    # ── Deep Integration Hooks ────────────────────────────────────

    def _intercept_task_steps(
        self, agent: Any, agent_name: str, crew_name: str
    ) -> None:
        """Hook into individual step execution within a task.

        If the agent exposes a ``step`` or ``_execute_step`` method, it is
        wrapped so that each intermediate step is logged and validated
        against governance policy.

        Args:
            agent: The CrewAI agent being governed.
            agent_name: Human-readable agent name for logging.
            crew_name: Human-readable crew name for logging.
        """
        for step_attr in ("step", "_execute_step"):
            original_step = getattr(agent, step_attr, None)
            if original_step is None or getattr(original_step, "_step_governed", False) is True:
                continue

            kernel = self

            @functools.wraps(original_step)
            def governed_step(*args: Any, _orig=original_step, _attr=step_attr, **kwargs: Any) -> Any:
                """Governed wrapper around a CrewAI task step.

                Intercepts individual step calls within a task, validates
                inputs against the active policy, and records each step
                in the audit trail before delegating to the original method.

                Args:
                    *args: Positional arguments forwarded to the original step.
                    **kwargs: Keyword arguments forwarded to the original step.

                Returns:
                    The result from the original step method.

                Raises:
                    PolicyViolationError: If the step input violates the active policy.
                """
                step_record = {
                    "crew": crew_name,
                    "agent": agent_name,
                    "timestamp": datetime.now().isoformat(),
                    "step_attr": _attr,
                }
                kernel._step_log.append(step_record)
                logger.debug(
                    "Step intercepted: crew=%s agent=%s step=%s",
                    crew_name, agent_name, _attr,
                )

                # Validate step input against policy
                step_input = args[0] if args else kwargs
                matched = kernel.policy.matches_pattern(str(step_input))
                if matched:
                    raise PolicyViolationError(
                        f"Step blocked: pattern '{matched[0]}' detected in step input"
                    )

                return _orig(*args, **kwargs)

            governed_step._step_governed = True
            setattr(agent, step_attr, governed_step)

    def _intercept_crew_memory(
        self, agent: Any, ctx: Any, agent_name: str
    ) -> None:
        """Intercept memory writes for a CrewAI agent's shared memory.

        CrewAI agents may have a ``memory`` or ``shared_memory`` attribute.
        This method wraps the memory's write / save methods with governance
        validation that checks for PII, secrets, and blocked patterns.

        Args:
            agent: The CrewAI agent being governed.
            ctx: Execution context for audit logging.
            agent_name: Human-readable agent name for logging.
        """
        for mem_attr in ("memory", "shared_memory", "long_term_memory"):
            memory = getattr(agent, mem_attr, None)
            if memory is None:
                continue

            for save_method_name in ("save", "save_context", "add"):
                save_fn = getattr(memory, save_method_name, None)
                if save_fn is None or getattr(save_fn, "_mem_governed", False) is True:
                    continue

                kernel = self

                @functools.wraps(save_fn)
                def governed_save(*args: Any, _orig=save_fn, _mname=save_method_name, **kwargs: Any) -> Any:
                    """Governed wrapper around CrewAI memory save operations.

                    Validates content before it is written to crew memory,
                    checking for PII patterns and policy-blocked content.
                    Records every save attempt in the memory audit log.

                    Args:
                        *args: Positional arguments forwarded to the original save.
                        **kwargs: Keyword arguments forwarded to the original save.

                    Returns:
                        The result from the original memory save method.

                    Raises:
                        PolicyViolationError: If the content contains PII or blocked patterns.
                    """
                    combined = str(args) + str(kwargs)

                    # PII / secrets check
                    for pattern in _PII_PATTERNS:
                        if pattern.search(combined):
                            raise PolicyViolationError(
                                f"Memory write blocked: sensitive data detected "
                                f"(pattern: {pattern.pattern})"
                            )

                    # Blocked patterns check
                    matched = kernel.policy.matches_pattern(combined)
                    if matched:
                        raise PolicyViolationError(
                            f"Memory write blocked: pattern '{matched[0]}' detected"
                        )

                    result = _orig(*args, **kwargs)
                    kernel._memory_audit_log.append({
                        "agent": agent_name,
                        "method": _mname,
                        "content_summary": combined[:200],
                        "timestamp": datetime.now().isoformat(),
                    })
                    return result

                governed_save._mem_governed = True
                setattr(memory, save_method_name, governed_save)

    def _detect_crew_delegation(
        self, agent: Any, ctx: Any, agent_name: str
    ) -> None:
        """Detect when a CrewAI agent delegates work to another agent.

        Wraps the ``delegate_work`` or ``execute_task`` related delegation
        methods to track and govern delegation chains.

        Args:
            agent: The CrewAI agent being governed.
            ctx: Execution context for audit logging.
            agent_name: Human-readable agent name for logging.
        """
        delegate_fn = getattr(agent, "delegate_work", None)
        if delegate_fn is None or getattr(delegate_fn, "_delegation_governed", False) is True:
            return

        kernel = self
        max_depth = self.policy.max_tool_calls

        @functools.wraps(delegate_fn)
        def governed_delegate(*args: Any, **kwargs: Any) -> Any:
            """Governed wrapper around CrewAI agent delegation.

            Intercepts delegation calls between agents, tracks delegation
            depth, and enforces the maximum delegation limit defined in
            the active policy.

            Args:
                *args: Positional arguments forwarded to the original delegate.
                **kwargs: Keyword arguments forwarded to the original delegate.

            Returns:
                The result from the delegated agent.

            Raises:
                PolicyViolationError: If the delegation depth exceeds the policy limit.
            """
            depth = len(kernel._delegation_log) + 1
            if depth > max_depth:
                raise PolicyViolationError(
                    f"Max delegation depth ({max_depth}) exceeded at depth {depth}"
                )

            record = {
                "delegator": agent_name,
                "depth": depth,
                "args_summary": str(args)[:200],
                "timestamp": datetime.now().isoformat(),
            }
            kernel._delegation_log.append(record)
            logger.info(
                "Crew delegation detected: agent=%s depth=%d",
                agent_name, depth,
            )
            return delegate_fn(*args, **kwargs)

        governed_delegate._delegation_governed = True
        agent.delegate_work = governed_delegate


# Convenience function
def wrap(crew: Any, policy: Optional[GovernancePolicy] = None) -> Any:
    """Quick wrapper for CrewAI crews"""
    logger.debug("Using convenience wrap function for crew")
    return CrewAIKernel(policy).wrap(crew)
