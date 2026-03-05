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

import logging
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


class CrewAIKernel(BaseIntegration):
    """
    CrewAI adapter for Agent OS.

    Supports:
    - Crew (kickoff, kickoff_async)
    - Individual agents within crews
    - Task execution monitoring
    - Individual tool call interception (allowed_tools, blocked_patterns)
    """

    def __init__(self, policy: Optional[GovernancePolicy] = None):
        super().__init__(policy)
        self._wrapped_crews: dict[int, Any] = {}
        logger.debug("CrewAIKernel initialized with policy=%s", policy)

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
                """Add governance hooks to individual agent and its tools"""
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

            def __getattr__(self, name):
                return getattr(self._original, name)

        return GovernedCrewAICrew()

    def unwrap(self, governed_crew: Any) -> Any:
        """Get original crew from wrapped version"""
        logger.debug("Unwrapping governed crew")
        return governed_crew._original


# Convenience function
def wrap(crew: Any, policy: Optional[GovernancePolicy] = None) -> Any:
    """Quick wrapper for CrewAI crews"""
    logger.debug("Using convenience wrap function for crew")
    return CrewAIKernel(policy).wrap(crew)
