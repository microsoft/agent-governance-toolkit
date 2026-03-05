# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
LlamaIndex Integration

Wraps LlamaIndex query engines, retrievers, and agents with Agent OS governance.

Usage:
    from agent_os.integrations import LlamaIndexKernel

    kernel = LlamaIndexKernel()
    governed_engine = kernel.wrap(my_query_engine)

    # Now all queries go through Agent OS governance
    result = governed_engine.query("What is the meaning of life?")
"""

from typing import Any, Optional

from .base import BaseIntegration, GovernancePolicy
from .langchain_adapter import PolicyViolationError


class LlamaIndexKernel(BaseIntegration):
    """
    LlamaIndex adapter for Agent OS.

    Supports:
    - QueryEngine (query, aquery)
    - RetrieverQueryEngine
    - ChatEngine (chat, achat, stream_chat)
    - AgentRunner (chat, query)
    """

    def __init__(self, policy: Optional[GovernancePolicy] = None):
        super().__init__(policy)
        self._wrapped_agents: dict[int, Any] = {}
        self._stopped: dict[str, bool] = {}

    def wrap(self, agent: Any) -> Any:
        """
        Wrap a LlamaIndex query engine, chat engine, or agent with governance.

        Intercepts:
        - query() / aquery()
        - chat() / achat()
        - stream_chat()
        - retrieve()
        """
        agent_id = getattr(agent, 'name', None) or f"llamaindex-{id(agent)}"
        ctx = self.create_context(agent_id)

        self._wrapped_agents[id(agent)] = agent
        self._stopped[agent_id] = False

        original = agent
        kernel = self

        class GovernedLlamaIndexAgent:
            """LlamaIndex engine wrapped with Agent OS governance"""

            def __init__(self):
                self._original = original
                self._ctx = ctx
                self._kernel = kernel
                self._agent_id = agent_id

            def _check_stopped(self):
                if kernel._stopped.get(self._agent_id):
                    raise PolicyViolationError(
                        f"Agent '{self._agent_id}' is stopped (SIGSTOP)"
                    )

            def query(self, query_str: Any, **kwargs) -> Any:
                """Governed query"""
                self._check_stopped()

                allowed, reason = self._kernel.pre_execute(self._ctx, query_str)
                if not allowed:
                    raise PolicyViolationError(reason)

                result = self._original.query(query_str, **kwargs)

                valid, reason = self._kernel.post_execute(self._ctx, result)
                if not valid:
                    raise PolicyViolationError(reason)

                return result

            async def aquery(self, query_str: Any, **kwargs) -> Any:
                """Governed async query"""
                self._check_stopped()

                allowed, reason = self._kernel.pre_execute(self._ctx, query_str)
                if not allowed:
                    raise PolicyViolationError(reason)

                result = await self._original.aquery(query_str, **kwargs)

                valid, reason = self._kernel.post_execute(self._ctx, result)
                if not valid:
                    raise PolicyViolationError(reason)

                return result

            def chat(self, message: str, **kwargs) -> Any:
                """Governed chat"""
                self._check_stopped()

                allowed, reason = self._kernel.pre_execute(self._ctx, message)
                if not allowed:
                    raise PolicyViolationError(reason)

                result = self._original.chat(message, **kwargs)

                valid, reason = self._kernel.post_execute(self._ctx, result)
                if not valid:
                    raise PolicyViolationError(reason)

                return result

            async def achat(self, message: str, **kwargs) -> Any:
                """Governed async chat"""
                self._check_stopped()

                allowed, reason = self._kernel.pre_execute(self._ctx, message)
                if not allowed:
                    raise PolicyViolationError(reason)

                result = await self._original.achat(message, **kwargs)

                valid, reason = self._kernel.post_execute(self._ctx, result)
                if not valid:
                    raise PolicyViolationError(reason)

                return result

            def stream_chat(self, message: str, **kwargs):
                """Governed streaming chat"""
                self._check_stopped()

                allowed, reason = self._kernel.pre_execute(self._ctx, message)
                if not allowed:
                    raise PolicyViolationError(reason)

                response = self._original.stream_chat(message, **kwargs)

                self._kernel.post_execute(self._ctx, None)
                return response

            def retrieve(self, query_str: Any, **kwargs) -> Any:
                """Governed retrieve"""
                self._check_stopped()

                allowed, reason = self._kernel.pre_execute(self._ctx, query_str)
                if not allowed:
                    raise PolicyViolationError(reason)

                result = self._original.retrieve(query_str, **kwargs)

                self._kernel.post_execute(self._ctx, result)
                return result

            def __getattr__(self, name):
                return getattr(self._original, name)

        return GovernedLlamaIndexAgent()

    def unwrap(self, governed_agent: Any) -> Any:
        """Get original engine from wrapped version"""
        return governed_agent._original

    def signal(self, agent_id: str, signal: str):
        """Send signal to a governed agent"""
        if signal == "SIGSTOP":
            self._stopped[agent_id] = True
        elif signal == "SIGCONT":
            self._stopped[agent_id] = False
        elif signal == "SIGKILL":
            self._stopped[agent_id] = True

        super().signal(agent_id, signal)


# Convenience function
def wrap(agent: Any, policy: Optional[GovernancePolicy] = None) -> Any:
    """Quick wrapper for LlamaIndex engines"""
    return LlamaIndexKernel(policy).wrap(agent)
