# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Copyright (c) Agent-Mesh Contributors. All rights reserved.
# Licensed under the MIT License.
"""Trust-aware LangChain tool wrappers.

Provides wrappers that inject trust verification before any
LangChain tool execution.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

from agentmesh.exceptions import TrustVerificationError

from .callback import InMemoryTrustStore

try:
    from langchain_core.tools import BaseTool
    from pydantic import BaseModel

    _HAS_LANGCHAIN = True
except ImportError:
    try:
        from langchain.tools import BaseTool
        from pydantic import BaseModel

        _HAS_LANGCHAIN = True
    except ImportError:
        _HAS_LANGCHAIN = False

        class BaseTool:  # type: ignore[no-redef]
            """Fallback when langchain is not installed."""

            name: str = ""
            description: str = ""

            def _run(self, *args: Any, **kwargs: Any) -> Any:
                raise NotImplementedError

        class BaseModel:  # type: ignore[no-redef]
            pass


logger = logging.getLogger(__name__)


def trust_verified_tool(
    tool: Any,
    agent_did: str,
    min_score: int = 500,
    trust_store: Optional[Any] = None,
) -> Callable[..., Any]:
    """Wrap a LangChain tool with trust verification.

    Returns a callable that checks the agent's trust score before
    delegating to the original tool's ``run`` method.

    Args:
        tool: A LangChain tool instance (must have a ``run`` method).
        agent_did: DID of the agent invoking the tool.
        min_score: Minimum trust score required (0–1000).
        trust_store: Optional trust store backend.

    Returns:
        A wrapper function that enforces trust before execution.

    Raises:
        TrustVerificationError: If the agent's trust score is below *min_score*.

    Example::

        from langchain_community.tools import DuckDuckGoSearchRun
        from agentmesh.integrations.langchain import trust_verified_tool

        search = DuckDuckGoSearchRun()
        safe_search = trust_verified_tool(search, "did:mesh:abc", min_score=600)
        result = safe_search("latest AI news")
    """
    store = trust_store or InMemoryTrustStore()

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        score = store.get_trust_score(agent_did)
        if score < min_score:
            raise TrustVerificationError(
                f"Agent {agent_did} trust score {score} "
                f"below required {min_score} for tool {getattr(tool, 'name', 'unknown')}"
            )
        logger.info(
            "Trust verified for tool %s (agent=%s, score=%d)",
            getattr(tool, "name", "unknown"),
            agent_did,
            score,
        )
        return tool.run(*args, **kwargs)

    wrapper.__name__ = f"trust_verified_{getattr(tool, 'name', 'tool')}"
    wrapper.__doc__ = f"Trust-verified wrapper for {getattr(tool, 'name', 'tool')}"
    return wrapper


class TrustVerifiedTool(BaseTool):  # type: ignore[misc]
    """A LangChain tool subclass that checks trust before execution.

    Wraps an inner callable with AgentMesh trust verification.
    The trust score is checked on every ``_run`` invocation.

    Args:
        name: Tool name.
        description: Tool description.
        agent_did: DID of the agent using this tool.
        min_trust_score: Minimum trust score required (0–1000).
        trust_store: Optional trust store backend.
        inner_fn: The actual function to execute after trust verification.

    Example::

        import ast
        from agentmesh.integrations.langchain import TrustVerifiedTool

        tool = TrustVerifiedTool(
            name="calculator",
            description="Evaluates a numeric literal safely",
            agent_did="did:mesh:abc123",
            min_trust_score=500,
            inner_fn=lambda q: str(ast.literal_eval(q)),  # safe: only evaluates Python literal values
        )
        result = tool.run("42")
    """

    # Instance attributes (not Pydantic fields for compatibility)
    _agent_did: str = ""
    _min_trust_score: int = 500
    _trust_store: Any = None
    _inner_fn: Any = None

    def __init__(
        self,
        name: str,
        description: str,
        agent_did: str,
        min_trust_score: int = 500,
        trust_store: Optional[Any] = None,
        inner_fn: Optional[Callable[..., Any]] = None,
        **kwargs: Any,
    ) -> None:
        if _HAS_LANGCHAIN:
            super().__init__(name=name, description=description, **kwargs)
        else:
            self.name = name
            self.description = description
        self._agent_did = agent_did
        self._min_trust_score = min_trust_score
        self._trust_store = trust_store or InMemoryTrustStore()
        self._inner_fn = inner_fn

    def _run(self, query: str, **kwargs: Any) -> Any:
        """Execute with trust verification."""
        score = self._trust_store.get_trust_score(self._agent_did)
        if score < self._min_trust_score:
            raise TrustVerificationError(
                f"Agent {self._agent_did} trust score {score} "
                f"below required {self._min_trust_score} for tool {self.name}"
            )
        logger.info(
            "Trust verified for tool %s (agent=%s, score=%d)",
            self.name,
            self._agent_did,
            score,
        )
        if self._inner_fn is not None:
            return self._inner_fn(query, **kwargs)
        raise NotImplementedError(f"No inner function provided for tool {self.name}")

    async def _arun(self, query: str, **kwargs: Any) -> Any:
        """Async execution delegates to sync _run."""
        return self._run(query, **kwargs)
