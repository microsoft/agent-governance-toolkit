# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for Agent OS unified package.

Run with: pytest tests/ -v
"""

import sys
from pathlib import Path

# Add modules to path for testing
REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "modules" / "control-plane" / "src"))
sys.path.insert(0, str(REPO_ROOT / "modules" / "iatp"))
sys.path.insert(0, str(REPO_ROOT / "modules" / "cmvk" / "src"))
sys.path.insert(0, str(REPO_ROOT / "modules" / "caas" / "src"))
sys.path.insert(0, str(REPO_ROOT / "modules" / "emk"))
sys.path.insert(0, str(REPO_ROOT / "modules" / "amb"))
sys.path.insert(0, str(REPO_ROOT / "modules" / "atr"))
sys.path.insert(0, str(REPO_ROOT / "modules" / "observability"))
sys.path.insert(0, str(REPO_ROOT / "modules"))
sys.path.insert(0, str(REPO_ROOT / "modules" / "mcp-kernel-server"))


# ── framework SDK stubs ───────────────────────────────────────────────────
#
# The adapters feature-detect their SDK at import time and disable whole
# mediation paths when it is missing, so an empty stub would leave those paths
# untested. These carry the specific symbols each adapter probes for, which is
# what makes the interception paths reachable. ``install`` is idempotent and
# must run before any adapter import.

import types  # noqa: E402
from typing import Any  # noqa: E402

_SIMPLE = (
    "boto3",
    "crewai",
    "langchain",
    "langgraph",
    "mistralai",
    "pydantic_ai",
    "semantic_kernel",
    "smolagents",
    "agent_shield",
    "agent_framework",
    "agents",
    "anthropic",
)


class DropMessage:
    """Stand-in for ``autogen_core.DropMessage``."""


class FunctionCall:
    """Stand-in for ``autogen_core.FunctionCall``."""

    def __init__(self, name: str = "tool", arguments: Any = "", id: str = "c1") -> None:
        self.name = name
        self.arguments = arguments
        self.id = id


class StateGraph:
    """Stand-in for ``langgraph.graph.StateGraph``."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.nodes: dict[str, Any] = {}

    def add_node(self, name: str, fn: Any = None, **kwargs: Any) -> "StateGraph":
        self.nodes[name] = fn
        return self

    def compile(self, **kwargs: Any) -> "CompiledStateGraph":
        return CompiledStateGraph(self)


class CompiledStateGraph:
    """Stand-in for ``langgraph.graph.state.CompiledStateGraph``."""

    def __init__(self, graph: Any = None) -> None:
        self.graph = graph

    def invoke(self, state: Any, **kwargs: Any) -> Any:
        return state


def _module(name: str) -> types.ModuleType:
    mod = sys.modules.get(name)
    if mod is None:
        mod = types.ModuleType(name)
        sys.modules[name] = mod
    return mod


def install() -> None:
    """Register the stub SDK modules the adapters probe for."""

    for name in _SIMPLE:
        _module(name)

    google = _module("google")
    google.__path__ = []  # type: ignore[attr-defined]
    for sub in ("google.generativeai", "google.adk"):
        mod = _module(sub)
        mod.__path__ = []  # type: ignore[attr-defined]

    # AutoGen gates its interception handler on these three symbols.
    autogen = _module("autogen_core")
    autogen.DropMessage = DropMessage  # type: ignore[attr-defined]
    autogen.FunctionCall = FunctionCall  # type: ignore[attr-defined]
    intervention = _module("autogen_core.intervention")
    autogen.intervention = intervention  # type: ignore[attr-defined]

    # LangGraph refuses to build a governed graph without these.
    langgraph = _module("langgraph")
    langgraph.__path__ = []  # type: ignore[attr-defined]
    graph = _module("langgraph.graph")
    graph.__path__ = []  # type: ignore[attr-defined]
    graph.StateGraph = StateGraph  # type: ignore[attr-defined]
    state = _module("langgraph.graph.state")
    state.CompiledStateGraph = CompiledStateGraph  # type: ignore[attr-defined]
