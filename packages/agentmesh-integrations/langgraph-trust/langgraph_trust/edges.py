"""Trust-aware edge conditions for LangGraph add_conditional_edges."""

from __future__ import annotations

from typing import Any, Callable

from langgraph_trust.state import TrustVerdict


def trust_edge(
    pass_node: str,
    fail_node: str,
    review_node: str | None = None,
) -> Callable[[dict[str, Any]], str]:
    """Return a condition function for ``add_conditional_edges``.

    Routes to ``pass_node`` when the trust verdict is PASS, ``fail_node``
    when FAIL, and optionally ``review_node`` when REVIEW (defaults to
    ``fail_node`` if not provided).

    Example::

        graph.add_conditional_edges(
            "trust_check",
            trust_edge(pass_node="execute", fail_node="human_review"),
        )
    """
    _review = review_node or fail_node

    def _route(state: dict[str, Any]) -> str:
        result = state.get("trust_result", {})
        verdict = result.get("verdict", "fail")
        if verdict == TrustVerdict.PASS.value:
            return pass_node
        if verdict == TrustVerdict.REVIEW.value:
            return _review
        return fail_node

    return _route


def trust_router(
    routes: dict[str, str],
    default: str = "__end__",
) -> Callable[[dict[str, Any]], str]:
    """General-purpose trust router mapping verdict values to node names.

    Example::

        graph.add_conditional_edges(
            "trust_check",
            trust_router({
                "pass": "execute",
                "fail": "quarantine",
                "review": "human_review",
            }),
        )
    """

    def _route(state: dict[str, Any]) -> str:
        result = state.get("trust_result", {})
        verdict = result.get("verdict", "fail")
        return routes.get(verdict, default)

    return _route
