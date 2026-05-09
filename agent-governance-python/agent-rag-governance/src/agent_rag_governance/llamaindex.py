# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""LlamaIndex adapter for agent-rag-governance.

Provides :class:`GovernedQueryEngine` — a drop-in wrapper around any
LlamaIndex ``BaseQueryEngine`` or ``BaseRetriever`` that enforces
:class:`~agent_rag_governance.policy.RAGPolicy` on every retrieval call.

The same four governance controls apply:

1. **Collection access control** — allow/deny list from :class:`RAGPolicy`.
2. **Rate limiting** — sliding-window cap on retrievals per agent per minute.
3. **Content scanning** — PII and prompt-injection detection on chunks.
4. **Audit logging** — structured JSON-lines record per call.

Usage::

    from agent_rag_governance import RAGGovernor, RAGPolicy
    from agent_rag_governance.llamaindex import GovernedQueryEngine

    policy = RAGPolicy(
        allowed_collections=["public_docs", "product_manuals"],
        denied_collections=["hr_records", "financial_data"],
        max_retrievals_per_minute=100,
        content_policies=["block_pii", "block_injections"],
        audit_enabled=True,
    )
    governor = RAGGovernor(policy=policy, agent_id="sales-agent-001")
    governed_engine = GovernedQueryEngine(
        query_engine=your_llama_query_engine,
        governor=governor,
        collection="public_docs",
    )

    # Drop-in replacement — same API as the original query engine
    response = governed_engine.query("what is our refund policy?")

LlamaIndex is an optional dependency. Install with::

    pip install "agent-rag-governance[llamaindex]"
"""

from __future__ import annotations

import logging
from typing import Any, List

from .governor import RAGGovernor

logger = logging.getLogger(__name__)


class GovernedQueryEngine:
    """A drop-in wrapper around any LlamaIndex query engine or retriever
    that enforces :class:`~agent_rag_governance.policy.RAGPolicy`.

    Supports both:

    - ``BaseQueryEngine`` — via ``.query()`` interface.
    - ``BaseRetriever`` — via ``.retrieve()`` interface.

    Instantiate directly with an explicit *governor*.

    Args:
        query_engine: Any LlamaIndex ``BaseQueryEngine`` or
            ``BaseRetriever`` instance.
        governor: The :class:`~agent_rag_governance.governor.RAGGovernor`
            that enforces policy on every call.
        collection: Logical collection name used for access-control
            checks and audit records. Defaults to ``"default"``.

    Example::

        governed_engine = GovernedQueryEngine(
            query_engine=index.as_query_engine(),
            governor=governor,
            collection="public_docs",
        )
        response = governed_engine.query("how do I reset my password?")
    """

    def __init__(
        self,
        query_engine: Any,
        governor: RAGGovernor,
        collection: str = "default",
    ) -> None:
        if not (hasattr(query_engine, "query") or hasattr(query_engine, "retrieve")):
            raise TypeError(
                f"{type(query_engine).__name__!r} must implement "
                ".query() or .retrieve()"
            )
        self._query_engine = query_engine
        self._governor = governor
        self._collection = collection

    def query(self, query: str, **kwargs: Any) -> Any:
        """Govern and execute a query call.

        Runs the full governance pipeline (collection check, rate limit,
        content scan, audit) through the governor's ``_execute`` path —
        identical to how ``retrieve()`` works — then reconstructs the
        original response with only the clean, governance-approved nodes.

        Args:
            query: The query string.
            **kwargs: Additional keyword arguments forwarded to the
                underlying engine's ``.query()`` method.

        Returns:
            The query response from the underlying engine, with any
            blocked chunks removed from the source nodes before the
            response reaches the caller.

        Raises:
            CollectionDeniedError: Collection is not permitted for this agent.
            RateLimitExceededError: Agent has exceeded its retrieval rate.
            ContentScanError: A chunk failed content scanning (only raised
                when *all* chunks are blocked — partial blocks are silently
                filtered and logged).
        """
        adapter = _LlamaQueryEngineAdapter(self._query_engine)
        clean_docs = self._governor._execute(
            retriever=adapter,
            collection=self._collection,
            query=query,
            kwargs=kwargs,
        )
        # Reconstruct response with only governance-approved nodes.
        # Always rebuild so source_nodes reflects what passed governance,
        # not the raw engine output.
        response = adapter.last_response
        if response is not None:
            response = self._rebuild_response(response, clean_docs)
        return response if response is not None else clean_docs

    def retrieve(self, query: str, **kwargs: Any) -> List[Any]:
        """Govern and execute a retrieve call.

        For LlamaIndex ``BaseRetriever`` — delegates to ``.retrieve()``
        instead of ``.query()``.

        Args:
            query: The query string.
            **kwargs: Additional keyword arguments forwarded to the
                underlying retriever's ``.retrieve()`` method.

        Returns:
            List of ``NodeWithScore`` objects that passed all governance checks.

        Raises:
            CollectionDeniedError: Collection is not permitted for this agent.
            RateLimitExceededError: Agent has exceeded its retrieval rate.
        """
        # Delegate to governor._execute using retrieve interface
        return self._governor._execute(
            retriever=_LlamaRetrieverAdapter(self._query_engine),
            collection=self._collection,
            query=query,
            kwargs=kwargs,
        )

    @staticmethod
    def _rebuild_response(response: Any, clean_nodes: List[Any]) -> Any:
        """Rebuild response with only clean nodes after content scanning."""
        if hasattr(response, "source_nodes"):
            try:
                response.source_nodes = clean_nodes
            except AttributeError:
                # Response is immutable — return as-is with warning
                logger.warning(
                    "Could not update source_nodes on response of type %s "
                    "after content scanning — returning original response",
                    type(response).__name__,
                )
        return response

    # Expose underlying query engine attributes transparently
    def __getattr__(self, name: str) -> Any:
        return getattr(self._query_engine, name)


class _LlamaRetrieverAdapter:
    """Internal adapter that translates LlamaIndex retriever interface
    to the ``invoke()`` / ``get_relevant_documents()`` interface expected
    by :meth:`~agent_rag_governance.governor.RAGGovernor._retrieve`.

    Not part of the public API.
    """

    def __init__(self, retriever: Any) -> None:
        self._retriever = retriever

    def invoke(self, query: str, **kwargs: Any) -> List[Any]:
        """Delegate to LlamaIndex ``.retrieve()`` method."""
        if hasattr(self._retriever, "retrieve"):
            return self._retriever.retrieve(query, **kwargs)
        raise TypeError(
            f"LlamaIndex retriever {type(self._retriever).__name__!r} "
            "has no .retrieve() method"
        )


class _LlamaQueryEngineAdapter:
    """Internal adapter that translates LlamaIndex query engine interface
    to the ``invoke()`` interface expected by
    :meth:`~agent_rag_governance.governor.RAGGovernor._retrieve`.

    Captures the full response object and exposes source nodes as a flat
    list so the governor's ``_execute`` pipeline can scan and redact them
    *before* the response reaches the caller.

    Not part of the public API.
    """

    def __init__(self, query_engine: Any) -> None:
        self._query_engine = query_engine
        self.last_response: Any = None

    def invoke(self, query: str, **kwargs: Any) -> List[Any]:
        """Execute the underlying query and return source nodes for scanning."""
        self.last_response = self._query_engine.query(query, **kwargs)
        # Return source nodes so governor._execute can scan them
        if hasattr(self.last_response, "source_nodes"):
            return list(self.last_response.source_nodes)
        if isinstance(self.last_response, list):
            return self.last_response
        return []
