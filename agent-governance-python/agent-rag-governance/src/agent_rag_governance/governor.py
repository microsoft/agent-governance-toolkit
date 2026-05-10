# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""RAGGovernor — governance wrapper for LangChain-compatible retrievers.

Intercepts every retrieval call and enforces:

1. **Collection access control** — allow/deny list from :class:`RAGPolicy`.
2. **Rate limiting** — sliding-window cap on retrievals per agent per minute.
3. **Content scanning** — PII and prompt-injection detection on chunks.
4. **Audit logging** — structured JSON-lines record per call.

Usage::

    from agent_rag_governance import RAGGovernor, RAGPolicy

    policy = RAGPolicy(
        allowed_collections=["public_docs", "product_manuals"],
        denied_collections=["hr_records", "financial_data"],
        max_retrievals_per_minute=100,
        content_policies=["block_pii", "block_injections"],
        audit_enabled=True,
    )
    governor = RAGGovernor(policy=policy, agent_id="sales-agent-001")
    governed_retriever = governor.wrap(your_langchain_retriever)

    # Drop-in replacement — same API as the original retriever
    docs = governed_retriever.invoke("what is our refund policy?")
"""

from __future__ import annotations

import logging
from typing import Any, List, Optional

from .audit import AuditLogger, make_entry
from .content_scanner import ContentScanner
from .exceptions import CollectionDeniedError, RateLimitExceededError
from .policy import RAGPolicy
from .rate_limiter import RateLimiter

logger = logging.getLogger(__name__)


class GovernedRetriever:
    """A drop-in wrapper around any retriever that enforces :class:`RAGPolicy`.

    Supports both the LangChain v0.2+ ``.invoke()`` interface and the
    legacy ``.get_relevant_documents()`` interface so it works with any
    LangChain version without requiring LangChain as a hard dependency.

    Do not instantiate directly — use :meth:`RAGGovernor.wrap`.
    """

    def __init__(
        self,
        retriever: Any,
        collection: str,
        governor: "RAGGovernor",
    ) -> None:
        self._retriever = retriever
        self._collection = collection
        self._governor = governor


    def invoke(self, query: str, **kwargs: Any) -> List[Any]:
        """Govern and execute a retrieval call.

        Args:
            query: The search query string.
            **kwargs: Additional keyword arguments forwarded to the
                underlying retriever's ``.invoke()`` method.

        Returns:
            List of document objects that passed all governance checks.

        Raises:
            CollectionDeniedError: Collection is not permitted for this agent.
            RateLimitExceededError: Agent has exceeded its retrieval rate.
            ContentScanError: A chunk failed content scanning (only raised
                when *all* chunks are blocked — partial blocks are silently
                filtered and logged).
        """
        return self._governor._execute(self._retriever, self._collection, query, kwargs)

    def get_relevant_documents(self, query: str) -> List[Any]:
        """LangChain v0.1 compatibility shim — delegates to :meth:`invoke`."""
        return self.invoke(query)

    # Expose underlying retriever attributes transparently
    def __getattr__(self, name: str) -> Any:
        return getattr(self._retriever, name)


class RAGGovernor:
    """Governance layer for RAG retrieval pipelines.

    Args:
        policy: Declarative governance configuration.
        agent_id: Stable identifier for the agent making retrievals.
            Used for rate limiting, audit records, and error messages.

    Example::

        governor = RAGGovernor(
            policy=RAGPolicy(
                denied_collections=["hr_records"],
                max_retrievals_per_minute=60,
                content_policies=["block_injections"],
            ),
            agent_id="support-bot",
        )
        retriever = governor.wrap(my_retriever, collection="public_docs")
        docs = retriever.invoke("how do I reset my password?")
    """

    def __init__(self, policy: RAGPolicy, agent_id: str = "default") -> None:
        self.policy = policy
        self.agent_id = agent_id
        self._rate_limiter = RateLimiter(window_seconds=60)
        self._content_scanner = ContentScanner(policy.content_policies)
        self._audit_logger: Optional[AuditLogger] = (
            AuditLogger(policy.audit_log_path) if policy.audit_enabled else None
        )

    def wrap(self, retriever: Any, collection: str = "default") -> GovernedRetriever:
        """Return a governed wrapper around *retriever* for *collection*.

        Args:
            retriever: Any object with an ``.invoke()`` or
                ``.get_relevant_documents()`` method.
            collection: Logical collection name used for access-control
                checks and audit records.

        Returns:
            A :class:`GovernedRetriever` that enforces this governor's policy.
        """
        return GovernedRetriever(retriever=retriever, collection=collection, governor=self)


    def _execute(
        self,
        retriever: Any,
        collection: str,
        query: str,
        kwargs: dict[str, Any],
    ) -> List[Any]:
        """Run the full governance pipeline for one retrieval call."""

        # 1. Collection access control
        self._check_collection(collection)

        # 2. Rate limiting
        self._check_rate(collection=collection, query=query)

        # 3. Retrieve
        docs = self._retrieve(retriever, query, kwargs)

        # 4. Content scanning
        clean_docs, num_blocked = self._scan_chunks(docs)

        # 5. Audit
        self._audit(
            collection=collection,
            query=query,
            num_retrieved=len(docs),
            num_blocked=num_blocked,
            decision="allowed",
        )

        return clean_docs

    def _check_collection(self, collection: str) -> None:
        allowed, reason = self.policy.is_collection_allowed(collection)
        if not allowed:
            if self._audit_logger:
                entry = make_entry(
                    agent_id=self.agent_id,
                    collection=collection,
                    query="",
                    num_chunks_retrieved=0,
                    num_chunks_blocked=0,
                    decision="denied",
                    policy_triggered=f"collection_{reason}",
                )
                self._audit_logger.emit(entry)
            raise CollectionDeniedError(collection, self.agent_id, reason)

    def _check_rate(self, *, collection: str, query: str) -> None:
        limit = self.policy.max_retrievals_per_minute
        if not self._rate_limiter.check(self.agent_id, limit):
            if self._audit_logger:
                entry = make_entry(
                    agent_id=self.agent_id,
                    collection=collection,
                    query=query,
                    num_chunks_retrieved=0,
                    num_chunks_blocked=0,
                    decision="rate_limited",
                    policy_triggered="max_retrievals_per_minute",
                )
                self._audit_logger.emit(entry)
            raise RateLimitExceededError(self.agent_id, limit)

    def _retrieve(self, retriever: Any, query: str, kwargs: dict[str, Any]) -> List[Any]:
        if hasattr(retriever, "invoke"):
            return retriever.invoke(query, **kwargs)
        if hasattr(retriever, "get_relevant_documents"):
            return retriever.get_relevant_documents(query)
        raise TypeError(
            f"Retriever {type(retriever).__name__!r} has no .invoke() or "
            ".get_relevant_documents() method"
        )

    def _scan_chunks(self, docs: List[Any]) -> tuple[List[Any], int]:
        """Scan chunks and return (clean_docs, num_blocked)."""
        if not self.policy.content_policies:
            return docs, 0

        texts = [self._doc_text(doc) for doc in docs]
        results = self._content_scanner.scan(texts)

        clean: list[Any] = []
        blocked = 0
        for doc, result in zip(docs, results):
            if result.blocked:
                blocked += 1
                logger.warning(
                    "chunk blocked agent=%s category=%s pattern=%r",
                    self.agent_id,
                    result.category,
                    result.pattern_matched,
                )
            else:
                clean.append(doc)

        return clean, blocked

    def _audit(
        self,
        *,
        collection: str,
        query: str,
        num_retrieved: int,
        num_blocked: int,
        decision: str,
        policy_triggered: Optional[str] = None,
    ) -> None:
        if self._audit_logger is None:
            return
        entry = make_entry(
            agent_id=self.agent_id,
            collection=collection,
            query=query,
            num_chunks_retrieved=num_retrieved,
            num_chunks_blocked=num_blocked,
            decision=decision,
            policy_triggered=policy_triggered,
        )
        self._audit_logger.emit(entry)

    @staticmethod
    def _doc_text(doc: Any) -> str:
        """Extract text from a document object."""
        if isinstance(doc, str):
            return doc
        if hasattr(doc, "page_content"):
            return str(doc.page_content)
        if hasattr(doc, "text"):
            return str(doc.text)
        return str(doc)
