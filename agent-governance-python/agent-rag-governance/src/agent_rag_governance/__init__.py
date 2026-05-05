# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""agent-rag-governance — retrieval access control and vector store policy enforcement.

Adds a governance layer specifically for RAG (Retrieval-Augmented Generation)
pipelines, closing the gap between write-time memory protection (MemoryGuard)
and output-quality checks (ContentGovernance).

Quick start::

    from agent_rag_governance import RAGGovernor, RAGPolicy

    policy = RAGPolicy(
        allowed_collections=["public_docs", "product_manuals"],
        denied_collections=["hr_records", "financial_data"],
        max_retrievals_per_minute=100,
        content_policies=["block_pii", "block_injections"],
        audit_enabled=True,
    )
    governor = RAGGovernor(policy=policy, agent_id="my-agent")
    governed_retriever = governor.wrap(your_langchain_retriever, collection="public_docs")
    docs = governed_retriever.invoke("what is our refund policy?")
"""

from .audit import AuditLogger, RAGAuditEntry
from .content_scanner import ContentScanner, ScanResult
from .exceptions import (
    CollectionDeniedError,
    ContentScanError,
    RAGGovernanceError,
    RateLimitExceededError,
)
from .governor import GovernedRetriever, RAGGovernor
from .policy import RAGPolicy
from .rate_limiter import RateLimiter

__version__ = "0.1.0"
__author__ = "Microsoft Corporation"

__all__ = [
    "RAGGovernor",
    "GovernedRetriever",
    "RAGPolicy",
    "RAGAuditEntry",
    "AuditLogger",
    "ContentScanner",
    "ScanResult",
    "RateLimiter",
    "RAGGovernanceError",
    "CollectionDeniedError",
    "RateLimitExceededError",
    "ContentScanError",
]
