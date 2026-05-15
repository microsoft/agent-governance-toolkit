# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Exceptions raised by the agent-rag-governance package."""

from __future__ import annotations


class RAGGovernanceError(Exception):
    """Base class for all agent-rag-governance errors."""


# Maps the machine-readable ``reason`` codes returned by
# ``RAGPolicy.is_collection_allowed`` to the human-readable phrase used
# in the exception message. The ``reason`` codes themselves are kept on
# the attribute (and forwarded to ``policy_triggered`` in audit entries)
# so callers can still pattern-match on them.
_REASON_PHRASES: dict[str, str] = {
    "denied": "explicitly denied",
    "not_allowed": "not in the allow list",
    "cedar_denied": "denied by Cedar policy",
}


class CollectionDeniedError(RAGGovernanceError):
    """Raised when an agent attempts to query a denied or unlisted collection.

    Attributes:
        collection: The collection name that was blocked.
        agent_id: The agent that attempted the retrieval.
        reason: One of ``"denied"`` (explicit deny list), ``"not_allowed"``
            (allow list is set and collection is absent), or
            ``"cedar_denied"`` (rejected by the Cedar policy engine).
    """

    def __init__(self, collection: str, agent_id: str, reason: str = "denied") -> None:
        self.collection = collection
        self.agent_id = agent_id
        self.reason = reason
        phrase = _REASON_PHRASES.get(reason, reason)
        super().__init__(
            f"Collection '{collection}' is {phrase} for agent '{agent_id}'"
        )


class RateLimitExceededError(RAGGovernanceError):
    """Raised when an agent exceeds the maximum retrievals per minute.

    Attributes:
        agent_id: The agent that exceeded the limit.
        limit: The configured maximum retrievals per minute.
        window_seconds: The sliding window duration in seconds.
    """

    def __init__(self, agent_id: str, limit: int, window_seconds: int = 60) -> None:
        self.agent_id = agent_id
        self.limit = limit
        self.window_seconds = window_seconds
        super().__init__(
            f"Agent '{agent_id}' exceeded retrieval limit of {limit} "
            f"per {window_seconds}s"
        )


class ContentScanError(RAGGovernanceError):
    """Raised when a retrieved chunk fails content scanning.

    Attributes:
        chunk_index: Zero-based index of the failing chunk.
        pattern_matched: Description of the pattern that triggered the block.
        category: Either ``"pii"`` or ``"injection"``.
    """

    def __init__(
        self, chunk_index: int, pattern_matched: str, category: str = "injection"
    ) -> None:
        self.chunk_index = chunk_index
        self.pattern_matched = pattern_matched
        self.category = category
        super().__init__(
            f"Chunk {chunk_index} blocked by content scan "
            f"[{category}]: {pattern_matched}"
        )
