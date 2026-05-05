# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""RAGPolicy — declarative governance configuration for RAG pipelines."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class RAGPolicy:
    """Governance policy for a RAG retriever.

    Args:
        allowed_collections: Explicit allow list of collection names.
            ``None`` means all collections are permitted (unless denied).
        denied_collections: Collections that are always blocked, regardless
            of the allow list.
        max_retrievals_per_minute: Maximum retrieval calls per agent per
            60-second sliding window. ``0`` disables rate limiting.
        content_policies: Active content scan categories. Supported values:
            ``"block_pii"`` and ``"block_injections"``. Empty list disables
            content scanning.
        audit_enabled: Whether to emit a structured audit entry per call.
        audit_log_path: File path for audit log (JSON lines). ``None``
            writes to stdout.

    Example::

        policy = RAGPolicy(
            allowed_collections=["public_docs", "product_manuals"],
            denied_collections=["hr_records", "financial_data"],
            max_retrievals_per_minute=100,
            content_policies=["block_pii", "block_injections"],
            audit_enabled=True,
        )
    """

    allowed_collections: Optional[List[str]] = None
    denied_collections: List[str] = field(default_factory=list)
    max_retrievals_per_minute: int = 0
    content_policies: List[str] = field(default_factory=list)
    audit_enabled: bool = True
    audit_log_path: Optional[str] = None

    def is_collection_allowed(self, collection: str) -> tuple[bool, str]:
        """Check whether *collection* is permitted under this policy.

        Returns:
            ``(allowed, reason)`` where *reason* is ``"ok"``, ``"denied"``,
            or ``"not_allowed"``.
        """
        if collection in self.denied_collections:
            return False, "denied"
        if self.allowed_collections is not None and collection not in self.allowed_collections:
            return False, "not_allowed"
        return True, "ok"
