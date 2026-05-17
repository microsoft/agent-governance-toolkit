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
            sliding window. ``0`` disables rate limiting. The window
            length defaults to 60 seconds but can be overridden with
            ``rate_limit_window_seconds``.
        rate_limit_window_seconds: Length of the sliding rate-limit
            window in seconds. Defaults to ``60``. Setting this lets
            callers tune the limiter for shorter (burst-resistant) or
            longer (quota-style) policies without monkey-patching the
            governor.
        content_policies: Active content scan categories. Supported values:
            ``"block_pii"`` and ``"block_injections"``. Empty list disables
            content scanning.
        audit_enabled: Whether to emit a structured audit entry per call.
        audit_log_path: File path for audit log (JSON lines). ``None``
            writes to stdout.
        cedar_policy: Inline Cedar policy string for collection access
            control. When provided, takes precedence over
            ``allowed_collections`` / ``denied_collections``.
        cedar_policy_path: Path to a ``.cedar`` policy file. Loaded at
            construction time. Ignored when ``cedar_policy`` is set.

    Example — simple allow/deny lists::

        policy = RAGPolicy(
            allowed_collections=["public_docs", "product_manuals"],
            denied_collections=["hr_records", "financial_data"],
            max_retrievals_per_minute=100,
            content_policies=["block_pii", "block_injections"],
            audit_enabled=True,
        )

    Example — Cedar policy for fine-grained access control::

        policy = RAGPolicy(
            cedar_policy=\\'\\'\\'
                permit(
                    principal == Agent::"sales-agent",
                    action == Action::"Retrieve",
                    resource == Collection::"public_docs"
                );
                forbid(
                    principal,
                    action == Action::"Retrieve",
                    resource == Collection::"hr_records"
                );
            \\'\\'\\'
            max_retrievals_per_minute=100,
            content_policies=["block_pii", "block_injections"],
            audit_enabled=True,
        )

    Example — Cedar policy from file::

        policy = RAGPolicy(
            cedar_policy_path="policies/rag_access.cedar",
            audit_enabled=True,
        )
    """

    allowed_collections: Optional[List[str]] = None
    denied_collections: List[str] = field(default_factory=list)
    max_retrievals_per_minute: int = 0
    rate_limit_window_seconds: int = 60
    content_policies: List[str] = field(default_factory=list)
    audit_enabled: bool = True
    audit_log_path: Optional[str] = None
    cedar_policy: Optional[str] = None
    cedar_policy_path: Optional[str] = None

    def __post_init__(self) -> None:
        """Load Cedar policy from file if path is provided.

        Also validates ``rate_limit_window_seconds`` — a non-positive
        window would either disable the limiter or push the sliding
        cutoff into the future, both of which are configuration
        errors.
        """
        if self.rate_limit_window_seconds <= 0:
            raise ValueError(
                "rate_limit_window_seconds must be positive; got "
                f"{self.rate_limit_window_seconds!r}"
            )
        if self.cedar_policy_path and not self.cedar_policy:
            from pathlib import Path
            path = Path(self.cedar_policy_path)
            if path.exists():
                self.cedar_policy = path.read_text()

    def is_collection_allowed(self, collection: str) -> tuple[bool, str]:
        """Check whether *collection* is permitted under this policy.

        When a Cedar policy is configured, delegates to the Cedar engine.
        Otherwise falls back to the allow/deny list check.

        Returns:
            ``(allowed, reason)`` where *reason* is ``"ok"``,
            ``"denied"``, ``"not_allowed"``, or ``"cedar_denied"``.
        """
        if self.cedar_policy:
            return self._check_cedar(collection)
        return self._check_lists(collection)

    def _check_lists(self, collection: str) -> tuple[bool, str]:
        """Check collection against allow/deny lists."""
        if collection in self.denied_collections:
            return False, "denied"
        if self.allowed_collections is not None and collection not in self.allowed_collections:
            return False, "not_allowed"
        return True, "ok"

    def _check_cedar(self, collection: str) -> tuple[bool, str]:
        """Check collection access using Cedar policy engine.

        Uses CedarBackend from agent-os for policy evaluation. When
        neither cedarpy nor Cedar CLI is available, the built-in fallback
        evaluator ignores resource constraints. In that case we apply
        our own resource-aware logic to ensure collection-level access
        control is enforced correctly.
        """
        try:
            from agent_os.policies.backends import CedarBackend, _parse_cedar_statements
        except ImportError:
            # agent-os not available — fall back to list-based check
            return self._check_lists(collection)

        resource_str = f'Collection::"{collection}"'
        backend = CedarBackend(policy_content=self.cedar_policy)
        decision = backend.evaluate({
            "tool_name": "retrieve",
            "agent_id": "agent",
            "resource": resource_str,
            "collection": collection,
        })

        # If cedarpy or CLI evaluated — trust the result fully
        if "builtin" not in decision.reason.lower():
            return (True, "ok") if decision.allowed else (False, "cedar_denied")

        # Built-in fallback ignores resource constraints — apply our own
        # resource-aware Cedar evaluation
        statements = _parse_cedar_statements(self.cedar_policy)
        action_str = 'Action::"Retrieve"'

        # Cedar semantics: forbid overrides permit, default deny
        for stmt in statements:
            if stmt["effect"] == "forbid":
                action_matches = (
                    stmt["action_constraint"] is None
                    or stmt["action_constraint"] == action_str
                )
                resource_matches = self._cedar_resource_matches(
                    stmt["raw"], resource_str
                )
                no_resource_constraint = "resource ==" not in stmt["raw"]
                if action_matches and (resource_matches or no_resource_constraint):
                    return False, "cedar_denied"

        # Check if any permit covers this collection
        for stmt in statements:
            if stmt["effect"] == "permit":
                action_matches = (
                    stmt["action_constraint"] is None
                    or stmt["action_constraint"] == action_str
                )
                resource_matches = self._cedar_resource_matches(
                    stmt["raw"], resource_str
                )
                no_resource_constraint = "resource ==" not in stmt["raw"]
                if action_matches and (resource_matches or no_resource_constraint):
                    return True, "ok"

        # No permit matched — default deny
        return False, "cedar_denied"

    @staticmethod
    def _cedar_resource_matches(statement_raw: str, resource_str: str) -> bool:
        """Check if a Cedar statement's resource constraint matches."""
        import re
        match = re.search(
            r'resource\s*==\s*(Collection::"[^"]+")',
            statement_raw
        )
        if not match:
            return False
        return match.group(1).strip() == resource_str
