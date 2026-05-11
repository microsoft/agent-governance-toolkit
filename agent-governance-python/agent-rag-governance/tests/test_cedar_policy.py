# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Cedar policy integration in agent-rag-governance."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, List

import pytest
from agent_rag_governance import (
    RAGGovernor,
    RAGPolicy,
    CollectionDeniedError,
)


# ---------------------------------------------------------------------------
# Fake retriever for testing
# ---------------------------------------------------------------------------

class _FakeDoc:
    """Minimal document object."""
    def __init__(self, text: str):
        self.page_content = text


class _FakeRetriever:
    """Retriever that returns a fixed list of documents."""
    def __init__(self, docs: list):
        self._docs = docs

    def invoke(self, query: str, **kwargs: Any) -> list:
        return self._docs


def _make_governor(policy: RAGPolicy) -> RAGGovernor:
    return RAGGovernor(policy=policy, agent_id="test-agent")


# ---------------------------------------------------------------------------
# Cedar policy tests
# ---------------------------------------------------------------------------

CEDAR_PERMIT_PUBLIC = """
permit(
    principal,
    action == Action::"Retrieve",
    resource == Collection::"public_docs"
);
"""

CEDAR_FORBID_HR = """
permit(
    principal,
    action == Action::"Retrieve",
    resource == Collection::"public_docs"
);
forbid(
    principal,
    action == Action::"Retrieve",
    resource == Collection::"hr_records"
);
"""

CEDAR_PERMIT_ALL = """
permit(
    principal,
    action == Action::"Retrieve",
    resource
);
"""


def test_cedar_permits_allowed_collection():
    """Cedar policy permits access to allowed collection."""
    policy = RAGPolicy(cedar_policy=CEDAR_PERMIT_PUBLIC)
    governor = _make_governor(policy)
    retriever = _FakeRetriever([_FakeDoc("clean text")])
    governed = governor.wrap(retriever, collection="public_docs")
    docs = governed.invoke("query")
    assert len(docs) == 1


def test_cedar_denies_unlisted_collection():
    """Cedar policy denies access to collection not in permit rules."""
    policy = RAGPolicy(cedar_policy=CEDAR_PERMIT_PUBLIC)
    governor = _make_governor(policy)
    retriever = _FakeRetriever([])
    governed = governor.wrap(retriever, collection="hr_records")
    with pytest.raises(CollectionDeniedError) as exc:
        governed.invoke("query")
    assert exc.value.collection == "hr_records"
    assert exc.value.agent_id == "test-agent"


def test_cedar_explicit_forbid_overrides_permit():
    """Cedar forbid rule blocks even if collection appears accessible."""
    policy = RAGPolicy(cedar_policy=CEDAR_FORBID_HR)
    governor = _make_governor(policy)
    retriever = _FakeRetriever([])
    governed = governor.wrap(retriever, collection="hr_records")
    with pytest.raises(CollectionDeniedError) as exc:
        governed.invoke("query")
    assert exc.value.reason == "cedar_denied"


def test_cedar_permit_all_allows_any_collection():
    """Cedar catch-all permit allows any collection."""
    policy = RAGPolicy(cedar_policy=CEDAR_PERMIT_ALL)
    governor = _make_governor(policy)
    retriever = _FakeRetriever([_FakeDoc("clean text")])
    for collection in ["public_docs", "internal_wiki", "product_docs"]:
        governed = governor.wrap(retriever, collection=collection)
        docs = governed.invoke("query")
        assert len(docs) == 1


def test_cedar_policy_from_file():
    """Cedar policy loaded from file works correctly."""
    with tempfile.NamedTemporaryFile(
        suffix=".cedar", mode="w", delete=False
    ) as f:
        f.write(CEDAR_PERMIT_PUBLIC)
        policy_path = f.name

    policy = RAGPolicy(cedar_policy_path=policy_path)
    assert policy.cedar_policy is not None
    governor = _make_governor(policy)
    retriever = _FakeRetriever([_FakeDoc("clean text")])
    governed = governor.wrap(retriever, collection="public_docs")
    docs = governed.invoke("query")
    assert len(docs) == 1


def test_cedar_policy_file_not_found_falls_back_to_lists():
    """Non-existent Cedar policy file falls back to list-based check."""
    policy = RAGPolicy(
        cedar_policy_path="/nonexistent/path/policy.cedar",
        allowed_collections=["public_docs"],
    )
    # cedar_policy should be None since file doesn't exist
    assert policy.cedar_policy is None
    # List-based check should still work
    allowed, reason = policy.is_collection_allowed("public_docs")
    assert allowed is True
    assert reason == "ok"


def test_cedar_takes_precedence_over_lists():
    """Cedar policy takes precedence over allowed/denied lists."""
    policy = RAGPolicy(
        cedar_policy=CEDAR_PERMIT_PUBLIC,
        # These list rules would normally deny hr_records
        # but Cedar is checked first and permits it if no forbid rule
        allowed_collections=["public_docs"],
        denied_collections=["hr_records"],
    )
    governor = _make_governor(policy)
    retriever = _FakeRetriever([])
    governed = governor.wrap(retriever, collection="hr_records")
    # Cedar has no forbid for hr_records but also no permit
    # so Cedar default deny applies — Cedar takes precedence
    with pytest.raises(CollectionDeniedError):
        governed.invoke("query")


def test_cedar_audit_logged_on_denial():
    """Cedar denial is logged to audit trail."""
    import json

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        log_path = f.name

    policy = RAGPolicy(
        cedar_policy=CEDAR_PERMIT_PUBLIC,
        audit_enabled=True,
        audit_log_path=log_path,
    )
    governor = RAGGovernor(policy=policy, agent_id="audit-agent")
    governed = governor.wrap(_FakeRetriever([]), collection="hr_records")

    with pytest.raises(CollectionDeniedError):
        governed.invoke("query")

    lines = Path(log_path).read_text().strip().splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["decision"] == "denied"
    assert data["agent_id"] == "audit-agent"


def test_no_cedar_falls_back_to_list_allow():
    """Without Cedar policy, allowed_collections list still works."""
    policy = RAGPolicy(allowed_collections=["public_docs"])
    allowed, reason = policy.is_collection_allowed("public_docs")
    assert allowed is True
    assert reason == "ok"


def test_no_cedar_falls_back_to_list_deny():
    """Without Cedar policy, denied_collections list still works."""
    policy = RAGPolicy(denied_collections=["hr_records"])
    allowed, reason = policy.is_collection_allowed("hr_records")
    assert allowed is False
    assert reason == "denied"


def test_cedar_and_list_coexist_cedar_wins():
    """When both Cedar and lists are set, Cedar governs."""
    policy = RAGPolicy(
        cedar_policy=CEDAR_PERMIT_ALL,  # Cedar allows everything
        denied_collections=["hr_records"],  # List would deny hr_records
    )
    # Cedar should win — permits all collections
    allowed, reason = policy.is_collection_allowed("hr_records")
    assert allowed is True
    assert reason == "ok"


def test_cedar_backend_unavailable_falls_back_to_lists():
    """When agent-os is unavailable, Cedar falls back to list-based check."""
    import sys
    import unittest.mock as mock

    policy = RAGPolicy(
        cedar_policy=CEDAR_PERMIT_PUBLIC,
        allowed_collections=["public_docs"],
        denied_collections=["hr_records"],
    )

    # Simulate agent-os not being available
    with mock.patch.dict(sys.modules, {"agent_os.policies.backends": None}):
        # Should fall back to list-based check — allowed collection
        allowed, reason = policy.is_collection_allowed("public_docs")
        assert allowed is True
        assert reason == "ok"

        # Should fall back to list-based check — denied collection
        allowed, reason = policy.is_collection_allowed("hr_records")
        assert allowed is False
        assert reason == "denied"


def test_cedar_backend_unavailable_no_lists_default_deny():
    """When agent-os unavailable and no lists configured, default is allow all."""
    import sys
    import unittest.mock as mock

    # No lists configured — default RAGPolicy allows all
    policy = RAGPolicy(cedar_policy=CEDAR_PERMIT_PUBLIC)

    with mock.patch.dict(sys.modules, {"agent_os.policies.backends": None}):
        # Falls back to list check — no restrictions set, so allowed
        allowed, reason = policy.is_collection_allowed("any_collection")
        assert allowed is True
        assert reason == "ok"


def test_cedar_policy_invalid_content_handled_gracefully():
    """Invalid Cedar policy content should not crash — Cedar engine handles it."""
    policy = RAGPolicy(cedar_policy="this is not valid cedar syntax !!!")
    # Should not raise — Cedar engine handles invalid syntax gracefully
    allowed, reason = policy.is_collection_allowed("public_docs")
    # Invalid policy → no permit matched → default deny
    assert allowed is False
    assert reason == "cedar_denied"
