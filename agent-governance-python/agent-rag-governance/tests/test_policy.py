# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import pytest
from agent_rag_governance.policy import RAGPolicy


def test_allow_all_when_no_allow_list():
    policy = RAGPolicy(denied_collections=[])
    allowed, reason = policy.is_collection_allowed("any_collection")
    assert allowed is True
    assert reason == "ok"


def test_denied_collection_blocked():
    policy = RAGPolicy(denied_collections=["hr_records"])
    allowed, reason = policy.is_collection_allowed("hr_records")
    assert allowed is False
    assert reason == "denied"


def test_denied_takes_priority_over_allowed():
    policy = RAGPolicy(
        allowed_collections=["hr_records"],
        denied_collections=["hr_records"],
    )
    allowed, reason = policy.is_collection_allowed("hr_records")
    assert allowed is False
    assert reason == "denied"


def test_not_in_allow_list_blocked():
    policy = RAGPolicy(allowed_collections=["public_docs"])
    allowed, reason = policy.is_collection_allowed("internal_wiki")
    assert allowed is False
    assert reason == "not_allowed"


def test_in_allow_list_permitted():
    policy = RAGPolicy(allowed_collections=["public_docs", "product_manuals"])
    allowed, reason = policy.is_collection_allowed("public_docs")
    assert allowed is True
    assert reason == "ok"


def test_none_allow_list_permits_any_non_denied():
    policy = RAGPolicy(allowed_collections=None, denied_collections=["financial_data"])
    assert policy.is_collection_allowed("anything")[0] is True
    assert policy.is_collection_allowed("financial_data")[0] is False
