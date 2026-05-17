# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for RAGPolicy.rate_limit_window_seconds exposure on the governor.

Confirms the field defaults to 60 (preserves prior behaviour),
configures the underlying RateLimiter, validates non-positive values,
and is reflected in RateLimitExceededError.window_seconds.
"""

from __future__ import annotations

import time

import pytest

from agent_rag_governance.exceptions import RateLimitExceededError
from agent_rag_governance.governor import RAGGovernor
from agent_rag_governance.policy import RAGPolicy


class _FakeDoc:
    def __init__(self, text: str) -> None:
        self.page_content = text


class _FakeRetriever:
    def __init__(self, docs: list[_FakeDoc]) -> None:
        self._docs = docs

    def invoke(self, query: str, **_: object) -> list[_FakeDoc]:
        return list(self._docs)


def _make_governor(policy: RAGPolicy) -> RAGGovernor:
    return RAGGovernor(policy=policy, agent_id="test-agent")


def test_default_window_is_sixty_seconds() -> None:
    policy = RAGPolicy()
    assert policy.rate_limit_window_seconds == 60


def test_governor_propagates_window_to_rate_limiter() -> None:
    policy = RAGPolicy(rate_limit_window_seconds=5)
    governor = _make_governor(policy)
    # Internal state intentionally pinned: callers shouldn't reach in,
    # but the regression is that the RateLimiter is constructed with the
    # configured window rather than the hard-coded 60.
    assert governor._rate_limiter._window == 5


def test_short_window_expires_faster_than_default() -> None:
    policy = RAGPolicy(
        allowed_collections=["docs"],
        max_retrievals_per_minute=2,
        rate_limit_window_seconds=1,
        audit_enabled=False,
    )
    governor = _make_governor(policy)
    retriever = _FakeRetriever([_FakeDoc("ok")])
    governed = governor.wrap(retriever, collection="docs")

    governed.invoke("q1")
    governed.invoke("q2")
    with pytest.raises(RateLimitExceededError) as exc:
        governed.invoke("q3")
    assert exc.value.window_seconds == 1
    assert "per 1s" in str(exc.value)

    # Window expires within a second, third call now succeeds.
    time.sleep(1.1)
    assert len(governed.invoke("q4")) == 1


def test_long_window_keeps_state_past_default() -> None:
    # A 300-second window must not silently fall back to 60; the
    # second-burst limit must persist even after 60s would have expired
    # the entries under the previous hard-coded behaviour.
    policy = RAGPolicy(
        allowed_collections=["docs"],
        max_retrievals_per_minute=1,
        rate_limit_window_seconds=300,
        audit_enabled=False,
    )
    governor = _make_governor(policy)
    retriever = _FakeRetriever([_FakeDoc("ok")])
    governed = governor.wrap(retriever, collection="docs")

    governed.invoke("q1")
    with pytest.raises(RateLimitExceededError) as exc:
        governed.invoke("q2")
    assert exc.value.window_seconds == 300


def test_non_positive_window_rejected() -> None:
    with pytest.raises(ValueError, match="rate_limit_window_seconds"):
        RAGPolicy(rate_limit_window_seconds=0)
    with pytest.raises(ValueError, match="rate_limit_window_seconds"):
        RAGPolicy(rate_limit_window_seconds=-5)
