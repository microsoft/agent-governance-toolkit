# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for human-readable phrasing of CollectionDeniedError messages.

The ``reason`` attribute remains a machine-readable code (``"denied"`` /
``"not_allowed"`` / ``"cedar_denied"``) so callers and audit entries can
still pattern-match on it. The exception *message* uses a human phrase
that reads naturally when interpolated by logs or surfaced to users.
"""

from __future__ import annotations

from agent_rag_governance.exceptions import (
    CollectionDeniedError,
    ContentScanError,
    RateLimitExceededError,
)


def test_denied_reason_renders_explicit_phrase() -> None:
    exc = CollectionDeniedError("hr_records", "agent-1", reason="denied")
    assert exc.reason == "denied"
    assert (
        str(exc)
        == "Collection 'hr_records' is explicitly denied for agent 'agent-1'"
    )


def test_not_allowed_reason_renders_allow_list_phrase() -> None:
    exc = CollectionDeniedError("internal_wiki", "agent-1", reason="not_allowed")
    assert exc.reason == "not_allowed"
    assert (
        str(exc)
        == "Collection 'internal_wiki' is not in the allow list for agent 'agent-1'"
    )


def test_cedar_denied_reason_renders_cedar_phrase() -> None:
    exc = CollectionDeniedError("financials", "agent-1", reason="cedar_denied")
    assert exc.reason == "cedar_denied"
    assert (
        str(exc)
        == "Collection 'financials' is denied by Cedar policy for agent 'agent-1'"
    )


def test_unknown_reason_falls_back_to_raw_code() -> None:
    # Defensive: any future or unmapped reason code is interpolated
    # verbatim rather than crashing.
    exc = CollectionDeniedError("col", "agent-1", reason="custom_code")
    assert exc.reason == "custom_code"
    assert str(exc) == "Collection 'col' is custom_code for agent 'agent-1'"


def test_rate_limit_message_unchanged() -> None:
    exc = RateLimitExceededError("agent-1", limit=10, window_seconds=60)
    assert exc.agent_id == "agent-1"
    assert exc.limit == 10
    assert exc.window_seconds == 60
    assert str(exc) == "Agent 'agent-1' exceeded retrieval limit of 10 per 60s"


def test_content_scan_message_unchanged() -> None:
    exc = ContentScanError(2, "SSN pattern", category="pii")
    assert exc.chunk_index == 2
    assert exc.pattern_matched == "SSN pattern"
    assert exc.category == "pii"
    assert str(exc) == "Chunk 2 blocked by content scan [pii]: SSN pattern"
