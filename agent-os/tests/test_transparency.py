# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for TransparencyInterceptor (EU AI Act Art. 13/50)."""

from __future__ import annotations

import pytest

from agent_os.transparency import (
    EMOTION_RECOGNITION_NOTICE,
    TransparencyInterceptor,
    TransparencyLevel,
    ToolCallRequest,
    ToolCallResult,
)


def _make_request(
    tool_name: str = "web_search",
    session_id: str = "sess-1",
    agent_id: str = "agent-1",
    transparency_level: str | None = None,
) -> ToolCallRequest:
    metadata: dict = {"session_id": session_id}
    if transparency_level is not None:
        metadata["transparency_level"] = transparency_level
    return ToolCallRequest(
        tool_name=tool_name,
        arguments={"query": "test"},
        agent_id=agent_id,
        metadata=metadata,
    )


class TestTransparencyInterceptor:
    def test_blocks_when_disclosure_not_confirmed(self):
        interceptor = TransparencyInterceptor()
        result = interceptor.intercept(_make_request())
        assert result.allowed is False
        assert "disclosure must be confirmed" in result.reason

    def test_allows_when_disclosure_confirmed(self):
        interceptor = TransparencyInterceptor()
        interceptor.confirm_disclosure("sess-1")
        result = interceptor.intercept(_make_request())
        assert result.allowed is True

    def test_injects_ai_disclosure_metadata(self):
        interceptor = TransparencyInterceptor()
        interceptor.confirm_disclosure("sess-1")
        result = interceptor.intercept(_make_request())
        assert result.allowed is True
        assert "_ai_disclosure" in result.audit_entry
        assert result.audit_entry["_ai_disclosure"]["level"] == "basic"
        assert "AI system" in result.audit_entry["_ai_disclosure"]["text"]

    def test_allows_without_confirmation_when_not_required(self):
        interceptor = TransparencyInterceptor(require_disclosure_confirmation=False)
        result = interceptor.intercept(_make_request())
        assert result.allowed is True

    def test_none_level_skips_all_checks(self):
        interceptor = TransparencyInterceptor()
        result = interceptor.intercept(_make_request(transparency_level="none"))
        assert result.allowed is True

    def test_emotion_recognition_blocks_without_acknowledgement(self):
        interceptor = TransparencyInterceptor(emotion_recognition_notice=True)
        interceptor.confirm_disclosure("sess-1")
        result = interceptor.intercept(_make_request())
        assert result.allowed is False
        assert "Art. 50(3)" in result.reason

    def test_emotion_recognition_allows_after_acknowledgement(self):
        interceptor = TransparencyInterceptor(emotion_recognition_notice=True)
        interceptor.confirm_disclosure("sess-1")
        interceptor.acknowledge_emotion_recognition("sess-1")
        result = interceptor.intercept(_make_request())
        assert result.allowed is True

    def test_enhanced_level_produces_different_text(self):
        interceptor = TransparencyInterceptor(
            default_level=TransparencyLevel.ENHANCED
        )
        interceptor.confirm_disclosure("sess-1")
        result = interceptor.intercept(_make_request())
        assert "high-risk" in result.audit_entry["_ai_disclosure"]["text"]

    def test_full_level_text(self):
        interceptor = TransparencyInterceptor(default_level=TransparencyLevel.FULL)
        interceptor.confirm_disclosure("sess-1")
        result = interceptor.intercept(_make_request())
        assert "Art. 14" in result.audit_entry["_ai_disclosure"]["text"]

    def test_request_level_overrides_default(self):
        interceptor = TransparencyInterceptor(default_level=TransparencyLevel.BASIC)
        interceptor.confirm_disclosure("sess-1")
        result = interceptor.intercept(_make_request(transparency_level="enhanced"))
        assert result.audit_entry["_ai_disclosure"]["level"] == "enhanced"

    def test_is_disclosure_confirmed(self):
        interceptor = TransparencyInterceptor()
        assert interceptor.is_disclosure_confirmed("sess-1") is False
        interceptor.confirm_disclosure("sess-1")
        assert interceptor.is_disclosure_confirmed("sess-1") is True

    def test_different_sessions_independent(self):
        interceptor = TransparencyInterceptor()
        interceptor.confirm_disclosure("sess-1")
        result1 = interceptor.intercept(_make_request(session_id="sess-1"))
        result2 = interceptor.intercept(_make_request(session_id="sess-2"))
        assert result1.allowed is True
        assert result2.allowed is False

    def test_get_disclosure_text_all_levels(self):
        interceptor = TransparencyInterceptor()
        for level in [TransparencyLevel.BASIC, TransparencyLevel.ENHANCED, TransparencyLevel.FULL]:
            text = interceptor.get_disclosure_text(level)
            assert len(text) > 0
            assert "AI" in text
