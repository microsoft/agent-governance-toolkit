# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the mute agent module."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import pytest

from agent_os.mute_agent import (
    BUILTIN_PATTERNS,
    MuteAgent,
    MutePolicy,
)


# ---------------------------------------------------------------------------
# Helpers — lightweight stand-in for ExecutionResult
# ---------------------------------------------------------------------------

@dataclass
class FakeResult:
    success: bool = True
    data: Any = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# MutePolicy defaults
# ---------------------------------------------------------------------------

class TestMutePolicy:
    def test_defaults_enable_all_builtins(self):
        p = MutePolicy()
        assert set(p.enabled_builtins) == set(BUILTIN_PATTERNS.keys())
        assert p.replacement == "[REDACTED]"

    def test_custom_replacement(self):
        p = MutePolicy(replacement="***")
        assert p.replacement == "***"


# ---------------------------------------------------------------------------
# MuteAgent — built-in patterns
# ---------------------------------------------------------------------------

class TestMuteAgentBuiltins:
    def test_redact_email(self):
        agent = MuteAgent()
        result = FakeResult(data="Contact alice@example.com for details")
        redacted = agent.mute(result)
        assert "alice@example.com" not in redacted.data
        assert "[REDACTED]" in redacted.data

    def test_redact_phone(self):
        agent = MuteAgent()
        result = FakeResult(data="Call (555) 123-4567 now")
        redacted = agent.mute(result)
        assert "123-4567" not in redacted.data

    def test_redact_ssn(self):
        agent = MuteAgent()
        result = FakeResult(data="SSN: 123-45-6789")
        redacted = agent.mute(result)
        assert "123-45-6789" not in redacted.data

    def test_redact_api_key(self):
        agent = MuteAgent()
        result = FakeResult(data="api_key: sk_live_abc123def456ghi7")
        redacted = agent.mute(result)
        assert "sk_live_abc123def456ghi7" not in redacted.data

    def test_no_false_positive_on_clean_text(self):
        agent = MuteAgent()
        text = "Hello world, no secrets here."
        result = FakeResult(data=text)
        redacted = agent.mute(result)
        assert redacted.data == text


# ---------------------------------------------------------------------------
# MuteAgent — custom patterns & keywords
# ---------------------------------------------------------------------------

class TestMuteAgentCustom:
    def test_custom_regex(self):
        policy = MutePolicy(
            enabled_builtins=[],
            custom_patterns=[r"SECRET-\d+"],
        )
        agent = MuteAgent(policy)
        result = FakeResult(data="Token is SECRET-42")
        redacted = agent.mute(result)
        assert "SECRET-42" not in redacted.data

    def test_sensitive_keyword(self):
        policy = MutePolicy(
            enabled_builtins=[],
            sensitive_keywords=["INTERNAL_PROJECT"],
        )
        agent = MuteAgent(policy)
        result = FakeResult(data="Working on INTERNAL_PROJECT launch")
        redacted = agent.mute(result)
        assert "INTERNAL_PROJECT" not in redacted.data

    def test_custom_replacement_text(self):
        policy = MutePolicy(
            enabled_builtins=["email"],
            replacement="<hidden>",
        )
        agent = MuteAgent(policy)
        result = FakeResult(data="Email: test@test.com")
        redacted = agent.mute(result)
        assert "<hidden>" in redacted.data


# ---------------------------------------------------------------------------
# MuteAgent — recursive scrubbing
# ---------------------------------------------------------------------------

class TestMuteAgentRecursive:
    def test_dict_data(self):
        agent = MuteAgent()
        result = FakeResult(data={"email": "user@example.com", "count": 5})
        redacted = agent.mute(result)
        assert "user@example.com" not in str(redacted.data)
        assert redacted.data["count"] == 5

    def test_list_data(self):
        agent = MuteAgent()
        result = FakeResult(data=["SSN: 111-22-3333", "ok"])
        redacted = agent.mute(result)
        assert "111-22-3333" not in str(redacted.data)
        assert "ok" in redacted.data

    def test_metadata_scrubbed(self):
        agent = MuteAgent()
        result = FakeResult(
            data="clean",
            metadata={"debug": "user@corp.com"},
        )
        redacted = agent.mute(result)
        assert "user@corp.com" not in str(redacted.metadata)

    def test_none_data_unchanged(self):
        agent = MuteAgent()
        result = FakeResult(data=None)
        redacted = agent.mute(result)
        assert redacted.data is None

    def test_scrub_text_standalone(self):
        agent = MuteAgent()
        assert "alice@test.com" not in agent.scrub_text("alice@test.com")
