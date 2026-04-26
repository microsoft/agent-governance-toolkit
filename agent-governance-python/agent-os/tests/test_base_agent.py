# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for configurable audit log size and metadata memory leak fixes."""

from __future__ import annotations

import sys
from typing import Any, Dict

import pytest

from agent_os.base_agent import AgentConfig, BaseAgent
from agent_os.stateless import ExecutionResult


class DummyAgent(BaseAgent):
    """Minimal agent for testing."""

    async def run(self, *args: Any, **kwargs: Any) -> ExecutionResult:
        return await self._execute("test-action", {"key": "value"})


# ---------------------------------------------------------------------------
# Issue #122: Configurable audit log size
# ---------------------------------------------------------------------------


class TestConfigurableAuditLogSize:
    """Tests for configurable audit log size (issue #122)."""

    def test_default_max_audit_log_size(self) -> None:
        config = AgentConfig(agent_id="test-agent")
        assert config.max_audit_log_size == 10000

    def test_custom_max_audit_log_size(self) -> None:
        config = AgentConfig(agent_id="test-agent", max_audit_log_size=50)
        assert config.max_audit_log_size == 50

    def test_agent_uses_config_value(self) -> None:
        config = AgentConfig(agent_id="test-agent", max_audit_log_size=5)
        agent = DummyAgent(config)
        assert agent._max_audit_entries == 5

    @pytest.mark.asyncio
    async def test_audit_log_trimmed_to_max_size(self) -> None:
        config = AgentConfig(agent_id="test-agent", max_audit_log_size=3)
        agent = DummyAgent(config)

        for _ in range(5):
            await agent.run()

        log = agent.get_audit_log()
        assert len(log) == 3

    @pytest.mark.asyncio
    async def test_audit_log_keeps_latest_entries(self) -> None:
        config = AgentConfig(agent_id="test-agent", max_audit_log_size=2)
        agent = DummyAgent(config)

        for _ in range(4):
            await agent.run()

        # After 4 entries with max 2, only the last 2 should remain
        assert len(agent._audit_log) == 2


# ---------------------------------------------------------------------------
# Issue #123: Metadata memory leak
# ---------------------------------------------------------------------------


class TestMetadataMemoryLeak:
    """Tests for metadata memory leak prevention (issue #123)."""

    def test_default_max_metadata_size_bytes(self) -> None:
        config = AgentConfig(agent_id="test-agent")
        assert config.max_metadata_size_bytes == 1_048_576

    def test_custom_max_metadata_size_bytes(self) -> None:
        config = AgentConfig(agent_id="test-agent", max_metadata_size_bytes=512)
        assert config.max_metadata_size_bytes == 512

    def test_metadata_deep_copied(self) -> None:
        """Metadata should be deep copied to prevent reference retention."""
        inner = {"nested": "value"}
        config = AgentConfig(agent_id="test-agent", metadata={"inner": inner})
        agent = DummyAgent(config)

        ctx = agent._new_context()
        # Mutating the original should not affect the context copy
        inner["nested"] = "changed"
        assert ctx.metadata["inner"]["nested"] == "value"

    def test_extra_metadata_deep_copied(self) -> None:
        """Extra metadata passed to _new_context should also be deep copied."""
        extra = {"list": [1, 2, 3]}
        config = AgentConfig(agent_id="test-agent")
        agent = DummyAgent(config)

        ctx = agent._new_context(**extra)
        extra["list"].append(4)
        assert ctx.metadata["list"] == [1, 2, 3]

    def test_oversized_metadata_rejected(self) -> None:
        """Metadata values exceeding max_metadata_size_bytes are rejected."""
        config = AgentConfig(
            agent_id="test-agent",
            max_metadata_size_bytes=64,
        )
        agent = DummyAgent(config)

        large_value = "x" * 10_000
        with pytest.raises(ValueError, match="exceeds limit"):
            agent._new_context(big=large_value)

    def test_small_metadata_accepted(self) -> None:
        """Metadata within size limits should pass without error."""
        config = AgentConfig(agent_id="test-agent", max_metadata_size_bytes=1_048_576)
        agent = DummyAgent(config)

        ctx = agent._new_context(small="hello")
        assert ctx.metadata["small"] == "hello"
