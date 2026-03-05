# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for handshake timeout configuration."""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from agentmesh.exceptions import HandshakeTimeoutError
from agentmesh.trust.handshake import TrustHandshake


class TestHandshakeTimeoutConfig:
    """Tests for timeout configuration on TrustHandshake."""

    def test_default_timeout(self):
        """Default timeout is 30 seconds."""
        hs = TrustHandshake(agent_did="did:mesh:abc123")
        assert hs.timeout_seconds == 30.0

    def test_custom_timeout(self):
        """Custom timeout is configurable."""
        hs = TrustHandshake(agent_did="did:mesh:abc123", timeout_seconds=10.0)
        assert hs.timeout_seconds == 10.0

    def test_zero_timeout_raises_value_error(self):
        """Zero timeout raises ValueError."""
        with pytest.raises(ValueError, match="timeout_seconds must be positive"):
            TrustHandshake(agent_did="did:mesh:abc123", timeout_seconds=0)

    def test_negative_timeout_raises_value_error(self):
        """Negative timeout raises ValueError."""
        with pytest.raises(ValueError, match="timeout_seconds must be positive"):
            TrustHandshake(agent_did="did:mesh:abc123", timeout_seconds=-5.0)

    def test_default_timeout_constant(self):
        """DEFAULT_TIMEOUT_SECONDS class constant is 30.0."""
        assert TrustHandshake.DEFAULT_TIMEOUT_SECONDS == 30.0


class TestHandshakeTimeoutBehavior:
    """Tests for timeout behavior during handshake."""

    @pytest.mark.asyncio
    async def test_timeout_raises_handshake_timeout_error(self):
        """Slow handshake raises HandshakeTimeoutError."""
        hs = TrustHandshake(agent_did="did:mesh:abc123", timeout_seconds=0.1)

        async def slow_response(*args, **kwargs):
            await asyncio.sleep(5)
            return None

        with patch.object(hs, "_get_peer_response", side_effect=slow_response):
            with pytest.raises(HandshakeTimeoutError, match="exceeded"):
                await hs.initiate(peer_did="did:mesh:peer456")

    @pytest.mark.asyncio
    async def test_successful_handshake_within_timeout(self):
        """Successful handshake within timeout works normally."""
        hs = TrustHandshake(agent_did="did:mesh:abc123", timeout_seconds=5.0)

        result = await hs.initiate(peer_did="did:mesh:peer456", use_cache=False)
        assert result.verified is True
        assert result.peer_did == "did:mesh:peer456"

    @pytest.mark.asyncio
    async def test_timeout_error_is_handshake_error(self):
        """HandshakeTimeoutError is a subclass of HandshakeError."""
        from agentmesh.exceptions import HandshakeError

        assert issubclass(HandshakeTimeoutError, HandshakeError)
