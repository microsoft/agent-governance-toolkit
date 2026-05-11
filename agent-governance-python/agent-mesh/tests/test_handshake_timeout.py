# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for handshake timeout configuration."""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from agentmesh.exceptions import HandshakeTimeoutError
from agentmesh.identity.agent_id import AgentIdentity, IdentityRegistry
from agentmesh.trust.handshake import TrustHandshake


def _make_identity(name: str) -> AgentIdentity:
    return AgentIdentity.create(
        name=name,
        sponsor=f"{name}@test.example.com",
        capabilities=["read:data"],
    )


def _make_registry(*identities: AgentIdentity) -> IdentityRegistry:
    registry = IdentityRegistry()
    for identity in identities:
        registry.register(identity)
    return registry


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
    @pytest.mark.slow
    async def test_timeout_raises_handshake_timeout_error(self):
        """Slow handshake raises HandshakeTimeoutError."""
        agent_a = _make_identity("timeout-a")
        agent_b = _make_identity("timeout-b")
        registry = _make_registry(agent_a, agent_b)

        hs = TrustHandshake(
            agent_did=str(agent_a.did),
            identity=agent_a,
            registry=registry,
            timeout_seconds=0.1,
        )

        async def slow_response(*args, **kwargs):
            await asyncio.sleep(5)
            return None

        with patch.object(hs, "_get_peer_response", side_effect=slow_response):
            with pytest.raises(HandshakeTimeoutError, match="exceeded"):
                await hs.initiate(peer_did=str(agent_b.did))

    @pytest.mark.asyncio
    async def test_successful_handshake_within_timeout(self):
        """Successful handshake within timeout works normally."""
        agent_a = _make_identity("fast-a")
        agent_b = _make_identity("fast-b")
        registry = _make_registry(agent_a, agent_b)

        hs = TrustHandshake(
            agent_did=str(agent_a.did),
            identity=agent_a,
            registry=registry,
            timeout_seconds=5.0,
        )

        result = await hs.initiate(
            peer_did=str(agent_b.did),
            required_trust_score=500,
            use_cache=False,
        )
        assert result.verified is True
        assert result.peer_did == str(agent_b.did)

    @pytest.mark.asyncio
    async def test_timeout_error_is_handshake_error(self):
        """HandshakeTimeoutError is a subclass of HandshakeError."""
        from agentmesh.exceptions import HandshakeError

        assert issubclass(HandshakeTimeoutError, HandshakeError)


class TestPendingChallengesCapUnderConcurrency:
    """Regression tests for the pending-challenges DoS cap under burst load."""

    @pytest.mark.asyncio
    async def test_concurrent_initiates_cannot_exceed_cap(self):
        """Many concurrent initiates must not blow past _max_pending_challenges.

        Previously the purge/check/insert sequence was unlocked: every
        coroutine could read len(...) < cap and then each insert past
        the cap before any of them yielded. With the async lock added,
        only ``cap`` insertions succeed; the rest get the
        "Too many pending challenges" failure.
        """
        agent_a = _make_identity("burst-a")
        agent_b = _make_identity("burst-b")
        registry = _make_registry(agent_a, agent_b)

        hs = TrustHandshake(
            agent_did=str(agent_a.did),
            identity=agent_a,
            registry=registry,
            timeout_seconds=2.0,
        )
        hs._max_pending_challenges = 5

        # Block _get_peer_response so challenges accumulate in the
        # pending dict for the duration of the test.
        gate = asyncio.Event()

        async def hold_open(*_args, **_kwargs):
            await gate.wait()
            return None

        peak = 0

        async def watch_size():
            nonlocal peak
            while not gate.is_set():
                peak = max(peak, len(hs._pending_challenges))
                await asyncio.sleep(0)

        with patch.object(hs, "_get_peer_response", side_effect=hold_open):
            watcher = asyncio.create_task(watch_size())
            tasks = [
                asyncio.create_task(
                    hs.initiate(
                        peer_did=str(agent_b.did),
                        required_trust_score=0,
                        use_cache=False,
                    )
                )
                for _ in range(40)
            ]

            # Give the event loop time to process the burst and have all
            # 40 attempt the purge/check/insert step.
            await asyncio.sleep(0.05)
            peak_observed = max(peak, len(hs._pending_challenges))
            gate.set()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            await watcher

        assert peak_observed <= hs._max_pending_challenges, (
            f"_pending_challenges hit {peak_observed} entries; "
            f"cap is {hs._max_pending_challenges}"
        )

        rate_limited = sum(
            1
            for r in results
            if not isinstance(r, BaseException)
            and not r.verified
            and r.rejection_reason
            and "Too many pending challenges" in r.rejection_reason
        )
        # Of 40 attempts with cap=5, at least ~35 must have hit the cap.
        assert rate_limited >= 30, (
            f"Expected most attempts to be rate-limited; got {rate_limited}/40"
        )
