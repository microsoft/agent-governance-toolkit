# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for Nexus Client
"""

import pytest
from datetime import datetime

from nexus.client import NexusClient
from nexus.crypto import generate_keypair
from nexus.schemas.manifest import AgentManifest, AgentIdentity, AgentCapabilities, AgentPrivacy
from nexus.dmz import DataHandlingPolicy
from nexus.exceptions import (
    IATPUnverifiedPeerException,
    IATPInsufficientTrustException,
)


def create_test_client(agent_id: str = "test-agent") -> tuple:
    """Create a (NexusClient, private_key_bytes) pair with a real Ed25519 keypair."""
    private_key_bytes, verification_key = generate_keypair()
    manifest = AgentManifest(
        identity=AgentIdentity(
            did=f"did:nexus:{agent_id}",
            verification_key=verification_key,
            owner_id="test-org",
        ),
        capabilities=AgentCapabilities(
            domains=["data-analysis"],
            reversibility="full",
        ),
        privacy=AgentPrivacy(
            retention_policy="ephemeral",
        ),
    )
    client = NexusClient(manifest, api_key="test", local_mode=True, private_key_bytes=private_key_bytes)
    return client


class TestNexusClient:
    """Tests for NexusClient in local mode."""

    @pytest.mark.asyncio
    async def test_register(self):
        """Test agent registration."""
        client = create_test_client()

        result = await client.register()

        assert result.success is True
        assert result.agent_did == "did:nexus:test-agent"

    @pytest.mark.asyncio
    async def test_verify_peer(self):
        """Test peer verification."""
        client = create_test_client("verifier")

        await client.register()

        # Register another agent sharing the same local registry
        peer_client = create_test_client("peer")
        peer_client._local_registry = client._local_registry
        await peer_client.register()

        # Build reputation for peer
        for _ in range(50):
            client._local_reputation.record_task_outcome("did:nexus:peer", "success")

        verification = await client.verify_peer("did:nexus:peer", min_score=400)

        assert verification.verified is True

    @pytest.mark.asyncio
    async def test_verify_unregistered_peer(self):
        """Test verifying unregistered peer."""
        client = create_test_client()

        await client.register()

        with pytest.raises(IATPUnverifiedPeerException):
            await client.verify_peer("did:nexus:unknown")

    @pytest.mark.asyncio
    async def test_quick_verify(self):
        """Test quick verification."""
        client = create_test_client()

        await client.register()

        # Unregistered peer
        assert await client.quick_verify("did:nexus:unknown") is False

    @pytest.mark.asyncio
    async def test_sync_reputation(self):
        """Test reputation sync."""
        client = create_test_client()

        await client.register()

        scores = await client.sync_reputation()

        assert isinstance(scores, dict)

    @pytest.mark.asyncio
    async def test_report_outcome(self):
        """Test reporting task outcomes."""
        client = create_test_client()

        await client.register()

        await client.report_outcome(
            task_id="task-123",
            peer_did="did:nexus:peer",
            outcome="success",
        )

        # Check history updated
        history = client._local_reputation._history_cache.get("did:nexus:peer")
        assert history is not None
        assert history.successful_tasks == 1

    @pytest.mark.asyncio
    async def test_create_escrow(self):
        """Test escrow creation."""
        client = create_test_client()

        await client.register()

        # Add credits
        client._local_escrow.add_credits("did:nexus:test-agent", 1000)

        receipt = await client.create_escrow(
            provider_did="did:nexus:provider",
            task_hash="task-hash",
            credits=100,
        )

        assert "escrow_id" in receipt

    @pytest.mark.asyncio
    async def test_get_credits(self):
        """Test credit balance."""
        client = create_test_client()

        await client.register()

        # Add credits
        client._local_escrow.add_credits("did:nexus:test-agent", 500)

        balance = await client.get_credits()
        assert balance == 500

    @pytest.mark.asyncio
    async def test_discover_agents(self):
        """Test agent discovery."""
        client = create_test_client()

        await client.register()

        agents = await client.discover_agents(min_score=0)

        assert len(agents) >= 1  # At least self


class TestNexusClientDMZ:
    """Tests for NexusClient DMZ functionality."""

    @pytest.mark.asyncio
    async def test_dmz_transfer(self):
        """Test DMZ data transfer."""
        client = create_test_client("sender")

        await client.register()

        policy = DataHandlingPolicy(
            max_retention_seconds=3600,
            allow_persistence=False,
            allow_training=False,
        )

        request = await client.initiate_dmz_transfer(
            receiver_did="did:nexus:receiver",
            data=b"sensitive data",
            classification="confidential",
            policy=policy,
        )

        assert "request_id" in request

    @pytest.mark.asyncio
    async def test_sign_dmz_policy(self):
        """Test DMZ policy signing."""
        client = create_test_client()

        await client.register()
        
        # Create a transfer
        policy = DataHandlingPolicy()
        request = await client.initiate_dmz_transfer(
            receiver_did="did:nexus:test-agent",  # Self as receiver
            data=b"data",
            classification="internal",
            policy=policy,
        )
        
        result = await client.sign_dmz_policy(request["request_id"])
        
        assert "policy_hash" in result


class TestNexusClientContextManager:
    """Tests for async context manager."""

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test using client as context manager."""
        client = create_test_client()

        async with client:
            assert client._local_registry.is_registered("did:nexus:test-agent")
