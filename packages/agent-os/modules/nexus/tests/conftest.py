# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Shared fixtures for Nexus tests."""

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

# Add parent of nexus package to path so 'nexus' is importable
_nexus_parent = os.path.join(os.path.dirname(__file__), "..", "..")
if _nexus_parent not in sys.path:
    sys.path.insert(0, _nexus_parent)

from nexus.reputation import ReputationEngine, ReputationHistory, TrustScore, TrustTier
from nexus.escrow import EscrowManager
from nexus.schemas.manifest import (
    AgentIdentity,
    AgentCapabilities,
    AgentPrivacy,
    MuteRules,
    AgentManifest,
)
from nexus.schemas.escrow import EscrowRequest, EscrowReceipt, EscrowStatus


@pytest.fixture
def reputation_engine():
    """Create a ReputationEngine with default threshold."""
    return ReputationEngine(trust_threshold=500)


@pytest.fixture
def escrow_manager(reputation_engine):
    """Create an EscrowManager with a reputation engine."""
    return EscrowManager(reputation_engine=reputation_engine)


@pytest.fixture
def sample_identity():
    """Create a sample AgentIdentity."""
    return AgentIdentity(
        did="did:nexus:test-agent-v1",
        verification_key="ed25519:testkey123abc",
        owner_id="org-test-corp",
        display_name="Test Agent",
        contact="test@example.com",
    )


@pytest.fixture
def sample_capabilities():
    """Create sample AgentCapabilities."""
    return AgentCapabilities(
        domains=["data-analysis", "code-generation"],
        tools=["python", "sql"],
        max_concurrency=10,
        sla_latency_ms=5000,
        idempotency=True,
        reversibility="full",
    )


@pytest.fixture
def sample_privacy():
    """Create sample AgentPrivacy."""
    return AgentPrivacy(
        retention_policy="ephemeral",
        pii_handling="reject",
        human_in_loop=False,
        training_consent=False,
    )


@pytest.fixture
def sample_manifest(sample_identity, sample_capabilities, sample_privacy):
    """Create a sample AgentManifest."""
    return AgentManifest(
        identity=sample_identity,
        capabilities=sample_capabilities,
        privacy=sample_privacy,
        verification_level="registered",
    )


@pytest.fixture
def sample_history():
    """Create a sample ReputationHistory."""
    return ReputationHistory(
        agent_did="did:nexus:test-agent-v1",
        successful_tasks=10,
        failed_tasks=1,
        total_tasks=11,
        disputes_won=2,
        disputes_lost=0,
        uptime_days=30,
        last_activity=datetime.now(timezone.utc),
    )


@pytest.fixture
def sample_escrow_request():
    """Create a sample EscrowRequest."""
    return EscrowRequest(
        requester_did="did:nexus:requester-agent",
        provider_did="did:nexus:provider-agent",
        task_hash="abc123def456",
        credits=100,
        timeout_seconds=3600,
        require_scak_validation=False,
    )


def make_manifest(
    did: str = "did:nexus:test-agent-v1",
    owner_id: str = "org-test-corp",
    verification_level: str = "registered",
    domains: list[str] | None = None,
    retention_policy: str = "ephemeral",
    pii_handling: str = "reject",
    training_consent: bool = False,
    idempotency: bool = False,
    reversibility: str = "partial",
    trust_score: int = 400,
) -> AgentManifest:
    """Helper to create manifests with custom parameters."""
    return AgentManifest(
        identity=AgentIdentity(
            did=did,
            verification_key="ed25519:testkey123abc",
            owner_id=owner_id,
        ),
        capabilities=AgentCapabilities(
            domains=domains or ["data-analysis"],
            idempotency=idempotency,
            reversibility=reversibility,
        ),
        privacy=AgentPrivacy(
            retention_policy=retention_policy,
            pii_handling=pii_handling,
            training_consent=training_consent,
        ),
        verification_level=verification_level,
        trust_score=trust_score,
    )
