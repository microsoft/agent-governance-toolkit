# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Shared fixtures for Nexus tests."""

import os
import sys
from datetime import datetime, timezone

import pytest

_nexus_parent = os.path.join(os.path.dirname(__file__), "..", "..")
if _nexus_parent not in sys.path:
    sys.path.insert(0, _nexus_parent)

from nexus.reputation import ReputationEngine, ReputationHistory
from nexus.escrow import EscrowManager
from nexus.schemas.manifest import AgentIdentity, AgentCapabilities, AgentPrivacy, AgentManifest
from nexus.schemas.escrow import EscrowRequest, EscrowReceipt, EscrowStatus
from tests.helpers import TEST_VERIFICATION_KEY, make_manifest  # noqa: F401 (re-exported)


@pytest.fixture
def reputation_engine():
    return ReputationEngine(trust_threshold=500)


@pytest.fixture
def escrow_manager(reputation_engine):
    return EscrowManager(reputation_engine=reputation_engine)


@pytest.fixture
def sample_identity():
    return AgentIdentity(
        did="did:nexus:test-agent-v1",
        verification_key=TEST_VERIFICATION_KEY,
        owner_id="org-test-corp",
        display_name="Test Agent",
        contact="test@example.com",
    )


@pytest.fixture
def sample_capabilities():
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
    return AgentPrivacy(
        retention_policy="ephemeral",
        pii_handling="reject",
        human_in_loop=False,
        training_consent=False,
    )


@pytest.fixture
def sample_manifest(sample_identity, sample_capabilities, sample_privacy):
    return AgentManifest(
        identity=sample_identity,
        capabilities=sample_capabilities,
        privacy=sample_privacy,
        verification_level="registered",
    )


@pytest.fixture
def sample_history():
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
    return EscrowRequest(
        requester_did="did:nexus:requester-agent",
        provider_did="did:nexus:provider-agent",
        task_hash="abc123def456",
        credits=100,
        timeout_seconds=3600,
        require_scak_validation=False,
    )
