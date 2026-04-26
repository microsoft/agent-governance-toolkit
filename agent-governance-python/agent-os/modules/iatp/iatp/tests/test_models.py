# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Unit tests for IATP models.
"""
from iatp.models import (
    AgentCapabilities,
    CapabilityManifest,
    PrivacyContract,
    RetentionPolicy,
    ReversibilityLevel,
    TrustLevel,
)


def test_capability_manifest_creation():
    """Test creating a capability manifest."""
    manifest = CapabilityManifest(
        agent_id="test-agent",
        agent_version="1.0.0",
        trust_level=TrustLevel.TRUSTED,
        capabilities=AgentCapabilities(
            idempotency=True,
            reversibility=ReversibilityLevel.FULL,
            undo_window="24h",
            sla_latency="1000ms"
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.EPHEMERAL,
            storage_location="us-east",
            human_review=False
        )
    )

    assert manifest.agent_id == "test-agent"
    assert manifest.trust_level == TrustLevel.TRUSTED
    assert manifest.capabilities.idempotency is True
    assert manifest.privacy_contract.retention == RetentionPolicy.EPHEMERAL


def test_capability_manifest_with_scopes():
    """Test creating a capability manifest with RBAC scopes."""
    manifest = CapabilityManifest(
        agent_id="coder-agent",
        agent_version="1.0.0",
        trust_level=TrustLevel.TRUSTED,
        capabilities=AgentCapabilities(
            idempotency=True,
            reversibility=ReversibilityLevel.FULL,
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.EPHEMERAL,
        ),
        scopes=["repo:read", "repo:write"]
    )

    assert manifest.agent_id == "coder-agent"
    assert manifest.scopes == ["repo:read", "repo:write"]


def test_capability_manifest_default_scopes():
    """Test that scopes defaults to empty list."""
    manifest = CapabilityManifest(
        agent_id="agent-without-scopes",
        trust_level=TrustLevel.STANDARD,
        capabilities=AgentCapabilities(),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.TEMPORARY,
        )
    )

    assert manifest.scopes == []


def test_trust_score_verified_partner():
    """Test trust score for verified partner."""
    manifest = CapabilityManifest(
        agent_id="verified-agent",
        trust_level=TrustLevel.VERIFIED_PARTNER,
        capabilities=AgentCapabilities(
            idempotency=True,
            reversibility=ReversibilityLevel.FULL
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.EPHEMERAL,
            human_review=False
        )
    )

    score = manifest.calculate_trust_score()
    assert score >= 8  # Verified partner with good privacy should score high


def test_trust_score_untrusted():
    """Test trust score for untrusted agent."""
    manifest = CapabilityManifest(
        agent_id="sketchy-agent",
        trust_level=TrustLevel.UNTRUSTED,
        capabilities=AgentCapabilities(
            idempotency=False,
            reversibility=ReversibilityLevel.NONE
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.FOREVER,
            human_review=True
        )
    )

    score = manifest.calculate_trust_score()
    assert score <= 3  # Untrusted agent with bad privacy should score low


def test_privacy_contract_defaults():
    """Test privacy contract default values."""
    contract = PrivacyContract(
        retention=RetentionPolicy.TEMPORARY
    )

    assert contract.human_review is False
    assert contract.encryption_at_rest is True
    assert contract.encryption_in_transit is True


def test_agent_capabilities_defaults():
    """Test agent capabilities default values."""
    capabilities = AgentCapabilities()

    assert capabilities.idempotency is False
    assert capabilities.reversibility == ReversibilityLevel.NONE
    assert capabilities.undo_window is None
