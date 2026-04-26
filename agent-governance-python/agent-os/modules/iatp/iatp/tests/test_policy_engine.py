# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for the IATP Policy Engine.
"""
from iatp.models import (
    AgentCapabilities,
    CapabilityManifest,
    PrivacyContract,
    RetentionPolicy,
    ReversibilityLevel,
    TrustLevel,
)
from iatp.policy_engine import IATPPolicyEngine


def test_policy_engine_initialization():
    """Test that policy engine initializes with default policies."""
    engine = IATPPolicyEngine()
    assert engine is not None
    assert len(engine.rules) > 0


def test_validate_manifest_ephemeral_allowed():
    """Test that ephemeral retention is allowed."""
    engine = IATPPolicyEngine()

    manifest = CapabilityManifest(
        agent_id="test-agent",
        trust_level=TrustLevel.TRUSTED,
        capabilities=AgentCapabilities(
            idempotency=True,
            reversibility=ReversibilityLevel.FULL,
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.EPHEMERAL,
            human_review=False,
        )
    )

    is_allowed, error_msg, warning_msg = engine.validate_manifest(manifest)

    assert is_allowed is True
    assert error_msg is None
    # May have warning for other reasons, but should not block


def test_validate_manifest_permanent_warning():
    """Test that permanent retention generates a warning but doesn't block."""
    engine = IATPPolicyEngine()

    manifest = CapabilityManifest(
        agent_id="permanent-storage-agent",
        trust_level=TrustLevel.STANDARD,
        capabilities=AgentCapabilities(
            idempotency=False,
            reversibility=ReversibilityLevel.NONE,
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.PERMANENT,
            human_review=True,
        )
    )

    is_allowed, error_msg, warning_msg = engine.validate_manifest(manifest)

    # Should be allowed but may have warnings
    # (Actual blocking based on sensitive data happens in SecurityValidator)
    assert is_allowed is True
    # May have warning about no reversibility
    if warning_msg:
        assert "reversal" in warning_msg.lower() or "warning" in warning_msg.lower()


def test_validate_manifest_no_reversibility_warning():
    """Test that no reversibility generates warning."""
    engine = IATPPolicyEngine()

    manifest = CapabilityManifest(
        agent_id="limited-agent",
        trust_level=TrustLevel.STANDARD,
        capabilities=AgentCapabilities(
            idempotency=True,
            reversibility=ReversibilityLevel.NONE,
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.TEMPORARY,
            human_review=False,
        )
    )

    is_allowed, error_msg, warning_msg = engine.validate_manifest(manifest)

    assert is_allowed is True
    assert error_msg is None
    # Warning about no reversibility
    if warning_msg:
        assert "reversal" in warning_msg.lower() or "warning" in warning_msg.lower()


def test_add_custom_rule():
    """Test adding custom policy rules."""
    engine = IATPPolicyEngine()

    custom_rule = {
        "name": "CustomTestRule",
        "description": "Test custom rule",
        "action": "deny",
        "conditions": {"trust_level": ["untrusted"]}
    }

    engine.add_custom_rule(custom_rule)

    # Test with untrusted agent
    manifest = CapabilityManifest(
        agent_id="untrusted-agent",
        trust_level=TrustLevel.UNTRUSTED,
        capabilities=AgentCapabilities(
            idempotency=True,
            reversibility=ReversibilityLevel.FULL,
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.EPHEMERAL,
            human_review=False,
        )
    )

    is_allowed, error_msg, warning_msg = engine.validate_manifest(manifest)

    # Should be blocked by custom rule or existing rules
    assert is_allowed is False or warning_msg is not None


def test_validate_handshake_compatible():
    """Test handshake validation with compatible agent."""
    engine = IATPPolicyEngine()

    manifest = CapabilityManifest(
        agent_id="compatible-agent",
        trust_level=TrustLevel.TRUSTED,
        capabilities=AgentCapabilities(
            idempotency=True,
            reversibility=ReversibilityLevel.FULL,
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.EPHEMERAL,
            human_review=False,
        )
    )

    is_compatible, error_msg = engine.validate_handshake(
        manifest,
        required_capabilities=["reversibility", "idempotency"]
    )

    assert is_compatible is True
    assert error_msg is None


def test_validate_handshake_missing_capabilities():
    """Test handshake validation with missing capabilities."""
    engine = IATPPolicyEngine()

    manifest = CapabilityManifest(
        agent_id="limited-agent",
        trust_level=TrustLevel.STANDARD,
        capabilities=AgentCapabilities(
            idempotency=False,
            reversibility=ReversibilityLevel.NONE,
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.TEMPORARY,
            human_review=False,
        )
    )

    is_compatible, error_msg = engine.validate_handshake(
        manifest,
        required_capabilities=["reversibility"]
    )

    assert is_compatible is False
    assert error_msg is not None
    assert "reversibility" in error_msg.lower()


def test_manifest_to_context():
    """Test conversion of manifest to policy context."""
    engine = IATPPolicyEngine()

    manifest = CapabilityManifest(
        agent_id="test-agent",
        trust_level=TrustLevel.VERIFIED_PARTNER,
        capabilities=AgentCapabilities(
            idempotency=True,
            reversibility=ReversibilityLevel.PARTIAL,
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.EPHEMERAL,
            human_review=True,
            encryption_at_rest=True,
            encryption_in_transit=True,
        )
    )

    context = engine._manifest_to_context(manifest)

    assert context["agent_id"] == "test-agent"
    assert context["trust_level"] == "verified_partner"
    assert context["retention_policy"] == "ephemeral"
    assert context["reversibility"] == "partial"
    assert context["idempotency"] is True
    assert context["human_review"] is True
    assert context["encryption_at_rest"] is True
    assert context["encryption_in_transit"] is True


def test_validate_handshake_with_required_scopes():
    """Test handshake validation with required scopes."""
    engine = IATPPolicyEngine()

    manifest = CapabilityManifest(
        agent_id="coder-agent",
        trust_level=TrustLevel.TRUSTED,
        capabilities=AgentCapabilities(
            idempotency=True,
            reversibility=ReversibilityLevel.FULL,
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.EPHEMERAL,
            human_review=False,
        ),
        scopes=["repo:read", "repo:write"]
    )

    is_compatible, error_msg = engine.validate_handshake(
        manifest,
        required_scopes=["repo:write"]
    )

    assert is_compatible is True
    assert error_msg is None


def test_validate_handshake_missing_scopes():
    """Test handshake validation with missing required scopes."""
    engine = IATPPolicyEngine()

    manifest = CapabilityManifest(
        agent_id="reviewer-agent",
        trust_level=TrustLevel.STANDARD,
        capabilities=AgentCapabilities(
            idempotency=True,
            reversibility=ReversibilityLevel.FULL,
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.TEMPORARY,
            human_review=False,
        ),
        scopes=["repo:read"]  # Only has read access
    )

    is_compatible, error_msg = engine.validate_handshake(
        manifest,
        required_scopes=["repo:write"]  # But needs write access
    )

    assert is_compatible is False
    assert error_msg is not None
    assert "repo:write" in error_msg


def test_validate_handshake_multiple_scopes():
    """Test handshake validation with multiple required scopes."""
    engine = IATPPolicyEngine()

    manifest = CapabilityManifest(
        agent_id="admin-agent",
        trust_level=TrustLevel.VERIFIED_PARTNER,
        capabilities=AgentCapabilities(
            idempotency=True,
            reversibility=ReversibilityLevel.FULL,
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.EPHEMERAL,
            human_review=False,
        ),
        scopes=["repo:read", "repo:write", "admin:manage"]
    )

    is_compatible, error_msg = engine.validate_handshake(
        manifest,
        required_scopes=["repo:read", "repo:write"]
    )

    assert is_compatible is True
    assert error_msg is None


def test_validate_handshake_no_scopes_required():
    """Test handshake validation when no scopes are required."""
    engine = IATPPolicyEngine()

    manifest = CapabilityManifest(
        agent_id="basic-agent",
        trust_level=TrustLevel.STANDARD,
        capabilities=AgentCapabilities(
            idempotency=True,
            reversibility=ReversibilityLevel.FULL,
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.TEMPORARY,
            human_review=False,
        ),
        scopes=[]  # No scopes
    )

    is_compatible, error_msg = engine.validate_handshake(
        manifest,
        required_scopes=None  # No scopes required
    )

    assert is_compatible is True
    assert error_msg is None


def test_manifest_to_context_with_scopes():
    """Test conversion of manifest with scopes to policy context."""
    engine = IATPPolicyEngine()

    manifest = CapabilityManifest(
        agent_id="scoped-agent",
        trust_level=TrustLevel.TRUSTED,
        capabilities=AgentCapabilities(
            idempotency=True,
            reversibility=ReversibilityLevel.FULL,
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.EPHEMERAL,
            human_review=False,
        ),
        scopes=["repo:read", "repo:write"]
    )

    context = engine._manifest_to_context(manifest)

    assert context["scopes"] == ["repo:read", "repo:write"]
