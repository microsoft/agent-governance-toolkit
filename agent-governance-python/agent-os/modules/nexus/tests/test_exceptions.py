# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Nexus exceptions."""

import os
import sys

import pytest

_nexus_parent = os.path.join(os.path.dirname(__file__), "..", "..")
if _nexus_parent not in sys.path:
    sys.path.insert(0, _nexus_parent)

from nexus.exceptions import (
    NexusError,
    IATPUnverifiedPeerException,
    IATPInsufficientTrustException,
    IATPAttestationExpiredException,
    IATPPolicyViolationException,
    EscrowError,
    EscrowNotFoundError,
    EscrowExpiredError,
    EscrowAlreadyResolvedError,
    InsufficientCreditsError,
    DisputeError,
    DisputeNotFoundError,
    DisputeAlreadyResolvedError,
    DisputeEvidenceError,
    RegistryError,
    AgentAlreadyRegisteredError,
    AgentNotFoundError,
    InvalidManifestError,
    DMZError,
    PolicyNotSignedError,
    DataClassificationError,
)


class TestNexusError:
    """Tests for the base NexusError."""

    def test_message_and_code(self):
        err = NexusError("something failed", code="TEST_CODE")
        assert err.message == "something failed"
        assert err.code == "TEST_CODE"
        assert "[TEST_CODE]" in str(err)

    def test_default_code(self):
        err = NexusError("oops")
        assert err.code == "NEXUS_ERROR"

    def test_is_exception(self):
        assert issubclass(NexusError, Exception)


class TestInheritanceHierarchy:
    """All custom exceptions inherit from NexusError."""

    @pytest.mark.parametrize("exc_cls", [
        IATPUnverifiedPeerException,
        IATPInsufficientTrustException,
        IATPAttestationExpiredException,
        IATPPolicyViolationException,
        EscrowError,
        EscrowNotFoundError,
        EscrowExpiredError,
        EscrowAlreadyResolvedError,
        InsufficientCreditsError,
        DisputeError,
        DisputeNotFoundError,
        DisputeAlreadyResolvedError,
        DisputeEvidenceError,
        RegistryError,
        AgentAlreadyRegisteredError,
        AgentNotFoundError,
        InvalidManifestError,
        DMZError,
        PolicyNotSignedError,
        DataClassificationError,
    ])
    def test_inherits_from_nexus_error(self, exc_cls):
        assert issubclass(exc_cls, NexusError)

    def test_escrow_errors_inherit_from_escrow_error(self):
        assert issubclass(EscrowNotFoundError, EscrowError)
        assert issubclass(EscrowExpiredError, EscrowError)
        assert issubclass(InsufficientCreditsError, EscrowError)

    def test_dispute_errors_inherit_from_dispute_error(self):
        assert issubclass(DisputeNotFoundError, DisputeError)
        assert issubclass(DisputeAlreadyResolvedError, DisputeError)

    def test_registry_errors_inherit_from_registry_error(self):
        assert issubclass(AgentAlreadyRegisteredError, RegistryError)
        assert issubclass(AgentNotFoundError, RegistryError)
        assert issubclass(InvalidManifestError, RegistryError)

    def test_dmz_errors_inherit_from_dmz_error(self):
        assert issubclass(PolicyNotSignedError, DMZError)
        assert issubclass(DataClassificationError, DMZError)


class TestIATPUnverifiedPeerException:
    """Tests for IATPUnverifiedPeerException."""

    def test_creates_registration_url(self):
        err = IATPUnverifiedPeerException("agent-x")
        assert "agent-x" in err.registration_url
        assert err.peer_id == "agent-x"

    def test_to_iatp_error(self):
        err = IATPUnverifiedPeerException("agent-x")
        result = err.to_iatp_error()
        assert result["error"] == "IATP_UNVERIFIED_PEER"
        assert result["peer_id"] == "agent-x"
        assert "registration_url" in result


class TestIATPInsufficientTrustException:
    """Tests for IATPInsufficientTrustException."""

    def test_score_gap(self):
        err = IATPInsufficientTrustException("did:nexus:a", current_score=300, required_score=700)
        assert err.score_gap == 400

    def test_to_iatp_error(self):
        err = IATPInsufficientTrustException("did:nexus:a", current_score=300, required_score=700)
        result = err.to_iatp_error()
        assert result["current_score"] == 300
        assert result["required_score"] == 700


class TestIATPAttestationExpiredException:
    """Tests for IATPAttestationExpiredException."""

    def test_message_includes_details(self):
        err = IATPAttestationExpiredException("did:nexus:a", "2024-01-01T00:00:00")
        assert "expired" in str(err).lower()
        assert err.peer_did == "did:nexus:a"
        assert err.expired_at == "2024-01-01T00:00:00"


class TestIATPPolicyViolationException:
    """Tests for IATPPolicyViolationException."""

    def test_attributes(self):
        err = IATPPolicyViolationException("did:nexus:a", "no pii consent", "pii_reject")
        assert err.peer_did == "did:nexus:a"
        assert err.violation == "no pii consent"
        assert err.required_policy == "pii_reject"


class TestEscrowExceptions:
    """Tests for escrow-related exceptions."""

    def test_escrow_not_found(self):
        err = EscrowNotFoundError("esc_123")
        assert err.escrow_id == "esc_123"
        assert err.code == "ESCROW_NOT_FOUND"

    def test_escrow_expired(self):
        err = EscrowExpiredError("esc_123", "2024-01-01")
        assert err.expired_at == "2024-01-01"
        assert err.code == "ESCROW_EXPIRED"

    def test_insufficient_credits(self):
        err = InsufficientCreditsError("did:nexus:a", required=500, available=100)
        assert err.required == 500
        assert err.available == 100
        assert err.code == "INSUFFICIENT_CREDITS"

    def test_escrow_already_resolved(self):
        err = EscrowAlreadyResolvedError("esc_123", "released")
        assert err.resolution_status == "released"


class TestDisputeExceptions:
    """Tests for dispute-related exceptions."""

    def test_dispute_not_found(self):
        err = DisputeNotFoundError("disp_123")
        assert err.dispute_id == "disp_123"
        assert err.code == "DISPUTE_NOT_FOUND"

    def test_dispute_already_resolved(self):
        err = DisputeAlreadyResolvedError("disp_123")
        assert "already been resolved" in str(err)

    def test_dispute_evidence_error(self):
        err = DisputeEvidenceError("disp_123", "hash mismatch")
        assert err.issue == "hash mismatch"


class TestRegistryExceptions:
    """Tests for registry-related exceptions."""

    def test_agent_already_registered(self):
        err = AgentAlreadyRegisteredError("did:nexus:a")
        assert err.agent_did == "did:nexus:a"
        assert err.code == "AGENT_ALREADY_REGISTERED"

    def test_agent_not_found(self):
        err = AgentNotFoundError("did:nexus:a")
        assert err.code == "AGENT_NOT_FOUND"

    def test_invalid_manifest(self):
        err = InvalidManifestError("did:nexus:a", ["missing owner", "bad DID"])
        assert len(err.validation_errors) == 2
        assert err.code == "INVALID_MANIFEST"


class TestDMZExceptions:
    """Tests for DMZ-related exceptions."""

    def test_policy_not_signed(self):
        err = PolicyNotSignedError("did:nexus:a", "hash_123")
        assert err.agent_did == "did:nexus:a"
        assert err.policy_hash == "hash_123"
        assert err.code == "POLICY_NOT_SIGNED"

    def test_data_classification_error(self):
        err = DataClassificationError("pii", "not allowed")
        assert err.classification == "pii"
        assert err.reason == "not allowed"
        assert err.code == "DATA_CLASSIFICATION_ERROR"
