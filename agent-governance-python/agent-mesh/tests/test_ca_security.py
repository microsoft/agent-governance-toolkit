# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Security regression tests for Certificate Authority.

Validates that:
- Sponsor signatures are cryptographically verified (CRIT-1 fix)
- Refresh tokens are validated against issued tokens (CRIT-2 fix)
- SVID certificate issuance and properties
- Full registration-to-rotation lifecycle
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography import x509

from agentmesh.core.identity.ca import (
    CertificateAuthority,
    RegistrationRequest,
    RegistrationResponse,
    SponsorRegistry,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_sponsor_keypair():
    """Generate a sponsor Ed25519 keypair."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def _sign_registration(
    private_key: ed25519.Ed25519PrivateKey,
    agent_name: str,
    sponsor_email: str,
    capabilities: list[str] | None = None,
) -> bytes:
    """Create a valid sponsor signature for a registration request."""
    capabilities = capabilities or []
    capabilities_str = ",".join(sorted(capabilities))
    payload = f"{agent_name}:{sponsor_email}:{capabilities_str}"
    return private_key.sign(payload.encode("utf-8"))


def _make_agent_public_key() -> bytes:
    """Generate a fresh Ed25519 agent public key."""
    private = ed25519.Ed25519PrivateKey.generate()
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _make_ca_with_sponsor(email: str = "sponsor@corp.com"):
    """Create a CA with a registered sponsor."""
    sponsor_private, sponsor_public = _make_sponsor_keypair()
    registry = SponsorRegistry()
    registry.register_sponsor(email, sponsor_public)
    ca = CertificateAuthority(sponsor_registry=registry)
    return ca, sponsor_private, email


# ---------------------------------------------------------------------------
# SponsorRegistry tests
# ---------------------------------------------------------------------------


class TestSponsorRegistry:
    """Tests for the SponsorRegistry."""

    def test_register_and_lookup(self):
        reg = SponsorRegistry()
        _, pub = _make_sponsor_keypair()
        reg.register_sponsor("test@example.com", pub)
        assert reg.is_registered("test@example.com")
        assert reg.get_public_key("test@example.com") is pub

    def test_unregistered_returns_none(self):
        reg = SponsorRegistry()
        assert reg.get_public_key("nobody@example.com") is None
        assert not reg.is_registered("nobody@example.com")

    def test_remove_sponsor(self):
        reg = SponsorRegistry()
        _, pub = _make_sponsor_keypair()
        reg.register_sponsor("rm@example.com", pub)
        reg.remove_sponsor("rm@example.com")
        assert not reg.is_registered("rm@example.com")


# ---------------------------------------------------------------------------
# CRIT-1: Sponsor signature verification
# ---------------------------------------------------------------------------


class TestSponsorSignatureVerification:
    """CRIT-1: Validates that _validate_sponsor_signature actually verifies."""

    def test_valid_sponsor_signature_accepted(self):
        ca, sponsor_key, email = _make_ca_with_sponsor()
        sig = _sign_registration(sponsor_key, "my-agent", email, ["read:data"])
        request = RegistrationRequest(
            agent_name="my-agent",
            public_key=_make_agent_public_key(),
            sponsor_email=email,
            sponsor_signature=sig,
            capabilities=["read:data"],
        )
        # Should not raise
        response = ca.register_agent(request)
        assert response.status == "success"
        assert response.initial_trust_score == 500

    def test_fabricated_signature_rejected(self):
        ca, _, email = _make_ca_with_sponsor()
        request = RegistrationRequest(
            agent_name="rogue-agent",
            public_key=_make_agent_public_key(),
            sponsor_email=email,
            sponsor_signature=b"totally-fake-signature",
            capabilities=[],
        )
        with pytest.raises(ValueError, match="Invalid sponsor signature"):
            ca.register_agent(request)

    def test_unregistered_sponsor_rejected(self):
        ca, sponsor_key, _ = _make_ca_with_sponsor("known@corp.com")
        sig = _sign_registration(sponsor_key, "agent", "unknown@evil.com")
        request = RegistrationRequest(
            agent_name="agent",
            public_key=_make_agent_public_key(),
            sponsor_email="unknown@evil.com",
            sponsor_signature=sig,
            capabilities=[],
        )
        with pytest.raises(ValueError, match="Invalid sponsor signature"):
            ca.register_agent(request)

    def test_wrong_key_signature_rejected(self):
        """Signature from a different key than the registered sponsor."""
        ca, _, email = _make_ca_with_sponsor()
        rogue_key = ed25519.Ed25519PrivateKey.generate()
        sig = _sign_registration(rogue_key, "agent", email)
        request = RegistrationRequest(
            agent_name="agent",
            public_key=_make_agent_public_key(),
            sponsor_email=email,
            sponsor_signature=sig,
            capabilities=[],
        )
        with pytest.raises(ValueError, match="Invalid sponsor signature"):
            ca.register_agent(request)

    def test_tampered_capabilities_rejected(self):
        """Signature valid for different capabilities than claimed."""
        ca, sponsor_key, email = _make_ca_with_sponsor()
        # Sign for ["read:data"] but request claims ["read:data", "admin:all"]
        sig = _sign_registration(sponsor_key, "agent", email, ["read:data"])
        request = RegistrationRequest(
            agent_name="agent",
            public_key=_make_agent_public_key(),
            sponsor_email=email,
            sponsor_signature=sig,
            capabilities=["read:data", "admin:all"],
        )
        with pytest.raises(ValueError, match="Invalid sponsor signature"):
            ca.register_agent(request)

    def test_empty_sponsor_registry_rejects_all(self):
        """CA with no registered sponsors rejects everything."""
        ca = CertificateAuthority()
        key = ed25519.Ed25519PrivateKey.generate()
        sig = _sign_registration(key, "agent", "anyone@example.com")
        request = RegistrationRequest(
            agent_name="agent",
            public_key=_make_agent_public_key(),
            sponsor_email="anyone@example.com",
            sponsor_signature=sig,
            capabilities=[],
        )
        with pytest.raises(ValueError, match="Invalid sponsor signature"):
            ca.register_agent(request)


# ---------------------------------------------------------------------------
# CRIT-2: Refresh token validation
# ---------------------------------------------------------------------------


class TestRefreshTokenValidation:
    """CRIT-2: Validates that rotate_credentials checks issued tokens."""

    def _register_agent(self, ca, sponsor_key, email):
        """Register an agent and return the response."""
        sig = _sign_registration(sponsor_key, "test-agent", email)
        request = RegistrationRequest(
            agent_name="test-agent",
            public_key=_make_agent_public_key(),
            sponsor_email=email,
            sponsor_signature=sig,
        )
        return ca.register_agent(request)

    def test_valid_refresh_token_accepted(self):
        ca, sponsor_key, email = _make_ca_with_sponsor()
        reg = self._register_agent(ca, sponsor_key, email)
        new_key = _make_agent_public_key()
        # Use the real refresh token from registration
        rotated = ca.rotate_credentials(
            reg.agent_did, reg.refresh_token, new_key
        )
        assert rotated.agent_did == reg.agent_did
        assert rotated.status == "success"

    def test_fabricated_token_rejected(self):
        ca, sponsor_key, email = _make_ca_with_sponsor()
        reg = self._register_agent(ca, sponsor_key, email)
        new_key = _make_agent_public_key()
        with pytest.raises(ValueError, match="Invalid or expired refresh token"):
            ca.rotate_credentials(reg.agent_did, "fake-token-12345", new_key)

    def test_token_bound_to_did(self):
        """Token from agent A cannot be used to rotate agent B's creds."""
        ca, sponsor_key, email = _make_ca_with_sponsor()
        reg_a = self._register_agent(ca, sponsor_key, email)
        new_key = _make_agent_public_key()
        with pytest.raises(ValueError, match="Invalid or expired refresh token"):
            ca.rotate_credentials("did:mesh:differentagent", reg_a.refresh_token, new_key)

    def test_token_single_use(self):
        """Refresh token can only be used once."""
        ca, sponsor_key, email = _make_ca_with_sponsor()
        reg = self._register_agent(ca, sponsor_key, email)
        new_key = _make_agent_public_key()
        # First use succeeds
        ca.rotate_credentials(reg.agent_did, reg.refresh_token, new_key)
        # Second use fails (token consumed)
        with pytest.raises(ValueError, match="Invalid or expired refresh token"):
            ca.rotate_credentials(reg.agent_did, reg.refresh_token, _make_agent_public_key())

    def test_rotated_credentials_have_new_refresh_token(self):
        """After rotation, a new valid refresh token is issued."""
        ca, sponsor_key, email = _make_ca_with_sponsor()
        reg = self._register_agent(ca, sponsor_key, email)
        new_key = _make_agent_public_key()
        rotated = ca.rotate_credentials(reg.agent_did, reg.refresh_token, new_key)
        # The new refresh token should also work
        another_key = _make_agent_public_key()
        rotated2 = ca.rotate_credentials(
            rotated.agent_did, rotated.refresh_token, another_key
        )
        assert rotated2.agent_did == reg.agent_did

    def test_missing_public_key_raises(self):
        ca, sponsor_key, email = _make_ca_with_sponsor()
        reg = self._register_agent(ca, sponsor_key, email)
        with pytest.raises(ValueError, match="New public key required"):
            ca.rotate_credentials(reg.agent_did, reg.refresh_token)


# ---------------------------------------------------------------------------
# Registration lifecycle tests
# ---------------------------------------------------------------------------


class TestRegistrationLifecycle:
    """End-to-end registration and credential properties."""

    def _register(self, ca, sponsor_key, email, name="test-agent", caps=None):
        sig = _sign_registration(sponsor_key, name, email, caps or [])
        request = RegistrationRequest(
            agent_name=name,
            public_key=_make_agent_public_key(),
            sponsor_email=email,
            sponsor_signature=sig,
            capabilities=caps or [],
        )
        return ca.register_agent(request)

    def test_response_contains_valid_svid_certificate(self):
        ca, sponsor_key, email = _make_ca_with_sponsor()
        resp = self._register(ca, sponsor_key, email)
        # DER bytes should parse as a valid X.509 certificate
        cert = x509.load_der_x509_certificate(resp.svid_certificate)
        # Subject CN should be the agent DID
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
        assert cn.value == resp.agent_did
        # Should have SPIFFE SAN
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
        assert any(resp.agent_did in uri for uri in uris)

    def test_response_contains_ca_pem_certificate(self):
        ca, sponsor_key, email = _make_ca_with_sponsor()
        resp = self._register(ca, sponsor_key, email)
        assert resp.ca_certificate.startswith("-----BEGIN CERTIFICATE-----")
        # Should parse as valid PEM
        x509.load_pem_x509_certificate(resp.ca_certificate.encode())

    def test_svid_certificate_signed_by_ca(self):
        ca, sponsor_key, email = _make_ca_with_sponsor()
        resp = self._register(ca, sponsor_key, email)
        svid_cert = x509.load_der_x509_certificate(resp.svid_certificate)
        # The CA public key should verify the SVID cert's signature
        ca.ca_public_key.verify(
            svid_cert.signature,
            svid_cert.tbs_certificate_bytes,
        )

    def test_svid_certificate_not_ca(self):
        ca, sponsor_key, email = _make_ca_with_sponsor()
        resp = self._register(ca, sponsor_key, email)
        cert = x509.load_der_x509_certificate(resp.svid_certificate)
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False

    def test_initial_trust_score_is_500(self):
        ca, sponsor_key, email = _make_ca_with_sponsor()
        resp = self._register(ca, sponsor_key, email)
        assert resp.initial_trust_score == 500

    def test_trust_dimensions_present(self):
        ca, sponsor_key, email = _make_ca_with_sponsor()
        resp = self._register(ca, sponsor_key, email)
        assert "policy_compliance" in resp.trust_dimensions
        assert "security_posture" in resp.trust_dimensions
        assert len(resp.trust_dimensions) == 5

    def test_tokens_have_correct_format(self):
        ca, sponsor_key, email = _make_ca_with_sponsor()
        resp = self._register(ca, sponsor_key, email)
        assert resp.access_token.startswith("agentmesh_access_")
        assert resp.refresh_token.startswith("agentmesh_refresh_")

    def test_token_ttl_matches_config(self):
        ca, sponsor_key, email = _make_ca_with_sponsor()
        resp = self._register(ca, sponsor_key, email)
        assert resp.token_ttl_seconds == 15 * 60  # default 15 min

    def test_custom_ttl(self):
        """CA with custom TTL issues certs with matching duration."""
        sponsor_private, sponsor_public = _make_sponsor_keypair()
        reg = SponsorRegistry()
        reg.register_sponsor("s@corp.com", sponsor_public)
        ca = CertificateAuthority(default_ttl_minutes=5, sponsor_registry=reg)
        resp = self._register(ca, sponsor_private, "s@corp.com")
        assert resp.token_ttl_seconds == 5 * 60

    def test_each_registration_gets_unique_did(self):
        ca, sponsor_key, email = _make_ca_with_sponsor()
        r1 = self._register(ca, sponsor_key, email, name="agent-1")
        r2 = self._register(ca, sponsor_key, email, name="agent-2")
        assert r1.agent_did != r2.agent_did

    def test_each_registration_gets_unique_tokens(self):
        ca, sponsor_key, email = _make_ca_with_sponsor()
        r1 = self._register(ca, sponsor_key, email, name="agent-1")
        r2 = self._register(ca, sponsor_key, email, name="agent-2")
        assert r1.access_token != r2.access_token
        assert r1.refresh_token != r2.refresh_token

    def test_svid_expiry_in_future(self):
        ca, sponsor_key, email = _make_ca_with_sponsor()
        resp = self._register(ca, sponsor_key, email)
        assert resp.svid_expires_at > datetime.now(timezone.utc)

    def test_registration_with_capabilities(self):
        ca, sponsor_key, email = _make_ca_with_sponsor()
        resp = self._register(ca, sponsor_key, email, caps=["read:data", "write:logs"])
        assert resp.status == "success"

    def test_registration_with_organization(self):
        ca, sponsor_key, email = _make_ca_with_sponsor()
        sig = _sign_registration(sponsor_key, "org-agent", email)
        request = RegistrationRequest(
            agent_name="org-agent",
            public_key=_make_agent_public_key(),
            sponsor_email=email,
            sponsor_signature=sig,
            organization="Contoso",
            organization_id="contoso-123",
        )
        resp = ca.register_agent(request)
        assert resp.status == "success"


# ---------------------------------------------------------------------------
# CA initialization tests
# ---------------------------------------------------------------------------


class TestCertificateAuthorityInit:
    """Tests for CA construction and self-signed cert."""

    def test_auto_generates_keypair(self):
        ca = CertificateAuthority()
        assert ca.ca_private_key is not None
        assert ca.ca_public_key is not None

    def test_auto_generates_self_signed_cert(self):
        ca = CertificateAuthority()
        cert = ca.ca_certificate
        # Self-signed: subject == issuer
        assert cert.subject == cert.issuer
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
        assert cn.value == "AgentMesh CA"

    def test_ca_cert_is_ca(self):
        ca = CertificateAuthority()
        bc = ca.ca_certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        )
        assert bc.value.ca is True

    def test_custom_keypair_accepted(self):
        key = ed25519.Ed25519PrivateKey.generate()
        ca = CertificateAuthority(ca_private_key=key)
        assert ca.ca_private_key is key

    def test_default_sponsor_registry_is_empty(self):
        ca = CertificateAuthority()
        assert not ca.sponsor_registry.is_registered("anyone@example.com")

    def test_issued_tokens_start_empty(self):
        ca = CertificateAuthority()
        assert len(ca._issued_refresh_tokens) == 0


# ---------------------------------------------------------------------------
# Token expiration edge cases
# ---------------------------------------------------------------------------


class TestRefreshTokenExpiration:
    """Edge cases for refresh token timing."""

    def _register_agent(self, ca, sponsor_key, email):
        sig = _sign_registration(sponsor_key, "test-agent", email)
        request = RegistrationRequest(
            agent_name="test-agent",
            public_key=_make_agent_public_key(),
            sponsor_email=email,
            sponsor_signature=sig,
        )
        return ca.register_agent(request)

    def test_expired_token_rejected(self):
        """Manually expire a token and verify it's rejected."""
        ca, sponsor_key, email = _make_ca_with_sponsor()
        reg = self._register_agent(ca, sponsor_key, email)

        # Find the token hash and force-expire it
        import hashlib
        token_hash = hashlib.sha256(reg.refresh_token.encode()).hexdigest()
        stored_did, _ = ca._issued_refresh_tokens[token_hash]
        ca._issued_refresh_tokens[token_hash] = (
            stored_did,
            datetime.now(timezone.utc) - timedelta(hours=1),
        )

        new_key = _make_agent_public_key()
        with pytest.raises(ValueError, match="Invalid or expired refresh token"):
            ca.rotate_credentials(reg.agent_did, reg.refresh_token, new_key)

    def test_multiple_agents_independent_tokens(self):
        """Each agent's tokens are independent."""
        ca, sponsor_key, email = _make_ca_with_sponsor()
        r1 = self._register_agent(ca, sponsor_key, email)
        r2 = self._register_agent(ca, sponsor_key, email)

        # Rotate agent 1's creds
        new_key = _make_agent_public_key()
        ca.rotate_credentials(r1.agent_did, r1.refresh_token, new_key)

        # Agent 2's token should still work
        new_key2 = _make_agent_public_key()
        rotated = ca.rotate_credentials(r2.agent_did, r2.refresh_token, new_key2)
        assert rotated.status == "success"
