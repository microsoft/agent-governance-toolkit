# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for mTLS identity verification."""

import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from agentmesh.identity.agent_id import AgentIdentity
from agentmesh.identity.mtls import MTLSConfig, MTLSIdentityVerifier


@pytest.fixture()
def agent() -> AgentIdentity:
    return AgentIdentity.create(
        name="mtls-test-agent",
        sponsor="test@example.com",
        capabilities=["read:data"],
        organization="TestOrg",
    )


@pytest.fixture()
def verifier(agent: AgentIdentity) -> MTLSIdentityVerifier:
    return MTLSIdentityVerifier(identity=agent)


class TestMTLSConfig:
    """Tests for MTLSConfig defaults and overrides."""

    def test_defaults(self):
        cfg = MTLSConfig()
        assert cfg.cert_path is None
        assert cfg.key_path is None
        assert cfg.ca_cert_path is None
        assert cfg.verify_peer is True
        assert cfg.require_client_cert is True

    def test_overrides(self):
        cfg = MTLSConfig(
            cert_path="/tmp/cert.pem",
            key_path="/tmp/key.pem",
            ca_cert_path="/tmp/ca.pem",
            verify_peer=False,
            require_client_cert=False,
        )
        assert cfg.cert_path == "/tmp/cert.pem"
        assert cfg.key_path == "/tmp/key.pem"
        assert cfg.ca_cert_path == "/tmp/ca.pem"
        assert cfg.verify_peer is False
        assert cfg.require_client_cert is False


class TestSelfSignedCert:
    """Tests for self-signed certificate generation."""

    def test_generates_valid_pem(self, verifier: MTLSIdentityVerifier):
        cert_pem, key_pem = verifier.create_self_signed_cert()
        assert cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")
        assert key_pem.startswith(b"-----BEGIN PRIVATE KEY-----")

    def test_cert_contains_agent_name(self, verifier: MTLSIdentityVerifier):
        cert_pem, _ = verifier.create_self_signed_cert()
        cert = x509.load_pem_x509_certificate(cert_pem)
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "mtls-test-agent"

    def test_cert_contains_organization(self, verifier: MTLSIdentityVerifier):
        cert_pem, _ = verifier.create_self_signed_cert()
        cert = x509.load_pem_x509_certificate(cert_pem)
        org = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        assert org == "TestOrg"

    def test_cert_embeds_did_in_san(self, verifier: MTLSIdentityVerifier):
        cert_pem, _ = verifier.create_self_signed_cert()
        cert = x509.load_pem_x509_certificate(cert_pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
        did_str = str(verifier.identity.did)
        assert did_str in uris

    def test_cert_embeds_did_in_serial_number(self, verifier: MTLSIdentityVerifier):
        cert_pem, _ = verifier.create_self_signed_cert()
        cert = x509.load_pem_x509_certificate(cert_pem)
        serial = cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value
        assert serial == str(verifier.identity.did)

    def test_default_org_when_none(self):
        agent = AgentIdentity.create(
            name="no-org-agent",
            sponsor="test@example.com",
        )
        v = MTLSIdentityVerifier(identity=agent)
        cert_pem, _ = v.create_self_signed_cert()
        cert = x509.load_pem_x509_certificate(cert_pem)
        org = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        assert org == "AgentMesh"


class TestSSLContext:
    """Tests for SSL context creation."""

    def test_server_side_context(self, verifier: MTLSIdentityVerifier):
        ctx = verifier.create_ssl_context(server_side=True)
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.verify_mode == ssl.CERT_REQUIRED

    def test_client_side_context(self, verifier: MTLSIdentityVerifier):
        ctx = verifier.create_ssl_context(server_side=False)
        assert isinstance(ctx, ssl.SSLContext)

    def test_server_optional_client_cert(self, agent: AgentIdentity):
        cfg = MTLSConfig(require_client_cert=False)
        v = MTLSIdentityVerifier(identity=agent, config=cfg)
        ctx = v.create_ssl_context(server_side=True)
        assert ctx.verify_mode == ssl.CERT_OPTIONAL

    def test_client_no_verify_peer(self, agent: AgentIdentity):
        cfg = MTLSConfig(verify_peer=False)
        v = MTLSIdentityVerifier(identity=agent, config=cfg)
        ctx = v.create_ssl_context(server_side=False)
        assert ctx.verify_mode == ssl.CERT_NONE


class TestPeerCertVerification:
    """Tests for peer certificate verification."""

    def test_verify_valid_cert(self, verifier: MTLSIdentityVerifier):
        cert_pem, _ = verifier.create_self_signed_cert()
        result = verifier.verify_peer_certificate(cert_pem)
        assert result["valid"] is True
        assert result["did"] == str(verifier.identity.did)
        assert result["subject"]["cn"] == "mtls-test-agent"
        assert result["subject"]["org"] == "TestOrg"
        assert "BEGIN PUBLIC KEY" in result["public_key"]

    def test_reject_invalid_cert(self, verifier: MTLSIdentityVerifier):
        with pytest.raises(ValueError, match="Invalid certificate"):
            verifier.verify_peer_certificate(b"not a certificate")

    def test_verify_cert_from_different_agent(self, verifier: MTLSIdentityVerifier):
        other = AgentIdentity.create(
            name="other-agent",
            sponsor="other@example.com",
        )
        other_v = MTLSIdentityVerifier(identity=other)
        cert_pem, _ = other_v.create_self_signed_cert()
        result = verifier.verify_peer_certificate(cert_pem)
        assert result["valid"] is True
        assert result["did"] == str(other.did)
        assert result["subject"]["cn"] == "other-agent"


class TestDIDExtraction:
    """Tests for DID extraction from certificate."""

    def test_extract_did_from_san(self, verifier: MTLSIdentityVerifier):
        cert_pem, _ = verifier.create_self_signed_cert()
        did = verifier.extract_did_from_cert(cert_pem)
        assert did == str(verifier.identity.did)
        assert did.startswith("did:mesh:")

    def test_extract_did_returns_none_for_invalid(self, verifier: MTLSIdentityVerifier):
        did = verifier.extract_did_from_cert(b"not a cert")
        assert did is None

    def test_extract_did_returns_none_for_cert_without_did(
        self, verifier: MTLSIdentityVerifier
    ):
        """A certificate with no DID in SAN or subject should return None."""
        key = ec.generate_private_key(ec.SECP256R1())
        from datetime import timezone
        import datetime as dt

        now = dt.datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "no-did")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "no-did")]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + dt.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        pem = cert.public_bytes(serialization.Encoding.PEM)
        did = verifier.extract_did_from_cert(pem)
        assert did is None
