# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for mTLS identity verification."""

import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

from agentmesh.identity.agent_id import AgentIdentity, IdentityRegistry
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


@pytest.fixture()
def registry_with_agents():
    """Create a registry with two registered agents."""
    agent_a = AgentIdentity.create(
        name="agent-a",
        sponsor="a@example.com",
        capabilities=["read:data"],
        organization="TestOrg",
    )
    agent_b = AgentIdentity.create(
        name="agent-b",
        sponsor="b@example.com",
        capabilities=["write:data"],
        organization="TestOrg",
    )
    registry = IdentityRegistry()
    registry.register(agent_a)
    registry.register(agent_b)
    return agent_a, agent_b, registry


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

    def test_cert_uses_ed25519_key(self, verifier: MTLSIdentityVerifier):
        """Certificate must use the agent's Ed25519 key, not a throwaway key."""
        cert_pem, _ = verifier.create_self_signed_cert()
        cert = x509.load_pem_x509_certificate(cert_pem)
        pub_key = cert.public_key()
        assert isinstance(pub_key, ed25519.Ed25519PublicKey)

    def test_cert_key_matches_identity_key(self, verifier: MTLSIdentityVerifier):
        """Certificate public key must be the agent's Ed25519 identity key."""
        cert_pem, _ = verifier.create_self_signed_cert()
        cert = x509.load_pem_x509_certificate(cert_pem)
        cert_key_bytes = cert.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        import base64
        identity_key_bytes = base64.b64decode(verifier.identity.public_key)
        assert cert_key_bytes == identity_key_bytes

    def test_cert_self_signature_valid(self, verifier: MTLSIdentityVerifier):
        """Certificate self-signature must verify with the embedded key."""
        cert_pem, _ = verifier.create_self_signed_cert()
        cert = x509.load_pem_x509_certificate(cert_pem)
        pub_key = cert.public_key()
        # Should not raise
        pub_key.verify(cert.signature, cert.tbs_certificate_bytes)

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

    def test_raises_without_private_key(self):
        """Cannot create a cert if the identity has no private key."""
        agent = AgentIdentity.create(
            name="no-key-agent",
            sponsor="test@example.com",
        )
        agent._private_key = None
        v = MTLSIdentityVerifier(identity=agent)
        with pytest.raises(ValueError, match="no private key"):
            v.create_self_signed_cert()


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

    def test_verify_cert_from_different_agent_no_registry(self, verifier: MTLSIdentityVerifier):
        """Without a registry, a valid cert from another agent passes
        self-signature check (it's validly signed by its own key)."""
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

    def test_reject_ecdsa_cert(self, verifier: MTLSIdentityVerifier):
        """ECDSA certificates must be rejected (wrong key type)."""
        from datetime import timezone
        import datetime as dt

        ecdsa_key = ec.generate_private_key(ec.SECP256R1())
        now = dt.datetime.now(timezone.utc)
        from cryptography.hazmat.primitives import hashes
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "ecdsa-forger"),
                x509.NameAttribute(NameOID.SERIAL_NUMBER, str(verifier.identity.did)),
            ]))
            .issuer_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "ecdsa-forger"),
            ]))
            .public_key(ecdsa_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + dt.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.UniformResourceIdentifier(str(verifier.identity.did)),
                ]),
                critical=False,
            )
            .sign(ecdsa_key, hashes.SHA256())
        )
        pem = cert.public_bytes(serialization.Encoding.PEM)
        result = verifier.verify_peer_certificate(pem)
        assert result["valid"] is False

    def test_reject_forged_did_with_registry(self, registry_with_agents):
        """A cert claiming agent_a's DID but signed by a different key
        must be rejected when a registry is configured."""
        agent_a, agent_b, registry = registry_with_agents

        # Create verifier with registry
        verifier = MTLSIdentityVerifier(
            identity=agent_a, registry=registry,
        )

        # Agent B creates a cert with its own key (correctly self-signed)
        # but we forge it to claim agent_a's DID
        forger_key = ed25519.Ed25519PrivateKey.generate()
        from datetime import timezone
        import datetime as dt

        now = dt.datetime.now(timezone.utc)
        forged_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "agent-a"),
                x509.NameAttribute(NameOID.SERIAL_NUMBER, str(agent_a.did)),
            ]))
            .issuer_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "agent-a"),
            ]))
            .public_key(forger_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + dt.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.UniformResourceIdentifier(str(agent_a.did)),
                ]),
                critical=False,
            )
            .sign(forger_key, None)
        )
        forged_pem = forged_cert.public_bytes(serialization.Encoding.PEM)

        result = verifier.verify_peer_certificate(forged_pem)
        assert result["valid"] is False
        assert result["did"] == str(agent_a.did)

    def test_accept_valid_cert_with_registry(self, registry_with_agents):
        """A correctly signed cert with matching registry key must pass."""
        agent_a, _, registry = registry_with_agents

        verifier = MTLSIdentityVerifier(
            identity=agent_a, registry=registry,
        )

        cert_pem, _ = verifier.create_self_signed_cert()
        result = verifier.verify_peer_certificate(cert_pem)
        assert result["valid"] is True
        assert result["did"] == str(agent_a.did)

    def test_cross_agent_verification_with_registry(self, registry_with_agents):
        """Agent A verifying agent B's legitimate cert (both in registry)."""
        agent_a, agent_b, registry = registry_with_agents

        verifier_a = MTLSIdentityVerifier(
            identity=agent_a, registry=registry,
        )

        # Agent B creates its own cert
        verifier_b = MTLSIdentityVerifier(identity=agent_b)
        cert_pem_b, _ = verifier_b.create_self_signed_cert()

        # Agent A verifies agent B's cert against the registry
        result = verifier_a.verify_peer_certificate(cert_pem_b)
        assert result["valid"] is True
        assert result["did"] == str(agent_b.did)

    def test_reject_revoked_identity_with_registry(self, registry_with_agents):
        """A cert from a revoked agent must be rejected."""
        agent_a, agent_b, registry = registry_with_agents

        # Create cert before revocation
        verifier_b = MTLSIdentityVerifier(identity=agent_b)
        cert_pem_b, _ = verifier_b.create_self_signed_cert()

        # Revoke agent B
        registry.revoke(str(agent_b.did), "compromised")

        # Verify with registry
        verifier_a = MTLSIdentityVerifier(
            identity=agent_a, registry=registry,
        )
        result = verifier_a.verify_peer_certificate(cert_pem_b)
        assert result["valid"] is False

    def test_reject_unregistered_did_with_registry(self, registry_with_agents):
        """A cert from an agent not in the registry must be rejected."""
        agent_a, _, registry = registry_with_agents

        # Create an unregistered agent
        unknown = AgentIdentity.create(
            name="unknown-agent",
            sponsor="unknown@example.com",
        )
        unknown_v = MTLSIdentityVerifier(identity=unknown)
        cert_pem, _ = unknown_v.create_self_signed_cert()

        # Verify with registry
        verifier = MTLSIdentityVerifier(
            identity=agent_a, registry=registry,
        )
        result = verifier.verify_peer_certificate(cert_pem)
        assert result["valid"] is False


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
        key = ed25519.Ed25519PrivateKey.generate()
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
            .sign(key, None)
        )
        pem = cert.public_bytes(serialization.Encoding.PEM)
        did = verifier.extract_did_from_cert(pem)
        assert did is None
