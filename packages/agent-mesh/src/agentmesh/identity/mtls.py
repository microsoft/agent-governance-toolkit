# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Mutual TLS Identity Verification

Provides mTLS support for agent-to-agent communication with X.509
certificates derived from Ed25519 agent identities. Agent DIDs are
embedded in certificate SANs for cryptographic identity binding.
"""

import ssl
import tempfile
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pydantic import BaseModel, Field

from agentmesh.identity.agent_id import AgentIdentity


class MTLSConfig(BaseModel):
    """Configuration for mutual TLS identity verification.

    Attributes:
        cert_path: Path to certificate PEM file, or None for ephemeral certs.
        key_path: Path to private key PEM file, or None for ephemeral keys.
        ca_cert_path: Path to CA certificate PEM file for peer verification.
        verify_peer: Whether to verify peer certificates.
        require_client_cert: Whether to require client certificates (server-side).
    """

    cert_path: Optional[str] = Field(None, description="Path to certificate PEM file")
    key_path: Optional[str] = Field(None, description="Path to private key PEM file")
    ca_cert_path: Optional[str] = Field(None, description="Path to CA certificate PEM file")
    verify_peer: bool = Field(default=True, description="Whether to verify peer certificates")
    require_client_cert: bool = Field(
        default=True, description="Whether to require client certificates"
    )


class MTLSIdentityVerifier:
    """Mutual TLS identity verifier using X.509 certificates.

    Creates self-signed certificates from Ed25519 agent identities and
    configures SSL contexts for mTLS communication. Agent DIDs are embedded
    in certificate Subject Alternative Names (SANs) as URI:did:mesh:xxx.
    """

    def __init__(
        self,
        identity: AgentIdentity,
        config: MTLSConfig | None = None,
    ) -> None:
        self.identity = identity
        self.config = config or MTLSConfig()

    def create_self_signed_cert(self) -> tuple[bytes, bytes]:
        """Generate a self-signed X.509 certificate from the agent identity.

        Uses an ECDSA P-256 signing key (X.509 requires a signing algorithm;
        the Ed25519 identity is bound via the certificate subject and SAN).

        Returns:
            Tuple of (cert_pem, key_pem) as bytes.
        """
        signing_key = ec.generate_private_key(ec.SECP256R1())

        did_str = str(self.identity.did)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.identity.name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.identity.organization or "AgentMesh"),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, did_str),
        ])

        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(signing_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.UniformResourceIdentifier(did_str),
                ]),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .sign(signing_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = signing_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return cert_pem, key_pem

    def create_ssl_context(self, server_side: bool = False) -> ssl.SSLContext:
        """Create a configured SSL context for mTLS.

        Args:
            server_side: If True, create a server-side context that requests
                client certificates. If False, create a client-side context.

        Returns:
            A configured ssl.SSLContext.
        """
        if server_side:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        if self.config.cert_path and self.config.key_path:
            ctx.load_cert_chain(self.config.cert_path, self.config.key_path)
        else:
            # Generate and load ephemeral self-signed cert
            cert_pem, key_pem = self.create_self_signed_cert()
            cert_file = key_file = None
            try:
                with tempfile.NamedTemporaryFile(
                    delete=False, suffix=".pem", mode="wb"
                ) as cf:
                    cf.write(cert_pem)
                    cert_file = cf.name
                with tempfile.NamedTemporaryFile(
                    delete=False, suffix=".pem", mode="wb"
                ) as kf:
                    kf.write(key_pem)
                    key_file = kf.name
                ctx.load_cert_chain(cert_file, key_file)
            finally:
                if cert_file:
                    os.unlink(cert_file)
                if key_file:
                    os.unlink(key_file)

        if self.config.ca_cert_path:
            ctx.load_verify_locations(self.config.ca_cert_path)

        if server_side and self.config.require_client_cert:
            ctx.verify_mode = ssl.CERT_REQUIRED
        elif server_side:
            ctx.verify_mode = ssl.CERT_OPTIONAL
        elif self.config.verify_peer:
            ctx.verify_mode = ssl.CERT_REQUIRED

        if not self.config.verify_peer and not server_side:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        return ctx

    def verify_peer_certificate(self, cert_pem: bytes) -> dict:
        """Extract and verify peer identity from a PEM-encoded certificate.

        Args:
            cert_pem: PEM-encoded X.509 certificate bytes.

        Returns:
            Dict with keys: did, public_key, valid, subject.

        Raises:
            ValueError: If cert_pem cannot be parsed.
        """
        try:
            cert = x509.load_pem_x509_certificate(cert_pem)
        except Exception as exc:
            raise ValueError(f"Invalid certificate: {exc}") from exc

        now = datetime.now(timezone.utc)
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        time_valid = not_before <= now <= not_after

        subject_parts = {
            attr.oid.dotted_string: attr.value for attr in cert.subject
        }
        cn = subject_parts.get(NameOID.COMMON_NAME.dotted_string, "")
        org = subject_parts.get(NameOID.ORGANIZATION_NAME.dotted_string, "")
        serial = subject_parts.get(NameOID.SERIAL_NUMBER.dotted_string, "")

        did = self.extract_did_from_cert(cert_pem)

        pub_key = cert.public_key()
        pub_key_pem = pub_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        valid = time_valid and did is not None

        return {
            "did": did,
            "public_key": pub_key_pem,
            "valid": valid,
            "subject": {"cn": cn, "org": org, "serial": serial},
        }

    def extract_did_from_cert(self, cert_pem: bytes) -> str | None:
        """Extract agent DID from certificate subject or SAN.

        Looks for a URI SAN matching ``did:mesh:*``, then falls back to
        the subject SERIAL_NUMBER attribute.

        Args:
            cert_pem: PEM-encoded X.509 certificate bytes.

        Returns:
            The DID string, or None if not found.
        """
        try:
            cert = x509.load_pem_x509_certificate(cert_pem)
        except Exception:
            return None

        # Check SAN URIs first
        try:
            san = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            for uri in san.value.get_values_for_type(
                x509.UniformResourceIdentifier
            ):
                if uri.startswith("did:mesh:"):
                    return uri
        except x509.ExtensionNotFound:
            pass

        # Fallback: subject SERIAL_NUMBER
        for attr in cert.subject:
            if attr.oid == NameOID.SERIAL_NUMBER and str(attr.value).startswith(
                "did:mesh:"
            ):
                return str(attr.value)

        return None
