# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Mutual TLS Identity Verification

Provides mTLS support for agent-to-agent communication with X.509
certificates derived from Ed25519 agent identities. Agent DIDs are
embedded in certificate SANs for cryptographic identity binding.

Certificates are signed with the agent's Ed25519 identity key (RFC 8410),
and peer verification includes self-signature validation and optional
registry-based key-to-DID cross-checking.
"""

from __future__ import annotations

import base64
import logging
import os
import ssl
import tempfile
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID
from dateutil.relativedelta import relativedelta
from pydantic import BaseModel, Field

from agentmesh.identity.agent_id import AgentIdentity

if TYPE_CHECKING:
    from agentmesh.identity.agent_id import IdentityRegistry

logger = logging.getLogger(__name__)


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
        registry: IdentityRegistry | None = None,
    ) -> None:
        self.identity = identity
        self.config = config or MTLSConfig()
        self.registry = registry

    def create_self_signed_cert(self) -> tuple[bytes, bytes]:
        """Generate a self-signed X.509 certificate from the agent identity.

        Uses the agent's Ed25519 identity key for certificate signing
        (RFC 8410), cryptographically binding the certificate to the
        agent's DID. The certificate's public key is the agent's Ed25519
        public key, and the self-signature proves possession of the
        corresponding private key.

        Returns:
            Tuple of (cert_pem, key_pem) as bytes.

        Raises:
            ValueError: If the agent identity has no private key.
        """
        private_key = self.identity._private_key
        if private_key is None:
            raise ValueError(
                "Agent identity has no private key available for certificate signing"
            )

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
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + relativedelta(years=1))
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
            .sign(private_key, None)  # Ed25519 uses no separate hash algorithm
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
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
            # Generate and load ephemeral self-signed cert. The cert and
            # private key live on disk only for the duration of
            # ``load_cert_chain``, but the previous NamedTemporaryFile
            # path used the process umask, which on default-configured
            # shared hosts left the *private key* world-readable while
            # OpenSSL parsed it. TemporaryDirectory is created with
            # 0o700 on POSIX and ACL'd to the current user on Windows,
            # so neither file is reachable by other local users.
            cert_pem, key_pem = self.create_self_signed_cert()
            with tempfile.TemporaryDirectory() as tmpdir:
                cert_file = os.path.join(tmpdir, "cert.pem")
                key_file = os.path.join(tmpdir, "key.pem")
                with open(cert_file, "wb") as cf:
                    cf.write(cert_pem)
                with open(key_file, "wb") as kf:
                    kf.write(key_pem)
                # Best-effort 0o600 on POSIX as defense in depth on top
                # of the restrictive directory permissions.
                for path in (cert_file, key_file):
                    try:
                        os.chmod(path, 0o600)
                    except (NotImplementedError, OSError):
                        pass
                ctx.load_cert_chain(cert_file, key_file)

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

        Verification checks (in order):
        1. Certificate is parseable as PEM X.509
        2. Certificate is within its validity period
        3. Certificate public key is Ed25519
        4. Certificate self-signature is valid (proves key possession)
        5. A ``did:mesh:*`` DID is present in SAN or subject
        6. If a registry is configured, the certificate's Ed25519 public
           key matches the registered key for the claimed DID

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

        sig_valid = self._verify_cert_signature(cert)

        key_bound = True
        if self.registry and did:
            key_bound = self._verify_key_binding(cert, did)

        valid = time_valid and did is not None and sig_valid and key_bound

        return {
            "did": did,
            "public_key": pub_key_pem,
            "valid": valid,
            "subject": {"cn": cn, "org": org, "serial": serial},
        }

    def _verify_cert_signature(self, cert: x509.Certificate) -> bool:
        """Verify the certificate's self-signature and Ed25519 key type.

        Returns False if the public key is not Ed25519 or if the
        self-signature does not verify.
        """
        pub_key = cert.public_key()
        if not isinstance(pub_key, ed25519.Ed25519PublicKey):
            logger.debug(
                "Certificate rejected: expected Ed25519 key, got %s",
                type(pub_key).__name__,
            )
            return False
        try:
            pub_key.verify(cert.signature, cert.tbs_certificate_bytes)
            return True
        except Exception:
            logger.debug("Certificate self-signature verification failed")
            return False

    def _verify_key_binding(self, cert: x509.Certificate, did: str) -> bool:
        """Cross-check the certificate's public key against the registry.

        Looks up the DID in the identity registry and verifies that the
        certificate's Ed25519 public key matches the registered key for
        that identity.
        """
        if not self.registry:
            return True

        peer_identity = self.registry.get(did)
        if peer_identity is None:
            logger.debug("Key binding failed: DID %s not in registry", did)
            return False

        if not peer_identity.is_active():
            logger.debug(
                "Key binding failed: DID %s has status '%s'",
                did,
                peer_identity.status,
            )
            return False

        try:
            registered_key_bytes = base64.b64decode(peer_identity.public_key)
            cert_key_bytes = cert.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            if cert_key_bytes != registered_key_bytes:
                logger.debug(
                    "Key binding failed: cert key does not match registered key for %s",
                    did,
                )
                return False
        except Exception:
            logger.debug("Key binding failed: unable to compare keys for %s", did)
            return False

        return True

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
