# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Core Identity - Certificate Authority

The Certificate Authority (CA) issues SPIFFE/SVID certificates for agent identities.
This is the root of trust for the AgentMesh.

Features:
- Issues short-lived SVID certificates (15-min default TTL)
- Validates human sponsor signatures via Ed25519 verification
- Generates agent DIDs
- Handles credential rotation with token validation
"""

import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID
from pydantic import BaseModel, Field

from ...identity import AgentDID

logger = logging.getLogger(__name__)


class SponsorRegistry:
    """Registry of authorized sponsors and their Ed25519 public keys.

    Must be populated before agent registration so the CA can verify
    that the sponsor signature on each ``RegistrationRequest`` is
    authentic.
    """

    def __init__(self) -> None:
        self._sponsors: dict[str, ed25519.Ed25519PublicKey] = {}

    def register_sponsor(
        self, email: str, public_key: ed25519.Ed25519PublicKey
    ) -> None:
        self._sponsors[email] = public_key

    def remove_sponsor(self, email: str) -> None:
        self._sponsors.pop(email, None)

    def get_public_key(self, email: str) -> ed25519.Ed25519PublicKey | None:
        return self._sponsors.get(email)

    def is_registered(self, email: str) -> bool:
        return email in self._sponsors


class RegistrationRequest(BaseModel):
    """Registration request from an agent."""

    agent_name: str
    agent_description: str | None = None
    organization: str | None = None
    organization_id: str | None = None

    # Cryptographic identity
    public_key: bytes  # Ed25519 public key
    key_algorithm: str = "Ed25519"

    # Human sponsor
    sponsor_email: str
    sponsor_id: str | None = None
    sponsor_signature: bytes

    # Capabilities
    capabilities: list[str] = Field(default_factory=list)
    supported_protocols: list[str] = Field(default_factory=list)

    # Delegation
    parent_did: str | None = None
    parent_signature: bytes | None = None

    # Metadata
    metadata: dict[str, str] = Field(default_factory=dict)
    requested_at: datetime = Field(default_factory=datetime.utcnow)


class RegistrationResponse(BaseModel):
    """Registration response with issued credentials."""

    agent_did: str
    agent_name: str

    # SVID certificate
    svid_certificate: bytes  # DER-encoded X.509 certificate
    svid_key_id: str
    svid_expires_at: datetime

    # Trust score
    initial_trust_score: int = 500
    trust_dimensions: dict[str, int] = Field(default_factory=dict)

    # Tokens
    access_token: str
    refresh_token: str
    token_ttl_seconds: int = 900  # 15 minutes

    # Registry
    registry_endpoint: str = "https://registry.agentmesh.io"
    ca_certificate: str  # PEM-encoded CA cert

    # Status
    status: str = "success"
    registered_at: datetime = Field(default_factory=datetime.utcnow)
    next_rotation_at: datetime


class CertificateAuthority:
    """
    Certificate Authority for AgentMesh.

    Issues SPIFFE/SVID certificates for agent identities.
    Requires a ``SponsorRegistry`` to verify sponsor signatures.
    """

    def __init__(
        self,
        ca_private_key: ed25519.Ed25519PrivateKey | None = None,
        ca_certificate: x509.Certificate | None = None,
        default_ttl_minutes: int = 15,
        sponsor_registry: SponsorRegistry | None = None,
    ):
        """
        Initialize the Certificate Authority.

        Args:
            ca_private_key: CA's private key (generates new if None)
            ca_certificate: CA's certificate (self-signs if None)
            default_ttl_minutes: Default TTL for issued certificates
            sponsor_registry: Registry of authorized sponsors
        """
        self.default_ttl_minutes = default_ttl_minutes
        self.sponsor_registry = sponsor_registry or SponsorRegistry()

        # Track issued refresh tokens: {token_hash: (agent_did, expires_at)}
        self._issued_refresh_tokens: dict[str, tuple[str, datetime]] = {}

        if ca_private_key is None:
            ca_private_key = ed25519.Ed25519PrivateKey.generate()
        self.ca_private_key = ca_private_key
        self.ca_public_key = ca_private_key.public_key()

        if ca_certificate is None:
            ca_certificate = self._generate_ca_certificate()
        self.ca_certificate = ca_certificate

    def _generate_ca_certificate(self) -> x509.Certificate:
        """Generate a self-signed CA certificate."""
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AgentMesh"),
            x509.NameAttribute(NameOID.COMMON_NAME, "AgentMesh CA"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.ca_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))  # 10 years
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(self.ca_private_key, None)  # Ed25519 doesn't use a hash algorithm
        )

        return cert

    def _validate_sponsor_signature(
        self,
        request: RegistrationRequest,
    ) -> bool:
        """
        Validate the sponsor's Ed25519 signature.

        The sponsor signs over: agent_name + sponsor_email + capabilities
        (concatenated with ':' separator).

        Returns:
            True if the signature is valid, False otherwise.
        """
        sponsor_key = self.sponsor_registry.get_public_key(request.sponsor_email)
        if sponsor_key is None:
            logger.warning(
                "Sponsor %s is not registered in the sponsor registry",
                request.sponsor_email,
            )
            return False

        # Reconstruct the signed payload
        capabilities_str = ",".join(sorted(request.capabilities))
        payload = f"{request.agent_name}:{request.sponsor_email}:{capabilities_str}"

        try:
            sponsor_key.verify(request.sponsor_signature, payload.encode("utf-8"))
            return True
        except Exception:
            logger.warning(
                "Sponsor signature verification failed for %s (sponsor=%s)",
                request.agent_name,
                request.sponsor_email,
            )
            return False

    def _generate_access_token(self, agent_did: str) -> str:
        """Generate an access token for the agent."""
        token_id = secrets.token_urlsafe(32)
        token = f"agentmesh_access_{agent_did.split(':')[-1][:16]}_{token_id[:16]}"
        return token

    def _generate_refresh_token(self, agent_did: str) -> str:
        """Generate a refresh token for credential rotation and track it."""
        token_id = secrets.token_urlsafe(32)
        token = f"agentmesh_refresh_{agent_did.split(':')[-1][:16]}_{token_id[:16]}"

        # Store hash of token for later validation
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        expires_at = datetime.now(timezone.utc) + timedelta(
            minutes=self.default_ttl_minutes * 2
        )
        self._issued_refresh_tokens[token_hash] = (agent_did, expires_at)

        return token

    def _validate_refresh_token(self, agent_did: str, refresh_token: str) -> bool:
        """Validate a refresh token against issued tokens.

        Returns:
            True if the token is valid and bound to the given DID.
        """
        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        entry = self._issued_refresh_tokens.get(token_hash)
        if entry is None:
            logger.warning("Refresh token not found for %s", agent_did)
            return False

        stored_did, expires_at = entry
        if stored_did != agent_did:
            logger.warning(
                "Refresh token DID mismatch: expected %s, got %s",
                stored_did,
                agent_did,
            )
            return False

        if datetime.now(timezone.utc) > expires_at:
            # Clean up expired token
            del self._issued_refresh_tokens[token_hash]
            logger.warning("Refresh token expired for %s", agent_did)
            return False

        # Consume the token (one-time use)
        del self._issued_refresh_tokens[token_hash]
        return True

    def _issue_svid_certificate(
        self,
        agent_did: str,
        public_key: bytes,
        ttl_minutes: int | None = None,
    ) -> tuple[bytes, str, datetime]:
        """
        Issue a SPIFFE/SVID certificate for an agent.

        Returns:
            (certificate_der, key_id, expires_at)
        """
        ttl = ttl_minutes or self.default_ttl_minutes
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=ttl)

        # Generate key ID
        key_id = f"key_{hashlib.sha256(public_key).hexdigest()[:16]}"

        # Create subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, agent_did),
        ])

        # Reconstruct public key object
        public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(public_key)

        # Build certificate
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_certificate.subject)
            .public_key(public_key_obj)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(expires_at)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            # Add SPIFFE ID as SAN
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.UniformResourceIdentifier(f"spiffe://agentmesh.io/{agent_did}"),
                ]),
                critical=False,
            )
            .sign(self.ca_private_key, None)  # Ed25519 doesn't use a hash algorithm
        )

        # Serialize to DER
        cert_der = cert.public_bytes(serialization.Encoding.DER)

        return cert_der, key_id, expires_at

    def _calculate_initial_trust_score(self) -> tuple[int, dict[str, int]]:
        """
        Calculate initial trust score for a new agent.

        New agents start with a score of 500/1000 with balanced dimensions.
        """
        dimensions = {
            "policy_compliance": 80,      # No violations yet
            "resource_efficiency": 50,    # No history
            "output_quality": 50,         # No history
            "security_posture": 70,       # Basic security
            "collaboration_health": 50,   # No peer interactions
        }

        total = 500  # Standard starting score

        return total, dimensions

    def register_agent(self, request: RegistrationRequest) -> RegistrationResponse:
        """
        Register a new agent and issue credentials.

        Args:
            request: Registration request

        Returns:
            Registration response with credentials

        Raises:
            ValueError: If validation fails
        """
        # Validate sponsor signature
        if not self._validate_sponsor_signature(request):
            raise ValueError("Invalid sponsor signature")

        # Generate DID
        agent_did = AgentDID.generate(
            request.agent_name,
            org=request.organization,
        )

        # Issue SVID certificate
        svid_cert, svid_key_id, svid_expires_at = self._issue_svid_certificate(
            str(agent_did),
            request.public_key,
        )

        # Generate tokens
        access_token = self._generate_access_token(str(agent_did))
        refresh_token = self._generate_refresh_token(str(agent_did))

        # Calculate initial trust score
        trust_score, dimensions = self._calculate_initial_trust_score()

        # Get CA certificate in PEM format
        ca_cert_pem = self.ca_certificate.public_bytes(
            serialization.Encoding.PEM
        ).decode()

        # Build response
        response = RegistrationResponse(
            agent_did=str(agent_did),
            agent_name=request.agent_name,
            svid_certificate=svid_cert,
            svid_key_id=svid_key_id,
            svid_expires_at=svid_expires_at,
            initial_trust_score=trust_score,
            trust_dimensions=dimensions,
            access_token=access_token,
            refresh_token=refresh_token,
            token_ttl_seconds=self.default_ttl_minutes * 60,
            ca_certificate=ca_cert_pem,
            next_rotation_at=svid_expires_at,
        )

        return response

    def rotate_credentials(
        self,
        agent_did: str,
        refresh_token: str,
        new_public_key: bytes | None = None,
    ) -> RegistrationResponse:
        """
        Rotate credentials for an existing agent.

        Args:
            agent_did: Agent's DID
            refresh_token: Valid refresh token (must match an issued token)
            new_public_key: Optional new public key for key rotation

        Returns:
            New credentials

        Raises:
            ValueError: If refresh token is invalid or new public key is missing.
        """
        # Validate the refresh token against issued tokens
        if not self._validate_refresh_token(agent_did, refresh_token):
            raise ValueError(
                "Invalid or expired refresh token for credential rotation"
            )

        # If no new key provided, we can't issue a new cert
        # In production, we'd retrieve the existing public key
        if new_public_key is None:
            raise ValueError("New public key required for credential rotation")

        # Issue new certificate
        svid_cert, svid_key_id, svid_expires_at = self._issue_svid_certificate(
            agent_did,
            new_public_key,
        )

        # Generate new tokens
        access_token = self._generate_access_token(agent_did)
        new_refresh_token = self._generate_refresh_token(agent_did)

        # Get current trust score (would query from reward engine)
        trust_score, dimensions = self._calculate_initial_trust_score()

        # Get CA certificate
        ca_cert_pem = self.ca_certificate.public_bytes(
            serialization.Encoding.PEM
        ).decode()

        response = RegistrationResponse(
            agent_did=agent_did,
            agent_name="",  # Not needed for rotation
            svid_certificate=svid_cert,
            svid_key_id=svid_key_id,
            svid_expires_at=svid_expires_at,
            initial_trust_score=trust_score,
            trust_dimensions=dimensions,
            access_token=access_token,
            refresh_token=new_refresh_token,
            token_ttl_seconds=self.default_ttl_minutes * 60,
            ca_certificate=ca_cert_pem,
            next_rotation_at=svid_expires_at,
        )

        return response
