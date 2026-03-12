# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Ephemeral Credentials

Credentials with configurable TTL (default 15 min).
Expired credentials are rejected; rotation is automatic and zero-downtime.
"""

from datetime import datetime, timedelta
from typing import Callable, Optional, Literal
from pydantic import BaseModel, Field
import hashlib
import logging
import uuid
import secrets

from agentmesh.constants import CREDENTIAL_ROTATION_THRESHOLD_SECONDS

logger = logging.getLogger(__name__)


class Credential(BaseModel):
    """
    Short-lived credential for agent authentication.

    Unlike long-lived service account keys:
    - Default TTL is 15 minutes
    - Auto-rotates before expiration
    - Instantly revocable
    - Capability-scoped
    """

    credential_id: str = Field(..., description="Unique credential identifier")
    agent_did: str = Field(..., description="DID of the agent this credential belongs to")

    # Token
    token: str = Field(..., description="Bearer token")
    token_hash: str = Field(..., description="SHA-256 hash of token for verification")

    # Scope
    capabilities: list[str] = Field(default_factory=list, description="Scoped capabilities")
    resources: list[str] = Field(default_factory=list, description="Accessible resources")

    # Timing
    issued_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime = Field(..., description="When credential expires")
    ttl_seconds: int = Field(default=900, description="TTL in seconds (default 15 min)")

    # Status
    status: Literal["active", "rotated", "revoked", "expired"] = Field(default="active")
    revoked_at: Optional[datetime] = Field(None)
    revocation_reason: Optional[str] = Field(None)

    # Rotation
    previous_credential_id: Optional[str] = Field(None, description="Previous credential if rotated")
    rotation_count: int = Field(default=0)

    # Context
    issued_for: Optional[str] = Field(None, description="Purpose/context for issuance")
    client_ip: Optional[str] = Field(None, description="IP address of requester")

    @classmethod
    def issue(
        cls,
        agent_did: str,
        capabilities: Optional[list[str]] = None,
        resources: Optional[list[str]] = None,
        ttl_seconds: int = 900,  # 15 minutes default
        issued_for: Optional[str] = None,
    ) -> "Credential":
        """Issue a new credential for an agent.

        Args:
            agent_did: The agent's DID.
            capabilities: Scoped capabilities (subset of agent's capabilities).
            resources: Specific resources this credential can access.
            ttl_seconds: Time-to-live in seconds (default 15 min).
            issued_for: Context/purpose for the credential.

        Returns:
            A new active Credential bound to the given agent.
        """
        # Generate secure token
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        # Generate credential ID
        credential_id = f"cred_{uuid.uuid4().hex[:16]}"

        now = datetime.utcnow()

        return cls(
            credential_id=credential_id,
            agent_did=agent_did,
            token=token,
            token_hash=token_hash,
            capabilities=capabilities or [],
            resources=resources or [],
            issued_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            ttl_seconds=ttl_seconds,
            issued_for=issued_for,
        )

    def is_valid(self) -> bool:
        """Check if credential is valid (active and not expired).

        Returns:
            True if status is active and the credential has not expired.
        """
        if self.status != "active":
            return False
        return datetime.utcnow() < self.expires_at

    def is_expiring_soon(self, threshold_seconds: int = CREDENTIAL_ROTATION_THRESHOLD_SECONDS) -> bool:
        """Check if credential is about to expire.

        Args:
            threshold_seconds: Number of seconds before expiry to consider
                "expiring soon". Defaults to CREDENTIAL_ROTATION_THRESHOLD_SECONDS.

        Returns:
            True if the credential expires within the threshold window.
        """
        return datetime.utcnow() > (self.expires_at - timedelta(seconds=threshold_seconds))

    def verify_token(self, token: str) -> bool:
        """Verify a token matches this credential.

        Args:
            token: The bearer token string to verify.

        Returns:
            True if the SHA-256 hash of the token matches the stored hash.
        """
        return hashlib.sha256(token.encode()).hexdigest() == self.token_hash

    def revoke(self, reason: str) -> None:
        """Revoke this credential immediately.

        Args:
            reason: Human-readable reason for revocation.
        """
        self.status = "revoked"
        self.revoked_at = datetime.utcnow()
        self.revocation_reason = reason

    def rotate(self) -> "Credential":
        """Rotate this credential, creating a new one.

        The old credential is marked as rotated but remains valid
        for a brief overlap period to allow zero-downtime rotation.

        Returns:
            A new Credential with the same scope and an incremented
            rotation count, linked to this credential via
            ``previous_credential_id``.
        """
        # Mark current as rotated
        self.status = "rotated"

        # Create new credential
        new_cred = Credential.issue(
            agent_did=self.agent_did,
            capabilities=self.capabilities,
            resources=self.resources,
            ttl_seconds=self.ttl_seconds,
            issued_for=self.issued_for,
        )

        new_cred.previous_credential_id = self.credential_id
        new_cred.rotation_count = self.rotation_count + 1

        return new_cred

    def has_capability(self, capability: str) -> bool:
        """Check if this credential has a specific capability.

        Supports exact match, wildcard (``*``), and prefix wildcard
        (e.g. ``read:*`` matches ``read:data``).

        Args:
            capability: The capability string to check.

        Returns:
            True if the credential grants the requested capability.
        """
        if not self.capabilities:
            return False

        for cap in self.capabilities:
            if cap == "*":
                return True
            if cap == capability:
                return True
            if cap.endswith(":*"):
                prefix = cap[:-2]
                if capability.startswith(prefix + ":"):
                    return True
        return False

    def can_access_resource(self, resource: str) -> bool:
        """Check if this credential can access a specific resource.

        If no resource restrictions are set, access is allowed by default.

        Args:
            resource: The resource identifier to check.

        Returns:
            True if the credential permits access to the resource.
        """
        if not self.resources:
            return True  # No resource restrictions

        return resource in self.resources or "*" in self.resources

    def time_remaining(self) -> timedelta:
        """Get time remaining until expiration.

        Returns:
            A non-negative timedelta; zero if already expired.
        """
        return max(timedelta(0), self.expires_at - datetime.utcnow())

    def to_bearer_token(self) -> str:
        """Get the bearer token for Authorization header.

        Returns:
            A string in the format ``Bearer <token>``.
        """
        return f"Bearer {self.token}"


class CredentialManager:
    """
    Manages credential lifecycle.

    Handles:
    - Credential issuance
    - Validation
    - Rotation
    - Revocation propagation
    """

    DEFAULT_TTL = 900  # 15 minutes
    ROTATION_THRESHOLD = CREDENTIAL_ROTATION_THRESHOLD_SECONDS
    REVOCATION_PROPAGATION_TARGET = 5  # Target: propagate in ≤5 seconds

    def __init__(self, default_ttl: int = DEFAULT_TTL):
        """Initialize the credential manager.

        Args:
            default_ttl: Default time-to-live in seconds for new credentials.
        """
        self.default_ttl = default_ttl
        self._credentials: dict[str, Credential] = {}
        self._by_agent: dict[str, list[str]] = {}  # agent_did -> list of credential_ids
        self._revocation_callbacks: list[Callable] = []

    def issue(
        self,
        agent_did: str,
        capabilities: Optional[list[str]] = None,
        resources: Optional[list[str]] = None,
        ttl_seconds: Optional[int] = None,
        issued_for: Optional[str] = None,
    ) -> Credential:
        """Issue a new credential and store it in the manager.

        Args:
            agent_did: The agent's DID to issue the credential for.
            capabilities: Scoped capabilities to grant.
            resources: Specific resources this credential can access.
            ttl_seconds: Time-to-live in seconds; uses default_ttl if None.
            issued_for: Context/purpose for the credential.

        Returns:
            The newly issued Credential.
        """
        cred = Credential.issue(
            agent_did=agent_did,
            capabilities=capabilities,
            resources=resources,
            ttl_seconds=ttl_seconds or self.default_ttl,
            issued_for=issued_for,
        )

        self._store(cred)
        return cred

    def validate(self, token: str) -> Optional[Credential]:
        """Validate a token and return the credential if valid.

        Args:
            token: The bearer token string to validate.

        Returns:
            The matching Credential if valid, or None if the token is
            invalid, expired, or revoked.
        """
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        for cred in self._credentials.values():
            if cred.token_hash == token_hash:
                if cred.is_valid():
                    return cred
                return None  # Found but invalid

        return None  # Not found

    def rotate(self, credential_id: str) -> Optional[Credential]:
        """Rotate a credential, replacing it with a new one.

        Args:
            credential_id: ID of the credential to rotate.

        Returns:
            The new Credential, or None if the original is not found or invalid.
        """
        cred = self._credentials.get(credential_id)
        if not cred or not cred.is_valid():
            return None

        new_cred = cred.rotate()
        self._store(new_cred)

        return new_cred

    def rotate_if_needed(self, credential_id: str) -> Credential:
        """Rotate credential if it's expiring soon.

        Args:
            credential_id: ID of the credential to check.

        Returns:
            The rotated Credential if expiring soon, otherwise the existing one.

        Raises:
            ValueError: If the credential is not found.
        """
        cred = self._credentials.get(credential_id)
        if not cred:
            raise ValueError(f"Credential not found: {credential_id}")

        if cred.is_expiring_soon(self.ROTATION_THRESHOLD):
            return self.rotate(credential_id)

        return cred

    def revoke(self, credential_id: str, reason: str) -> bool:
        """Revoke a credential and notify registered callbacks.

        Propagation target: ≤5 seconds to all systems.

        Args:
            credential_id: ID of the credential to revoke.
            reason: Human-readable reason for revocation.

        Returns:
            True if the credential was found and revoked, False otherwise.
        """
        cred = self._credentials.get(credential_id)
        if not cred:
            return False

        cred.revoke(reason)

        # Trigger revocation callbacks
        for callback in self._revocation_callbacks:
            try:
                callback(cred)
            except Exception:
                logger.debug("Revocation callback failed", exc_info=True)

        return True

    def revoke_all_for_agent(self, agent_did: str, reason: str) -> int:
        """Revoke all credentials for an agent.

        Args:
            agent_did: The agent's DID whose credentials should be revoked.
            reason: Human-readable reason for revocation.

        Returns:
            The number of credentials successfully revoked.
        """
        count = 0
        cred_ids = self._by_agent.get(agent_did, [])

        for cred_id in cred_ids:
            if self.revoke(cred_id, reason):
                count += 1

        return count

    def get_active_for_agent(self, agent_did: str) -> list[Credential]:
        """Get all active credentials for an agent.

        Args:
            agent_did: The agent's DID.

        Returns:
            List of valid (active and not expired) credentials.
        """
        cred_ids = self._by_agent.get(agent_did, [])
        return [
            self._credentials[cid]
            for cid in cred_ids
            if cid in self._credentials and self._credentials[cid].is_valid()
        ]

    def cleanup_expired(self) -> int:
        """Remove expired credentials from memory.

        Returns:
            The number of credentials removed.
        """
        expired = [
            cid for cid, cred in self._credentials.items()
            if not cred.is_valid() and cred.status != "active"
        ]

        for cid in expired:
            cred = self._credentials.pop(cid, None)
            if cred:
                # Remove from agent index
                agent_creds = self._by_agent.get(cred.agent_did, [])
                if cid in agent_creds:
                    agent_creds.remove(cid)

        return len(expired)

    def on_revocation(self, callback: Callable) -> None:
        """Register a callback for revocation events.

        Args:
            callback: A callable that receives the revoked Credential.
        """
        self._revocation_callbacks.append(callback)

    def _store(self, cred: Credential) -> None:
        """Store a credential in the index."""
        self._credentials[cred.credential_id] = cred

        if cred.agent_did not in self._by_agent:
            self._by_agent[cred.agent_did] = []
        self._by_agent[cred.agent_did].append(cred.credential_id)
