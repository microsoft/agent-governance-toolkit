# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Provider-neutral attestation models for confidential agent identity."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Final

from pydantic import BaseModel, Field, field_validator, model_validator

REPORT_DATA_CONTEXT: Final[bytes] = b"agentmesh-attest-v1"
ED25519_PUBLIC_KEY_SIZE: Final[int] = 32
SHA256_DIGEST_SIZE: Final[int] = 32
SHA256_HEX_SIZE: Final[int] = 64
MAX_LENGTH_PREFIX_VALUE: Final[int] = 65535
DEFAULT_EVIDENCE_TTL_SECONDS: Final[int] = 300


class ConfidentialLevel(StrEnum):
    """Classification of an agent execution environment."""

    STANDARD = "standard"
    SECURE_BOOT = "secure_boot"
    TEE_VM = "tee_vm"
    TEE_CONTAINER = "tee_container"
    TEE_HARDWARE = "tee_hardware"


class KeyOrigin(StrEnum):
    """Origin of the agent signing key."""

    LOCAL = "local"
    SKR = "skr"
    TEE_GENERATED = "tee_generated"

    @property
    def is_tee_bound(self) -> bool:
        """Whether this key origin means private key material is TEE-bound."""
        return self in {KeyOrigin.SKR, KeyOrigin.TEE_GENERATED}


class ImageMatchPolicy(StrEnum):
    """How verifier reference values match measured agent images."""

    EXACT_HASH = "exact_hash"
    SIGNING_IDENTITY = "signing_identity"
    STABLE_CLAIMS = "stable_claims"


def public_key_hash_hex(public_key: bytes) -> str:
    """Return the SHA-256 hash of a raw Ed25519 public key as lowercase hex."""
    if len(public_key) != ED25519_PUBLIC_KEY_SIZE:
        raise ValueError("Ed25519 public keys must be exactly 32 bytes")
    return hashlib.sha256(public_key).hexdigest()


def compute_report_data_hash(
    agent_did: str,
    challenge_id: str,
    nonce: str,
    public_key_hash: bytes | str,
) -> bytes:
    """Compute ADR 0010 canonical report-data binding.

    The hash binds attestation evidence to the agent DID, handshake challenge,
    nonce, and Ed25519 public key hash. ``agent_did`` and ``challenge_id`` are
    UTF-8 strings with 2-byte big-endian length prefixes. ``nonce`` follows the
    existing AgentMesh handshake representation and is UTF-8 encoded without an
    additional length prefix. ``public_key_hash`` is the raw 32-byte SHA-256
    digest of the agent's Ed25519 public key.
    """
    public_key_hash_bytes = _digest_bytes(public_key_hash, field_name="public_key_hash")
    payload = b"".join(
        (
            REPORT_DATA_CONTEXT,
            _length_prefixed_utf8(agent_did, field_name="agent_did"),
            _length_prefixed_utf8(challenge_id, field_name="challenge_id"),
            _utf8_required(nonce, field_name="nonce"),
            public_key_hash_bytes,
        )
    )
    return hashlib.sha256(payload).digest()


def compute_report_data_hash_hex(
    agent_did: str,
    challenge_id: str,
    nonce: str,
    public_key_hash: bytes | str,
) -> str:
    """Compute ADR 0010 canonical report-data binding as lowercase hex."""
    return compute_report_data_hash(agent_did, challenge_id, nonce, public_key_hash).hex()


def matches_report_data_binding(
    report_data_hash: bytes | str,
    agent_did: str,
    challenge_id: str,
    nonce: str,
    public_key_hash: bytes | str,
) -> bool:
    """Return whether a report-data hash matches the expected ADR 0010 binding."""
    expected = compute_report_data_hash(
        agent_did=agent_did,
        challenge_id=challenge_id,
        nonce=nonce,
        public_key_hash=public_key_hash,
    )
    actual = _digest_bytes(report_data_hash, field_name="report_data_hash")
    return actual == expected


class AttestationEvidence(BaseModel):
    """Raw provider evidence bound to an agent identity and handshake challenge."""

    platform: str = Field(..., description="Attestation platform identifier")
    evidence: str = Field(..., description="Provider-specific evidence blob")
    agent_did: str = Field(..., description="Agent DID bound into report data")
    challenge_id: str = Field(..., description="Handshake challenge identifier")
    nonce: str = Field(..., description="Handshake nonce bound into report data")
    public_key_hash: str = Field(
        ...,
        description="Lowercase hex SHA-256 hash of the agent Ed25519 public key",
    )
    report_data_hash: str = Field(
        ...,
        description="Lowercase hex ADR 0010 canonical report-data hash",
    )
    key_origin: KeyOrigin = KeyOrigin.LOCAL
    runtime_measurements: dict[str, str] = Field(default_factory=dict)
    secure_boot_verified: bool = False
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC) + timedelta(seconds=DEFAULT_EVIDENCE_TTL_SECONDS)
    )

    @field_validator("platform", "evidence", "agent_did", "challenge_id", "nonce")
    @classmethod
    def _validate_required_text(cls, value: str, info: Any) -> str:
        if not value:
            raise ValueError(f"{info.field_name} must not be empty")
        return value

    @field_validator("public_key_hash", "report_data_hash")
    @classmethod
    def _validate_digest_hex(cls, value: str) -> str:
        return _digest_hex(value)

    @field_validator("timestamp", "expires_at")
    @classmethod
    def _normalize_datetime(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _validate_evidence_window_and_binding(self) -> AttestationEvidence:
        if self.expires_at <= self.timestamp:
            raise ValueError("expires_at must be later than timestamp")
        if not self.matches_binding(
            agent_did=self.agent_did,
            challenge_id=self.challenge_id,
            nonce=self.nonce,
            public_key_hash=self.public_key_hash,
        ):
            raise ValueError("report_data_hash does not match ADR 0010 binding")
        return self

    @property
    def key_bound_to_tee(self) -> bool:
        """Whether the evidence claims a TEE-bound key origin."""
        return self.key_origin.is_tee_bound

    def is_expired(self, now: datetime | None = None) -> bool:
        """Return whether this evidence is outside its freshness window."""
        current = _normalize_datetime(now or datetime.now(UTC))
        return current >= self.expires_at

    def matches_binding(
        self,
        agent_did: str,
        challenge_id: str,
        nonce: str,
        public_key_hash: bytes | str,
    ) -> bool:
        """Return whether this evidence matches the expected binding inputs."""
        return matches_report_data_binding(
            report_data_hash=self.report_data_hash,
            agent_did=agent_did,
            challenge_id=challenge_id,
            nonce=nonce,
            public_key_hash=public_key_hash,
        )


class AttestationClaims(BaseModel):
    """Structured claims extracted from verified attestation evidence."""

    platform: str
    confidential_level: ConfidentialLevel = ConfidentialLevel.STANDARD
    key_origin: KeyOrigin = KeyOrigin.LOCAL
    platform_verified: bool = False
    report_data_match: bool = False
    tcb_status: str = "unknown"
    runtime_measurements: dict[str, str] = Field(default_factory=dict)
    verified_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None
    claims: dict[str, str] = Field(default_factory=dict)

    @field_validator("platform", "tcb_status")
    @classmethod
    def _validate_required_text(cls, value: str, info: Any) -> str:
        if not value:
            raise ValueError(f"{info.field_name} must not be empty")
        return value

    @field_validator("verified_at", "expires_at")
    @classmethod
    def _normalize_datetime(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return _normalize_datetime(value)

    @property
    def key_bound_to_tee(self) -> bool:
        """Whether verified claims indicate TEE-bound key material."""
        return self.key_origin.is_tee_bound

    def is_expired(self, now: datetime | None = None) -> bool:
        """Return whether these claims are outside their freshness window."""
        if self.expires_at is None:
            return False
        current = _normalize_datetime(now or datetime.now(UTC))
        return current >= self.expires_at


class ReferenceValues(BaseModel):
    """Expected measurements and claims for an accepted platform configuration."""

    required_platform: str | None = None
    expected_measurements: dict[str, str] = Field(default_factory=dict)
    required_claims: dict[str, str] = Field(default_factory=dict)
    allowed_tcb_statuses: list[str] = Field(default_factory=lambda: ["up_to_date"])
    require_debug_disabled: bool = True
    image_match_policy: ImageMatchPolicy = ImageMatchPolicy.EXACT_HASH
    allowed_image_signers: list[str] = Field(default_factory=list)


def _length_prefixed_utf8(value: str, *, field_name: str) -> bytes:
    encoded = _utf8_required(value, field_name=field_name)
    if len(encoded) > MAX_LENGTH_PREFIX_VALUE:
        raise ValueError(f"{field_name} must be at most {MAX_LENGTH_PREFIX_VALUE} bytes")
    return len(encoded).to_bytes(2, "big") + encoded


def _utf8_required(value: str, *, field_name: str) -> bytes:
    if not value:
        raise ValueError(f"{field_name} must not be empty")
    return value.encode("utf-8")


def _digest_hex(value: str) -> str:
    """Normalize a hex-encoded SHA-256 digest to lowercase and validate length."""
    normalized = value.lower()
    _digest_bytes(normalized, field_name="digest")
    return normalized


def _digest_bytes(value: bytes | str, *, field_name: str) -> bytes:
    """Validate and convert a SHA-256 digest from bytes or hex string.

    Accepts either raw 32-byte digest or 64-character lowercase hex string.
    Raises ValueError with the field name if validation fails.
    """
    if isinstance(value, bytes):
        if len(value) != SHA256_DIGEST_SIZE:
            raise ValueError(f"{field_name} must be exactly {SHA256_DIGEST_SIZE} bytes")
        return value
    if len(value) != SHA256_HEX_SIZE:
        raise ValueError(f"{field_name} must be exactly {SHA256_HEX_SIZE} hex characters")
    try:
        digest = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be lowercase hex") from exc
    if len(digest) != SHA256_DIGEST_SIZE:
        raise ValueError(f"{field_name} must encode exactly {SHA256_DIGEST_SIZE} bytes")
    return digest


def _normalize_datetime(value: datetime) -> datetime:
    """Ensure a datetime is timezone-aware and normalized to UTC.

    Naive datetimes are assumed to be UTC. Aware datetimes are converted.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
