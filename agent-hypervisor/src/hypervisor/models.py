# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Core data models for the Agent Hypervisor."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum

from hypervisor.constants import (
    MAX_AGENT_ID_LENGTH,
    MAX_API_PATH_LENGTH,
    MAX_DURATION_LIMIT,
    MAX_NAME_LENGTH,
    MAX_PARTICIPANTS_LIMIT,
    MAX_UNDO_WINDOW,
    RING_1_TRUST_THRESHOLD,
    RING_2_TRUST_THRESHOLD,
    RISK_WEIGHT_FULL,
    RISK_WEIGHT_NONE,
    RISK_WEIGHT_PARTIAL,
    SESSION_DEFAULT_MIN_EFF_SCORE,
)

# Agent ID: DID format (did:method:id) or simple alphanumeric identifiers.
# Restrict to safe characters — no @, no consecutive special chars.
_AGENT_ID_PATTERN = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9._:-]*[a-zA-Z0-9])?$")
# Aliases for backward compatibility
_MAX_AGENT_ID_LENGTH = MAX_AGENT_ID_LENGTH
_MAX_NAME_LENGTH = MAX_NAME_LENGTH
_MAX_API_PATH_LENGTH = MAX_API_PATH_LENGTH
_MAX_PARTICIPANTS_LIMIT = MAX_PARTICIPANTS_LIMIT
_MAX_DURATION_LIMIT = MAX_DURATION_LIMIT
_MAX_UNDO_WINDOW = MAX_UNDO_WINDOW


class ConsistencyMode(str, Enum):
    """Session consistency mode. Strong requires consensus; Eventual uses gossip."""

    STRONG = "strong"
    EVENTUAL = "eventual"


class ExecutionRing(int, Enum):
    """
    Hardware-inspired execution privilege rings.

    Ring 0 (Root): Hypervisor config & penalty — requires SRE Witness.
    Ring 1 (Privileged): Non-reversible actions — requires eff_score > 0.95 + consensus.
    Ring 2 (Standard): Reversible actions — requires eff_score > 0.60.
    Ring 3 (Sandbox): Read-only / research — default for unknown agents.
    """

    RING_0_ROOT = 0
    RING_1_PRIVILEGED = 1
    RING_2_STANDARD = 2
    RING_3_SANDBOX = 3

    @classmethod
    def from_eff_score(cls, eff_score: float, has_consensus: bool = False) -> ExecutionRing:
        """Derive ring level from effective reputation score."""
        if eff_score > RING_1_TRUST_THRESHOLD and has_consensus:
            return cls.RING_1_PRIVILEGED
        elif eff_score > RING_2_TRUST_THRESHOLD:
            return cls.RING_2_STANDARD
        else:
            return cls.RING_3_SANDBOX


class ReversibilityLevel(str, Enum):
    """How reversible an action is."""

    FULL = "full"
    PARTIAL = "partial"
    NONE = "none"

    @property
    def risk_weight_range(self) -> tuple[float, float]:
        """Return the (min, max) risk weight ω for this reversibility level."""
        if self == ReversibilityLevel.FULL:
            return RISK_WEIGHT_FULL
        elif self == ReversibilityLevel.PARTIAL:
            return RISK_WEIGHT_PARTIAL
        else:
            return RISK_WEIGHT_NONE

    @property
    def default_risk_weight(self) -> float:
        """Return the default ω for this level."""
        lo, hi = self.risk_weight_range
        return (lo + hi) / 2


class SessionState(str, Enum):
    """Lifecycle state of a Shared Session."""

    CREATED = "created"
    HANDSHAKING = "handshaking"
    ACTIVE = "active"
    TERMINATING = "terminating"
    ARCHIVED = "archived"


def _validate_identifier(value: str, field_name: str) -> None:
    """Validate an identifier string (agent DID, action ID, etc.)."""
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string, got {type(value).__name__}")
    if not value or not value.strip():
        raise ValueError(f"{field_name} must not be empty")
    if len(value) > _MAX_AGENT_ID_LENGTH:
        raise ValueError(
            f"{field_name} exceeds maximum length of {_MAX_AGENT_ID_LENGTH} characters"
        )
    if not _AGENT_ID_PATTERN.match(value):
        raise ValueError(
            f"{field_name} contains invalid characters: {value!r}. "
            f"Only alphanumeric, hyphens, underscores, colons, and dots are allowed."
        )


def _validate_api_path(value: str, field_name: str) -> None:
    """Validate an API path string."""
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string, got {type(value).__name__}")
    if not value or not value.strip():
        raise ValueError(f"{field_name} must not be empty")
    if len(value) > _MAX_API_PATH_LENGTH:
        raise ValueError(
            f"{field_name} exceeds maximum length of {_MAX_API_PATH_LENGTH} characters"
        )


@dataclass
class SessionConfig:
    """Configuration for a new Shared Session."""

    consistency_mode: ConsistencyMode = ConsistencyMode.EVENTUAL
    max_participants: int = 10
    max_duration_seconds: int = 3600
    min_eff_score: float = SESSION_DEFAULT_MIN_EFF_SCORE
    enable_audit: bool = True
    enable_blockchain_commitment: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.max_participants, int):
            raise TypeError(
                f"max_participants must be an integer, got {type(self.max_participants).__name__}"
            )
        if self.max_participants < 1:
            raise ValueError(
                f"max_participants must be at least 1, got {self.max_participants}"
            )
        if self.max_participants > _MAX_PARTICIPANTS_LIMIT:
            raise ValueError(
                f"max_participants must not exceed {_MAX_PARTICIPANTS_LIMIT}, "
                f"got {self.max_participants}"
            )
        if not isinstance(self.max_duration_seconds, int):
            raise TypeError(
                f"max_duration_seconds must be an integer, "
                f"got {type(self.max_duration_seconds).__name__}"
            )
        if self.max_duration_seconds < 1:
            raise ValueError(
                f"max_duration_seconds must be at least 1, got {self.max_duration_seconds}"
            )
        if self.max_duration_seconds > _MAX_DURATION_LIMIT:
            raise ValueError(
                f"max_duration_seconds must not exceed {_MAX_DURATION_LIMIT} (7 days), "
                f"got {self.max_duration_seconds}"
            )
        if not isinstance(self.min_eff_score, (int, float)):
            raise TypeError(
                f"min_eff_score must be a number, got {type(self.min_eff_score).__name__}"
            )
        if not (0.0 <= self.min_eff_score <= 1.0):
            raise ValueError(
                f"min_eff_score must be between 0.0 and 1.0, got {self.min_eff_score}"
            )


@dataclass
class SessionParticipant:
    """An agent participating in a session."""

    agent_did: str
    ring: ExecutionRing = ExecutionRing.RING_3_SANDBOX
    sigma_raw: float = 0.0
    eff_score: float = 0.0
    joined_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    is_active: bool = True

    def __post_init__(self) -> None:
        _validate_identifier(self.agent_did, "agent_did")
        if not isinstance(self.ring, ExecutionRing):
            try:
                self.ring = ExecutionRing(self.ring)
            except (ValueError, KeyError):
                raise ValueError(
                    f"ring must be a valid ExecutionRing (0-3), got {self.ring!r}"
                )
        if not isinstance(self.sigma_raw, (int, float)):
            raise TypeError(
                f"sigma_raw must be a number, got {type(self.sigma_raw).__name__}"
            )
        if not (0.0 <= self.sigma_raw <= 1.0):
            raise ValueError(
                f"sigma_raw must be between 0.0 and 1.0, got {self.sigma_raw}"
            )
        if not isinstance(self.eff_score, (int, float)):
            raise TypeError(
                f"eff_score must be a number, got {type(self.eff_score).__name__}"
            )
        if not (0.0 <= self.eff_score <= 1.0):
            raise ValueError(
                f"eff_score must be between 0.0 and 1.0, got {self.eff_score}"
            )


@dataclass
class ActionDescriptor:
    """Describes an action from an IATP Capability Manifest."""

    action_id: str
    name: str
    execute_api: str
    undo_api: str | None = None
    reversibility: ReversibilityLevel = ReversibilityLevel.NONE
    undo_window_seconds: int = 0
    compensation_method: str | None = None
    is_read_only: bool = False
    is_admin: bool = False

    def __post_init__(self) -> None:
        _validate_identifier(self.action_id, "action_id")
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("name must be a non-empty string")
        if len(self.name) > _MAX_NAME_LENGTH:
            raise ValueError(
                f"name exceeds maximum length of {_MAX_NAME_LENGTH} characters"
            )
        _validate_api_path(self.execute_api, "execute_api")
        if self.undo_api is not None:
            _validate_api_path(self.undo_api, "undo_api")
        if not isinstance(self.undo_window_seconds, int):
            raise TypeError(
                f"undo_window_seconds must be an integer, "
                f"got {type(self.undo_window_seconds).__name__}"
            )
        if self.undo_window_seconds < 0:
            raise ValueError(
                f"undo_window_seconds must not be negative, got {self.undo_window_seconds}"
            )
        if self.undo_window_seconds > _MAX_UNDO_WINDOW:
            raise ValueError(
                f"undo_window_seconds must not exceed {_MAX_UNDO_WINDOW} (24 hours), "
                f"got {self.undo_window_seconds}"
            )

    @property
    def risk_weight(self) -> float:
        """Compute ω from reversibility level."""
        return self.reversibility.default_risk_weight

    @property
    def required_ring(self) -> ExecutionRing:
        """Determine minimum ring required for this action."""
        if self.is_admin:
            return ExecutionRing.RING_0_ROOT
        elif self.reversibility == ReversibilityLevel.NONE and not self.is_read_only:
            return ExecutionRing.RING_1_PRIVILEGED
        elif self.is_read_only:
            return ExecutionRing.RING_3_SANDBOX
        else:
            return ExecutionRing.RING_2_STANDARD
