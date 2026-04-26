# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Lifecycle data models.

Defines the states, policies, and events for managing agent lifecycles.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AgentLifecycleState(str, Enum):
    """States in the agent lifecycle."""

    PENDING_APPROVAL = "pending_approval"
    PROVISIONED = "provisioned"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ROTATING_CREDENTIALS = "rotating_credentials"
    DECOMMISSIONING = "decommissioning"
    DECOMMISSIONED = "decommissioned"
    ORPHANED = "orphaned"


class LifecycleEventType(str, Enum):
    """Types of lifecycle events for audit trail."""

    REQUESTED = "requested"
    APPROVED = "approved"
    REJECTED = "rejected"
    PROVISIONED = "provisioned"
    ACTIVATED = "activated"
    CREDENTIAL_ROTATED = "credential_rotated"
    CREDENTIAL_EXPIRED = "credential_expired"
    HEARTBEAT = "heartbeat"
    HEARTBEAT_MISSED = "heartbeat_missed"
    SUSPENDED = "suspended"
    RESUMED = "resumed"
    ORPHAN_DETECTED = "orphan_detected"
    DECOMMISSION_STARTED = "decommission_started"
    DECOMMISSIONED = "decommissioned"
    OWNER_CHANGED = "owner_changed"


class CredentialPolicy(BaseModel):
    """Policy governing credential lifecycle."""

    max_credential_ttl: timedelta = Field(
        default=timedelta(hours=24),
        description="Maximum time a credential is valid before rotation",
    )
    rotation_overlap: timedelta = Field(
        default=timedelta(minutes=5),
        description="Grace period where old and new credentials are both valid",
    )
    auto_rotate: bool = Field(
        default=True,
        description="Automatically rotate credentials before expiry",
    )
    revoke_on_decommission: bool = Field(
        default=True,
        description="Immediately revoke all credentials on decommission",
    )


class LifecyclePolicy(BaseModel):
    """Policy governing the agent lifecycle."""

    require_approval: bool = Field(
        default=True,
        description="Require human approval before provisioning",
    )
    require_owner: bool = Field(
        default=True,
        description="Every agent must have an assigned owner",
    )
    heartbeat_interval: timedelta = Field(
        default=timedelta(minutes=5),
        description="Expected interval between agent heartbeats",
    )
    orphan_threshold: timedelta = Field(
        default=timedelta(hours=24),
        description="Mark agent as orphaned after this period without heartbeat",
    )
    max_inactive_days: int = Field(
        default=90,
        description="Decommission agents inactive longer than this",
    )
    credential_policy: CredentialPolicy = Field(
        default_factory=CredentialPolicy,
    )


class LifecycleEvent(BaseModel):
    """An immutable audit event in the agent lifecycle."""

    event_type: LifecycleEventType
    agent_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    actor: str = Field(default="system", description="Who/what triggered this event")
    details: dict[str, Any] = Field(default_factory=dict)
    previous_state: AgentLifecycleState | None = None
    new_state: AgentLifecycleState | None = None


class ManagedAgent(BaseModel):
    """An agent under lifecycle management.

    Extends the AgentMesh identity concept with lifecycle metadata:
    ownership, state machine, credential tracking, and heartbeat monitoring.
    """

    agent_id: str = Field(description="Unique agent identifier (DID or UUID)")
    name: str
    owner: str = Field(description="Email or team responsible for this agent")
    purpose: str = Field(default="", description="Business justification for this agent")
    agent_type: str = Field(default="autonomous", description="Agent type/framework")

    # Lifecycle state
    state: AgentLifecycleState = Field(default=AgentLifecycleState.PENDING_APPROVAL)

    # Credential tracking
    credential_id: str | None = Field(default=None, description="Current credential identifier")
    credential_issued_at: datetime | None = None
    credential_expires_at: datetime | None = None

    # Heartbeat tracking
    last_heartbeat: datetime | None = None
    heartbeat_count: int = 0

    # Metadata
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    decommissioned_at: datetime | None = None
    tags: dict[str, str] = Field(default_factory=dict)

    # Audit trail
    events: list[LifecycleEvent] = Field(default_factory=list)

    def record_event(self, event: LifecycleEvent) -> None:
        """Record a lifecycle event and update state."""
        self.events.append(event)
        if event.new_state:
            self.state = event.new_state
        self.updated_at = event.timestamp

    @property
    def is_active(self) -> bool:
        return self.state in (
            AgentLifecycleState.ACTIVE,
            AgentLifecycleState.ROTATING_CREDENTIALS,
        )

    @property
    def credential_expired(self) -> bool:
        if not self.credential_expires_at:
            return True
        return datetime.now(timezone.utc) > self.credential_expires_at

    @property
    def days_since_heartbeat(self) -> float | None:
        if not self.last_heartbeat:
            return None
        delta = datetime.now(timezone.utc) - self.last_heartbeat
        return delta.total_seconds() / 86400
