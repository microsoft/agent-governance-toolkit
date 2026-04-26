# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Event bus and analytics plane for AgentMesh."""

from .analytics import AnalyticsPlane, AnalyticsSnapshot
from .bus import (
    ALL_EVENT_TYPES,
    EVENT_AGENT_REGISTERED,
    EVENT_AGENT_REVOKED,
    EVENT_AUDIT_ENTRY,
    EVENT_AUTHORITY_RESOLVED,
    EVENT_HANDSHAKE_COMPLETED,
    EVENT_POLICY_EVALUATED,
    EVENT_POLICY_VIOLATED,
    EVENT_TRUST_FAILED,
    EVENT_TRUST_SCORE_CHANGED,
    EVENT_TRUST_VERIFIED,
    AsyncEventBus,
    Event,
    EventBus,
    EventHandler,
    InMemoryEventBus,
)

__all__ = [
    "Event",
    "EventBus",
    "EventHandler",
    "InMemoryEventBus",
    "AsyncEventBus",
    "AnalyticsPlane",
    "AnalyticsSnapshot",
    "EVENT_TRUST_VERIFIED",
    "EVENT_TRUST_FAILED",
    "EVENT_TRUST_SCORE_CHANGED",
    "EVENT_POLICY_EVALUATED",
    "EVENT_POLICY_VIOLATED",
    "EVENT_AUTHORITY_RESOLVED",
    "EVENT_AGENT_REGISTERED",
    "EVENT_AGENT_REVOKED",
    "EVENT_AUDIT_ENTRY",
    "EVENT_HANDSHAKE_COMPLETED",
    "ALL_EVENT_TYPES",
]
