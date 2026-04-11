# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Credential rotation for managed agents.

Provides automatic and manual credential rotation with configurable
TTLs, overlap periods, and revocation on decommission.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .models import (
    LifecycleEvent,
    LifecycleEventType,
)
from .manager import LifecycleManager


class CredentialRotator:
    """Manages credential rotation across the agent fleet.

    Scans for agents with expiring credentials and rotates them
    according to the lifecycle policy.
    """

    def __init__(self, manager: LifecycleManager) -> None:
        self._manager = manager

    def check_and_rotate(self) -> list[dict[str, str]]:
        """Check all active agents and rotate expiring credentials.

        Returns list of rotation results:
        [{"agent_id": "...", "action": "rotated|expired|ok", "detail": "..."}]
        """
        results: list[dict[str, str]] = []
        policy = self._manager.policy.credential_policy
        now = datetime.now(timezone.utc)

        for agent in self._manager.agents:
            if not agent.is_active:
                continue

            # No credential at all
            if not agent.credential_id:
                self._manager.rotate_credentials(agent.agent_id)
                results.append({
                    "agent_id": agent.agent_id,
                    "action": "issued",
                    "detail": "No credential found, issued new one",
                })
                continue

            # Already expired
            if agent.credential_expired:
                if policy.auto_rotate:
                    self._manager.rotate_credentials(agent.agent_id)
                    results.append({
                        "agent_id": agent.agent_id,
                        "action": "rotated",
                        "detail": "Credential expired, auto-rotated",
                    })
                else:
                    agent.record_event(LifecycleEvent(
                        event_type=LifecycleEventType.CREDENTIAL_EXPIRED,
                        agent_id=agent.agent_id,
                        details={"expired_at": str(agent.credential_expires_at)},
                    ))
                    results.append({
                        "agent_id": agent.agent_id,
                        "action": "expired",
                        "detail": "Credential expired, auto-rotate disabled",
                    })
                continue

            # Approaching expiry (within overlap window)
            if agent.credential_expires_at:
                time_remaining = agent.credential_expires_at - now
                if time_remaining <= policy.rotation_overlap and policy.auto_rotate:
                    self._manager.rotate_credentials(agent.agent_id)
                    results.append({
                        "agent_id": agent.agent_id,
                        "action": "rotated",
                        "detail": f"Pre-expiry rotation ({time_remaining} remaining)",
                    })
                    continue

            results.append({
                "agent_id": agent.agent_id,
                "action": "ok",
                "detail": "Credential valid",
            })

        return results

    def revoke_all(self, agent_id: str) -> None:
        """Revoke all credentials for an agent."""
        agent = self._manager.get(agent_id)
        if agent:
            agent.credential_id = None
            agent.credential_expires_at = None
            agent.credential_issued_at = None
