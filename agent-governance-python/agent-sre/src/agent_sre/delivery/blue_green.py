# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""Blue-green deployment strategy for AI agents.

Manages dual-environment deployments with deploy, validate, switch, and rollback
lifecycle. Supports health checks and rollback on validation failure.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from collections.abc import Callable


class Environment(Enum):
    """Deployment environment identifier."""

    BLUE = "blue"
    GREEN = "green"


class EnvironmentState(Enum):
    """Current state of a deployment environment."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    DEPLOYING = "deploying"
    VALIDATING = "validating"
    DRAINING = "draining"


class AgentEnvironment(BaseModel):
    """Represents a single deployment environment for an agent."""

    name: Environment
    state: EnvironmentState
    agent_version: str = ""
    deployed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    health_status: str = "unknown"  # healthy, unhealthy, unknown
    metadata: dict[str, Any] = Field(default_factory=dict)


class BlueGreenConfig(BaseModel):
    """Configuration for blue-green deployment behavior."""

    validation_timeout_seconds: int = 60
    drain_timeout_seconds: int = 30
    health_check_interval_seconds: int = 5
    auto_rollback_on_failure: bool = True


class BlueGreenEvent:
    """An event emitted during a blue-green deployment lifecycle."""

    def __init__(
        self,
        event_type: str,
        environment: Environment,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.event_type = event_type
        self.environment = environment
        self.timestamp: float = time.time()
        self.details: dict[str, Any] = details or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "environment": self.environment.value,
            "timestamp": self.timestamp,
            "details": self.details,
        }


class BlueGreenManager:
    """Manages blue-green deployments for AI agents.

    Maintains two environments (blue and green) and orchestrates the deploy →
    validate → switch lifecycle with automatic rollback on failure.
    """

    def __init__(self, config: BlueGreenConfig | None = None) -> None:
        self.config = config or BlueGreenConfig()
        self._blue = AgentEnvironment(name=Environment.BLUE, state=EnvironmentState.ACTIVE)
        self._green = AgentEnvironment(name=Environment.GREEN, state=EnvironmentState.INACTIVE)
        self._active_env: Environment = Environment.BLUE
        self._previous_active: Environment | None = None
        self.events: list[BlueGreenEvent] = []

    def _emit(
        self,
        event_type: str,
        environment: Environment,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.events.append(BlueGreenEvent(event_type, environment, details))

    def _env(self, name: Environment) -> AgentEnvironment:
        return self._blue if name == Environment.BLUE else self._green

    def _set_env(self, name: Environment, env: AgentEnvironment) -> None:
        if name == Environment.BLUE:
            self._blue = env
        else:
            self._green = env

    def get_active(self) -> AgentEnvironment:
        """Return the currently active environment."""
        return self._env(self._active_env)

    def get_inactive(self) -> AgentEnvironment:
        """Return the standby (inactive) environment."""
        inactive = (
            Environment.GREEN if self._active_env == Environment.BLUE else Environment.BLUE
        )
        return self._env(inactive)

    def deploy(self, version: str) -> AgentEnvironment:
        """Deploy a new agent version to the inactive environment.

        Args:
            version: The agent version string to deploy.

        Returns:
            The updated inactive environment in DEPLOYING state.

        Raises:
            RuntimeError: If the inactive environment is not in INACTIVE state.
        """
        inactive = self.get_inactive()
        if inactive.state not in (EnvironmentState.INACTIVE, EnvironmentState.ACTIVE):
            msg = (
                f"Cannot deploy to {inactive.name.value}: "
                f"environment is in {inactive.state.value} state"
            )
            raise RuntimeError(msg)

        updated = inactive.model_copy(
            update={
                "state": EnvironmentState.DEPLOYING,
                "agent_version": version,
                "deployed_at": datetime.now(timezone.utc),
                "health_status": "unknown",
            }
        )
        self._set_env(updated.name, updated)
        self._emit("deploy", updated.name, {"version": version})
        return updated

    def validate(self, health_check_fn: Callable[..., bool]) -> bool:
        """Run health check on the inactive environment.

        Args:
            health_check_fn: A callable that returns True if the environment is healthy.

        Returns:
            True if validation passed, False otherwise.
        """
        inactive = self.get_inactive()
        updated = inactive.model_copy(update={"state": EnvironmentState.VALIDATING})
        self._set_env(updated.name, updated)
        self._emit("validate_start", updated.name)

        is_healthy = False
        elapsed = 0.0
        interval = self.config.health_check_interval_seconds
        timeout = self.config.validation_timeout_seconds
        while True:
            try:
                if health_check_fn():
                    is_healthy = True
                    break
            except Exception:
                logger.debug("Health check failed for %s", inactive.name.value, exc_info=True)
            elapsed += interval
            if elapsed >= timeout:
                break
            time.sleep(interval)

        health = "healthy" if is_healthy else "unhealthy"
        updated = self._env(updated.name).model_copy(update={"health_status": health})

        if not is_healthy:
            updated = updated.model_copy(update={"state": EnvironmentState.INACTIVE})
            self._set_env(updated.name, updated)
            self._emit("validate_failed", updated.name, {"health_status": health})
            return False

        self._set_env(updated.name, updated)
        self._emit("validate_passed", updated.name, {"health_status": health})
        return True

    def switch(self) -> AgentEnvironment:
        """Switch traffic from the active to the inactive environment.

        The current active environment transitions to DRAINING, and the inactive
        environment becomes ACTIVE.

        Returns:
            The newly active environment.

        Raises:
            RuntimeError: If the inactive environment has not been validated as healthy.
        """
        inactive = self.get_inactive()
        if inactive.health_status != "healthy":
            msg = (
                f"Cannot switch to {inactive.name.value}: "
                f"health_status is {inactive.health_status}"
            )
            raise RuntimeError(msg)

        active = self.get_active()

        # Drain the current active
        draining = active.model_copy(update={"state": EnvironmentState.DRAINING})
        self._set_env(draining.name, draining)
        self._emit("drain_start", draining.name)

        # Activate the inactive
        new_active = inactive.model_copy(update={"state": EnvironmentState.ACTIVE})
        self._set_env(new_active.name, new_active)

        self._previous_active = self._active_env
        self._active_env = new_active.name

        # Wait for in-flight requests to complete
        logger.info(
            "Draining %s for %ds before deactivation",
            draining.name.value,
            self.config.drain_timeout_seconds,
        )
        time.sleep(self.config.drain_timeout_seconds)

        # Complete drain → inactive
        drained = self._env(draining.name).model_copy(
            update={"state": EnvironmentState.INACTIVE}
        )
        self._set_env(drained.name, drained)
        self._emit("switch", new_active.name, {"previous": drained.name.value})
        return new_active

    def rollback(self) -> AgentEnvironment:
        """Switch back to the previous active environment.

        Returns:
            The restored active environment.

        Raises:
            RuntimeError: If there is no previous environment to rollback to.
        """
        if self._previous_active is None:
            raise RuntimeError("No previous environment to rollback to")

        prev = self._env(self._previous_active)
        current = self.get_active()

        # Drain current
        draining = current.model_copy(update={"state": EnvironmentState.DRAINING})
        self._set_env(draining.name, draining)

        # Reactivate previous
        restored = prev.model_copy(update={"state": EnvironmentState.ACTIVE})
        self._set_env(restored.name, restored)

        self._active_env = restored.name
        self._previous_active = None

        # Complete drain
        drained = self._env(draining.name).model_copy(
            update={"state": EnvironmentState.INACTIVE}
        )
        self._set_env(drained.name, drained)
        self._emit("rollback", restored.name, {"rolled_back_from": draining.name.value})
        return restored

    def get_status(self) -> dict[str, Any]:
        """Return the status of both environments.

        Returns:
            Dictionary with blue, green, and active_environment keys.
        """
        return {
            "blue": self._blue.model_dump(),
            "green": self._green.model_dump(),
            "active_environment": self._active_env.value,
            "events_count": len(self.events),
        }
