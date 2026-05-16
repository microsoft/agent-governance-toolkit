# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
External Policy Backend Protocol

Defines a unified interface for pluggable policy evaluators (OPA, Cedar, or
any custom backend). Backends register themselves with BackendRegistry for
discovery by name.

Usage:
    from agentmesh.governance.backend import (
        ExternalPolicyBackend,
        PolicyDecisionResult,
        BackendRegistry,
    )

    # Register a backend
    BackendRegistry.register(my_opa_evaluator)

    # Retrieve by name
    backend = BackendRegistry.get("opa")
    decision = backend.evaluate("export", {"agent": {"role": "analyst"}})
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@dataclass
class PolicyDecisionResult:
    """Unified result from any external policy backend.

    Attributes:
        allowed: Whether the policy permits the action.
        reason: Human-readable explanation of the decision.
        backend: Name of the backend that produced this decision.
        latency_ms: Evaluation latency in milliseconds.
        raw_response: Backend-specific response data for debugging.
    """

    allowed: bool
    reason: str = ""
    backend: str = ""
    latency_ms: float = 0.0
    raw_response: Any = field(default=None, repr=False)


@runtime_checkable
class ExternalPolicyBackend(Protocol):
    """Protocol for pluggable policy evaluators.

    Any class implementing these three members can be registered with
    BackendRegistry and used interchangeably by the governance layer.
    """

    @property
    def name(self) -> str:
        """Unique identifier for this backend (e.g., 'opa', 'cedar')."""
        ...

    def evaluate(self, action: str, context: dict[str, Any]) -> PolicyDecisionResult:
        """Evaluate a policy decision.

        Args:
            action: The action being requested (e.g., 'read', 'export', 'delete').
            context: Runtime context for evaluation. Typical keys include
                'agent', 'resource', 'environment', 'trust_score'.

        Returns:
            PolicyDecisionResult with the evaluation outcome.
        """
        ...

    def healthy(self) -> bool:
        """Check whether this backend is available and operational.

        Returns:
            True if the backend can accept evaluate() calls.
        """
        ...


class BackendRegistry:
    """Registry for discovering and retrieving policy backends by name.

    Backends are stored globally. Use register() to add backends and get()
    to retrieve them.
    """

    _backends: dict[str, ExternalPolicyBackend] = {}

    @classmethod
    def register(cls, backend: ExternalPolicyBackend) -> None:
        """Register a policy backend.

        Args:
            backend: An object implementing ExternalPolicyBackend.

        Raises:
            TypeError: If the backend does not satisfy the protocol.
        """
        if not isinstance(backend, ExternalPolicyBackend):
            raise TypeError(
                f"{type(backend).__name__} does not implement ExternalPolicyBackend"
            )
        cls._backends[backend.name] = backend
        logger.info("Registered policy backend: %s", backend.name)

    @classmethod
    def unregister(cls, name: str) -> None:
        """Remove a backend from the registry.

        Args:
            name: Backend identifier to remove.
        """
        cls._backends.pop(name, None)

    @classmethod
    def get(cls, name: str) -> ExternalPolicyBackend:
        """Retrieve a registered backend by name.

        Args:
            name: Backend identifier.

        Returns:
            The registered backend.

        Raises:
            KeyError: If no backend with that name is registered.
        """
        if name not in cls._backends:
            available = list(cls._backends.keys()) or ["(none)"]
            raise KeyError(
                f"No backend registered with name '{name}'. "
                f"Available: {', '.join(available)}"
            )
        return cls._backends[name]

    @classmethod
    def list_backends(cls) -> list[str]:
        """Return names of all registered backends."""
        return list(cls._backends.keys())

    @classmethod
    def clear(cls) -> None:
        """Remove all registered backends. Primarily for testing."""
        cls._backends.clear()
