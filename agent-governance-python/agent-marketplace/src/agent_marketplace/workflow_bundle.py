# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Composable workflow bundles for the agent marketplace.

Bundles package related agents, skills, tools, and knowledge resources
into a single deployable unit with shared dependencies and governance.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ComponentType(str, Enum):
    """Type of component within a workflow bundle."""

    AGENT = "agent"
    SKILL = "skill"
    TOOL = "tool"
    KNOWLEDGE = "knowledge"


@dataclass
class BundleComponent:
    """A single component within a workflow bundle."""

    component_type: ComponentType
    name: str
    version: str
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowBundle:
    """A composable bundle of marketplace components."""

    name: str
    version: str
    description: str = ""
    components: list[BundleComponent] = field(default_factory=list)
    shared_dependencies: list[str] = field(default_factory=list)
    governance_policy: str = ""


class BundleValidationError(Exception):
    """Raised when a workflow bundle fails validation."""


class BundleRegistry:
    """Registry for managing workflow bundles."""

    def __init__(self) -> None:
        self._bundles: dict[str, WorkflowBundle] = {}

    def register(self, bundle: WorkflowBundle) -> None:
        """Register a workflow bundle.

        Raises ``BundleValidationError`` if validation fails.
        """
        errors = self.validate_bundle(bundle)
        if errors:
            raise BundleValidationError(
                f"Bundle '{bundle.name}' is invalid: {'; '.join(errors)}",
            )
        key = f"{bundle.name}@{bundle.version}"
        self._bundles[key] = bundle

    def get(self, name: str, version: str) -> WorkflowBundle | None:
        """Retrieve a bundle by name and version."""
        return self._bundles.get(f"{name}@{version}")

    def list_bundles(self) -> list[WorkflowBundle]:
        """Return all registered bundles."""
        return list(self._bundles.values())

    def validate_bundle(self, bundle: WorkflowBundle) -> list[str]:
        """Validate a bundle and return a list of error messages (empty = valid)."""
        errors: list[str] = []
        if not bundle.name:
            errors.append("Bundle name is required")
        if not bundle.version:
            errors.append("Bundle version is required")
        if not bundle.components:
            errors.append("Bundle must contain at least one component")
        seen_names: set[str] = set()
        for comp in bundle.components:
            if not comp.name:
                errors.append("Component name is required")
            if not comp.version:
                errors.append(f"Component '{comp.name}' is missing a version")
            if comp.name in seen_names:
                errors.append(f"Duplicate component name: '{comp.name}'")
            seen_names.add(comp.name)
        return errors

    def search(self, component_type: ComponentType | None = None) -> list[WorkflowBundle]:
        """Search bundles optionally filtered by component type."""
        if component_type is None:
            return self.list_bundles()
        return [
            b for b in self._bundles.values()
            if any(c.component_type == component_type for c in b.components)
        ]

    @property
    def count(self) -> int:
        """Return the number of registered bundles."""
        return len(self._bundles)