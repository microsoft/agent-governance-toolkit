# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Registry for storing and retrieving tool specifications.

The registry is a lightweight lookup mechanism that stores tool specs
but does NOT execute them. Execution is the responsibility of the
Agent Runtime (Control Plane).
"""

from __future__ import annotations

import re
import warnings
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple

from .schema import CostLevel, SideEffect, ToolHandle, ToolSpec

if TYPE_CHECKING:
    pass


class RegistryError(Exception):
    """Base exception for registry errors."""

    pass


class ToolNotFoundError(RegistryError):
    """Raised when a tool is not found in the registry."""

    pass


class ToolAlreadyExistsError(RegistryError):
    """Raised when attempting to register a tool that already exists."""

    pass


class VersionConstraintError(RegistryError):
    """Raised when no tool version matches the constraint."""

    pass


def parse_version(version: str) -> Tuple[int, int, int]:
    """Parse a semantic version string into a tuple.

    Args:
        version: Version string (e.g., "1.2.3").

    Returns:
        Tuple of (major, minor, patch).
    """
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", version)
    if match:
        return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    return (0, 0, 0)


def version_matches(version: str, constraint: str) -> bool:
    """Check if a version matches a constraint.

    Supports constraints like:
    - "1.0.0" - exact match
    - ">=1.0.0" - greater than or equal
    - ">1.0.0" - greater than
    - "<=1.0.0" - less than or equal
    - "<1.0.0" - less than
    - "^1.0.0" - compatible with (same major version)
    - "~1.0.0" - approximately (same major.minor)
    - "*" - any version

    Args:
        version: The version to check.
        constraint: The version constraint.

    Returns:
        True if version matches constraint.
    """
    if constraint == "*" or constraint == "":
        return True

    v = parse_version(version)

    # Handle comparison operators
    if constraint.startswith(">="):
        c = parse_version(constraint[2:])
        return v >= c
    elif constraint.startswith("<="):
        c = parse_version(constraint[2:])
        return v <= c
    elif constraint.startswith(">"):
        c = parse_version(constraint[1:])
        return v > c
    elif constraint.startswith("<"):
        c = parse_version(constraint[1:])
        return v < c
    elif constraint.startswith("^"):
        # Caret: compatible with major version
        c = parse_version(constraint[1:])
        return v[0] == c[0] and v >= c
    elif constraint.startswith("~"):
        # Tilde: compatible with major.minor
        c = parse_version(constraint[1:])
        return v[0] == c[0] and v[1] == c[1] and v >= c
    else:
        # Exact match
        c = parse_version(constraint)
        return v == c


class Registry:
    """Lightweight tool registry using a local dictionary store.

    This registry stores tool specifications and their callables but does NOT
    execute them. It's purely a lookup and discovery mechanism.

    The actual execution is handled by the Agent Runtime (Control Plane).

    Supports versioning: multiple versions of the same tool can be registered.
    """

    def __init__(
        self,
        container: Optional[Any] = None,  # DependencyContainer
        metrics_collector: Optional[Any] = None,  # MetricsCollector
        access_manager: Optional[Any] = None,  # AccessControlManager
    ):
        """Initialize an empty registry.

        Args:
            container: Optional dependency container for injection.
            metrics_collector: Optional metrics collector.
            access_manager: Optional access control manager.
        """
        # Key: tool_name, Value: dict of version -> ToolSpec
        self._tools: Dict[str, Dict[str, ToolSpec]] = {}
        self._container = container
        self._metrics = metrics_collector
        self._access_manager = access_manager

    def register_tool(
        self, spec: ToolSpec, callable_func: Optional[Callable] = None, replace: bool = False
    ) -> None:
        """Register a tool in the registry.

        Args:
            spec: The tool specification
            callable_func: The actual callable function (stored but not executed)
            replace: Whether to replace if tool version already exists

        Raises:
            ToolAlreadyExistsError: If tool version exists and replace=False
        """
        tool_name = spec.metadata.name
        tool_version = spec.metadata.version

        # Initialize version dict if needed
        if tool_name not in self._tools:
            self._tools[tool_name] = {}

        if tool_version in self._tools[tool_name] and not replace:
            raise ToolAlreadyExistsError(
                f"Tool '{tool_name}' version '{tool_version}' already exists. "
                "Use replace=True to overwrite."
            )

        # Store the callable but NEVER execute it
        if callable_func is not None:
            spec._callable_func = callable_func

        self._tools[tool_name][tool_version] = spec

    def get_tool(
        self, name: str, version: Optional[str] = None, include_deprecated: bool = False
    ) -> ToolSpec:
        """Retrieve a tool specification by name and optional version constraint.

        Args:
            name: The tool name
            version: Version constraint (e.g., ">=1.0.0", "^1.0.0", "1.2.3")
                    If None, returns the latest version.
            include_deprecated: Whether to include deprecated versions

        Returns:
            The tool specification (includes the callable but doesn't execute it)

        Raises:
            ToolNotFoundError: If tool is not found
            VersionConstraintError: If no version matches constraint
        """
        if name not in self._tools:
            raise ToolNotFoundError(f"Tool '{name}' not found in registry")

        versions = self._tools[name]

        if not versions:
            raise ToolNotFoundError(f"Tool '{name}' has no registered versions")

        # Filter out deprecated if needed
        available = {
            v: spec
            for v, spec in versions.items()
            if include_deprecated or not spec.metadata.deprecated
        }

        if not available:
            raise ToolNotFoundError(
                f"Tool '{name}' has no non-deprecated versions. "
                "Use include_deprecated=True to access deprecated versions."
            )

        if version is None:
            # Return latest version
            latest_version = max(available.keys(), key=parse_version)
            return available[latest_version]

        # Find matching versions
        matching = [(v, spec) for v, spec in available.items() if version_matches(v, version)]

        if not matching:
            raise VersionConstraintError(
                f"No version of '{name}' matches constraint '{version}'. "
                f"Available versions: {list(available.keys())}"
            )

        # Return the highest matching version
        best_version = max(matching, key=lambda x: parse_version(x[0]))
        return best_version[1]

    def get_tool_handle(
        self, name: str, version: Optional[str] = None, include_deprecated: bool = False
    ) -> ToolHandle:
        """Get a ToolHandle for executing a tool with all policies applied.

        Args:
            name: The tool name
            version: Version constraint
            include_deprecated: Whether to include deprecated versions

        Returns:
            ToolHandle ready for execution
        """
        spec = self.get_tool(name, version, include_deprecated)

        # Warn if deprecated
        if spec.metadata.deprecated:
            msg = f"Tool '{name}' version '{spec.version}' is deprecated."
            if spec.metadata.deprecated_message:
                msg += f" {spec.metadata.deprecated_message}"
            warnings.warn(msg, DeprecationWarning, stacklevel=2)

        return ToolHandle(
            spec=spec,
            container=self._container,
            metrics_collector=self._metrics,
            access_manager=self._access_manager,
        )

    def get_all_versions(self, name: str) -> List[str]:
        """Get all registered versions of a tool.

        Args:
            name: The tool name

        Returns:
            List of version strings, sorted newest first

        Raises:
            ToolNotFoundError: If tool is not found
        """
        if name not in self._tools:
            raise ToolNotFoundError(f"Tool '{name}' not found in registry")

        versions = list(self._tools[name].keys())
        return sorted(versions, key=parse_version, reverse=True)

    def get_callable(self, name: str, version: Optional[str] = None) -> Callable:
        """Get the callable function for a tool.

        This returns the function object but does NOT execute it.
        The caller (Agent Runtime) is responsible for execution.

        Args:
            name: The tool name
            version: Optional version constraint

        Returns:
            The callable function object

        Raises:
            ToolNotFoundError: If tool is not found
            ValueError: If tool has no callable
        """
        tool = self.get_tool(name, version)

        if tool._callable_func is None:
            raise ValueError(f"Tool '{name}' has no callable function")

        return tool._callable_func

    def list_tools(
        self,
        tag: Optional[str] = None,
        cost: Optional[CostLevel] = None,
        side_effect: Optional[SideEffect] = None,
        include_all_versions: bool = False,
        include_deprecated: bool = False,
    ) -> List[ToolSpec]:
        """List all registered tools with optional filtering.

        Args:
            tag: Filter by tag
            cost: Filter by cost level
            side_effect: Filter by side effect
            include_all_versions: If True, return all versions. If False, only latest.
            include_deprecated: Whether to include deprecated tools

        Returns:
            List of matching tool specifications
        """
        tools: List[ToolSpec] = []

        for _name, versions in self._tools.items():
            if include_all_versions:
                specs = list(versions.values())
            else:
                # Get latest version
                if versions:
                    latest_version = max(versions.keys(), key=parse_version)
                    specs = [versions[latest_version]]
                else:
                    specs = []

            for spec in specs:
                # Filter deprecated
                if not include_deprecated and spec.metadata.deprecated:
                    continue

                # Apply filters
                if tag is not None and tag not in spec.metadata.tags:
                    continue
                if cost is not None and spec.metadata.cost != cost:
                    continue
                if side_effect is not None and side_effect not in spec.metadata.side_effects:
                    continue

                tools.append(spec)

        return tools

    def search_tools(self, query: str, include_all_versions: bool = False) -> List[ToolSpec]:
        """Search tools by name, description, or tags.

        Args:
            query: Search query string
            include_all_versions: Whether to search all versions

        Returns:
            List of matching tool specifications
        """
        query_lower = query.lower()
        results = []

        for _name, versions in self._tools.items():
            if include_all_versions:
                specs = list(versions.values())
            else:
                if versions:
                    latest_version = max(versions.keys(), key=parse_version)
                    specs = [versions[latest_version]]
                else:
                    specs = []

            for tool in specs:
                # Check name
                if query_lower in tool.metadata.name.lower():
                    results.append(tool)
                    continue

                # Check description
                if query_lower in tool.metadata.description.lower():
                    results.append(tool)
                    continue

                # Check tags
                if any(query_lower in tag.lower() for tag in tool.metadata.tags):
                    results.append(tool)
                    continue

        return results

    def unregister_tool(self, name: str, version: Optional[str] = None) -> None:
        """Remove a tool from the registry.

        Args:
            name: The tool name
            version: Specific version to remove, or None to remove all versions

        Raises:
            ToolNotFoundError: If tool is not found
        """
        if name not in self._tools:
            raise ToolNotFoundError(f"Tool '{name}' not found in registry")

        if version is None:
            # Remove all versions
            del self._tools[name]
        else:
            if version not in self._tools[name]:
                raise ToolNotFoundError(f"Tool '{name}' version '{version}' not found in registry")
            del self._tools[name][version]

            # Clean up if no versions left
            if not self._tools[name]:
                del self._tools[name]

    def deprecate_tool(self, name: str, version: str, message: Optional[str] = None) -> None:
        """Mark a tool version as deprecated.

        Args:
            name: Tool name
            version: Version to deprecate
            message: Optional deprecation message/migration guide

        Raises:
            ToolNotFoundError: If tool/version not found
        """
        if name not in self._tools or version not in self._tools[name]:
            raise ToolNotFoundError(f"Tool '{name}' version '{version}' not found")

        spec = self._tools[name][version]
        spec.metadata.deprecated = True
        spec.metadata.deprecated_message = message

    def clear(self) -> None:
        """Remove all tools from the registry."""
        self._tools.clear()

    def __len__(self) -> int:
        """Return the number of registered tools (unique names)."""
        return len(self._tools)

    def total_versions(self) -> int:
        """Return the total number of registered tool versions."""
        return sum(len(versions) for versions in self._tools.values())

    def __contains__(self, name: str) -> bool:
        """Check if a tool is registered."""
        return name in self._tools
