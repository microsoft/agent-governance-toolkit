# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Plugin Registry

In-memory and file-based registry for discovering, searching, and managing
AgentMesh plugins. Supports semver-aware version matching.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from agent_marketplace.manifest import MarketplaceError, PluginManifest, PluginType

logger = logging.getLogger(__name__)


class PluginRegistry:
    """Registry for plugin manifests with search and version matching.

    Stores plugin metadata in memory with optional file-based persistence.

    Args:
        storage_path: Optional path to a JSON file for persistent storage.

    Example:
        >>> registry = PluginRegistry()
        >>> registry.register(manifest)
        >>> results = registry.search("governance")
    """

    def __init__(self, storage_path: Optional[Path] = None) -> None:
        self._plugins: dict[str, dict[str, PluginManifest]] = {}
        self._storage_path = storage_path
        if storage_path and storage_path.exists():
            self._load_from_file()

    # ------------------------------------------------------------------
    # CRUD operations
    # ------------------------------------------------------------------

    def register(self, manifest: PluginManifest) -> None:
        """Register a plugin manifest.

        Args:
            manifest: The manifest to register.

        Raises:
            MarketplaceError: If the exact name+version already exists.
        """
        versions = self._plugins.setdefault(manifest.name, {})
        if manifest.version in versions:
            raise MarketplaceError(
                f"Plugin {manifest.name}@{manifest.version} is already registered"
            )
        versions[manifest.version] = manifest
        logger.info("Registered plugin %s@%s", manifest.name, manifest.version)
        self._persist()

    def unregister(self, name: str, version: Optional[str] = None) -> None:
        """Remove a plugin from the registry.

        Args:
            name: Plugin name.
            version: Specific version to remove. If ``None``, removes all versions.

        Raises:
            MarketplaceError: If the plugin or version is not found.
        """
        if name not in self._plugins:
            raise MarketplaceError(f"Plugin not found: {name}")
        if version:
            if version not in self._plugins[name]:
                raise MarketplaceError(f"Version not found: {name}@{version}")
            del self._plugins[name][version]
            if not self._plugins[name]:
                del self._plugins[name]
        else:
            del self._plugins[name]
        logger.info("Unregistered plugin %s (version=%s)", name, version or "all")
        self._persist()

    def get_plugin(self, name: str, version: Optional[str] = None) -> PluginManifest:
        """Retrieve a specific plugin manifest.

        When *version* is ``None`` the latest version (highest semver) is returned.

        Args:
            name: Plugin name.
            version: Exact version string, or ``None`` for latest.

        Returns:
            The matching PluginManifest.

        Raises:
            MarketplaceError: If the plugin or version is not found.
        """
        if name not in self._plugins:
            raise MarketplaceError(f"Plugin not found: {name}")
        versions = self._plugins[name]
        if version:
            if version not in versions:
                raise MarketplaceError(f"Version not found: {name}@{version}")
            return versions[version]
        # Return latest by semver
        latest = max(versions.keys(), key=_semver_tuple)
        return versions[latest]

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def search(self, query: str) -> list[PluginManifest]:
        """Search plugins by name or description substring.

        Args:
            query: Case-insensitive search string.

        Returns:
            List of matching manifests (latest version of each).
        """
        query_lower = query.lower()
        results: list[PluginManifest] = []
        for versions in self._plugins.values():
            latest = max(versions.values(), key=lambda m: _semver_tuple(m.version))
            if query_lower in latest.name.lower() or query_lower in latest.description.lower():
                results.append(latest)
        return results

    def list_plugins(self, type_filter: Optional[PluginType] = None) -> list[PluginManifest]:
        """List all registered plugins (latest version of each).

        Args:
            type_filter: Optional filter by plugin type.

        Returns:
            List of manifests.
        """
        results: list[PluginManifest] = []
        for versions in self._plugins.values():
            latest = max(versions.values(), key=lambda m: _semver_tuple(m.version))
            if type_filter is None or latest.plugin_type == type_filter:
                results.append(latest)
        return results

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _persist(self) -> None:
        """Write current state to the storage file (if configured)."""
        if not self._storage_path:
            return
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        data: list[dict] = []  # type: ignore[type-arg]
        for versions in self._plugins.values():
            for manifest in versions.values():
                data.append(manifest.model_dump())
        with open(self._storage_path, "w") as f:
            json.dump(data, f, indent=2)
        logger.debug("Persisted %d plugin entries to %s", len(data), self._storage_path)

    def _load_from_file(self) -> None:
        """Restore registry state from the storage file."""
        if not self._storage_path or not self._storage_path.exists():
            return
        with open(self._storage_path) as f:
            data = json.load(f)
        for entry in data:
            manifest = PluginManifest(**entry)
            self._plugins.setdefault(manifest.name, {})[manifest.version] = manifest
        logger.debug("Loaded %d plugin entries from %s", len(data), self._storage_path)


def _semver_tuple(version: str) -> tuple[int, ...]:
    """Convert a version string to a comparable tuple."""
    return tuple(int(p) for p in version.split("."))
