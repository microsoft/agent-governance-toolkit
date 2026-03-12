# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Plugin Installer

Download, verify, install, and uninstall AgentMesh plugins with dependency
resolution and basic plugin sandboxing (restricted imports).
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Optional

from agent_marketplace.manifest import (
    MANIFEST_FILENAME,
    MarketplaceError,
    PluginManifest,
    load_manifest,
)
from agent_marketplace.registry import PluginRegistry
from agent_marketplace.signing import verify_signature

logger = logging.getLogger(__name__)

# Modules that plugins are NOT allowed to import
RESTRICTED_MODULES = frozenset(
    {
        "subprocess",
        "os",
        "shutil",
        "ctypes",
        "importlib",
    }
)


class PluginInstaller:
    """Install, uninstall, and manage AgentMesh plugins.

    Args:
        plugins_dir: Directory where plugins are installed.
        registry: Plugin registry to resolve names/versions.
        trusted_keys: Optional mapping of author → Ed25519 public key for
            signature verification.

    Example:
        >>> installer = PluginInstaller(Path("./plugins"), registry)
        >>> installer.install("my-plugin", "1.0.0")
    """

    def __init__(
        self,
        plugins_dir: Path,
        registry: PluginRegistry,
        trusted_keys: Optional[dict] = None,  # type: ignore[type-arg]
    ) -> None:
        self._plugins_dir = plugins_dir
        self._registry = registry
        self._trusted_keys = trusted_keys or {}
        self._plugins_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Install / Uninstall
    # ------------------------------------------------------------------

    def install(
        self,
        name: str,
        version: Optional[str] = None,
        *,
        verify: bool = True,
        _seen: Optional[set[str]] = None,
    ) -> Path:
        """Install a plugin from the registry.

        Steps:
            1. Resolve manifest from registry.
            2. Verify Ed25519 signature (if a trusted key is available).
            3. Resolve and install dependencies (recursively).
            4. Create plugin directory with manifest copy.

        Args:
            name: Plugin name.
            version: Desired version (``None`` for latest).
            verify: Whether to verify the signature.

        Returns:
            Path to the installed plugin directory.

        Raises:
            MarketplaceError: On resolution, verification, or dependency errors.
        """
        manifest = self._registry.get_plugin(name, version)

        # Signature verification
        if verify and manifest.signature and manifest.author in self._trusted_keys:
            public_key = self._trusted_keys[manifest.author]
            verify_signature(manifest, public_key)
            logger.info("Signature verified for %s@%s", name, manifest.version)

        # Dependency resolution
        if _seen is None:
            _seen = set()
        self._resolve_dependencies(manifest, _seen=_seen)

        # Install to plugins directory
        dest = self._plugins_dir / name
        dest.mkdir(parents=True, exist_ok=True)
        manifest_file = dest / MANIFEST_FILENAME
        import yaml

        data = manifest.model_dump(mode="json")
        with open(manifest_file, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=True)

        logger.info("Installed plugin %s@%s to %s", name, manifest.version, dest)
        return dest

    def uninstall(self, name: str) -> None:
        """Remove an installed plugin.

        Args:
            name: Plugin name.

        Raises:
            MarketplaceError: If the plugin is not installed.
        """
        dest = self._plugins_dir / name
        if not dest.exists():
            raise MarketplaceError(f"Plugin not installed: {name}")
        shutil.rmtree(dest)
        logger.info("Uninstalled plugin %s", name)

    def list_installed(self) -> list[PluginManifest]:
        """Return manifests for all installed plugins.

        Returns:
            List of installed plugin manifests.
        """
        results: list[PluginManifest] = []
        if not self._plugins_dir.exists():
            return results
        for child in sorted(self._plugins_dir.iterdir()):
            manifest_path = child / MANIFEST_FILENAME
            if manifest_path.exists():
                try:
                    results.append(load_manifest(manifest_path))
                except MarketplaceError:
                    logger.warning("Skipping invalid plugin at %s", child)
        return results

    # ------------------------------------------------------------------
    # Dependency resolution
    # ------------------------------------------------------------------

    def _resolve_dependencies(
        self,
        manifest: PluginManifest,
        *,
        _seen: set[str],
    ) -> None:
        """Recursively resolve and install plugin dependencies.

        Args:
            manifest: The manifest whose dependencies should be resolved.
            _seen: Set of already-visited plugin names (cycle detection).

        Raises:
            MarketplaceError: On circular dependencies or missing plugins.
        """
        if manifest.name in _seen:
            raise MarketplaceError(f"Circular dependency detected: {manifest.name}")
        _seen.add(manifest.name)

        for dep_spec in manifest.dependencies:
            dep_name, dep_version = _parse_dependency(dep_spec)
            dest = self._plugins_dir / dep_name
            if dest.exists():
                continue  # already installed
            self.install(dep_name, dep_version, verify=False, _seen=_seen)

    # ------------------------------------------------------------------
    # Sandboxing
    # ------------------------------------------------------------------

    @staticmethod
    def check_sandbox(module_name: str) -> bool:
        """Check whether a module import is allowed under sandboxing rules.

        Args:
            module_name: Fully-qualified module name.

        Returns:
            ``True`` if the import is allowed, ``False`` otherwise.
        """
        top_level = module_name.split(".")[0]
        return top_level not in RESTRICTED_MODULES


def _parse_dependency(dep_spec: str) -> tuple[str, Optional[str]]:
    """Parse a dependency specifier like ``plugin-name>=1.0.0``.

    Returns:
        Tuple of (name, version_or_none).
    """
    for op in (">=", "==", "<=", ">", "<"):
        if op in dep_spec:
            name, version = dep_spec.split(op, 1)
            return name.strip(), version.strip()
    return dep_spec.strip(), None

