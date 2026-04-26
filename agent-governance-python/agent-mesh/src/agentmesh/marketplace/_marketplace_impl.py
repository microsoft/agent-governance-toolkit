# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Standalone plugin marketplace implementation.

This module provides a self-contained implementation that only requires
``pydantic``, ``pyyaml``, and ``cryptography`` — all of which are already
core dependencies of ``agentmesh``.  It is used as a fallback by
``agentmesh.marketplace`` when ``agent_marketplace`` is not installed.
"""

from __future__ import annotations

import base64
import enum
import json
import logging
import shutil
from pathlib import Path
from typing import Any, Optional

import yaml
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

MANIFEST_FILENAME = "agent-plugin.yaml"


class MarketplaceError(Exception):
    """Errors related to the plugin marketplace."""


class PluginType(str, enum.Enum):
    """Supported plugin types."""

    POLICY_TEMPLATE = "policy_template"
    INTEGRATION = "integration"
    AGENT = "agent"
    VALIDATOR = "validator"


class PluginManifest(BaseModel):
    """Schema for an AgentMesh plugin manifest."""

    name: str = Field(..., description="Unique plugin name (kebab-case)")
    version: str = Field(..., description="Semver version string")
    description: str = Field(..., description="Short human-readable description")
    author: str = Field(..., description="Author name or email")
    plugin_type: PluginType = Field(..., description="Type of plugin")
    capabilities: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    min_agentmesh_version: Optional[str] = Field(None)
    signature: Optional[str] = Field(None)

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v or not v.strip():
            raise MarketplaceError("Plugin name must not be empty")
        if not all(c.isalnum() or c in "-_" for c in v):
            raise MarketplaceError(
                "Plugin name must contain only alphanumeric characters, hyphens, or underscores"
            )
        return v

    @field_validator("version")
    @classmethod
    def validate_version(cls, v: str) -> str:
        parts = v.split(".")
        if len(parts) < 2 or len(parts) > 3:
            raise MarketplaceError(f"Invalid version format: {v} (expected MAJOR.MINOR[.PATCH])")
        for part in parts:
            if not part.isdigit():
                raise MarketplaceError(f"Invalid version component: {part}")
        return v

    @field_validator("author")
    @classmethod
    def validate_author(cls, v: str) -> str:
        if not v or not v.strip():
            raise MarketplaceError("Author must not be empty")
        return v

    def signable_bytes(self) -> bytes:
        data = self.model_dump(exclude={"signature"})
        return yaml.dump(data, sort_keys=True).encode()


def load_manifest(path: Path) -> PluginManifest:
    if path.is_dir():
        path = path / MANIFEST_FILENAME
    if not path.exists():
        raise MarketplaceError(f"Manifest not found: {path}")
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
        return PluginManifest(**data)
    except Exception as exc:
        raise MarketplaceError(f"Failed to load manifest: {exc}") from exc


def save_manifest(manifest: PluginManifest, path: Path) -> Path:
    if path.is_dir():
        path = path / MANIFEST_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    data = manifest.model_dump(mode="json")
    with open(path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=True)
    return path


class PluginSigner:
    """Sign and verify plugin manifests using Ed25519 keys."""

    def __init__(self, private_key: ed25519.Ed25519PrivateKey) -> None:
        self._private_key = private_key

    @property
    def public_key(self) -> ed25519.Ed25519PublicKey:
        return self._private_key.public_key()

    def sign(self, manifest: PluginManifest) -> PluginManifest:
        data = manifest.signable_bytes()
        sig = self._private_key.sign(data)
        return manifest.model_copy(update={"signature": base64.b64encode(sig).decode()})


def verify_signature(
    manifest: PluginManifest,
    public_key: ed25519.Ed25519PublicKey,
) -> bool:
    if not manifest.signature:
        raise MarketplaceError("Manifest has no signature")
    try:
        sig_bytes = base64.b64decode(manifest.signature)
        data = manifest.signable_bytes()
        public_key.verify(sig_bytes, data)
        return True
    except Exception as exc:
        raise MarketplaceError(f"Signature verification failed: {exc}") from exc


def _semver_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in version.split("."))


class PluginRegistry:
    """Registry for plugin manifests."""

    def __init__(self, storage_path: Optional[Path] = None) -> None:
        self._plugins: dict[str, dict[str, PluginManifest]] = {}
        self._storage_path = storage_path
        if storage_path and storage_path.exists():
            self._load_from_file()

    def register(self, manifest: PluginManifest) -> None:
        versions = self._plugins.setdefault(manifest.name, {})
        if manifest.version in versions:
            raise MarketplaceError(
                f"Plugin {manifest.name}@{manifest.version} is already registered"
            )
        versions[manifest.version] = manifest
        self._persist()

    def unregister(self, name: str, version: Optional[str] = None) -> None:
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
        self._persist()

    def get_plugin(self, name: str, version: Optional[str] = None) -> PluginManifest:
        if name not in self._plugins:
            raise MarketplaceError(f"Plugin not found: {name}")
        versions = self._plugins[name]
        if version:
            if version not in versions:
                raise MarketplaceError(f"Version not found: {name}@{version}")
            return versions[version]
        latest = max(versions.keys(), key=_semver_tuple)
        return versions[latest]

    def search(self, query: str) -> list[PluginManifest]:
        query_lower = query.lower()
        results: list[PluginManifest] = []
        for versions in self._plugins.values():
            latest = max(versions.values(), key=lambda m: _semver_tuple(m.version))
            if query_lower in latest.name.lower() or query_lower in latest.description.lower():
                results.append(latest)
        return results

    def list_plugins(self, type_filter: Optional[PluginType] = None) -> list[PluginManifest]:
        results: list[PluginManifest] = []
        for versions in self._plugins.values():
            latest = max(versions.values(), key=lambda m: _semver_tuple(m.version))
            if type_filter is None or latest.plugin_type == type_filter:
                results.append(latest)
        return results

    def _persist(self) -> None:
        if not self._storage_path:
            return
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        data: list[Any] = []
        for versions in self._plugins.values():
            for manifest in versions.values():
                data.append(manifest.model_dump())
        with open(self._storage_path, "w") as f:
            json.dump(data, f, indent=2)

    def _load_from_file(self) -> None:
        if not self._storage_path or not self._storage_path.exists():
            return
        with open(self._storage_path) as f:
            data = json.load(f)
        for entry in data:
            manifest = PluginManifest(**entry)
            self._plugins.setdefault(manifest.name, {})[manifest.version] = manifest


RESTRICTED_MODULES = frozenset({"subprocess", "os", "shutil", "ctypes", "importlib"})


class PluginInstaller:
    """Install, uninstall, and manage AgentMesh plugins."""

    def __init__(
        self,
        plugins_dir: Path,
        registry: PluginRegistry,
        trusted_keys: Optional[dict[str, Any]] = None,
    ) -> None:
        self._plugins_dir = plugins_dir
        self._registry = registry
        self._trusted_keys = trusted_keys or {}
        self._plugins_dir.mkdir(parents=True, exist_ok=True)

    def install(
        self,
        name: str,
        version: Optional[str] = None,
        *,
        verify: bool = True,
        _seen: Optional[set[str]] = None,
    ) -> Path:
        manifest = self._registry.get_plugin(name, version)
        # Signature verification — only when keys are configured and signature exists
        if verify and self._trusted_keys and manifest.signature:
            if manifest.author not in self._trusted_keys:
                raise MarketplaceError(
                    f"Plugin {name}@{manifest.version} signed by untrusted "
                    f"author '{manifest.author}'"
                )
            verify_signature(manifest, self._trusted_keys[manifest.author])
        if _seen is None:
            _seen = set()
        self._resolve_dependencies(manifest, _seen=_seen)
        dest = self._plugins_dir / name
        dest.mkdir(parents=True, exist_ok=True)
        manifest_file = dest / MANIFEST_FILENAME
        data = manifest.model_dump(mode="json")
        with open(manifest_file, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=True)
        return dest

    def uninstall(self, name: str) -> None:
        dest = self._plugins_dir / name
        if not dest.exists():
            raise MarketplaceError(f"Plugin not installed: {name}")
        shutil.rmtree(dest)

    def list_installed(self) -> list[PluginManifest]:
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

    def _resolve_dependencies(self, manifest: PluginManifest, *, _seen: set[str]) -> None:
        if manifest.name in _seen:
            raise MarketplaceError(f"Circular dependency detected: {manifest.name}")
        _seen.add(manifest.name)
        for dep_spec in manifest.dependencies:
            dep_name, dep_version = _parse_dependency(dep_spec)
            dest = self._plugins_dir / dep_name
            if dest.exists():
                continue
            self.install(dep_name, dep_version, verify=True, _seen=_seen)

    @staticmethod
    def check_sandbox(module_name: str) -> bool:
        top_level = module_name.split(".")[0]
        return top_level not in RESTRICTED_MODULES


def _parse_dependency(dep_spec: str) -> tuple[str, Optional[str]]:
    for op in (">=", "==", "<=", ">", "<"):
        if op in dep_spec:
            name, version = dep_spec.split(op, 1)
            return name.strip(), version.strip()
    return dep_spec.strip(), None


__all__ = [
    "MANIFEST_FILENAME",
    "MarketplaceError",
    "PluginInstaller",
    "PluginManifest",
    "PluginRegistry",
    "PluginSigner",
    "PluginType",
    "load_manifest",
    "save_manifest",
    "verify_signature",
]
