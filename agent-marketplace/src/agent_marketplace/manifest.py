# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Plugin Manifest Schema

Defines the schema for AgentMesh plugin manifests (agent-plugin.yaml).
Supports plugin types: policy_template, integration, agent, validator.
"""

from __future__ import annotations

import enum
import logging
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field, field_validator

from agent_marketplace.exceptions import MarketplaceError

logger = logging.getLogger(__name__)

MANIFEST_FILENAME = "agent-plugin.yaml"


class PluginType(str, enum.Enum):
    """Supported plugin types."""

    POLICY_TEMPLATE = "policy_template"
    INTEGRATION = "integration"
    AGENT = "agent"
    VALIDATOR = "validator"


class PluginManifest(BaseModel):
    """Schema for an AgentMesh plugin manifest.

    Each plugin ships an ``agent-plugin.yaml`` describing its metadata,
    capabilities, dependencies, and cryptographic signature.

    Example:
        >>> manifest = PluginManifest(
        ...     name="my-plugin",
        ...     version="1.0.0",
        ...     description="Example plugin",
        ...     author="alice@example.com",
        ...     plugin_type=PluginType.INTEGRATION,
        ... )
    """

    name: str = Field(..., description="Unique plugin name (kebab-case)")
    version: str = Field(..., description="Semver version string")
    description: str = Field(..., description="Short human-readable description")
    author: str = Field(..., description="Author name or email")
    plugin_type: PluginType = Field(..., description="Type of plugin")
    capabilities: list[str] = Field(default_factory=list, description="Declared capabilities")
    dependencies: list[str] = Field(
        default_factory=list, description="Required plugins (name>=version)"
    )
    min_agentmesh_version: Optional[str] = Field(
        None, description="Minimum AgentMesh version required"
    )
    signature: Optional[str] = Field(None, description="Base64-encoded Ed25519 signature")
    organization: Optional[str] = Field(
        None,
        description="Owning organization (None = global/shared plugin)",
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Ensure name is non-empty and uses valid characters."""
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
        """Validate basic semver format (MAJOR.MINOR.PATCH)."""
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
        """Return the canonical bytes used for signing (excludes signature field)."""
        data = self.model_dump(exclude={"signature"})
        # Deterministic YAML serialization
        return yaml.dump(data, sort_keys=True).encode()


def load_manifest(path: Path) -> PluginManifest:
    """Load a plugin manifest from a YAML file.

    Args:
        path: Path to the manifest file or directory containing one.

    Returns:
        Parsed PluginManifest.

    Raises:
        MarketplaceError: If the file is missing or invalid.
    """
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
    """Save a plugin manifest to a YAML file.

    Args:
        manifest: The manifest to save.
        path: Directory or file path to write to.

    Returns:
        The path to the written file.
    """
    if path.is_dir():
        path = path / MANIFEST_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    data = manifest.model_dump(mode="json")
    with open(path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=True)
    logger.info("Saved manifest to %s", path)
    return path
