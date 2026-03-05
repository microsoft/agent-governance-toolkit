# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Plugin Marketplace

Discover, install, verify, and manage AgentMesh plugins.
"""

from agentmesh.exceptions import MarketplaceError

from .installer import PluginInstaller
from .manifest import (
    MANIFEST_FILENAME,
    PluginManifest,
    PluginType,
    load_manifest,
    save_manifest,
)
from .registry import PluginRegistry
from .signing import PluginSigner, verify_signature

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
