# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Marketplace — Plugin lifecycle management for the Agent Governance Toolkit.

Discover, install, verify, and manage plugins with Ed25519 signing
and semver-aware version resolution.
"""

from agent_marketplace.exceptions import MarketplaceError
from agent_marketplace.installer import PluginInstaller
from agent_marketplace.manifest import (
    MANIFEST_FILENAME,
    PluginManifest,
    PluginType,
    load_manifest,
    save_manifest,
)
from agent_marketplace.registry import PluginRegistry
from agent_marketplace.signing import PluginSigner, verify_signature

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
