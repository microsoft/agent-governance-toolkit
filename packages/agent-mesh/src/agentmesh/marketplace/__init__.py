# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Plugin Marketplace — backward-compatibility shim.

The marketplace has moved to the **agent-marketplace** package.
All symbols are re-exported here so existing ``from agentmesh.marketplace …``
imports continue to work.

.. deprecated::
    Import directly from ``agent_marketplace`` instead.
"""

# ruff: noqa: F401
from agent_marketplace import (  # noqa: F401 – re-export
    MANIFEST_FILENAME,
    MarketplaceError,
    PluginInstaller,
    PluginManifest,
    PluginRegistry,
    PluginSigner,
    PluginType,
    load_manifest,
    save_manifest,
    verify_signature,
)

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
