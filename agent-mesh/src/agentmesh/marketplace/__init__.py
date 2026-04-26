# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Plugin Marketplace — backward-compatibility shim.

Attempts to import the canonical implementation from the
``agent_marketplace`` package.  When ``agent_marketplace`` is not
installed the standalone fallback in
``agentmesh.marketplace._marketplace_impl`` is re-exported so that
``agentmesh`` continues to work without requiring the optional
marketplace package.

.. deprecated::
    Import directly from ``agent_marketplace`` instead.
"""

from __future__ import annotations

try:
    from agent_marketplace import (  # noqa: F401
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
except ImportError:
    from agentmesh.marketplace._marketplace_impl import (  # noqa: F401
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
    "PluginSandbox",
    "PluginSandboxError",
    "PluginSigner",
    "PluginType",
    "load_manifest",
    "save_manifest",
    "verify_signature",
]

from agentmesh.marketplace.sandbox import PluginSandbox, PluginSandboxError  # noqa: E402, F401
