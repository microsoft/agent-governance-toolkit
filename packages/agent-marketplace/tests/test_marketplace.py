# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Smoke tests for the agent-marketplace package."""

from __future__ import annotations

import pytest


def test_top_level_imports():
    """All public symbols are importable from the top-level package."""
    from agent_marketplace import (
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
    assert MarketplaceError is not None
    assert callable(load_manifest)
    assert callable(save_manifest)
    assert callable(verify_signature)


def test_marketplace_error_standalone():
    """MarketplaceError no longer requires agentmesh."""
    from agent_marketplace.exceptions import MarketplaceError

    err = MarketplaceError("test error")
    assert str(err) == "test error"
    assert isinstance(err, Exception)


def test_backward_compat_shim():
    """Importing from agentmesh.marketplace still works."""
    from agentmesh.marketplace import PluginManifest, PluginRegistry

    assert PluginManifest is not None
    assert PluginRegistry is not None


def test_plugin_type_enum():
    from agent_marketplace import PluginType

    assert hasattr(PluginType, "POLICY_TEMPLATE")
    assert hasattr(PluginType, "INTEGRATION")
    assert hasattr(PluginType, "AGENT")
    assert hasattr(PluginType, "VALIDATOR")
