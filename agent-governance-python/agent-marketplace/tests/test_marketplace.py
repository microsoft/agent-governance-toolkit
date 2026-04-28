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


class TestTrustedKeysImmutability:
    """Verify that PluginInstaller.trusted_keys is frozen at construction."""

    def test_trusted_keys_cannot_be_mutated(self, tmp_path):
        """Attempting to add a key after construction must raise TypeError."""
        from cryptography.hazmat.primitives.asymmetric import ed25519

        from agent_marketplace import PluginInstaller, PluginRegistry

        registry = PluginRegistry()
        installer = PluginInstaller(
            plugins_dir=tmp_path / "plugins",
            registry=registry,
            trusted_keys={"author": ed25519.Ed25519PrivateKey.generate().public_key()},
        )
        with pytest.raises(TypeError):
            installer._trusted_keys["evil"] = "injected"  # type: ignore[index]

    def test_original_dict_mutation_does_not_affect_installer(self, tmp_path):
        """Mutating the original dict after construction must not change installer state."""
        from cryptography.hazmat.primitives.asymmetric import ed25519

        from agent_marketplace import PluginInstaller, PluginRegistry

        registry = PluginRegistry()
        original = {"author": ed25519.Ed25519PrivateKey.generate().public_key()}
        installer = PluginInstaller(
            plugins_dir=tmp_path / "plugins",
            registry=registry,
            trusted_keys=original,
        )
        original["evil"] = "injected"
        assert "evil" not in installer._trusted_keys
