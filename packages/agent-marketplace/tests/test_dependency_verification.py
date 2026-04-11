# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for MSRC [112466] — dependency verification bypass.

Verifies that the ``verify`` flag is correctly propagated through
``_resolve_dependencies``, preventing unsigned dependencies from being
installed when the caller requests ``verify=True``.
"""

from __future__ import annotations

import functools
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from agent_marketplace.installer import PluginInstaller
from agent_marketplace.manifest import MarketplaceError, PluginManifest, PluginType
from agent_marketplace.registry import PluginRegistry
from agent_marketplace.signing import PluginSigner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_registry_and_keys():
    """Create a registry, signer, and trusted-keys dict for testing."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    signer = PluginSigner(private_key)
    trusted_keys = {"trusted-author": private_key.public_key()}
    registry = PluginRegistry()
    return registry, signer, trusted_keys


def _signed_manifest(signer, name, author="trusted-author", deps=None):
    """Create and sign a plugin manifest."""
    manifest = PluginManifest(
        name=name,
        version="1.0.0",
        author=author,
        description=f"Test plugin {name}",
        plugin_type=PluginType.INTEGRATION,
        dependencies=deps or [],
    )
    return signer.sign(manifest)


def _unsigned_manifest(name, author="attacker", deps=None):
    """Create an unsigned plugin manifest."""
    return PluginManifest(
        name=name,
        version="1.0.0",
        author=author,
        description=f"Unsigned plugin {name}",
        plugin_type=PluginType.INTEGRATION,
        dependencies=deps or [],
        signature=None,
    )


# ---------------------------------------------------------------------------
# MSRC PoC — unsigned dependency must be rejected when verify=True
# ---------------------------------------------------------------------------

class TestDependencyVerificationPropagation:
    """Reproduce the MSRC [112466] PoC and verify the fix."""

    def test_unsigned_dependency_rejected_when_verify_true(self, tmp_path):
        """verify=True on parent must propagate to dependencies."""
        registry, signer, trusted_keys = _make_registry_and_keys()

        # Register a signed parent that depends on an unsigned child
        unsigned_dep = _unsigned_manifest("evil-dep")
        registry.register(unsigned_dep)

        signed_parent = _signed_manifest(
            signer, "trusted-plugin", deps=["evil-dep>=1.0.0"]
        )
        registry.register(signed_parent)

        installer = PluginInstaller(tmp_path, registry, trusted_keys=trusted_keys)

        # Installing with verify=True must reject the unsigned dependency
        with pytest.raises(MarketplaceError, match="no signature"):
            installer.install("trusted-plugin", verify=True)

        # The unsigned dependency must NOT be on disk
        assert not (tmp_path / "evil-dep").exists()

    def test_unsigned_dependency_allowed_when_verify_false(self, tmp_path):
        """verify=False explicitly skips verification for all deps."""
        registry, signer, trusted_keys = _make_registry_and_keys()

        unsigned_dep = _unsigned_manifest("benign-dep")
        registry.register(unsigned_dep)

        signed_parent = _signed_manifest(
            signer, "trusted-plugin", deps=["benign-dep>=1.0.0"]
        )
        registry.register(signed_parent)

        installer = PluginInstaller(tmp_path, registry, trusted_keys=trusted_keys)

        # verify=False should allow unsigned deps
        installer.install("trusted-plugin", verify=False)
        assert (tmp_path / "benign-dep").exists()

    def test_verify_flag_trace_through_dependency_chain(self, tmp_path):
        """Trace that verify= is passed correctly at every level."""
        registry, signer, trusted_keys = _make_registry_and_keys()

        # Chain: parent → child → grandchild (all signed)
        grandchild = _signed_manifest(signer, "grandchild")
        registry.register(grandchild)

        child = _signed_manifest(
            signer, "child", deps=["grandchild>=1.0.0"]
        )
        registry.register(child)

        parent = _signed_manifest(
            signer, "parent", deps=["child>=1.0.0"]
        )
        registry.register(parent)

        installer = PluginInstaller(tmp_path, registry, trusted_keys=trusted_keys)

        # Trace the verify flag at each install call
        trace = []
        original_install = PluginInstaller.install

        @functools.wraps(original_install)
        def traced_install(self, name, version=None, *, verify=True, _seen=None):
            trace.append({"plugin": name, "verify": verify})
            return original_install(self, name, version, verify=verify, _seen=_seen)

        PluginInstaller.install = traced_install
        try:
            installer.install("parent", verify=True)
        finally:
            PluginInstaller.install = original_install

        # Every install call must have verify=True
        for entry in trace:
            assert entry["verify"] is True, (
                f"Plugin {entry['plugin']} installed with verify=False — "
                "verification flag not propagated"
            )

    def test_untrusted_author_dependency_rejected(self, tmp_path):
        """Dependency signed by untrusted author is rejected with verify=True."""
        registry, signer, trusted_keys = _make_registry_and_keys()

        # Create a second signer (untrusted) for the dependency
        untrusted_key = ed25519.Ed25519PrivateKey.generate()
        untrusted_signer = PluginSigner(untrusted_key)

        evil_dep = untrusted_signer.sign(PluginManifest(
            name="evil-dep",
            version="1.0.0",
            author="untrusted-author",
            description="Signed by untrusted author",
            plugin_type=PluginType.INTEGRATION,
            dependencies=[],
        ))
        registry.register(evil_dep)

        signed_parent = _signed_manifest(
            signer, "trusted-plugin", deps=["evil-dep>=1.0.0"]
        )
        registry.register(signed_parent)

        installer = PluginInstaller(tmp_path, registry, trusted_keys=trusted_keys)

        with pytest.raises(MarketplaceError, match="untrusted"):
            installer.install("trusted-plugin", verify=True)

        assert not (tmp_path / "evil-dep").exists()


class TestFailClosedVerification:
    """Verify install() fails closed when verify=True."""

    def test_unsigned_plugin_rejected(self, tmp_path):
        """A plugin with no signature is rejected when verify=True."""
        registry = PluginRegistry()
        registry.register(_unsigned_manifest("no-sig-plugin"))

        installer = PluginInstaller(
            tmp_path, registry, trusted_keys={"other": None}
        )

        with pytest.raises(MarketplaceError, match="no signature"):
            installer.install("no-sig-plugin", verify=True)

    def test_unknown_author_rejected(self, tmp_path):
        """A plugin signed by unknown author is rejected when verify=True."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        signer = PluginSigner(private_key)
        manifest = signer.sign(PluginManifest(
            name="mystery-plugin",
            version="1.0.0",
            author="unknown-author",
            description="Signed by unknown",
            plugin_type=PluginType.INTEGRATION,
            dependencies=[],
        ))

        registry = PluginRegistry()
        registry.register(manifest)

        installer = PluginInstaller(
            tmp_path, registry, trusted_keys={"trusted-author": private_key.public_key()}
        )

        with pytest.raises(MarketplaceError, match="untrusted"):
            installer.install("mystery-plugin", verify=True)
