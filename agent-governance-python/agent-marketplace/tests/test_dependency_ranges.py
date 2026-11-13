# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Dependency constraints must govern installation, including existing plugins."""

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_marketplace.installer import PluginInstaller
from agent_marketplace.manifest import MarketplaceError, PluginManifest, PluginType
from agent_marketplace.registry import PluginRegistry
from agent_marketplace.signing import PluginSigner


def installer_with_versions(tmp_path: Path, requirement: str) -> PluginInstaller:
    key = Ed25519PrivateKey.generate()
    signer = PluginSigner(key)
    registry = PluginRegistry()
    for name, version, dependencies in [
        ("dep", "1.0.0", []),
        ("dep", "1.5.0", []),
        ("dep", "3.0.0", []),
        ("app", "1.0.0", [requirement]),
    ]:
        registry.register(signer.sign(PluginManifest(
            name=name, version=version, author="test-author",
            description="Dependency test", plugin_type=PluginType.INTEGRATION,
            dependencies=dependencies,
        )))
    return PluginInstaller(tmp_path / "plugins", registry, {"test-author": key.public_key()})


@pytest.mark.parametrize(("requirement", "expected"), [
    ("dep>=1.0,<2.0", "1.5.0"),
    ("dep>=1.0,<2.0,!=1.5.0", "1.0.0"),
    ("dep~=1.0", "1.5.0"),
    ("dep==1.5.0", "1.5.0"),
    ("dep>=1.0,<4.0", "3.0.0"),
    ("dep", "3.0.0"),
])
def test_install_selects_highest_satisfying_version(tmp_path, requirement, expected):
    installer = installer_with_versions(tmp_path, requirement)
    installer.install("app")
    installed = {m.name: m.version for m in installer.list_installed()}
    assert installed == {"app": "1.0.0", "dep": expected}


def test_no_matching_version_fails_before_installing_dependency(tmp_path):
    installer = installer_with_versions(tmp_path, "dep>=4.0")
    with pytest.raises(MarketplaceError, match="satisf"):
        installer.install("app")
    assert installer.list_installed() == []
    assert not (tmp_path / "plugins" / "dep").exists()


def test_existing_incompatible_version_is_not_silently_accepted(tmp_path):
    installer = installer_with_versions(tmp_path, "dep>=1.0,<2.0")
    installer.install("dep", "3.0.0")
    with pytest.raises(MarketplaceError, match="satisf"):
        installer.install("app")
    assert {m.name: m.version for m in installer.list_installed()} == {"dep": "3.0.0"}


def test_existing_compatible_version_is_kept(tmp_path):
    installer = installer_with_versions(tmp_path, "dep>=1.0,<2.0")
    installer.install("dep", "1.0.0")
    installer.install("app")
    assert {m.name: m.version for m in installer.list_installed()} == {
        "app": "1.0.0", "dep": "1.0.0",
    }
