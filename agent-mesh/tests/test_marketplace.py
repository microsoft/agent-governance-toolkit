# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for AgentMesh Plugin Marketplace."""

import json
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric import ed25519

from agentmesh.marketplace import (
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


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_manifest(**overrides) -> PluginManifest:  # type: ignore[no-untyped-def]
    defaults = {
        "name": "test-plugin",
        "version": "1.0.0",
        "description": "A test plugin",
        "author": "tester@example.com",
        "plugin_type": PluginType.INTEGRATION,
    }
    defaults.update(overrides)
    return PluginManifest(**defaults)


@pytest.fixture()
def manifest() -> PluginManifest:
    return _make_manifest()


@pytest.fixture()
def ed25519_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


# ---------------------------------------------------------------------------
# Manifest validation
# ---------------------------------------------------------------------------


class TestPluginManifest:
    """Tests for manifest validation and serialization."""

    def test_valid_manifest(self, manifest: PluginManifest) -> None:
        assert manifest.name == "test-plugin"
        assert manifest.plugin_type == PluginType.INTEGRATION

    def test_empty_name_rejected(self) -> None:
        with pytest.raises(MarketplaceError, match="must not be empty"):
            _make_manifest(name="")

    def test_invalid_name_characters(self) -> None:
        with pytest.raises(MarketplaceError, match="alphanumeric"):
            _make_manifest(name="bad name!")

    def test_invalid_version_format(self) -> None:
        with pytest.raises(MarketplaceError, match="Invalid version"):
            _make_manifest(version="not-a-version")

    def test_two_part_version_ok(self) -> None:
        m = _make_manifest(version="1.0")
        assert m.version == "1.0"

    def test_empty_author_rejected(self) -> None:
        with pytest.raises(MarketplaceError, match="Author must not be empty"):
            _make_manifest(author="")

    def test_plugin_types(self) -> None:
        for ptype in PluginType:
            m = _make_manifest(plugin_type=ptype)
            assert m.plugin_type == ptype

    def test_signable_bytes_deterministic(self, manifest: PluginManifest) -> None:
        assert manifest.signable_bytes() == manifest.signable_bytes()

    def test_signable_bytes_excludes_signature(self) -> None:
        m1 = _make_manifest()
        m2 = _make_manifest(signature="abc123")
        assert m1.signable_bytes() == m2.signable_bytes()


class TestManifestIO:
    """Tests for loading and saving manifests."""

    def test_save_and_load(self, tmp_path: Path, manifest: PluginManifest) -> None:
        path = save_manifest(manifest, tmp_path)
        loaded = load_manifest(path)
        assert loaded.name == manifest.name
        assert loaded.version == manifest.version

    def test_load_from_directory(self, tmp_path: Path, manifest: PluginManifest) -> None:
        save_manifest(manifest, tmp_path)
        loaded = load_manifest(tmp_path)
        assert loaded.name == manifest.name

    def test_load_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(MarketplaceError, match="not found"):
            load_manifest(tmp_path / "nonexistent.yaml")


# ---------------------------------------------------------------------------
# Registry CRUD
# ---------------------------------------------------------------------------


class TestPluginRegistry:
    """Tests for the plugin registry."""

    def test_register_and_get(self, manifest: PluginManifest) -> None:
        registry = PluginRegistry()
        registry.register(manifest)
        result = registry.get_plugin("test-plugin")
        assert result.version == "1.0.0"

    def test_duplicate_registration_rejected(self, manifest: PluginManifest) -> None:
        registry = PluginRegistry()
        registry.register(manifest)
        with pytest.raises(MarketplaceError, match="already registered"):
            registry.register(manifest)

    def test_unregister(self, manifest: PluginManifest) -> None:
        registry = PluginRegistry()
        registry.register(manifest)
        registry.unregister("test-plugin")
        with pytest.raises(MarketplaceError, match="not found"):
            registry.get_plugin("test-plugin")

    def test_unregister_specific_version(self) -> None:
        registry = PluginRegistry()
        registry.register(_make_manifest(version="1.0.0"))
        registry.register(_make_manifest(version="2.0.0"))
        registry.unregister("test-plugin", version="1.0.0")
        result = registry.get_plugin("test-plugin")
        assert result.version == "2.0.0"

    def test_unregister_nonexistent(self) -> None:
        registry = PluginRegistry()
        with pytest.raises(MarketplaceError, match="not found"):
            registry.unregister("ghost")

    def test_get_latest_version(self) -> None:
        registry = PluginRegistry()
        registry.register(_make_manifest(version="1.0.0"))
        registry.register(_make_manifest(version="2.3.1"))
        registry.register(_make_manifest(version="1.9.0"))
        result = registry.get_plugin("test-plugin")
        assert result.version == "2.3.1"

    def test_get_specific_version(self) -> None:
        registry = PluginRegistry()
        registry.register(_make_manifest(version="1.0.0"))
        registry.register(_make_manifest(version="2.0.0"))
        result = registry.get_plugin("test-plugin", version="1.0.0")
        assert result.version == "1.0.0"

    def test_get_nonexistent_version(self) -> None:
        registry = PluginRegistry()
        registry.register(_make_manifest(version="1.0.0"))
        with pytest.raises(MarketplaceError, match="Version not found"):
            registry.get_plugin("test-plugin", version="9.9.9")

    def test_search_by_name(self) -> None:
        registry = PluginRegistry()
        registry.register(_make_manifest(name="governance-check"))
        registry.register(_make_manifest(name="data-loader"))
        results = registry.search("governance")
        assert len(results) == 1
        assert results[0].name == "governance-check"

    def test_search_by_description(self) -> None:
        registry = PluginRegistry()
        registry.register(_make_manifest(description="Validates compliance rules"))
        results = registry.search("compliance")
        assert len(results) == 1

    def test_search_no_results(self) -> None:
        registry = PluginRegistry()
        registry.register(_make_manifest())
        assert registry.search("zzz-nonexistent") == []

    def test_list_plugins_no_filter(self) -> None:
        registry = PluginRegistry()
        registry.register(_make_manifest(name="a-plugin"))
        registry.register(_make_manifest(name="b-plugin"))
        assert len(registry.list_plugins()) == 2

    def test_list_plugins_type_filter(self) -> None:
        registry = PluginRegistry()
        registry.register(
            _make_manifest(name="policy-tpl", plugin_type=PluginType.POLICY_TEMPLATE)
        )
        registry.register(_make_manifest(name="int-plugin", plugin_type=PluginType.INTEGRATION))
        results = registry.list_plugins(type_filter=PluginType.POLICY_TEMPLATE)
        assert len(results) == 1
        assert results[0].name == "policy-tpl"

    def test_file_persistence(self, tmp_path: Path) -> None:
        storage = tmp_path / "registry.json"
        reg1 = PluginRegistry(storage_path=storage)
        reg1.register(_make_manifest())
        # New instance should restore state
        reg2 = PluginRegistry(storage_path=storage)
        assert reg2.get_plugin("test-plugin").version == "1.0.0"


# ---------------------------------------------------------------------------
# Signing & verification
# ---------------------------------------------------------------------------


class TestPluginSigning:
    """Tests for Ed25519 signing and verification."""

    def test_sign_and_verify(
        self,
        manifest: PluginManifest,
        ed25519_keypair: tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey],
    ) -> None:
        private_key, public_key = ed25519_keypair
        signer = PluginSigner(private_key)
        signed = signer.sign(manifest)
        assert signed.signature is not None
        assert verify_signature(signed, public_key) is True

    def test_tampered_manifest_fails(
        self,
        manifest: PluginManifest,
        ed25519_keypair: tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey],
    ) -> None:
        private_key, public_key = ed25519_keypair
        signer = PluginSigner(private_key)
        signed = signer.sign(manifest)
        # Tamper with the description
        tampered = signed.model_copy(update={"description": "hacked!"})
        with pytest.raises(MarketplaceError, match="verification failed"):
            verify_signature(tampered, public_key)

    def test_wrong_key_fails(
        self,
        manifest: PluginManifest,
        ed25519_keypair: tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey],
    ) -> None:
        private_key, _ = ed25519_keypair
        signer = PluginSigner(private_key)
        signed = signer.sign(manifest)
        wrong_key = ed25519.Ed25519PrivateKey.generate().public_key()
        with pytest.raises(MarketplaceError, match="verification failed"):
            verify_signature(signed, wrong_key)

    def test_missing_signature_raises(self, manifest: PluginManifest) -> None:
        public_key = ed25519.Ed25519PrivateKey.generate().public_key()
        with pytest.raises(MarketplaceError, match="no signature"):
            verify_signature(manifest, public_key)

    def test_signer_public_key(
        self,
        ed25519_keypair: tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey],
    ) -> None:
        private_key, public_key = ed25519_keypair
        signer = PluginSigner(private_key)
        # Public key bytes should match
        from cryptography.hazmat.primitives import serialization

        expected = public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        actual = signer.public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        assert expected == actual


# ---------------------------------------------------------------------------
# Installer
# ---------------------------------------------------------------------------


class TestPluginInstaller:
    """Tests for plugin installation, uninstallation, and sandboxing."""

    def test_install_and_list(self, tmp_path: Path, manifest: PluginManifest) -> None:
        registry = PluginRegistry()
        registry.register(manifest)
        installer = PluginInstaller(plugins_dir=tmp_path / "plugins", registry=registry)
        dest = installer.install("test-plugin")
        assert (dest / MANIFEST_FILENAME).exists()
        installed = installer.list_installed()
        assert len(installed) == 1
        assert installed[0].name == "test-plugin"

    def test_uninstall(self, tmp_path: Path, manifest: PluginManifest) -> None:
        registry = PluginRegistry()
        registry.register(manifest)
        installer = PluginInstaller(plugins_dir=tmp_path / "plugins", registry=registry)
        installer.install("test-plugin")
        installer.uninstall("test-plugin")
        assert installer.list_installed() == []

    def test_uninstall_nonexistent(self, tmp_path: Path) -> None:
        registry = PluginRegistry()
        installer = PluginInstaller(plugins_dir=tmp_path / "plugins", registry=registry)
        with pytest.raises(MarketplaceError, match="not installed"):
            installer.uninstall("ghost")

    def test_install_with_dependency(self, tmp_path: Path) -> None:
        registry = PluginRegistry()
        dep = _make_manifest(name="dep-plugin", version="1.0.0")
        main = _make_manifest(name="main-plugin", dependencies=["dep-plugin>=1.0.0"])
        registry.register(dep)
        registry.register(main)
        installer = PluginInstaller(plugins_dir=tmp_path / "plugins", registry=registry)
        installer.install("main-plugin")
        installed_names = [p.name for p in installer.list_installed()]
        assert "main-plugin" in installed_names
        assert "dep-plugin" in installed_names

    def test_circular_dependency_detected(self, tmp_path: Path) -> None:
        registry = PluginRegistry()
        a = _make_manifest(name="plugin-a", dependencies=["plugin-b"])
        b = _make_manifest(name="plugin-b", dependencies=["plugin-a"])
        registry.register(a)
        registry.register(b)
        installer = PluginInstaller(plugins_dir=tmp_path / "plugins", registry=registry)
        with pytest.raises(MarketplaceError, match="Circular dependency"):
            installer.install("plugin-a")

    def test_sandbox_allows_safe_modules(self) -> None:
        assert PluginInstaller.check_sandbox("json") is True
        assert PluginInstaller.check_sandbox("pydantic.fields") is True

    def test_sandbox_blocks_restricted_modules(self) -> None:
        assert PluginInstaller.check_sandbox("subprocess") is False
        assert PluginInstaller.check_sandbox("os.path") is False
        assert PluginInstaller.check_sandbox("ctypes") is False

    def test_install_with_signature_verification(
        self,
        tmp_path: Path,
        ed25519_keypair: tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey],
    ) -> None:
        private_key, public_key = ed25519_keypair
        signer = PluginSigner(private_key)
        manifest = _make_manifest(author="trusted-author")
        signed = signer.sign(manifest)
        registry = PluginRegistry()
        registry.register(signed)
        installer = PluginInstaller(
            plugins_dir=tmp_path / "plugins",
            registry=registry,
            trusted_keys={"trusted-author": public_key},
        )
        dest = installer.install("test-plugin")
        assert dest.exists()
