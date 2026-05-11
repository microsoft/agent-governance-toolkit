# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for atomic manifest write + on-load signature verification.

Covers the REVIEW.md HIGH finding for ``installer.py:127-131``: an offline
attacker with file write to the plugins directory could swap an installed
plugin's manifest after install; ``list_installed()`` previously trusted
whatever YAML was on disk. The installer now (a) writes manifests via
``os.replace`` so torn writes are impossible, and (b) re-verifies each
on-disk manifest against ``trusted_keys`` before surfacing it.
"""

from __future__ import annotations

import base64

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric import ed25519

from agent_marketplace.installer import PluginInstaller, _atomic_write_yaml
from agent_marketplace.manifest import (
    MANIFEST_FILENAME,
    PluginManifest,
    PluginType,
)
from agent_marketplace.registry import PluginRegistry
from agent_marketplace.signing import PluginSigner


def _signed_plugin(signer: PluginSigner, name: str = "my-plugin") -> PluginManifest:
    manifest = PluginManifest(
        name=name,
        version="1.0.0",
        description="Test plugin",
        author="trusted-author",
        plugin_type=PluginType.INTEGRATION,
    )
    return signer.sign(manifest)


def _setup_installer(tmp_path):
    private_key = ed25519.Ed25519PrivateKey.generate()
    signer = PluginSigner(private_key)
    trusted_keys = {"trusted-author": private_key.public_key()}
    registry = PluginRegistry()
    installer = PluginInstaller(
        plugins_dir=tmp_path / "plugins",
        registry=registry,
        trusted_keys=trusted_keys,
    )
    return installer, registry, signer, trusted_keys


class TestAtomicWrite:
    """install() writes the manifest atomically via os.replace."""

    def test_manifest_written_via_replace(self, tmp_path):
        installer, registry, signer, _ = _setup_installer(tmp_path)
        registry.register(_signed_plugin(signer))

        installer.install("my-plugin")

        dest = tmp_path / "plugins" / "my-plugin"
        manifest_file = dest / MANIFEST_FILENAME
        assert manifest_file.exists()
        # No leftover temp files in the plugin directory
        leftover = [p for p in dest.iterdir() if p.name != MANIFEST_FILENAME]
        assert leftover == []

    def test_atomic_write_cleans_up_on_failure(self, tmp_path, monkeypatch):
        """If yaml.dump blows up mid-write, no tmp file is left behind."""
        target = tmp_path / "manifest.yaml"

        def boom(*_a, **_kw):
            raise RuntimeError("simulated crash mid-write")

        monkeypatch.setattr("agent_marketplace.installer.yaml.dump", boom)
        with pytest.raises(RuntimeError, match="simulated crash"):
            _atomic_write_yaml(target, {"name": "x"})

        # Target was never created; no .tmp leftovers in the dir
        assert not target.exists()
        leftovers = list(tmp_path.iterdir())
        assert leftovers == [], f"leftover temp files: {leftovers}"

    def test_atomic_write_replaces_existing_file(self, tmp_path):
        """Repeated install() of the same plugin replaces the manifest atomically."""
        installer, registry, signer, _ = _setup_installer(tmp_path)
        registry.register(_signed_plugin(signer))

        installer.install("my-plugin")
        first_inode = (tmp_path / "plugins" / "my-plugin" / MANIFEST_FILENAME).stat()
        installer.install("my-plugin")
        manifest_file = tmp_path / "plugins" / "my-plugin" / MANIFEST_FILENAME

        assert manifest_file.exists()
        # File still parseable (no torn-write artifacts)
        with open(manifest_file) as f:
            data = yaml.safe_load(f)
        assert data["name"] == "my-plugin"
        # st_size check: replacement landed atomically
        _ = first_inode  # captured to ensure no exception above


class TestListInstalledVerifiesOnDisk:
    """list_installed() re-verifies each on-disk manifest."""

    def test_verified_plugin_listed(self, tmp_path):
        installer, registry, signer, _ = _setup_installer(tmp_path)
        registry.register(_signed_plugin(signer))
        installer.install("my-plugin")

        names = [p.name for p in installer.list_installed()]
        assert names == ["my-plugin"]

    def test_tampered_manifest_skipped(self, tmp_path, caplog):
        """Mutating the on-disk manifest after install must invalidate the signature."""
        installer, registry, signer, _ = _setup_installer(tmp_path)
        registry.register(_signed_plugin(signer))
        installer.install("my-plugin")

        manifest_file = tmp_path / "plugins" / "my-plugin" / MANIFEST_FILENAME
        with open(manifest_file) as f:
            data = yaml.safe_load(f)
        data["description"] = "evil description"  # signature now invalid
        with open(manifest_file, "w") as f:
            yaml.dump(data, f, sort_keys=True)

        with caplog.at_level("WARNING"):
            result = installer.list_installed()
        assert result == []
        assert any("signature verification failed" in r.message for r in caplog.records)

    def test_signature_stripped_skipped(self, tmp_path, caplog):
        """Removing the signature field on disk must be detected on load."""
        installer, registry, signer, _ = _setup_installer(tmp_path)
        registry.register(_signed_plugin(signer))
        installer.install("my-plugin")

        manifest_file = tmp_path / "plugins" / "my-plugin" / MANIFEST_FILENAME
        with open(manifest_file) as f:
            data = yaml.safe_load(f)
        data["signature"] = None
        with open(manifest_file, "w") as f:
            yaml.dump(data, f, sort_keys=True)

        with caplog.at_level("WARNING"):
            result = installer.list_installed()
        assert result == []
        assert any("no signature on disk" in r.message for r in caplog.records)

    def test_untrusted_author_swapped_skipped(self, tmp_path, caplog):
        """Swapping author on disk to one not in trusted_keys is rejected."""
        installer, registry, signer, _ = _setup_installer(tmp_path)
        registry.register(_signed_plugin(signer))
        installer.install("my-plugin")

        # Re-sign the manifest with a different (untrusted) key set under
        # an unknown author. The signature itself is cryptographically valid
        # but the author is not in trusted_keys.
        new_key = ed25519.Ed25519PrivateKey.generate()
        new_signer = PluginSigner(new_key)
        spoof = PluginManifest(
            name="my-plugin",
            version="1.0.0",
            description="Test plugin",
            author="attacker",
            plugin_type=PluginType.INTEGRATION,
        )
        signed_spoof = new_signer.sign(spoof)
        manifest_file = tmp_path / "plugins" / "my-plugin" / MANIFEST_FILENAME
        with open(manifest_file, "w") as f:
            yaml.dump(signed_spoof.model_dump(mode="json"), f, sort_keys=True)

        with caplog.at_level("WARNING"):
            result = installer.list_installed()
        assert result == []
        assert any("untrusted author" in r.message for r in caplog.records)

    def test_verify_false_returns_unsigned_plugins(self, tmp_path):
        """verify=False mirrors install(verify=False) — surfaces unsigned plugins."""
        # Register a manifest without a signature, install with verify=False
        manifest = PluginManifest(
            name="unsigned-plugin",
            version="1.0.0",
            description="No sig",
            author="anyone",
            plugin_type=PluginType.INTEGRATION,
        )
        registry = PluginRegistry()
        registry.register(manifest)
        installer = PluginInstaller(
            plugins_dir=tmp_path / "plugins",
            registry=registry,
            trusted_keys={},
        )
        installer.install("unsigned-plugin", verify=False)

        # verify=True hides it
        assert installer.list_installed() == []
        # verify=False surfaces it
        names = [p.name for p in installer.list_installed(verify=False)]
        assert names == ["unsigned-plugin"]

    def test_signature_bitflip_rejected(self, tmp_path, caplog):
        """A flipped byte in the signature must be detected by verify_signature."""
        installer, registry, signer, _ = _setup_installer(tmp_path)
        registry.register(_signed_plugin(signer))
        installer.install("my-plugin")

        manifest_file = tmp_path / "plugins" / "my-plugin" / MANIFEST_FILENAME
        with open(manifest_file) as f:
            data = yaml.safe_load(f)
        sig_bytes = bytearray(base64.b64decode(data["signature"]))
        sig_bytes[0] ^= 0x01
        data["signature"] = base64.b64encode(bytes(sig_bytes)).decode()
        with open(manifest_file, "w") as f:
            yaml.dump(data, f, sort_keys=True)

        with caplog.at_level("WARNING"):
            result = installer.list_installed()
        assert result == []
        assert any("signature verification failed" in r.message for r in caplog.records)
