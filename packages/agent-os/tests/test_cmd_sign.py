# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the ``agentos sign`` CLI command."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric import ed25519

from agent_os.cli.cmd_sign import (
    cmd_sign_keygen,
    cmd_sign_plugin,
    cmd_sign_verify,
    _load_manifest,
    _load_private_key,
    _load_public_key,
    _save_manifest,
)
from agentmesh.marketplace.manifest import PluginManifest, PluginType


@pytest.fixture()
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture()
def sample_manifest(tmp_dir: Path) -> Path:
    """Create a sample plugin directory with agent-plugin.yaml."""
    plugin_dir = tmp_dir / "my-plugin"
    plugin_dir.mkdir()
    manifest = {
        "name": "my-plugin",
        "version": "1.0.0",
        "description": "Test plugin",
        "author": "test@example.com",
        "plugin_type": "integration",
        "capabilities": ["search"],
    }
    (plugin_dir / "agent-plugin.yaml").write_text(
        yaml.dump(manifest), encoding="utf-8"
    )
    return plugin_dir


@pytest.fixture()
def keypair(tmp_dir: Path) -> tuple[Path, Path]:
    """Generate a keypair and return (private_key_path, public_key_path)."""
    from cryptography.hazmat.primitives import serialization

    key = ed25519.Ed25519PrivateKey.generate()
    priv_path = tmp_dir / "signing.key"
    pub_path = tmp_dir / "signing.pub"

    priv_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    pub_path.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return priv_path, pub_path


class TestKeygen:
    def test_generates_keypair(self, tmp_dir: Path):
        class Args:
            out = str(tmp_dir / "keys")

        result = cmd_sign_keygen(Args())
        assert result == 0
        assert (tmp_dir / "keys" / "signing.key").exists()
        assert (tmp_dir / "keys" / "signing.pub").exists()

    def test_keys_are_valid_ed25519(self, tmp_dir: Path):
        class Args:
            out = str(tmp_dir / "keys")

        cmd_sign_keygen(Args())
        priv = _load_private_key(tmp_dir / "keys" / "signing.key")
        pub = _load_public_key(tmp_dir / "keys" / "signing.pub")
        assert isinstance(priv, ed25519.Ed25519PrivateKey)
        assert isinstance(pub, ed25519.Ed25519PublicKey)


class TestSignPlugin:
    def test_signs_manifest(self, sample_manifest: Path, keypair: tuple[Path, Path]):
        priv_path, _ = keypair

        class Args:
            plugin_dir = str(sample_manifest)
            key = str(priv_path)

        result = cmd_sign_plugin(Args())
        assert result == 0

        manifest = _load_manifest(sample_manifest)
        assert manifest.signature is not None
        assert len(manifest.signature) > 0

    def test_missing_key_fails(self, sample_manifest: Path, tmp_dir: Path):
        class Args:
            plugin_dir = str(sample_manifest)
            key = str(tmp_dir / "nonexistent.key")

        with pytest.raises(SystemExit):
            cmd_sign_plugin(Args())

    def test_missing_manifest_fails(self, tmp_dir: Path, keypair: tuple[Path, Path]):
        priv_path, _ = keypair
        empty_dir = tmp_dir / "empty"
        empty_dir.mkdir()

        class Args:
            plugin_dir = str(empty_dir)
            key = str(priv_path)

        with pytest.raises(SystemExit):
            cmd_sign_plugin(Args())


class TestVerify:
    def test_valid_signature_passes(self, sample_manifest: Path, keypair: tuple[Path, Path]):
        priv_path, pub_path = keypair

        # Sign first
        class SignArgs:
            plugin_dir = str(sample_manifest)
            key = str(priv_path)

        cmd_sign_plugin(SignArgs())

        # Verify
        class VerifyArgs:
            plugin_dir = str(sample_manifest)
            pubkey = str(pub_path)
            json = False

        result = cmd_sign_verify(VerifyArgs())
        assert result == 0

    def test_wrong_key_fails(self, sample_manifest: Path, keypair: tuple[Path, Path], tmp_dir: Path):
        priv_path, _ = keypair

        # Sign with original key
        class SignArgs:
            plugin_dir = str(sample_manifest)
            key = str(priv_path)

        cmd_sign_plugin(SignArgs())

        # Generate a different key and try to verify
        from cryptography.hazmat.primitives import serialization

        other_key = ed25519.Ed25519PrivateKey.generate()
        other_pub_path = tmp_dir / "other.pub"
        other_pub_path.write_bytes(
            other_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

        class VerifyArgs:
            plugin_dir = str(sample_manifest)
            pubkey = str(other_pub_path)
            json = False

        result = cmd_sign_verify(VerifyArgs())
        assert result == 1

    def test_unsigned_manifest_fails(self, sample_manifest: Path, keypair: tuple[Path, Path]):
        _, pub_path = keypair

        class VerifyArgs:
            plugin_dir = str(sample_manifest)
            pubkey = str(pub_path)
            json = False

        result = cmd_sign_verify(VerifyArgs())
        assert result == 1

    def test_json_output(self, sample_manifest: Path, keypair: tuple[Path, Path], capsys):
        priv_path, pub_path = keypair

        class SignArgs:
            plugin_dir = str(sample_manifest)
            key = str(priv_path)

        cmd_sign_plugin(SignArgs())

        class VerifyArgs:
            plugin_dir = str(sample_manifest)
            pubkey = str(pub_path)
            json = True

        result = cmd_sign_verify(VerifyArgs())
        assert result == 0
        captured = capsys.readouterr()
        assert '"valid": true' in captured.out


class TestLoadSaveManifest:
    def test_round_trip(self, sample_manifest: Path):
        manifest = _load_manifest(sample_manifest)
        assert manifest.name == "my-plugin"
        assert manifest.version == "1.0.0"

        manifest_copy = manifest.model_copy(update={"signature": "test-sig"})
        _save_manifest(manifest_copy, sample_manifest)

        reloaded = _load_manifest(sample_manifest)
        assert reloaded.signature == "test-sig"
