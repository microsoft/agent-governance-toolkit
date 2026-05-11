# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for artifact download, SHA-256 verification, and on-disk re-verification.

Covers the architectural gap described in the issue: PluginInstaller.install()
previously only wrote a manifest copy — no plugin code was ever downloaded.
These tests verify that:
  - When artifact_url + artifact_sha256 are set, install() downloads the zip,
    verifies its SHA-256, unpacks it under plugins_dir/<name>/, and keeps
    .artifact.zip for on-disk re-verification.
  - A SHA-256 mismatch is rejected.
  - artifact_url without artifact_sha256 is rejected when verify=True.
  - _verify_on_disk() re-checks the stored .artifact.zip hash.
  - Tampering .artifact.zip after install is detected by list_installed().
  - artifact_url without artifact_sha256 is allowed when verify=False.
"""

from __future__ import annotations

import hashlib
import http.server
import io
import threading
import zipfile
from pathlib import Path
from typing import Optional

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from agent_marketplace.installer import ARTIFACT_FILENAME, PluginInstaller
from agent_marketplace.manifest import (
    MANIFEST_FILENAME,
    MarketplaceError,
    PluginManifest,
    PluginType,
)
from agent_marketplace.registry import PluginRegistry
from agent_marketplace.signing import PluginSigner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_zip(files: dict[str, bytes]) -> bytes:
    """Build an in-memory zip archive from a dict of filename → bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _StaticFileHandler(http.server.BaseHTTPRequestHandler):
    """Minimal HTTP handler that serves a single in-memory file."""

    content: bytes = b""  # set by _serve_bytes()

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Length", str(len(self.content)))
        self.end_headers()
        self.wfile.write(self.content)

    def log_message(self, *_args) -> None:  # suppress server output in tests
        pass


def _serve_bytes(data: bytes) -> tuple[http.server.HTTPServer, str]:
    """Start a local HTTP server serving *data* on GET /.  Returns (server, url)."""

    class Handler(_StaticFileHandler):
        content = data

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{port}/"


def _setup(tmp_path: Path) -> tuple[PluginInstaller, PluginRegistry, PluginSigner]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    signer = PluginSigner(private_key)
    trusted_keys = {"author@example.com": private_key.public_key()}
    registry = PluginRegistry()
    installer = PluginInstaller(
        plugins_dir=tmp_path / "plugins",
        registry=registry,
        trusted_keys=trusted_keys,
    )
    return installer, registry, signer


def _make_manifest(
    signer: PluginSigner,
    name: str = "test-plugin",
    artifact_url: Optional[str] = None,
    artifact_sha256: Optional[str] = None,
) -> PluginManifest:
    manifest = PluginManifest(
        name=name,
        version="1.0.0",
        description="Test plugin",
        author="author@example.com",
        plugin_type=PluginType.INTEGRATION,
        artifact_url=artifact_url,
        artifact_sha256=artifact_sha256,
    )
    return signer.sign(manifest)


# ---------------------------------------------------------------------------
# Tests: artifact download + unpack
# ---------------------------------------------------------------------------


class TestArtifactDownloadAndUnpack:
    """install() downloads and unpacks the artifact when artifact_url is set."""

    def test_artifact_unpacked_and_zip_kept(self, tmp_path):
        """Files from the artifact zip are unpacked; .artifact.zip is retained."""
        artifact_zip = _make_zip({"plugin.py": b"# plugin code\n"})
        server, url = _serve_bytes(artifact_zip)
        try:
            installer, registry, signer = _setup(tmp_path)
            manifest = _make_manifest(
                signer,
                artifact_url=url,
                artifact_sha256=_sha256_hex(artifact_zip),
            )
            registry.register(manifest)

            dest = installer.install("test-plugin")

            assert (dest / "plugin.py").read_bytes() == b"# plugin code\n"
            assert (dest / ARTIFACT_FILENAME).exists()
            assert (dest / MANIFEST_FILENAME).exists()
        finally:
            server.shutdown()

    def test_no_artifact_url_only_manifest_written(self, tmp_path):
        """Without artifact_url, only the manifest is written (manifest-registration mode)."""
        installer, registry, signer = _setup(tmp_path)
        manifest = _make_manifest(signer)  # no artifact_url
        registry.register(manifest)

        dest = installer.install("test-plugin")

        assert (dest / MANIFEST_FILENAME).exists()
        assert not (dest / ARTIFACT_FILENAME).exists()

    def test_multiple_files_in_zip_all_extracted(self, tmp_path):
        """All files from the archive are extracted under the plugin dir."""
        artifact_zip = _make_zip(
            {
                "main.py": b"# main\n",
                "helpers/util.py": b"# util\n",
            }
        )
        server, url = _serve_bytes(artifact_zip)
        try:
            installer, registry, signer = _setup(tmp_path)
            manifest = _make_manifest(
                signer,
                artifact_url=url,
                artifact_sha256=_sha256_hex(artifact_zip),
            )
            registry.register(manifest)
            dest = installer.install("test-plugin")

            assert (dest / "main.py").read_bytes() == b"# main\n"
            assert (dest / "helpers" / "util.py").read_bytes() == b"# util\n"
        finally:
            server.shutdown()


# ---------------------------------------------------------------------------
# Tests: SHA-256 verification
# ---------------------------------------------------------------------------


class TestArtifactSHA256Verification:
    """install() rejects artifacts whose hash does not match the manifest."""

    def test_correct_hash_accepted(self, tmp_path):
        artifact_zip = _make_zip({"x.py": b"x"})
        server, url = _serve_bytes(artifact_zip)
        try:
            installer, registry, signer = _setup(tmp_path)
            manifest = _make_manifest(
                signer,
                artifact_url=url,
                artifact_sha256=_sha256_hex(artifact_zip),
            )
            registry.register(manifest)
            # Must not raise
            installer.install("test-plugin")
        finally:
            server.shutdown()

    def test_wrong_hash_rejected(self, tmp_path):
        """A hash mismatch must raise MarketplaceError and leave no artifact on disk."""
        artifact_zip = _make_zip({"x.py": b"x"})
        bad_hash = "a" * 64  # wrong SHA-256
        server, url = _serve_bytes(artifact_zip)
        try:
            installer, registry, signer = _setup(tmp_path)
            manifest = _make_manifest(
                signer,
                artifact_url=url,
                artifact_sha256=bad_hash,
            )
            registry.register(manifest)

            with pytest.raises(MarketplaceError, match="SHA-256 mismatch"):
                installer.install("test-plugin")

            # Plugin directory must not contain the artifact
            dest = tmp_path / "plugins" / "test-plugin"
            assert not (dest / ARTIFACT_FILENAME).exists()
        finally:
            server.shutdown()

    def test_artifact_url_without_sha256_rejected_when_verify_true(self, tmp_path):
        """artifact_url without artifact_sha256 must fail when verify=True."""
        artifact_zip = _make_zip({"x.py": b"x"})
        server, url = _serve_bytes(artifact_zip)
        try:
            installer, registry, signer = _setup(tmp_path)
            # Sign a manifest that has artifact_url but no artifact_sha256.
            # We have to bypass the model to create this state.
            base = PluginManifest(
                name="test-plugin",
                version="1.0.0",
                description="Test",
                author="author@example.com",
                plugin_type=PluginType.INTEGRATION,
                artifact_url=url,
                artifact_sha256=None,
            )
            signed = signer.sign(base)
            registry.register(signed)

            with pytest.raises(MarketplaceError, match="no artifact_sha256"):
                installer.install("test-plugin", verify=True)
        finally:
            server.shutdown()

    def test_artifact_url_without_sha256_allowed_when_verify_false(self, tmp_path):
        """artifact_url without artifact_sha256 is permitted with verify=False."""
        artifact_zip = _make_zip({"x.py": b"x"})
        server, url = _serve_bytes(artifact_zip)
        try:
            registry = PluginRegistry()
            installer = PluginInstaller(
                plugins_dir=tmp_path / "plugins",
                registry=registry,
                trusted_keys={},
            )
            base = PluginManifest(
                name="test-plugin",
                version="1.0.0",
                description="Test",
                author="author@example.com",
                plugin_type=PluginType.INTEGRATION,
                artifact_url=url,
                artifact_sha256=None,
            )
            registry.register(base)

            # Must not raise
            dest = installer.install("test-plugin", verify=False)
            # Files still get extracted even without hash check
            assert (dest / "x.py").exists()
        finally:
            server.shutdown()


# ---------------------------------------------------------------------------
# Tests: on-disk re-verification of artifact hash
# ---------------------------------------------------------------------------


class TestOnDiskArtifactReVerification:
    """list_installed() re-verifies .artifact.zip hash when artifact_sha256 is set."""

    def test_valid_artifact_listed(self, tmp_path):
        artifact_zip = _make_zip({"x.py": b"x"})
        server, url = _serve_bytes(artifact_zip)
        try:
            installer, registry, signer = _setup(tmp_path)
            manifest = _make_manifest(
                signer,
                artifact_url=url,
                artifact_sha256=_sha256_hex(artifact_zip),
            )
            registry.register(manifest)
            installer.install("test-plugin")

            names = [p.name for p in installer.list_installed()]
            assert names == ["test-plugin"]
        finally:
            server.shutdown()

    def test_tampered_artifact_zip_skipped(self, tmp_path, caplog):
        """Replacing .artifact.zip with different bytes after install is detected."""
        artifact_zip = _make_zip({"x.py": b"x"})
        server, url = _serve_bytes(artifact_zip)
        try:
            installer, registry, signer = _setup(tmp_path)
            manifest = _make_manifest(
                signer,
                artifact_url=url,
                artifact_sha256=_sha256_hex(artifact_zip),
            )
            registry.register(manifest)
            installer.install("test-plugin")

            # Replace the stored artifact with different bytes
            artifact_path = tmp_path / "plugins" / "test-plugin" / ARTIFACT_FILENAME
            artifact_path.write_bytes(b"corrupted content")

            with caplog.at_level("WARNING"):
                result = installer.list_installed()
            assert result == []
            assert any("artifact hash verification failed" in r.message for r in caplog.records)
        finally:
            server.shutdown()

    def test_missing_artifact_zip_skipped(self, tmp_path, caplog):
        """Deleting .artifact.zip after install must be detected by list_installed()."""
        artifact_zip = _make_zip({"x.py": b"x"})
        server, url = _serve_bytes(artifact_zip)
        try:
            installer, registry, signer = _setup(tmp_path)
            manifest = _make_manifest(
                signer,
                artifact_url=url,
                artifact_sha256=_sha256_hex(artifact_zip),
            )
            registry.register(manifest)
            installer.install("test-plugin")

            # Remove the stored artifact
            artifact_path = tmp_path / "plugins" / "test-plugin" / ARTIFACT_FILENAME
            artifact_path.unlink()

            with caplog.at_level("WARNING"):
                result = installer.list_installed()
            assert result == []
            assert any(".artifact.zip missing" in r.message for r in caplog.records)
        finally:
            server.shutdown()

    def test_no_artifact_url_plugin_lists_without_artifact_zip(self, tmp_path):
        """Manifest-only plugins (no artifact_url) pass on-disk verification without .artifact.zip."""
        installer, registry, signer = _setup(tmp_path)
        manifest = _make_manifest(signer)  # no artifact_url/sha256
        registry.register(manifest)
        installer.install("test-plugin")

        names = [p.name for p in installer.list_installed()]
        assert names == ["test-plugin"]


# ---------------------------------------------------------------------------
# Tests: security guards
# ---------------------------------------------------------------------------


class TestSecurityGuards:
    """URL scheme validation and zip-slip protection."""

    def test_file_scheme_url_rejected(self, tmp_path):
        """artifact_url with file:// scheme must be rejected before any download."""
        installer, registry, signer = _setup(tmp_path)
        # Create a local file to ensure the path exists
        local_file = tmp_path / "evil.zip"
        local_file.write_bytes(b"irrelevant")
        manifest = _make_manifest(
            signer,
            artifact_url=f"file://{local_file}",
            artifact_sha256="a" * 64,
        )
        registry.register(manifest)

        with pytest.raises(MarketplaceError, match="http or https"):
            installer.install("test-plugin")

    def test_custom_scheme_rejected(self, tmp_path):
        """Non-http/https schemes (e.g., ftp://) are rejected."""
        installer, registry, signer = _setup(tmp_path)
        manifest = _make_manifest(
            signer,
            artifact_url="ftp://example.com/plugin.zip",
            artifact_sha256="a" * 64,
        )
        registry.register(manifest)

        with pytest.raises(MarketplaceError, match="http or https"):
            installer.install("test-plugin")

    def test_zip_slip_rejected(self, tmp_path):
        """Archive members with paths that escape dest must raise MarketplaceError."""
        # Build a zip with a path-traversal member
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../../evil.py", b"evil")  # type: ignore[arg-type]
        artifact_zip = buf.getvalue()
        server, url = _serve_bytes(artifact_zip)
        try:
            installer, registry, signer = _setup(tmp_path)
            manifest = _make_manifest(
                signer,
                artifact_url=url,
                artifact_sha256=_sha256_hex(artifact_zip),
            )
            registry.register(manifest)

            with pytest.raises(MarketplaceError, match="unsafe path"):
                installer.install("test-plugin")

            # The evil file must not have been written outside the plugin dir
            assert not (tmp_path / "evil.py").exists()
        finally:
            server.shutdown()



class TestArtifactHashInSignableBytes:
    """artifact_sha256 is part of signable_bytes() so the signature binds the artifact."""

    def test_artifact_sha256_included_in_signable_bytes(self):
        import json

        m_with = PluginManifest(
            name="p",
            version="1.0.0",
            description="d",
            author="a",
            plugin_type=PluginType.INTEGRATION,
            artifact_url="https://example.com/p.zip",
            artifact_sha256="abc123",
        )
        m_without = PluginManifest(
            name="p",
            version="1.0.0",
            description="d",
            author="a",
            plugin_type=PluginType.INTEGRATION,
        )
        # Both must produce valid JSON
        data_with = json.loads(m_with.signable_bytes().decode("ascii"))
        json.loads(m_without.signable_bytes().decode("ascii"))  # must not raise

        assert data_with["artifact_sha256"] == "abc123"
        assert data_with["artifact_url"] == "https://example.com/p.zip"
        # Different content → different signable bytes
        assert m_with.signable_bytes() != m_without.signable_bytes()

    def test_changing_artifact_sha256_invalidates_signature(self, tmp_path, caplog):
        """Mutating artifact_sha256 in the manifest on disk must fail signature check."""
        artifact_zip = _make_zip({"x.py": b"x"})
        server, url = _serve_bytes(artifact_zip)
        try:
            installer, registry, signer = _setup(tmp_path)
            manifest = _make_manifest(
                signer,
                artifact_url=url,
                artifact_sha256=_sha256_hex(artifact_zip),
            )
            registry.register(manifest)
            installer.install("test-plugin")

            # Change artifact_sha256 on the stored manifest (attacker swap)
            import yaml

            mpath = tmp_path / "plugins" / "test-plugin" / MANIFEST_FILENAME
            with open(mpath) as f:
                data = yaml.safe_load(f)
            data["artifact_sha256"] = "b" * 64  # attacker changes the hash
            with open(mpath, "w") as f:
                yaml.dump(data, f, sort_keys=True)

            # list_installed() must skip the plugin because signature covers
            # artifact_sha256 — changing it invalidates the Ed25519 signature.
            with caplog.at_level("WARNING"):
                result = installer.list_installed()
            assert result == []
            assert any("signature verification failed" in r.message for r in caplog.records)
        finally:
            server.shutdown()
