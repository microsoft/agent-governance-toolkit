# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for PluginInstaller.scan_source_files and check_sandbox predicate.

Covers the security-contract clarification from the GitHub issue:
check_sandbox() is a policy predicate; actual install-time enforcement is
provided by scan_source_files(), which install() calls automatically.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_marketplace.installer import PluginInstaller, RESTRICTED_MODULES


# ---------------------------------------------------------------------------
# check_sandbox — policy predicate (not enforcement)
# ---------------------------------------------------------------------------


class TestCheckSandboxPredicate:
    """check_sandbox is a predicate — True means allowed, False means restricted."""

    def test_safe_module_allowed(self) -> None:
        assert PluginInstaller.check_sandbox("json") is True
        assert PluginInstaller.check_sandbox("re") is True
        assert PluginInstaller.check_sandbox("pydantic.fields") is True

    def test_restricted_top_level(self) -> None:
        for name in RESTRICTED_MODULES:
            assert PluginInstaller.check_sandbox(name) is False

    def test_restricted_submodule(self) -> None:
        assert PluginInstaller.check_sandbox("os.path") is False
        assert PluginInstaller.check_sandbox("subprocess.run") is False
        assert PluginInstaller.check_sandbox("ctypes.cdll") is False


# ---------------------------------------------------------------------------
# scan_source_files — install-time enforcement
# ---------------------------------------------------------------------------


class TestScanSourceFiles:
    """scan_source_files() detects restricted imports via AST analysis."""

    def test_empty_directory_returns_no_violations(self, tmp_path: Path) -> None:
        assert PluginInstaller.scan_source_files(tmp_path) == []

    def test_no_python_files_returns_no_violations(self, tmp_path: Path) -> None:
        (tmp_path / "agent-plugin.yaml").write_text("name: x\n")
        assert PluginInstaller.scan_source_files(tmp_path) == []

    def test_clean_python_file_returns_no_violations(self, tmp_path: Path) -> None:
        (tmp_path / "plugin.py").write_text("import json\nimport re\n")
        assert PluginInstaller.scan_source_files(tmp_path) == []

    def test_import_statement_violation_detected(self, tmp_path: Path) -> None:
        (tmp_path / "bad.py").write_text("import subprocess\n")
        violations = PluginInstaller.scan_source_files(tmp_path)
        assert len(violations) == 1
        assert "subprocess" in violations[0]

    def test_from_import_violation_detected(self, tmp_path: Path) -> None:
        (tmp_path / "bad.py").write_text("from os import path\n")
        violations = PluginInstaller.scan_source_files(tmp_path)
        assert len(violations) == 1
        assert "os" in violations[0]

    def test_multiple_violations_all_reported(self, tmp_path: Path) -> None:
        (tmp_path / "bad.py").write_text(
            "import subprocess\nimport os\nfrom ctypes import cdll\n"
        )
        violations = PluginInstaller.scan_source_files(tmp_path)
        assert len(violations) == 3

    def test_submodule_import_violation_detected(self, tmp_path: Path) -> None:
        (tmp_path / "bad.py").write_text("import os.path\n")
        violations = PluginInstaller.scan_source_files(tmp_path)
        assert len(violations) == 1
        assert "os" in violations[0]

    def test_nested_directory_scanned(self, tmp_path: Path) -> None:
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "plugin.py").write_text("import shutil\n")
        violations = PluginInstaller.scan_source_files(tmp_path)
        assert len(violations) == 1
        assert "shutil" in violations[0]

    def test_syntax_error_file_skipped_with_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        (tmp_path / "broken.py").write_text("def f(:\n")  # invalid syntax
        with caplog.at_level("WARNING"):
            violations = PluginInstaller.scan_source_files(tmp_path)
        assert violations == []
        assert any("Could not parse" in r.message for r in caplog.records)

    def test_all_restricted_modules_detected(self, tmp_path: Path) -> None:
        source = "\n".join(f"import {m}" for m in sorted(RESTRICTED_MODULES))
        (tmp_path / "all_restricted.py").write_text(source + "\n")
        violations = PluginInstaller.scan_source_files(tmp_path)
        assert len(violations) == len(RESTRICTED_MODULES)


# ---------------------------------------------------------------------------
# install() wires scan_source_files — restricted plugins are rejected
# ---------------------------------------------------------------------------


class TestInstallRejectsRestrictedImports:
    """install() raises MarketplaceError when plugin source imports restricted modules."""

    def _make_signed_plugin(self, name: str = "bad-plugin"):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from agent_marketplace.manifest import PluginManifest, PluginType
        from agent_marketplace.signing import PluginSigner

        private_key = ed25519.Ed25519PrivateKey.generate()
        signer = PluginSigner(private_key)
        manifest = PluginManifest(
            name=name,
            version="1.0.0",
            description="Bad plugin",
            author="trusted-author",
            plugin_type=PluginType.INTEGRATION,
        )
        return signer.sign(manifest), private_key.public_key()

    def test_install_rejects_plugin_with_restricted_import(
        self, tmp_path: Path
    ) -> None:
        from agent_marketplace.manifest import MarketplaceError
        from agent_marketplace.installer import PluginInstaller
        from agent_marketplace.registry import PluginRegistry

        signed, public_key = self._make_signed_plugin()
        registry = PluginRegistry()
        registry.register(signed)
        installer = PluginInstaller(
            plugins_dir=tmp_path / "plugins",
            registry=registry,
            trusted_keys={"trusted-author": public_key},
        )

        # Place a Python file with a restricted import in the plugin dir
        # before install() writes the manifest (simulates bundled source).
        plugin_dir = tmp_path / "plugins" / "bad-plugin"
        plugin_dir.mkdir(parents=True)
        (plugin_dir / "main.py").write_text("import subprocess\n")

        with pytest.raises(MarketplaceError, match="restricted modules"):
            installer.install("bad-plugin")

        # Plugin directory must be cleaned up after rejection.
        assert not plugin_dir.exists()

    def test_install_succeeds_when_no_restricted_imports(
        self, tmp_path: Path
    ) -> None:
        from agent_marketplace.installer import PluginInstaller
        from agent_marketplace.registry import PluginRegistry

        signed, public_key = self._make_signed_plugin(name="good-plugin")
        registry = PluginRegistry()
        registry.register(signed)
        installer = PluginInstaller(
            plugins_dir=tmp_path / "plugins",
            registry=registry,
            trusted_keys={"trusted-author": public_key},
        )

        # Plugin directory has only safe code.
        plugin_dir = tmp_path / "plugins" / "good-plugin"
        plugin_dir.mkdir(parents=True)
        (plugin_dir / "main.py").write_text("import json\n")

        dest = installer.install("good-plugin")
        assert dest.exists()
