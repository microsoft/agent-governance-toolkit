# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for SupplyChainGuard."""

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agent_compliance.supply_chain import (
    SupplyChainConfig,
    SupplyChainFinding,
    SupplyChainGuard,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def guard() -> SupplyChainGuard:
    return SupplyChainGuard()


@pytest.fixture
def strict_guard() -> SupplyChainGuard:
    return SupplyChainGuard(
        SupplyChainConfig(
            freshness_days=14,
            allow_ranges=False,
            known_packages={"my-internal-pkg"},
            typosquat_threshold=0.80,
        )
    )


# ---------------------------------------------------------------------------
# check_package_json
# ---------------------------------------------------------------------------

class TestCheckPackageJson:
    def test_flags_caret_range(self, guard: SupplyChainGuard, tmp_path: Path) -> None:
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {"express": "^4.18.0"},
        }))
        findings = guard.check_package_json(str(pkg))
        assert any(f.rule == "unpinned-range" and f.package == "express" for f in findings)

    def test_flags_tilde_range(self, guard: SupplyChainGuard, tmp_path: Path) -> None:
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {"lodash": "~4.17.21"},
        }))
        findings = guard.check_package_json(str(pkg))
        assert any(f.rule == "unpinned-range" and f.package == "lodash" for f in findings)

    def test_exact_version_passes(self, guard: SupplyChainGuard, tmp_path: Path) -> None:
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {"express": "4.18.0"},
        }))
        findings = guard.check_package_json(str(pkg))
        assert not any(f.rule == "unpinned-range" for f in findings)

    def test_allow_ranges_config(self, tmp_path: Path) -> None:
        guard = SupplyChainGuard(SupplyChainConfig(allow_ranges=True))
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {"express": "^4.18.0"},
        }))
        findings = guard.check_package_json(str(pkg))
        assert not any(f.rule == "unpinned-range" for f in findings)

    def test_dev_dependencies_checked(self, guard: SupplyChainGuard, tmp_path: Path) -> None:
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "devDependencies": {"jest": "^29.0.0"},
        }))
        findings = guard.check_package_json(str(pkg))
        assert any(f.rule == "unpinned-range" and f.package == "jest" for f in findings)


# ---------------------------------------------------------------------------
# check_requirements
# ---------------------------------------------------------------------------

class TestCheckRequirements:
    def test_unpinned_version_flagged(self, guard: SupplyChainGuard, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("requests>=2.28.0\n")
        findings = guard.check_requirements(str(req))
        assert any(f.rule == "unpinned-version" and f.package == "requests" for f in findings)

    def test_pinned_version_passes(self, guard: SupplyChainGuard, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.31.0\n")
        findings = guard.check_requirements(str(req))
        assert not any(f.rule == "unpinned-version" for f in findings)

    def test_no_version_flagged(self, guard: SupplyChainGuard, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("flask\n")
        findings = guard.check_requirements(str(req))
        assert any(f.rule == "unpinned-version" and f.package == "flask" for f in findings)

    def test_comments_ignored(self, guard: SupplyChainGuard, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("# This is a comment\nrequests==2.31.0\n")
        findings = guard.check_requirements(str(req))
        assert not any(f.rule == "unpinned-version" for f in findings)

    def test_multiple_packages(self, guard: SupplyChainGuard, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.31.0\nflask>=2.0\nnumpy\n")
        findings = guard.check_requirements(str(req))
        unpinned = [f for f in findings if f.rule == "unpinned-version"]
        assert len(unpinned) == 2


# ---------------------------------------------------------------------------
# check_pyproject
# ---------------------------------------------------------------------------

class TestCheckPyproject:
    def test_loose_constraint_flagged(self, guard: SupplyChainGuard, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(
            '[project]\nname = "test"\n'
            'dependencies = [\n'
            '    "requests>=2.28.0",\n'
            ']\n'
        )
        findings = guard.check_pyproject(str(pp))
        assert any(
            f.rule == "loose-constraint" and f.package == "requests"
            for f in findings
        )

    def test_pinned_passes(self, guard: SupplyChainGuard, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(
            '[project]\nname = "test"\n'
            'dependencies = [\n'
            '    "requests==2.31.0",\n'
            ']\n'
        )
        findings = guard.check_pyproject(str(pp))
        assert not any(f.rule == "loose-constraint" for f in findings)

    def test_optional_dependencies_checked(
        self, guard: SupplyChainGuard, tmp_path: Path,
    ) -> None:
        """Regression: PEP 621 [project.optional-dependencies] groups
        were silently skipped by the prior string-match parser.
        """
        pp = tmp_path / "pyproject.toml"
        pp.write_text(
            '[project]\nname = "test"\n'
            'dependencies = []\n\n'
            '[project.optional-dependencies]\n'
            'dev = ["pytest>=7.0"]\n'
            'docs = ["sphinx>=5"]\n'
        )
        findings = guard.check_pyproject(str(pp))
        names = {f.package for f in findings if f.rule == "loose-constraint"}
        assert "pytest" in names
        assert "sphinx" in names

    def test_poetry_dependencies_checked(
        self, guard: SupplyChainGuard, tmp_path: Path,
    ) -> None:
        """Regression: Poetry's [tool.poetry.dependencies] table was
        silently skipped by the prior parser. Caret strings should
        flag, exact versions should pass, and the special "python"
        key (Python version constraint, not a real dependency) should
        not surface.
        """
        pp = tmp_path / "pyproject.toml"
        pp.write_text(
            '[tool.poetry]\nname = "test"\nversion = "0.1.0"\n\n'
            '[tool.poetry.dependencies]\n'
            'python = "^3.10"\n'
            'requests = "^2.28"\n'
            'pinned = "1.2.3"\n'
        )
        findings = guard.check_pyproject(str(pp))
        names = {f.package for f in findings if f.rule == "loose-constraint"}
        assert "requests" in names
        assert "pinned" not in names
        assert "python" not in names

    def test_poetry_legacy_dev_dependencies_checked(
        self, guard: SupplyChainGuard, tmp_path: Path,
    ) -> None:
        """Poetry legacy [tool.poetry.dev-dependencies] table coverage."""
        pp = tmp_path / "pyproject.toml"
        pp.write_text(
            '[tool.poetry]\nname = "test"\nversion = "0.1.0"\n\n'
            '[tool.poetry.dev-dependencies]\n'
            'pytest = "^7.0"\n'
        )
        findings = guard.check_pyproject(str(pp))
        assert any(f.package == "pytest" and f.rule == "loose-constraint" for f in findings)

    def test_poetry_modern_group_dependencies_checked(
        self, guard: SupplyChainGuard, tmp_path: Path,
    ) -> None:
        """Poetry modern [tool.poetry.group.<name>.dependencies] coverage."""
        pp = tmp_path / "pyproject.toml"
        pp.write_text(
            '[tool.poetry]\nname = "test"\nversion = "0.1.0"\n\n'
            '[tool.poetry.group.test.dependencies]\n'
            'pytest = "^7.0"\n'
            '[tool.poetry.group.docs.dependencies]\n'
            'sphinx = "^5.0"\n'
        )
        findings = guard.check_pyproject(str(pp))
        names = {f.package for f in findings if f.rule == "loose-constraint"}
        assert {"pytest", "sphinx"} <= names

    def test_poetry_table_form_git_dep_flagged(
        self, guard: SupplyChainGuard, tmp_path: Path,
    ) -> None:
        """Regression: Poetry inline-table deps with git/path/url
        sources bypass the index trust boundary entirely. The prior
        string-match parser couldn't see them at all.
        """
        pp = tmp_path / "pyproject.toml"
        pp.write_text(
            '[tool.poetry]\nname = "test"\nversion = "0.1.0"\n\n'
            '[tool.poetry.dependencies]\n'
            'evil = {git = "https://github.com/attacker/evil.git", rev = "main"}\n'
        )
        findings = guard.check_pyproject(str(pp))
        assert any(
            f.package == "evil" and f.rule == "non-semver-specifier"
            for f in findings
        )

    def test_poetry_table_form_path_dep_flagged(
        self, guard: SupplyChainGuard, tmp_path: Path,
    ) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(
            '[tool.poetry]\nname = "test"\nversion = "0.1.0"\n\n'
            '[tool.poetry.dependencies]\n'
            'local-evil = {path = "../malicious", develop = true}\n'
        )
        findings = guard.check_pyproject(str(pp))
        assert any(
            f.package == "local-evil" and f.rule == "non-semver-specifier"
            for f in findings
        )

    def test_poetry_table_form_pinned_passes(
        self, guard: SupplyChainGuard, tmp_path: Path,
    ) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(
            '[tool.poetry]\nname = "test"\nversion = "0.1.0"\n\n'
            '[tool.poetry.dependencies]\n'
            'requests = {version = "2.31.0", python = ">=3.10"}\n'
        )
        findings = guard.check_pyproject(str(pp))
        assert not any(f.package == "requests" for f in findings)

    def test_pep621_multiline_dependencies(
        self, guard: SupplyChainGuard, tmp_path: Path,
    ) -> None:
        """Regression: deps split across multiple lines confused the
        prior string-match parser. tomllib sees them as a list.
        """
        pp = tmp_path / "pyproject.toml"
        pp.write_text(
            '[project]\nname = "test"\n'
            'dependencies = [\n'
            '  "requests>=2.28.0",\n'
            '  "click==8.1.0",\n'
            '  # comment in the middle\n'
            '  "rich>=13",\n'
            ']\n'
        )
        findings = guard.check_pyproject(str(pp))
        names = {f.package for f in findings if f.rule == "loose-constraint"}
        assert "requests" in names
        assert "rich" in names
        assert "click" not in names

    def test_malformed_toml_returns_empty(
        self, guard: SupplyChainGuard, tmp_path: Path,
    ) -> None:
        """A pyproject.toml that tomllib cannot parse must not crash —
        return an empty list of findings.
        """
        pp = tmp_path / "pyproject.toml"
        pp.write_text("[project\nname = unterminated\n")
        findings = guard.check_pyproject(str(pp))
        assert findings == []


# ---------------------------------------------------------------------------
# check_cargo_toml
# ---------------------------------------------------------------------------

class TestCheckCargoToml:
    def test_unpinned_version_flagged(self, guard: SupplyChainGuard, tmp_path: Path) -> None:
        cargo = tmp_path / "Cargo.toml"
        cargo.write_text(
            '[package]\nname = "test"\n\n'
            '[dependencies]\n'
            'serde = "1.0"\n'
        )
        findings = guard.check_cargo_toml(str(cargo))
        assert any(
            f.rule == "unpinned-cargo" and f.package == "serde"
            for f in findings
        )

    def test_pinned_version_passes(self, guard: SupplyChainGuard, tmp_path: Path) -> None:
        cargo = tmp_path / "Cargo.toml"
        cargo.write_text(
            '[package]\nname = "test"\n\n'
            '[dependencies]\n'
            'serde = "1.0.193"\n'
        )
        findings = guard.check_cargo_toml(str(cargo))
        assert not any(f.rule == "unpinned-cargo" for f in findings)


# ---------------------------------------------------------------------------
# check_typosquatting
# ---------------------------------------------------------------------------

class TestCheckTyposquatting:
    def test_typosquat_flagged(self, guard: SupplyChainGuard) -> None:
        finding = guard.check_typosquatting("reqeusts", ecosystem="pypi")
        assert finding is not None
        assert finding.rule == "typosquat"
        assert finding.severity == "critical"

    def test_legitimate_package_passes(self, guard: SupplyChainGuard) -> None:
        finding = guard.check_typosquatting("requests", ecosystem="pypi")
        assert finding is None

    def test_unrelated_package_passes(self, guard: SupplyChainGuard) -> None:
        finding = guard.check_typosquatting("my-unique-tool", ecosystem="pypi")
        assert finding is None

    def test_npm_typosquat(self, guard: SupplyChainGuard) -> None:
        finding = guard.check_typosquatting("expresss", ecosystem="npm")
        assert finding is not None
        assert finding.rule == "typosquat"

    def test_known_packages_allowlist(self, strict_guard: SupplyChainGuard) -> None:
        finding = strict_guard.check_typosquatting("my-internal-pkg", ecosystem="pypi")
        assert finding is None


# ---------------------------------------------------------------------------
# check_freshness
# ---------------------------------------------------------------------------

class TestCheckFreshness:
    def test_recent_publish_triggers_finding(self, guard: SupplyChainGuard) -> None:
        recent = datetime.now(timezone.utc) - timedelta(days=2)
        finding = guard.check_freshness("evil-pkg", "1.0.0", recent)
        assert finding is not None
        assert finding.rule == "fresh-publish"
        assert finding.severity == "high"

    def test_old_publish_passes(self, guard: SupplyChainGuard) -> None:
        old = datetime.now(timezone.utc) - timedelta(days=30)
        finding = guard.check_freshness("stable-pkg", "2.0.0", old)
        assert finding is None

    def test_boundary_exactly_at_threshold(self, guard: SupplyChainGuard) -> None:
        boundary = datetime.now(timezone.utc) - timedelta(days=7, seconds=1)
        finding = guard.check_freshness("boundary-pkg", "1.0.0", boundary)
        assert finding is None

    def test_custom_freshness_days(self, strict_guard: SupplyChainGuard) -> None:
        ten_days_ago = datetime.now(timezone.utc) - timedelta(days=10)
        finding = strict_guard.check_freshness("new-pkg", "0.1.0", ten_days_ago)
        assert finding is not None  # threshold is 14 days


# ---------------------------------------------------------------------------
# scan_directory
# ---------------------------------------------------------------------------

class TestScanDirectory:
    def test_finds_all_dependency_files(self, guard: SupplyChainGuard, tmp_path: Path) -> None:
        # requirements.txt
        (tmp_path / "requirements.txt").write_text("flask\n")
        # package.json
        (tmp_path / "package.json").write_text(json.dumps({
            "dependencies": {"react": "^18.0.0"},
        }))
        # pyproject.toml
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "t"\n'
            'dependencies = [\n'
            '    "numpy>=1.24",\n'
            ']\n'
        )
        # Cargo.toml
        (tmp_path / "Cargo.toml").write_text(
            '[package]\nname = "t"\n\n'
            '[dependencies]\n'
            'tokio = "1.0"\n'
        )

        findings = guard.scan_directory(str(tmp_path))

        rules = {f.rule for f in findings}
        assert "unpinned-version" in rules    # requirements.txt
        assert "unpinned-range" in rules       # package.json
        assert "loose-constraint" in rules     # pyproject.toml
        assert "unpinned-cargo" in rules       # Cargo.toml

    def test_empty_directory(self, guard: SupplyChainGuard, tmp_path: Path) -> None:
        findings = guard.scan_directory(str(tmp_path))
        assert findings == []


# ---------------------------------------------------------------------------
# SupplyChainConfig customisation
# ---------------------------------------------------------------------------

class TestSupplyChainConfig:
    def test_default_config(self) -> None:
        cfg = SupplyChainConfig()
        assert cfg.freshness_days == 7
        assert cfg.allow_ranges is False
        assert cfg.known_packages is None
        assert cfg.typosquat_threshold == 0.85

    def test_custom_config(self) -> None:
        cfg = SupplyChainConfig(
            freshness_days=30,
            allow_ranges=True,
            known_packages={"my-pkg"},
            typosquat_threshold=0.90,
        )
        assert cfg.freshness_days == 30
        assert cfg.allow_ranges is True
        assert cfg.known_packages == {"my-pkg"}
        assert cfg.typosquat_threshold == 0.90

    def test_guard_uses_config(self, tmp_path: Path) -> None:
        cfg = SupplyChainConfig(allow_ranges=True)
        guard = SupplyChainGuard(cfg)
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"dependencies": {"express": "^4.18.0"}}))
        findings = guard.check_package_json(str(pkg))
        assert not any(f.rule == "unpinned-range" for f in findings)


# ---------------------------------------------------------------------------
# scan_lockfile_drift
# ---------------------------------------------------------------------------

class TestScanLockfileDrift:
    def test_missing_lockfile(self, guard: SupplyChainGuard, tmp_path: Path) -> None:
        manifest = tmp_path / "requirements.txt"
        manifest.write_text("requests==2.31.0\n")
        findings = guard.scan_lockfile_drift(
            str(manifest), str(tmp_path / "nonexistent.lock")
        )
        assert any(f.rule == "missing-lockfile" for f in findings)

    def test_lockfile_in_sync(self, guard: SupplyChainGuard, tmp_path: Path) -> None:
        manifest = tmp_path / "requirements.txt"
        manifest.write_text("requests==2.31.0\n")
        lock = tmp_path / "requirements.lock"
        lock.write_text("requests==2.31.0\n")
        findings = guard.scan_lockfile_drift(str(manifest), str(lock))
        assert not any(f.rule == "lockfile-drift" for f in findings)

    def test_lockfile_drift_detected(self, guard: SupplyChainGuard, tmp_path: Path) -> None:
        manifest = tmp_path / "requirements.txt"
        manifest.write_text("requests==2.31.0\nflask==3.0.0\n")
        lock = tmp_path / "requirements.lock"
        lock.write_text("requests==2.31.0\n")
        findings = guard.scan_lockfile_drift(str(manifest), str(lock))
        assert any(f.rule == "lockfile-drift" and f.package == "flask" for f in findings)
