# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Package identity and scaffold boundary checks."""

import importlib
import json
import tomllib
from pathlib import Path
from urllib.parse import urlparse

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PACKAGE_ROOT.parent


def test_source_package_is_importable() -> None:
    module = importlib.import_module("agent_governance_studio")
    assert module.__file__ is not None
    assert Path(module.__file__).resolve() == (
        PACKAGE_ROOT / "src" / "agent_governance_studio" / "__init__.py"
    )


def test_distribution_identity_and_metadata() -> None:
    data = tomllib.loads((PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = data["project"]
    assert project["name"] == "agent-governance-studio"
    assert project["version"] == (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    assert project["description"].startswith("Public Preview")
    assert project["license"]["text"] == "MIT"
    assert project["authors"][0]["name"] == "Microsoft Corporation"
    assert (PACKAGE_ROOT / "LICENSE").read_text(encoding="utf-8") == (
        REPO_ROOT / "LICENSE"
    ).read_text(encoding="utf-8")


def test_no_runtime_dependencies_or_unimplemented_cli_registration() -> None:
    project = tomllib.loads(
        (PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]
    assert not project.get("dependencies")
    assert not project.get("scripts")
    assert not project.get("entry-points")


def test_frontend_identity_and_non_empty_validation_commands() -> None:
    package = json.loads((PACKAGE_ROOT / "web" / "package.json").read_text(encoding="utf-8"))
    assert package["name"] == "@microsoft/agent-governance-studio"
    assert package["version"] == (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    assert package["description"].startswith("Public Preview")
    assert package["dependencies"]["react"].startswith("18.")
    assert package["dependencies"]["react-dom"].startswith("18.")
    assert "@tanstack/react-query" in package["dependencies"]
    assert {"vite", "typescript", "postcss", "tailwindcss"} <= (
        package["devDependencies"].keys()
    )
    assert package["devDependencies"]["tailwindcss"].startswith("3.")
    assert "@tailwindcss/vite" not in package["devDependencies"]
    assert package["scripts"] == {
        "lint": "eslint . --max-warnings=0",
        "test": "vitest run",
        "build": "tsc --noEmit && vite build",
    }
    for section in ("dependencies", "devDependencies"):
        assert all(
            version and version[0].isdigit() and "^" not in version and "~" not in version
            for version in package[section].values()
        )


def test_frontend_lockfile_pins_and_verifies_the_declared_dependencies() -> None:
    manifest = json.loads((PACKAGE_ROOT / "web" / "package.json").read_text(encoding="utf-8"))
    lock = json.loads((PACKAGE_ROOT / "web" / "package-lock.json").read_text(encoding="utf-8"))
    assert lock["lockfileVersion"] == 3
    assert lock["name"] == manifest["name"]
    assert lock["version"] == manifest["version"]
    for section in ("dependencies", "devDependencies"):
        assert lock["packages"][""][section] == manifest[section]
    for name, details in lock["packages"].items():
        if not name:
            continue
        assert not details.get("inBundle"), name
        package = name.rsplit("node_modules/", 1)[-1]
        version = details["version"]
        resolved = details["resolved"]
        parsed = urlparse(resolved)
        assert parsed.scheme == "https" and parsed.hostname == "registry.npmjs.org"
        assert not parsed.username and not parsed.password and not parsed.query and not parsed.fragment
        assert resolved == (
            f"https://registry.npmjs.org/{package}/-/"
            f"{package.rsplit('/', 1)[-1]}-{version}.tgz"
        )
        assert details["integrity"].startswith("sha512-"), name
