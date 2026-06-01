#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUST_PACKAGES = {
    "core/Cargo.toml": "agent_control_specification_core",
    "sdk/rust/Cargo.toml": "agent_control_specification",
    "sdk/python/Cargo.toml": "agent_control_specification_py",
    "sdk/node/Cargo.toml": "agent-control-specification-node",
    "integrations/rig/Cargo.toml": "agent_control_specification_rig",
    "integrations/openai/Cargo.toml": "agent_control_specification_openai",
    "integrations/mcp/Cargo.toml": "agent_control_specification_mcp",
    "integrations/annotators/Cargo.toml": "agent_control_specification_annotators",
    "integrations/otel/Cargo.toml": "agent_control_specification_otel",
}
PYTHON_PACKAGES = {
    "sdk/python/pyproject.toml": "agent-control-specification",
    "generator/pyproject.toml": "acs-generator",
}
DOTNET_PACKAGES = {
    "sdk/dotnet/src/AgentControlSpecification/AgentControlSpecification.csproj": "AgentControlSpecification",
    "sdk/dotnet/src/AgentControlSpecification.AI/AgentControlSpecification.AI.csproj": "AgentControlSpecification.AI",
    "sdk/dotnet/src/AgentControlSpecification.SemanticKernel/AgentControlSpecification.SemanticKernel.csproj": "AgentControlSpecification.SemanticKernel",
    "sdk/dotnet/src/AgentControlSpecification.AutoGen/AgentControlSpecification.AutoGen.csproj": "AgentControlSpecification.AutoGen",
    "sdk/dotnet/src/AgentControlSpecification.AgentFramework/AgentControlSpecification.AgentFramework.csproj": "AgentControlSpecification.AgentFramework",
}
NODE_OPTIONAL_PREFIXES = (
    "agent-control-specification-darwin-",
    "agent-control-specification-linux-",
    "agent-control-specification-win32-",
    "agent-control-specification-opa-",
)


def read_toml(path: str) -> dict:
    return tomllib.loads((ROOT / path).read_text())


def add_error(errors: list[str], path: str, field: str, expected: str, actual: str | None) -> None:
    errors.append(f"{path}: expected {field} {expected!r}, got {actual!r}")


def python_version_for(semver: str) -> str:
    match = re.fullmatch(r"(\d+\.\d+\.\d+)-beta\.(\d+)", semver)
    if match:
        return f"{match.group(1)}b{match.group(2)}"
    return semver


def is_node_optional_package(name: str) -> bool:
    return any(name.startswith(prefix) for prefix in NODE_OPTIONAL_PREFIXES)


def main() -> int:
    errors: list[str] = []
    versions: dict[str, str] = {}

    for path, expected_name in RUST_PACKAGES.items():
        package = read_toml(path)["package"]
        if package.get("name") != expected_name:
            add_error(errors, path, "package.name", expected_name, package.get("name"))
        if not package.get("description"):
            add_error(errors, path, "package.description", "non-empty description", package.get("description"))
        versions[path] = package.get("version", "")

    for path, expected_name in PYTHON_PACKAGES.items():
        python_project = read_toml(path)
        py_project = python_project["project"]
        if py_project.get("name") != expected_name:
            add_error(errors, path, "project.name", expected_name, py_project.get("name"))
        versions[path] = py_project.get("version", "")

    python_project = read_toml("sdk/python/pyproject.toml")
    if python_project.get("tool", {}).get("maturin", {}).get("module-name") != "agent_control_specification._native":
        add_error(
            errors,
            "sdk/python/pyproject.toml",
            "tool.maturin.module-name",
            "agent_control_specification._native",
            python_project.get("tool", {}).get("maturin", {}).get("module-name"),
        )

    node_package = json.loads((ROOT / "sdk/node/package.json").read_text())
    if node_package.get("name") != "agent-control-specification":
        add_error(errors, "sdk/node/package.json", "name", "agent-control-specification", node_package.get("name"))
    if node_package.get("napi", {}).get("name") != "agent-control-specification":
        add_error(errors, "sdk/node/package.json", "napi.name", "agent-control-specification", node_package.get("napi", {}).get("name"))
    versions["sdk/node/package.json"] = node_package.get("version", "")
    node_version = node_package.get("version", "")
    optional_dependencies = node_package.get("optionalDependencies", {})
    npm_package_dir = ROOT / "sdk/node/npm"
    optional_package_names: set[str] = set()
    for package_dir in sorted(path for path in npm_package_dir.iterdir() if path.is_dir()):
        package_path = package_dir / "package.json"
        if not package_path.exists():
            continue
        package_json = json.loads(package_path.read_text())
        package_name = package_json.get("name")
        if not isinstance(package_name, str) or not is_node_optional_package(package_name):
            continue
        optional_package_names.add(package_name)
        if package_name != package_dir.name:
            add_error(errors, str(package_path.relative_to(ROOT)), "name", package_dir.name, package_name)
        if package_json.get("version") != node_version:
            add_error(errors, str(package_path.relative_to(ROOT)), "version", node_version, package_json.get("version"))
        if optional_dependencies.get(package_name) != node_version:
            add_error(
                errors,
                "sdk/node/package.json",
                f"optionalDependencies.{package_name}",
                node_version,
                optional_dependencies.get(package_name),
            )

    for package_name in sorted(optional_dependencies):
        if is_node_optional_package(package_name) and package_name not in optional_package_names:
            add_error(errors, "sdk/node/npm", "optional package directory", package_name, None)

    for dotnet_path, expected_package_id in DOTNET_PACKAGES.items():
        dotnet_root = ET.parse(ROOT / dotnet_path).getroot()
        package_id = dotnet_root.findtext(".//PackageId")
        if package_id != expected_package_id:
            add_error(errors, dotnet_path, "PackageId", expected_package_id, package_id)
        versions[dotnet_path] = dotnet_root.findtext(".//Version") or ""

    expected_version = versions["core/Cargo.toml"]
    expected_python_version = python_version_for(expected_version)
    for path, version in sorted(versions.items()):
        expected = expected_python_version if path in PYTHON_PACKAGES else expected_version
        if version != expected:
            add_error(errors, path, "version", expected, version)

    if errors:
        print("Package metadata drift detected", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(f"Package metadata is consistent for version {expected_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
