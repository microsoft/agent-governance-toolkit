#!/usr/bin/env python3
from __future__ import annotations

import json
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
    "integrations/annotators/Cargo.toml": "agent_control_specification_annotators",
    "integrations/otel/Cargo.toml": "agent_control_specification_otel",
}


def read_toml(path: str) -> dict:
    return tomllib.loads((ROOT / path).read_text())


def add_error(errors: list[str], path: str, field: str, expected: str, actual: str | None) -> None:
    errors.append(f"{path}: expected {field} {expected!r}, got {actual!r}")


def main() -> int:
    errors: list[str] = []
    versions: dict[str, str] = {}

    for path, expected_name in RUST_PACKAGES.items():
        package = read_toml(path)["package"]
        if package.get("name") != expected_name:
            add_error(errors, path, "package.name", expected_name, package.get("name"))
        versions[path] = package.get("version", "")

    python_project = read_toml("sdk/python/pyproject.toml")
    py_project = python_project["project"]
    if py_project.get("name") != "agent-control-specification":
        add_error(errors, "sdk/python/pyproject.toml", "project.name", "agent-control-specification", py_project.get("name"))
    if python_project.get("tool", {}).get("maturin", {}).get("module-name") != "agent_control_specification._native":
        add_error(
            errors,
            "sdk/python/pyproject.toml",
            "tool.maturin.module-name",
            "agent_control_specification._native",
            python_project.get("tool", {}).get("maturin", {}).get("module-name"),
        )
    versions["sdk/python/pyproject.toml"] = py_project.get("version", "")

    node_package = json.loads((ROOT / "sdk/node/package.json").read_text())
    if node_package.get("name") != "agent-control-specification":
        add_error(errors, "sdk/node/package.json", "name", "agent-control-specification", node_package.get("name"))
    if node_package.get("napi", {}).get("name") != "agent-control-specification":
        add_error(errors, "sdk/node/package.json", "napi.name", "agent-control-specification", node_package.get("napi", {}).get("name"))
    versions["sdk/node/package.json"] = node_package.get("version", "")

    dotnet_path = "sdk/dotnet/src/AgentControlSpecification/AgentControlSpecification.csproj"
    dotnet_root = ET.parse(ROOT / dotnet_path).getroot()
    package_id = dotnet_root.findtext(".//PackageId")
    if package_id != "AgentControlSpecification":
        add_error(errors, dotnet_path, "PackageId", "AgentControlSpecification", package_id)
    versions[dotnet_path] = dotnet_root.findtext(".//Version") or ""

    expected_version = versions["core/Cargo.toml"]
    for path, version in sorted(versions.items()):
        if version != expected_version:
            add_error(errors, path, "version", expected_version, version)

    if errors:
        print("Package metadata drift detected", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(f"Package metadata is consistent for version {expected_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
