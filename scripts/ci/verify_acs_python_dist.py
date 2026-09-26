# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Verify the complete ACS Python release artifact set."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from pathlib import Path
import re
import tomllib
from typing import cast


_WHEEL_PATTERN = re.compile(
    r"^agent_control_specification-(?P<version>[A-Za-z0-9_.!+]+)-"
    r"cp311-abi3-(?P<platform>[A-Za-z0-9_.]+)\.whl$"
)
_SDIST_PATTERN = re.compile(
    r"^agent_control_specification-(?P<version>[A-Za-z0-9_.!+]+)\.tar\.gz$"
)
_EXPECTED_PLATFORM_KINDS = {
    "linux-x86_64",
    "linux-aarch64",
    "macos-x86_64",
    "macos-arm64",
    "windows-x86_64",
}


def _platform_kind(platform: str) -> str:
    if platform == "manylinux_2_28_x86_64":
        return "linux-x86_64"
    if platform == "manylinux_2_28_aarch64":
        return "linux-aarch64"
    if platform == "macosx_10_12_x86_64":
        return "macos-x86_64"
    if platform == "macosx_11_0_arm64":
        return "macos-arm64"
    if platform == "win_amd64":
        return "windows-x86_64"
    raise ValueError(f"unexpected ACS wheel platform: {platform}")


def _project_version(pyproject: Path) -> str:
    with pyproject.open("rb") as stream:
        document: dict[str, object] = tomllib.load(stream)
    project = document.get("project")
    if not isinstance(project, dict):
        raise ValueError(f"missing [project] table in {pyproject}")
    version = cast(Mapping[str, object], project).get("version")
    if not isinstance(version, str) or not version:
        raise ValueError(f"missing project.version in {pyproject}")
    return version


def verify_distribution(directory: Path, pyproject: Path) -> tuple[str, set[str]]:
    """Validate one complete ACS Python distribution directory."""
    resolved_directory = directory.resolve(strict=True)
    if not resolved_directory.is_dir():
        raise ValueError(f"distribution path is not a directory: {resolved_directory}")

    entries = sorted(resolved_directory.iterdir())
    if any(not entry.is_file() for entry in entries):
        raise ValueError("ACS distribution directory must contain regular files only")
    if len(entries) != 6:
        raise ValueError(f"expected exactly six ACS artifacts, found {len(entries)}")

    expected_version = _project_version(pyproject.resolve(strict=True))
    versions: set[str] = set()
    platform_kinds: set[str] = set()
    sdist_count = 0
    for entry in entries:
        if wheel_match := _WHEEL_PATTERN.fullmatch(entry.name):
            versions.add(wheel_match.group("version"))
            kind = _platform_kind(wheel_match.group("platform"))
            if kind in platform_kinds:
                raise ValueError(f"duplicate ACS wheel platform: {kind}")
            platform_kinds.add(kind)
            continue
        if sdist_match := _SDIST_PATTERN.fullmatch(entry.name):
            versions.add(sdist_match.group("version"))
            sdist_count += 1
            continue
        raise ValueError(f"unexpected ACS distribution artifact: {entry.name}")

    if versions != {expected_version}:
        raise ValueError(
            f"ACS artifact versions {sorted(versions)} do not match {expected_version}"
        )
    if platform_kinds != _EXPECTED_PLATFORM_KINDS:
        missing = sorted(_EXPECTED_PLATFORM_KINDS - platform_kinds)
        extra = sorted(platform_kinds - _EXPECTED_PLATFORM_KINDS)
        raise ValueError(
            f"ACS wheel platform mismatch; missing={missing}, extra={extra}"
        )
    if sdist_count != 1:
        raise ValueError(f"expected one ACS source distribution, found {sdist_count}")
    return expected_version, platform_kinds


def main(argv: Sequence[str] | None = None) -> int:
    """Run the ACS Python distribution verification gate."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--pyproject", type=Path, required=True)
    args = parser.parse_args(argv)
    version, platforms = verify_distribution(args.directory, args.pyproject)
    print(f"Verified ACS Python {version} for {', '.join(sorted(platforms))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
