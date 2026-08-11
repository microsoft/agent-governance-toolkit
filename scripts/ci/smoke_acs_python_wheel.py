# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Install one ACS wheel in isolation and exercise its native extension."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping, Sequence
import importlib
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import cast


def _exercise_installed_package(install_dir: Path) -> Path:
    """Import the installed ACS package from an isolated path and exercise its native extension."""
    resolved_install_dir = install_dir.resolve(strict=True)
    if not resolved_install_dir.is_dir():
        raise ValueError(f"install path is not a directory: {resolved_install_dir}")
    # Import through the real machinery so a wheel with a broken package layout
    # (missing __init__.py or a submodule that cannot be imported) fails here instead of passing.
    sys.path.insert(0, str(resolved_install_dir))
    importlib.import_module("agent_control_specification")
    native = importlib.import_module("agent_control_specification._native")

    parse_manifest = cast(Callable[[str], object], native.parse_manifest)
    parsed = parse_manifest(
        "agent_control_specification_version: 0.3.1-beta\n"
        "metadata:\n  name: wheel-smoke\n"
    )
    if not isinstance(parsed, Mapping):
        raise RuntimeError("native manifest parser did not return a mapping")
    parsed_mapping = cast(Mapping[str, object], parsed)
    metadata = parsed_mapping.get("metadata")
    if not isinstance(metadata, Mapping):
        raise RuntimeError("native manifest parser returned invalid metadata")
    metadata_mapping = cast(Mapping[str, object], metadata)
    if metadata_mapping.get("name") != "wheel-smoke":
        raise RuntimeError("native manifest parser returned an unexpected result")
    native_file = getattr(native, "__file__", None)
    return Path(native_file) if native_file is not None else resolved_install_dir


def smoke_wheel(wheel: Path) -> None:
    """Load and exercise the native extension from an isolated wheel install."""
    resolved_wheel = wheel.resolve(strict=True)
    if resolved_wheel.suffix != ".whl":
        raise ValueError(f"expected a wheel path, received {resolved_wheel}")

    with tempfile.TemporaryDirectory(prefix="acs-wheel-smoke-") as target:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-compile",
                "--no-deps",
                "--target",
                target,
                str(resolved_wheel),
            ],
            check=True,
            timeout=120,
        )
        subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--install-dir",
                target,
            ],
            check=True,
            timeout=120,
        )


def main(argv: Sequence[str] | None = None) -> int:
    """Run the ACS wheel smoke test."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path, nargs="?")
    parser.add_argument("--install-dir", type=Path)
    args = parser.parse_args(argv)
    if (args.wheel is None) == (args.install_dir is None):
        parser.error("provide exactly one wheel or --install-dir")
    if args.install_dir is not None:
        extension = _exercise_installed_package(args.install_dir)
        print(f"Loaded and exercised {extension.name}")
        return 0
    if args.wheel is None:
        raise RuntimeError("wheel argument was not validated")
    smoke_wheel(args.wheel)
    print(f"Installed and exercised the native extension from {args.wheel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
