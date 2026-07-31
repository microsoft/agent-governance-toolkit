"""Install one ACS wheel in isolation and exercise its native extension."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping, Sequence
import importlib.machinery
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
from types import ModuleType
from typing import cast


def _exercise_installed_extension(package_dir: Path) -> Path:
    """Load and exercise an already-installed ACS native extension."""
    resolved_package_dir = package_dir.resolve(strict=True)
    if not resolved_package_dir.is_dir():
        raise ValueError(f"package path is not a directory: {resolved_package_dir}")
    candidates = [
        resolved_package_dir / f"_native{suffix}"
        for suffix in importlib.machinery.EXTENSION_SUFFIXES
        if (resolved_package_dir / f"_native{suffix}").is_file()
    ]
    if len(candidates) != 1:
        raise RuntimeError(f"expected one native extension, found {candidates}")

    package = ModuleType("agent_control_specification")
    setattr(package, "__path__", [str(resolved_package_dir)])
    sys.modules[package.__name__] = package
    module_name = "agent_control_specification._native"
    spec = importlib.util.spec_from_file_location(module_name, candidates[0])
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {candidates[0]}")
    native = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = native
    spec.loader.exec_module(native)

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
    return candidates[0]


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
        package_dir = Path(target) / "agent_control_specification"
        subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--installed-package",
                str(package_dir),
            ],
            check=True,
            timeout=120,
        )


def main(argv: Sequence[str] | None = None) -> int:
    """Run the ACS wheel smoke test."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path, nargs="?")
    parser.add_argument("--installed-package", type=Path)
    args = parser.parse_args(argv)
    if (args.wheel is None) == (args.installed_package is None):
        parser.error("provide exactly one wheel or --installed-package")
    if args.installed_package is not None:
        extension = _exercise_installed_extension(args.installed_package)
        print(f"Loaded and exercised {extension.name}")
        return 0
    if args.wheel is None:
        raise RuntimeError("wheel argument was not validated")
    smoke_wheel(args.wheel)
    print(f"Installed and exercised the native extension from {args.wheel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
