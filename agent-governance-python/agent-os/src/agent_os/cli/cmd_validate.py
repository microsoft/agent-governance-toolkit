# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Validate native ACS manifests from the ``agentos`` CLI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .output import Colors


def _manifest_files(raw_paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for raw_path in raw_paths:
        if "*" in raw_path or "?" in raw_path:
            files.extend(sorted(Path(".").glob(raw_path)))
        else:
            files.append(Path(raw_path))
    return files


def _validate_manifest(path: Path) -> tuple[list[str], list[str]]:
    """Return native manifest errors and warnings for one path."""
    from agt.policies import AgtManifest

    errors: list[str] = []
    warnings: list[str] = []
    if not path.is_file():
        return [f"{path}: File not found"], warnings
    if path.suffix.lower() not in {".yaml", ".yml", ".json"}:
        return [f"{path}: Manifest must be YAML or JSON"], warnings

    try:
        manifest = AgtManifest.from_path(path)
        manifest.resolved_document(path.parent)
    except Exception as exc:
        return [f"{path}: {exc}"], warnings

    if not manifest.intervention_points:
        warnings.append(f"{path}: Manifest defines no intervention points")
    return errors, warnings


def _json_result(
    *,
    files: list[Path],
    errors: list[str],
    warnings: list[str],
) -> dict[str, Any]:
    return {
        "passed": not errors,
        "files": [str(path) for path in files],
        "errors": errors,
        "warnings": warnings,
    }


def cmd_validate(args: argparse.Namespace) -> int:
    """Validate one or more native ACS manifests."""
    files = _manifest_files(list(getattr(args, "files", ()) or ()))
    if not files:
        print("No manifest files specified.")
        print("Pass a native ACS manifest path or glob.")
        return 0

    all_errors: list[str] = []
    all_warnings: list[str] = []
    for path in files:
        errors, warnings = _validate_manifest(path)
        all_errors.extend(errors)
        all_warnings.extend(warnings)

    strict = bool(getattr(args, "strict", False))
    if strict and all_warnings:
        all_errors.extend(
            f"{warning} (strict mode)" for warning in all_warnings
        )

    if bool(getattr(args, "json", False)):
        print(
            json.dumps(
                _json_result(
                    files=files,
                    errors=all_errors,
                    warnings=all_warnings,
                ),
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(f"\n{Colors.BOLD}Validating Native ACS Manifests{Colors.RESET}\n")
        for path in files:
            state = (
                f"{Colors.RED}FAILED{Colors.RESET}"
                if any(error.startswith(f"{path}:") for error in all_errors)
                else f"{Colors.GREEN}VALID{Colors.RESET}"
            )
            print(f"  {path}: {state}")
        for warning in all_warnings:
            print(f"  {Colors.YELLOW}warning{Colors.RESET}: {warning}")
        for error in all_errors:
            print(f"  {Colors.RED}error{Colors.RESET}: {error}")

    return 1 if all_errors else 0
