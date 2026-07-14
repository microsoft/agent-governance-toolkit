# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Pre-commit hooks for plugin manifest validation.

Entry points for ``.pre-commit-hooks.yaml``:

- ``validate-manifest`` — schema validation of plugin manifests
- ``evaluate-governance`` — native runtime evaluation of plugin manifests
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from agent_marketplace.exceptions import MarketplaceError
from agent_marketplace.manifest import PluginManifest


def _load_manifest_file(path: Path) -> dict:
    """Load a manifest from JSON or YAML."""
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        return json.loads(text)
    return yaml.safe_load(text)


def validate_manifest_cli() -> int:
    """Validate plugin manifest files against the PluginManifest schema.

    Returns 0 if all files are valid, 1 if any fail.
    """
    parser = argparse.ArgumentParser(
        prog="validate-plugin-manifest",
        description="Validate plugin manifest schema",
    )
    parser.add_argument("files", nargs="+", help="Manifest files to validate")
    args = parser.parse_args()

    failures = 0
    for filepath in args.files:
        path = Path(filepath)
        try:
            data = _load_manifest_file(path)
            PluginManifest(**data)
            print(f"  ✓ {path}")
        except MarketplaceError as exc:
            print(f"  ✗ {path}: {exc}", file=sys.stderr)
            failures += 1
        except (json.JSONDecodeError, yaml.YAMLError) as exc:
            print(f"  ✗ {path}: invalid format — {exc}", file=sys.stderr)
            failures += 1
        except Exception as exc:  # noqa: BLE001
            print(f"  ✗ {path}: {exc}", file=sys.stderr)
            failures += 1

    if failures:
        print(f"\n{failures} manifest(s) failed validation.", file=sys.stderr)
        return 1

    print(f"\n{len(args.files)} manifest(s) valid.")
    return 0


def evaluate_governance_cli() -> int:
    """Evaluate plugin manifests against a native ACS manifest."""
    parser = argparse.ArgumentParser(
        prog="evaluate-plugin-governance",
        description="Evaluate plugin manifests with the native ACS runtime",
    )
    parser.add_argument("files", nargs="+", help="Plugin manifest files to evaluate")
    parser.add_argument("--manifest", required=True, help="Path to a native ACS manifest")
    args = parser.parse_args()

    try:
        from agt.policies import AgtRuntime
        runtime = AgtRuntime.from_manifest(Path(args.manifest))
    except (ImportError, OSError, ValueError) as exc:
        print(f"Unable to load native governance runtime: {exc}", file=sys.stderr)
        return 1

    violations = 0
    for filepath in args.files:
        path = Path(filepath)
        try:
            data = _load_manifest_file(path)
            plugin = PluginManifest(**data)
            snapshot = {
                "plugin_name": plugin.name,
                "plugin_type": plugin.plugin_type.value,
                "capabilities": plugin.capabilities,
                "author": plugin.author,
                "has_signature": plugin.signature is not None,
            }
            evaluation = runtime.evaluate("plugin_manifest", snapshot)
            message = evaluation.message or evaluation.reason_code or evaluation.verdict
            if evaluation.is_allowed():
                print(f"  ✓ {path}: {evaluation.verdict} — {message}")
            else:
                print(f"  ✗ {path}: {evaluation.verdict} — {message}", file=sys.stderr)
                violations += 1
        except Exception as exc:  # noqa: BLE001
            print(f"  ✗ {path}: evaluation error — {exc}", file=sys.stderr)
            violations += 1

    if violations:
        print(f"\n{violations} manifest(s) failed governance.", file=sys.stderr)
        return 1
    print(f"\n{len(args.files)} manifest(s) passed governance.")
    return 0


def main() -> None:
    """CLI dispatcher for ``python -m agent_marketplace.hooks``."""
    if len(sys.argv) < 2:
        print("Usage: python -m agent_marketplace.hooks <command> [args...]")
        print("Commands: validate-manifest, evaluate-governance")
        sys.exit(1)

    command = sys.argv.pop(1)

    if command == "validate-manifest":
        sys.exit(validate_manifest_cli())
    elif command == "evaluate-governance":
        sys.exit(evaluate_governance_cli())
    else:
        print(f"Unknown command: {command}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
