# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Pre-commit hooks for plugin manifest validation.

Entry points for ``.pre-commit-hooks.yaml``:

- ``validate-manifest`` — schema validation of plugin manifests
- ``evaluate-policy``   — policy evaluation of plugin manifests
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


def evaluate_policy_cli() -> int:
    """Evaluate plugin manifests against a governance policy.

    Returns 0 if all manifests comply, 1 if any violate.
    """
    parser = argparse.ArgumentParser(
        prog="evaluate-plugin-policy",
        description="Evaluate plugin manifests against governance policy",
    )
    parser.add_argument("files", nargs="+", help="Manifest files to evaluate")
    parser.add_argument(
        "--policy",
        required=True,
        help="Path to policy YAML file or directory",
    )
    args = parser.parse_args()

    try:
        from agent_os.policies import PolicyEvaluator
    except ImportError:
        print(
            "agent-os-kernel is required for policy evaluation. "
            "Install with: pip install agent-os-kernel",
            file=sys.stderr,
        )
        return 1

    evaluator = PolicyEvaluator()
    policy_path = Path(args.policy)
    if policy_path.is_dir():
        evaluator.load_policies(str(policy_path))
    else:
        evaluator.load_policies(str(policy_path.parent))

    violations = 0
    for filepath in args.files:
        path = Path(filepath)
        try:
            data = _load_manifest_file(path)
            manifest = PluginManifest(**data)

            context = {
                "plugin_name": manifest.name,
                "plugin_type": manifest.plugin_type.value,
                "capabilities": manifest.capabilities,
                "author": manifest.author,
                "has_signature": manifest.signature is not None,
            }

            decision = evaluator.evaluate(context)
            if decision.allowed:
                print(f"  ✓ {path}: {decision.action} — {decision.reason}")
            else:
                print(
                    f"  ✗ {path}: {decision.action} — {decision.reason}",
                    file=sys.stderr,
                )
                violations += 1

        except Exception as exc:  # noqa: BLE001
            print(f"  ✗ {path}: evaluation error — {exc}", file=sys.stderr)
            violations += 1

    if violations:
        print(f"\n{violations} manifest(s) violate policy.", file=sys.stderr)
        return 1

    print(f"\n{len(args.files)} manifest(s) comply with policy.")
    return 0


def main() -> None:
    """CLI dispatcher for ``python -m agent_marketplace.hooks``."""
    if len(sys.argv) < 2:
        print("Usage: python -m agent_marketplace.hooks <command> [args...]")
        print("Commands: validate-manifest, evaluate-policy")
        sys.exit(1)

    command = sys.argv.pop(1)

    if command == "validate-manifest":
        sys.exit(validate_manifest_cli())
    elif command == "evaluate-policy":
        sys.exit(evaluate_policy_cli())
    else:
        print(f"Unknown command: {command}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
