#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Governance Toolkit CLI.

Commands:
    verify       Run OWASP ASI 2026 governance verification
    integrity    Verify or generate module integrity manifest
    lint-policy  Lint YAML policy files for common mistakes
"""

from __future__ import annotations

import argparse
from typing import Optional
import os
import sys
import json


def handle_error(e: Exception, output_json: bool = False, custom_msg: Optional[str] = None):
    """Centralized error handler for compliance CLI."""
    is_known = isinstance(e, (IOError, ValueError, KeyError, PermissionError, FileNotFoundError))

    if custom_msg:
        err_msg = custom_msg
    elif is_known:
        err_msg = "A validation or file access error occurred."
    else:
        err_msg = "A governance processing error occurred."

    if output_json:
        print(json.dumps({"status": "fail" if not is_known else "error", "message": err_msg, "type": "ValidationError" if is_known else "InternalError"}, indent=2))
    else:
        print(f"Error: {err_msg}", file=sys.stderr)


def cmd_verify(args: argparse.Namespace) -> int:
    """Run governance verification."""
    from agent_compliance.verify import GovernanceVerifier

    try:
        verifier = GovernanceVerifier()
        attestation = verifier.verify()

        if args.json:
            print(attestation.to_json())
        elif args.badge:
            print(attestation.badge_markdown())
        else:
            print(attestation.summary())

        return 0 if attestation.passed else 1
    except Exception as e:
        handle_error(e, args.json)
        return 1


def cmd_integrity(args: argparse.Namespace) -> int:
    """Run integrity verification or generate manifest."""
    from agent_compliance.integrity import IntegrityVerifier

    try:
        if args.generate and args.manifest:
            print(
                "Error: --manifest and --generate are mutually exclusive",
                file=sys.stderr,
            )
            return 1

        if args.generate:
            verifier = IntegrityVerifier()
            manifest = verifier.generate_manifest(args.generate)
            print(f"Manifest written to {args.generate}")
            print(f"  Files hashed: {len(manifest['files'])}")
            print(f"  Functions hashed: {len(manifest['functions'])}")
            return 0

        if args.manifest and not os.path.exists(args.manifest):
            print(
                f"Error: manifest file not found: {args.manifest}",
                file=sys.stderr,
            )
            return 1

        verifier = IntegrityVerifier(manifest_path=args.manifest)
        report = verifier.verify()

        if args.json:
            import json

            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(report.summary())

        return 0 if report.passed else 1
    except Exception as e:
        handle_error(e, args.json)
        return 1


def cmd_lint_policy(args: argparse.Namespace) -> int:
    """Lint YAML policy files for common mistakes."""
    from agent_compliance.lint_policy import lint_path

    try:
        result = lint_path(args.path)

        if args.json:
            import json

            print(json.dumps(result.to_dict(), indent=2))
        else:
            for msg in result.messages:
                print(msg)
            if result.messages:
                print()
            print(result.summary())

        if args.strict and result.warnings:
            return 1
        return 0 if result.passed else 1
    except Exception as e:
        handle_error(e, args.json)
        return 1


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="agent-compliance",
        description="Agent Governance Toolkit — Compliance & Verification CLI",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # verify command
    verify_parser = subparsers.add_parser(
        "verify",
        help="Run OWASP ASI 2026 governance verification",
    )
    verify_parser.add_argument(
        "--json", action="store_true", help="Output JSON attestation"
    )
    verify_parser.add_argument(
        "--badge", action="store_true", help="Output markdown badge only"
    )

    # integrity command
    integrity_parser = subparsers.add_parser(
        "integrity",
        help="Verify or generate module integrity manifest",
    )
    integrity_parser.add_argument(
        "--manifest", type=str, help="Path to integrity.json manifest to verify against"
    )
    integrity_parser.add_argument(
        "--generate",
        type=str,
        metavar="OUTPUT_PATH",
        help="Generate integrity manifest at the given path",
    )
    integrity_parser.add_argument(
        "--json", action="store_true", help="Output JSON report"
    )

    # lint-policy command
    lint_parser = subparsers.add_parser(
        "lint-policy",
        help="Lint YAML policy files for common mistakes",
    )
    lint_parser.add_argument(
        "path", type=str, help="Path to a YAML policy file or directory"
    )
    lint_parser.add_argument(
        "--json", action="store_true", help="Output JSON report"
    )
    lint_parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings as errors (exit 1 if any warnings)",
    )

    args = parser.parse_args()

    if args.command == "verify":
        return cmd_verify(args)
    elif args.command == "integrity":
        return cmd_integrity(args)
    elif args.command == "lint-policy":
        return cmd_lint_policy(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
