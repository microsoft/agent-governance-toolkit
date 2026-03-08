#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Governance Toolkit CLI.

Commands:
    verify      Run OWASP ASI 2026 governance verification
    integrity   Verify or generate module integrity manifest
"""

from __future__ import annotations

import argparse
import sys


def cmd_verify(args: argparse.Namespace) -> int:
    """Run governance verification."""
    from agent_compliance.verify import GovernanceVerifier

    verifier = GovernanceVerifier()
    attestation = verifier.verify()

    if args.json:
        print(attestation.to_json())
    elif args.badge:
        print(attestation.badge_markdown())
    else:
        print(attestation.summary())

    return 0 if attestation.passed else 1


def cmd_integrity(args: argparse.Namespace) -> int:
    """Run integrity verification or generate manifest."""
    from agent_compliance.integrity import IntegrityVerifier

    if args.generate:
        verifier = IntegrityVerifier()
        manifest = verifier.generate_manifest(args.generate)
        print(f"Manifest written to {args.generate}")
        print(f"  Files hashed: {len(manifest['files'])}")
        print(f"  Functions hashed: {len(manifest['functions'])}")
        return 0

    verifier = IntegrityVerifier(manifest_path=args.manifest)
    report = verifier.verify()

    if args.json:
        import json

        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.summary())

    return 0 if report.passed else 1


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

    args = parser.parse_args()

    if args.command == "verify":
        return cmd_verify(args)
    elif args.command == "integrity":
        return cmd_integrity(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
