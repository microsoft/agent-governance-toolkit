# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Command-line policy check for the OpenShell ACS integration."""

from __future__ import annotations

import argparse
import json
import sys

from .skill import GovernanceSkill, ShellPolicyViolation


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="openshell-governance")
    parser.add_argument("--manifest", required=True, help="Path to an ACS manifest")
    parser.add_argument("--agent-id")
    parser.add_argument("--shell", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if not args.command:
        parser.error("a command is required")

    command: object = " ".join(args.command) if args.shell else args.command
    skill = GovernanceSkill.from_manifest(args.manifest, agent_id=args.agent_id)
    try:
        transformed, result = skill.authorize_shell_command(
            command, api="openshell-governance", shell=args.shell
        )
    except ShellPolicyViolation as exc:
        print(
            json.dumps(
                {"decision": exc.result.verdict.decision.value, "reason": str(exc)}
            )
        )
        return 1
    except PermissionError as exc:
        print(json.dumps({"decision": "deny", "reason": str(exc)}))
        return 1
    print(
        json.dumps(
            {
                "decision": result.verdict.decision.value,
                "command": transformed,
                "reason": result.verdict.reason,
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
