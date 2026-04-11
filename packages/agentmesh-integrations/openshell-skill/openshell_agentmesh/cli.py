# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""CLI entry point for the OpenShell governance skill."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from openshell_agentmesh.skill import GovernanceSkill


def _check_policy(args: argparse.Namespace) -> int:
    """Evaluate an action against governance policies."""
    skill = GovernanceSkill(policy_dir=Path(args.policy_dir))
    context = json.loads(args.context) if args.context else {}
    decision = skill.check_policy(args.action, context)
    print(json.dumps({
        "allowed": decision.allowed,
        "action": decision.action,
        "reason": decision.reason,
        "policy_name": decision.policy_name,
    }))
    return 0 if decision.allowed else 1


def _trust_score(args: argparse.Namespace) -> int:
    """Get the trust score for an agent DID."""
    skill = GovernanceSkill()
    score = skill.get_trust_score(args.agent_did)
    print(json.dumps({"agent_did": args.agent_did, "trust_score": score}))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="openshell-governance",
        description="Agent Governance Toolkit — OpenShell skill CLI",
    )
    sub = parser.add_subparsers(dest="command")

    # check-policy
    cp = sub.add_parser("check-policy", help="Check if an action is allowed by policy")
    cp.add_argument("--action", required=True, help="Action to evaluate")
    cp.add_argument("--context", default="{}", help="JSON context string")
    cp.add_argument("--policy-dir", required=True, help="Directory with YAML policies")

    # trust-score
    ts = sub.add_parser("trust-score", help="Get trust score for an agent")
    ts.add_argument("--agent-did", required=True, help="Agent DID")

    args = parser.parse_args(argv)
    if args.command == "check-policy":
        return _check_policy(args)
    elif args.command == "trust-score":
        return _trust_score(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
