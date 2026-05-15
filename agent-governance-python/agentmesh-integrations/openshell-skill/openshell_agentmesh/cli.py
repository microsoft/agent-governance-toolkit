# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""CLI entry point for the OpenShell governance skill."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from openshell_agentmesh.skill import GovernanceSkill


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="openshell-governance",
        description="Policy enforcement CLI for OpenShell sandboxed agents.",
    )
    sub = parser.add_subparsers(dest="command")

    cp = sub.add_parser("check-policy", help="Evaluate an action against loaded policies")
    cp.add_argument("--action", required=True, help="Action string to evaluate (e.g. shell:python)")
    cp.add_argument("--context", default="{}", help="JSON object with evaluation context")
    cp.add_argument("--policy-dir", required=True, help="Path to directory containing policy YAML files")

    ts = sub.add_parser("trust-score", help="Query the trust score for an agent DID")
    ts.add_argument("--agent-did", required=True, help="Agent DID to look up")

    args = parser.parse_args(argv)

    if args.command == "check-policy":
        policy_path = Path(args.policy_dir)
        if not policy_path.is_dir():
            print(json.dumps({"error": f"Policy directory not found: {args.policy_dir}"}), file=sys.stderr)
            return 2
        try:
            ctx = json.loads(args.context)
        except json.JSONDecodeError as exc:
            print(json.dumps({"error": f"Invalid --context JSON: {exc}"}), file=sys.stderr)
            return 2
        skill = GovernanceSkill(policy_dir=policy_path)
        d = skill.check_policy(args.action, ctx)
        print(json.dumps({"allowed": d.allowed, "action": d.action, "reason": d.reason, "policy_name": d.policy_name}))
        return 0 if d.allowed else 1

    if args.command == "trust-score":
        skill = GovernanceSkill()
        print(json.dumps({"agent_did": args.agent_did, "trust_score": skill.get_trust_score(args.agent_did)}))
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())