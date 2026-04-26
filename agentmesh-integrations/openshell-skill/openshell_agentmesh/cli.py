# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""CLI entry point for the OpenShell governance skill."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from openshell_agentmesh.skill import GovernanceSkill

def main(argv=None):
    parser = argparse.ArgumentParser(prog="openshell-governance")
    sub = parser.add_subparsers(dest="command")
    cp = sub.add_parser("check-policy")
    cp.add_argument("--action", required=True)
    cp.add_argument("--context", default="{}")
    cp.add_argument("--policy-dir", required=True)
    ts = sub.add_parser("trust-score")
    ts.add_argument("--agent-did", required=True)
    args = parser.parse_args(argv)
    if args.command == "check-policy":
        skill = GovernanceSkill(policy_dir=Path(args.policy_dir))
        ctx = json.loads(args.context) if args.context else {}
        d = skill.check_policy(args.action, ctx)
        print(json.dumps({"allowed": d.allowed, "action": d.action, "reason": d.reason, "policy_name": d.policy_name}))
        return 0 if d.allowed else 1
    elif args.command == "trust-score":
        skill = GovernanceSkill()
        print(json.dumps({"agent_did": args.agent_did, "trust_score": skill.get_trust_score(args.agent_did)}))
        return 0
    parser.print_help()
    return 1

if __name__ == "__main__":
    sys.exit(main())