# Copyright (c) 2026 Tom Farley (ScopeBlind).
# Licensed under the MIT License.
"""CLI entry point for the sb-runtime governance skill."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sb_runtime_agentmesh.receipts import Signer, verify_receipt
from sb_runtime_agentmesh.skill import GovernanceSkill, SandboxBackend


def _load_signer(key_path: Path | None) -> Signer:
    if key_path is None:
        return Signer.generate()
    return Signer.from_pem(key_path.read_bytes())


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="sb-runtime-governance")
    sub = parser.add_subparsers(dest="command")

    cp = sub.add_parser(
        "check-policy",
        help="Evaluate policy and emit a signed decision receipt",
    )
    cp.add_argument("--action", required=True)
    cp.add_argument("--context", default="{}")
    cp.add_argument("--policy-dir", required=True)
    cp.add_argument(
        "--sandbox-backend",
        choices=[b.value for b in SandboxBackend],
        default=SandboxBackend.SB_RUNTIME_BUILTIN.value,
    )
    cp.add_argument("--ring", type=int, default=3)
    cp.add_argument("--key", type=Path, default=None, help="Operator Ed25519 key (PEM)")
    cp.add_argument("--no-sign", action="store_true", help="Skip receipt signing")
    cp.add_argument(
        "--receipts-dir",
        type=Path,
        default=None,
        help="If set, write the signed receipt to <receipts-dir>/<timestamp>.json",
    )

    ts = sub.add_parser("trust-score")
    ts.add_argument("--agent-did", required=True)

    vf = sub.add_parser("verify", help="Verify a receipt file against an Ed25519 public key (PEM)")
    vf.add_argument("receipt", type=Path)
    vf.add_argument("--public-key", type=Path, required=True)

    pk = sub.add_parser("public-key", help="Print operator public key (PEM)")
    pk.add_argument("--key", type=Path, default=None)

    args = parser.parse_args(argv)

    if args.command == "check-policy":
        signer = _load_signer(args.key)
        skill = GovernanceSkill(
            policy_dir=Path(args.policy_dir),
            signer=signer,
            sandbox_backend=SandboxBackend(args.sandbox_backend),
            ring=args.ring,
        )
        ctx = json.loads(args.context) if args.context else {}
        decision = skill.check_policy(args.action, ctx, sign=not args.no_sign)
        output = {
            "allowed": decision.allowed,
            "action": decision.action,
            "reason": decision.reason,
            "policy_name": decision.policy_name,
            "policy_digest": decision.policy_digest,
            "ring": decision.ring,
            "sandbox_backend": decision.sandbox_backend.value,
            "receipt": decision.receipt,
        }
        if args.receipts_dir and decision.receipt is not None:
            args.receipts_dir.mkdir(parents=True, exist_ok=True)
            from datetime import datetime, timezone

            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            out_path = args.receipts_dir / f"{stamp}.json"
            out_path.write_text(json.dumps(decision.receipt, indent=2, sort_keys=True))
            output["receipt_path"] = str(out_path)
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0 if decision.allowed else 1

    if args.command == "trust-score":
        skill = GovernanceSkill()
        print(
            json.dumps(
                {
                    "agent_did": args.agent_did,
                    "trust_score": skill.get_trust_score(args.agent_did),
                }
            )
        )
        return 0

    if args.command == "verify":
        from cryptography.hazmat.primitives import serialization

        pub = serialization.load_pem_public_key(args.public_key.read_bytes())
        envelope = json.loads(args.receipt.read_text())
        ok = verify_receipt(envelope, pub)
        print(json.dumps({"verified": ok, "kid": envelope.get("signature", {}).get("kid")}))
        return 0 if ok else 1

    if args.command == "public-key":
        signer = _load_signer(args.key)
        sys.stdout.write(signer.public_pem().decode("ascii"))
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
