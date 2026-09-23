#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Offline verifier for MCP governance receipt chains.

Verifies Ed25519 signatures, RFC 8785 canonical payloads, and hash-chain
contiguity from a JSON export file.  No network access required.

Usage:
    python scripts/verify_receipts.py receipts.json [--json]
"""

import argparse
import json
import sys
from typing import Any, Dict, List, Tuple

from mcp_receipt_governed.receipt import (
    GovernanceReceipt,
    verify_receipt,
    verify_receipt_authorization,
)

_EXIT_OK = 0
_EXIT_CHAIN_ERROR = 1
_EXIT_LOAD_ERROR = 2


def _reconstruct(data: Dict[str, Any]) -> GovernanceReceipt:
    return GovernanceReceipt(
        receipt_id=data.get("receipt_id", ""),
        tool_name=data.get("tool_name", ""),
        agent_did=data.get("agent_did", ""),
        cedar_policy_id=data.get("cedar_policy_id", ""),
        cedar_decision=data.get("cedar_decision", "deny"),
        args_hash=data.get("args_hash", ""),
        timestamp=data.get("timestamp", 0.0),
        session_id=data.get("session_id"),
        parent_receipt_hash=data.get("parent_receipt_hash"),
        signature=data.get("signature"),
        signer_public_key=data.get("signer_public_key"),
        assurance_level=data.get("assurance_level", "self_attested"),
        authorizer_id=data.get("authorizer_id"),
        authorization_expires_at=data.get("authorization_expires_at"),
        authorization_nonce=data.get("authorization_nonce"),
        authorization_signature=data.get("authorization_signature"),
        authorizer_public_key=data.get("authorizer_public_key"),
        error=data.get("error"),
    )


def verify_chain(
    receipts_data: List[Dict[str, Any]],
    *,
    trusted_authorizer_keys: List[str],
    require_external_authorization: bool,
) -> Tuple[int, List[Dict[str, Any]]]:
    """Verify a chain of exported receipts.

    Returns (exit_code, per_receipt_results). exit_code 0 = valid, 1 = errors.
    """
    if not receipts_data:
        print("  (empty chain - nothing to verify)")
        return _EXIT_OK, []

    total_errors = 0
    expected_parent = None
    results: List[Dict[str, Any]] = []

    for i, data in enumerate(receipts_data):
        r = _reconstruct(data)
        rid = r.receipt_id[:12] + "..." if len(r.receipt_id) > 12 else r.receipt_id
        print(f"  [{i}] {rid}  (tool: {r.tool_name})")
        errs: List[str] = []

        if r.parent_receipt_hash != expected_parent:
            msg = (
                f"Hash chain broken - expected {(expected_parent or 'None')[:16]}..., "
                f"got {(r.parent_receipt_hash or 'None')[:16]}..."
            )
            print(f"      [FAIL] {msg}")
            errs.append(msg)
        else:
            print("      [OK] Hash chain contiguous")

        stored = data.get("payload_hash")
        if stored and r.payload_hash() != stored:
            msg = "Payload hash mismatch"
            print(f"      [FAIL] {msg}")
            errs.append(msg)
        else:
            print("      [OK] Payload hash verified")

        if r.signature:
            if verify_receipt(r):
                print("      [OK] Ed25519 signature valid")
            else:
                msg = "Ed25519 signature verification failed"
                print(f"      [FAIL] {msg}")
                errs.append(msg)
        else:
            print("      [WARN] Unsigned receipt")

        if r.assurance_level == "externally_authorized":
            authorization_errors = verify_receipt_authorization(
                r,
                trusted_authorizer_keys=trusted_authorizer_keys,
            )
            if authorization_errors:
                for error in authorization_errors:
                    print(f"      [FAIL] {error}")
                errs.extend(authorization_errors)
            else:
                print("      [OK] External authorization valid and trusted")
        elif r.assurance_level == "self_attested":
            if any(
                value is not None
                for value in (
                    r.authorizer_id,
                    r.authorization_expires_at,
                    r.authorization_nonce,
                    r.authorization_signature,
                    r.authorizer_public_key,
                )
            ):
                msg = "Self-attested receipt contains external authorization metadata"
                print(f"      [FAIL] {msg}")
                errs.append(msg)
            if require_external_authorization:
                msg = "External authorization is required but receipt is self-attested"
                print(f"      [FAIL] {msg}")
                errs.append(msg)
        else:
            msg = f"Unknown assurance level {r.assurance_level!r}"
            print(f"      [FAIL] {msg}")
            errs.append(msg)

        total_errors += len(errs)
        expected_parent = r.payload_hash()
        results.append({"index": i, "receipt_id": r.receipt_id, "tool_name": r.tool_name, "passed": not errs, "errors": errs})
        print()

    return (_EXIT_OK if total_errors == 0 else _EXIT_CHAIN_ERROR), results


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify MCP governance receipt chains offline.")
    parser.add_argument("receipts_file", help="JSON file from ReceiptStore.export()")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Structured JSON output for CI/CD")
    parser.add_argument(
        "--trusted-authorizer-key",
        action="append",
        default=[],
        help="Trusted external authorizer Ed25519 public key (repeatable)",
    )
    parser.add_argument(
        "--require-external-authorization",
        action="store_true",
        help="Reject receipts that are only self-attested",
    )
    args = parser.parse_args()

    if not args.json_output:
        print("\n+------------------------------------------------------+")
        print("| MCP Receipt Chain - Offline Verification            |")
        print("+------------------------------------------------------+\n")

    try:
        with open(args.receipts_file, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        if args.json_output:
            print(json.dumps({"error": str(exc), "exit_code": _EXIT_LOAD_ERROR}, indent=2))
        else:
            print(f"  Error loading {args.receipts_file}: {exc}")
        return _EXIT_LOAD_ERROR

    if not args.json_output:
        print(f"  Loaded {len(data)} receipt(s) from {args.receipts_file}\n")

    exit_code, per_receipt = verify_chain(
        data,
        trusted_authorizer_keys=args.trusted_authorizer_key,
        require_external_authorization=args.require_external_authorization,
    )

    if args.json_output:
        print(json.dumps({"file": args.receipts_file, "total_receipts": len(data), "passed": exit_code == _EXIT_OK, "exit_code": exit_code, "receipts": per_receipt}, indent=2))
    elif exit_code == _EXIT_OK:
        print("  Verification passed - chain is contiguous and signatures are valid.\n")
    else:
        print("  Verification failed - the receipt chain has integrity issues.\n")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
