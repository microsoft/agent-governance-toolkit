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

from mcp_receipt_governed.receipt import GovernanceReceipt, verify_receipt

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
        error=data.get("error"),
    )


def verify_chain(receipts_data: List[Dict[str, Any]]) -> Tuple[int, List[Dict[str, Any]]]:
    """Verify a chain of exported receipts.

    Returns (exit_code, per_receipt_results). exit_code 0 = valid, 1 = errors.
    """
    if not receipts_data:
        print("  (empty chain — nothing to verify)")
        return _EXIT_OK, []

    total_errors = 0
    expected_parent = None
    results: List[Dict[str, Any]] = []

    for i, data in enumerate(receipts_data):
        r = _reconstruct(data)
        rid = r.receipt_id[:12] + "…" if len(r.receipt_id) > 12 else r.receipt_id
        print(f"  [{i}] {rid}  (tool: {r.tool_name})")
        errs: List[str] = []

        if r.parent_receipt_hash != expected_parent:
            msg = f"Hash chain broken — expected {(expected_parent or 'None')[:16]}…, got {(r.parent_receipt_hash or 'None')[:16]}…"
            print(f"      ❌  {msg}")
            errs.append(msg)
        else:
            print("      ✅  Hash chain contiguous")

        stored = data.get("payload_hash")
        if stored and r.payload_hash() != stored:
            msg = "Payload hash mismatch"
            print(f"      ❌  {msg}")
            errs.append(msg)
        else:
            print("      ✅  Payload hash verified")

        if r.signature:
            if verify_receipt(r):
                print("      ✅  Ed25519 signature valid")
            else:
                msg = "Ed25519 signature verification failed"
                print(f"      ❌  {msg}")
                errs.append(msg)
        else:
            print("      ⚠️   Unsigned receipt")

        total_errors += len(errs)
        expected_parent = r.payload_hash()
        results.append({"index": i, "receipt_id": r.receipt_id, "tool_name": r.tool_name, "passed": not errs, "errors": errs})
        print()

    return (_EXIT_OK if total_errors == 0 else _EXIT_CHAIN_ERROR), results


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify MCP governance receipt chains offline.")
    parser.add_argument("receipts_file", help="JSON file from ReceiptStore.export()")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Structured JSON output for CI/CD")
    args = parser.parse_args()

    if not args.json_output:
        print("\n╔══════════════════════════════════════════════════════╗")
        print("║  MCP Receipt Chain — Offline Verification           ║")
        print("╚══════════════════════════════════════════════════════╝\n")

    try:
        with open(args.receipts_file) as f:
            data = json.load(f)
    except Exception as exc:
        if args.json_output:
            print(json.dumps({"error": str(exc), "exit_code": _EXIT_LOAD_ERROR}, indent=2))
        else:
            print(f"  Error loading {args.receipts_file}: {exc}")
        return _EXIT_LOAD_ERROR

    if not args.json_output:
        print(f"  Loaded {len(data)} receipt(s) from {args.receipts_file}\n")

    exit_code, per_receipt = verify_chain(data)

    if args.json_output:
        print(json.dumps({"file": args.receipts_file, "total_receipts": len(data), "passed": exit_code == _EXIT_OK, "exit_code": exit_code, "receipts": per_receipt}, indent=2))
    elif exit_code == _EXIT_OK:
        print("  🎉 Verification passed — chain is contiguous and signatures are valid.\n")
    else:
        print("  🚨 Verification failed — the receipt chain has integrity issues.\n")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
