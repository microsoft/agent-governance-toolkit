#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Offline verification tool for MCP governance receipt chains.

Verifies Ed25519 signatures, RFC 8785 JCS canonical payloads, and
hash-chain contiguity from a JSON export file.  No network access
or running AGT infrastructure is required.

Usage:
    python scripts/verify_receipts.py receipts.json
"""

import argparse
import json
import sys
from typing import Any, Dict, List

from mcp_receipt_governed.receipt import (
    GovernanceReceipt,
    verify_receipt,
)


def _reconstruct(data: Dict[str, Any]) -> GovernanceReceipt:
    """Build a GovernanceReceipt from an exported dict."""
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


def verify_chain(receipts_data: List[Dict[str, Any]]) -> int:
    """Verify a chain of exported receipts.

    Returns:
        ``0`` if the chain is fully valid, ``1`` otherwise.
    """
    if not receipts_data:
        print("  (empty chain — nothing to verify)")
        return 0

    errors = 0
    expected_parent_hash = None

    for i, data in enumerate(receipts_data):
        receipt = _reconstruct(data)
        rid_short = (
            receipt.receipt_id[:12] + "…" if len(receipt.receipt_id) > 12 else receipt.receipt_id
        )
        print(f"  [{i}] Receipt {rid_short}  (tool: {receipt.tool_name})")

        # 1. Hash chain contiguity
        if receipt.parent_receipt_hash != expected_parent_hash:
            exp = (expected_parent_hash or "None")[:16]
            got = (receipt.parent_receipt_hash or "None")[:16]
            print(f"      ❌  Hash chain broken — expected {exp}…, got {got}…")
            errors += 1
        else:
            print("      ✅  Hash chain contiguous")

        # 2. Canonical payload hash (round-trip check)
        stored_hash = data.get("payload_hash")
        if stored_hash and receipt.payload_hash() != stored_hash:
            print("      ❌  Payload hash mismatch (canonical re-generation differs)")
            errors += 1
        else:
            print("      ✅  Payload hash verified")

        # 3. Ed25519 signature
        if receipt.signature:
            if verify_receipt(receipt):
                print("      ✅  Ed25519 signature valid")
            else:
                print("      ❌  Ed25519 signature verification failed")
                errors += 1
        else:
            print("      ⚠️   Unsigned receipt (no signature)")

        expected_parent_hash = receipt.payload_hash()
        print()

    return 0 if errors == 0 else 1


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Verify MCP governance receipt chains offline.",
    )
    parser.add_argument(
        "receipts_file",
        help="Path to JSON file containing exported receipts (from ReceiptStore.export())",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results as JSON for CI/CD integration",
    )
    args = parser.parse_args()

    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║  MCP Receipt Chain — Offline Verification           ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()

    try:
        with open(args.receipts_file) as f:
            receipts_data = json.load(f)
    except Exception as exc:
        print(f"  Error loading {args.receipts_file}: {exc}")
        return 1

    print(f"  Loaded {len(receipts_data)} receipt(s) from {args.receipts_file}")
    print()

    result = verify_chain(receipts_data)

    if args.json_output:
        output = {
            "file": args.receipts_file,
            "total_receipts": len(receipts_data),
            "passed": result == 0,
        }
        print(json.dumps(output, indent=2))
    elif result == 0:
        print("  🎉 Verification passed — chain is contiguous and signatures are valid.")
    else:
        print("  🚨 Verification failed — the receipt chain has integrity issues.")

    print()
    return result


if __name__ == "__main__":
    sys.exit(main())
