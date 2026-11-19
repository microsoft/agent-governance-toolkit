#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Verify exported demo evidence against a separately retained trust snapshot."""

import argparse
import json
from pathlib import Path

from demo import valid_signature, verify_journal


def verify_export(bundle: dict, trust: dict) -> bool:
    """Check the signed journal and nested proofs using caller-provided keys.

    This checks recorded software evidence, not whether a physical event really
    happened. Do not derive trusted keys from the evidence being checked.
    """
    try:
        if (
            bundle["schema"] != "humanoid-action-export-demo/1"
            or bundle["simulation"] is not True
        ):
            return False
        events = bundle["events"]
        if not verify_journal(events, trust["journal_key"], trust["expected_head"]):
            return False
        for event in events:
            body = event["body"]
            receipt = body.get("controller_receipt")
            if receipt is not None:
                baseline = body["kind"] == "motion_only_baseline"
                expected_name = (
                    "motion-only-controller-simulator"
                    if baseline
                    else "governed-controller-simulator"
                )
                key = trust["baseline_key" if baseline else "controller_key"]
                if not valid_signature(receipt, key):
                    return False
                if receipt["body"]["controller"] != expected_name:
                    return False
                if receipt["body"]["action_digest"] != body["action_digest"]:
                    return False
            if "request" in body:
                if not valid_signature(body["request"], trust["agent_key"]):
                    return False
            if "approval" in body:
                if not valid_signature(body["approval"], trust["operator_key"]):
                    return False
                if body["approval"]["body"]["action_digest"] != body["action_digest"]:
                    return False
        return True
    except (KeyError, TypeError, ValueError):
        return False


def main() -> int:
    """Return a nonzero exit status for invalid or unreadable evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument(
        "--trust",
        type=Path,
        required=True,
        help="Trust snapshot retained separately from the evidence",
    )
    args = parser.parse_args()
    try:
        bundle = json.loads(args.evidence.read_text())
        trust = json.loads(args.trust.read_text())
    except (OSError, ValueError) as exc:
        print(f"FAIL: cannot load evidence: {exc}")
        return 1
    passed = verify_export(bundle, trust)
    print(
        "PASS: signed software records verified"
        if passed
        else "FAIL: evidence verification rejected"
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
