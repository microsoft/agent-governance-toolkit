#!/usr/bin/env python3
"""
Ontology Diff Report – Show changes between ontology versions.
"""

import json
import os
from src.capability_review_queue import CapabilityReviewQueue

def main():
    queue = CapabilityReviewQueue()
    ledger = queue.get_ledger_entries()
    if not ledger:
        print("No ontology changes found.")
        return

    print("\n📜 Ontology Evolution Report")
    print("=" * 70)
    print(f"Total versions: {len(ledger)}")
    print()
    for change in ledger:
        print(f"Version {change.version}: {change.action} {change.capability_name}")
        print(f"  Added by: {change.reviewer}")
        print(f"  Reasoning: {change.reasoning}")
        print(f"  Timestamp: {change.timestamp}")
        print(f"  Actions: {', '.join([a['action'] for a in change.required_actions])}")
        print()

    # Generate summary
    total = len(ledger)
    print(f"Summary: {total} capability(s) added to the ontology.")

if __name__ == "__main__":
    main()