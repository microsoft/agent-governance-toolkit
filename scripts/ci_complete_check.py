#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Report failed GitHub Actions needs entries for the ci-complete gate."""

from __future__ import annotations

import json
import sys
from typing import Any

FAILED_RESULTS = frozenset({"failure", "cancelled", "timed_out", "action_required"})


def failed_job_names(needs: dict[str, Any]) -> list[str]:
    """Return names of required jobs that did not complete successfully."""
    return [
        name
        for name, info in needs.items()
        if isinstance(info, dict) and info.get("result") in FAILED_RESULTS
    ]


def main() -> int:
    try:
        needs = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        print(f"Invalid needs JSON: {exc}", file=sys.stderr)
        return 2

    if not isinstance(needs, dict):
        print("Invalid needs JSON: expected an object", file=sys.stderr)
        return 2

    failed = failed_job_names(needs)
    print(",".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
