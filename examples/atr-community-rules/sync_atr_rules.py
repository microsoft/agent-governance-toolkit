# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#!/usr/bin/env python3
"""
Sync ATR (Agent Threat Rules) YAML rules into AGT PolicyDocument format.

Reads ATR rule files from a directory and converts them to a single YAML file
compatible with AGT's PolicyEvaluator.load_policies().

Usage:
    # From node_modules (after `npm install agent-threat-rules`)
    python sync_atr_rules.py --atr-dir node_modules/agent-threat-rules/rules/

    # From a local clone
    python sync_atr_rules.py --atr-dir /path/to/agent-threat-rules/rules/

    # Specify output path
    python sync_atr_rules.py --atr-dir ./rules/ --output atr_policy.yaml
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

import yaml


# ---------------------------------------------------------------------------
# ATR severity -> AGT priority mapping
# ---------------------------------------------------------------------------
SEVERITY_TO_PRIORITY: dict[str, int] = {
    "critical": 100,
    "high": 80,
    "medium": 60,
    "low": 40,
    "informational": 20,
}

# ---------------------------------------------------------------------------
# ATR category -> AGT context field mapping
#
# AGT PolicyEvaluator matches rules against a context dict.  This mapping
# determines which context field each ATR category should inspect.
# ---------------------------------------------------------------------------
CATEGORY_TO_FIELD: dict[str, str] = {
    "prompt-injection": "user_input",
    "tool-poisoning": "tool_description",
    "skill-compromise": "tool_description",
    "context-exfiltration": "tool_response",
    "privilege-escalation": "user_input",
    "agent-manipulation": "user_input",
    "excessive-autonomy": "user_input",
    "model-security": "user_input",
    "data-poisoning": "user_input",
}


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load a single YAML file, returning an empty dict on failure."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
            return data if isinstance(data, dict) else {}
    except (yaml.YAMLError, OSError) as exc:
        print(f"WARNING: skipping {path}: {exc}", file=sys.stderr)
        return {}


def _extract_regex_patterns(detection: dict[str, Any]) -> list[str]:
    """Extract all regex patterns from an ATR detection block."""
    patterns: list[str] = []
    for condition in detection.get("conditions", []):
        if condition.get("operator") == "regex" and condition.get("value"):
            patterns.append(condition["value"])
    return patterns


def _atr_to_agt_rule(atr: dict[str, Any], pattern: str, index: int) -> dict[str, Any]:
    """Convert one ATR detection condition into an AGT rule entry."""
    atr_id = atr.get("id", "unknown")
    category = atr.get("tags", {}).get("category", "prompt-injection")
    severity = atr.get("severity", "medium").lower()
    title = atr.get("title", "Untitled ATR rule")

    # Determine the context field based on the original ATR field or category
    field = CATEGORY_TO_FIELD.get(category, "user_input")

    # Build a unique rule name
    rule_name = re.sub(r"[^a-z0-9-]", "-", atr_id.lower())
    if index > 0:
        rule_name = f"{rule_name}-{index}"

    return {
        "name": rule_name,
        "condition": {
            "field": field,
            "operator": "matches",
            "value": pattern,
        },
        "action": "deny",
        "priority": SEVERITY_TO_PRIORITY.get(severity, 60),
        "message": f"[{atr_id}] {title}",
    }


def convert_atr_directory(atr_dir: Path) -> dict[str, Any]:
    """
    Walk an ATR rules directory and produce an AGT PolicyDocument dict.

    Each ATR rule may contain multiple detection conditions (regex patterns).
    Every pattern becomes a separate AGT rule to preserve detection granularity.
    """
    rules: list[dict[str, Any]] = []
    rule_files = sorted(atr_dir.rglob("*.yaml"))

    if not rule_files:
        print(f"ERROR: no YAML files found in {atr_dir}", file=sys.stderr)
        sys.exit(1)

    for path in rule_files:
        atr = _load_yaml(path)
        if not atr or "detection" not in atr:
            continue

        patterns = _extract_regex_patterns(atr["detection"])
        for i, pattern in enumerate(patterns):
            rules.append(_atr_to_agt_rule(atr, pattern, i))

    print(f"Converted {len(rules)} detection patterns from {len(rule_files)} ATR files.", file=sys.stderr)

    return {
        "version": "1.0",
        "name": "atr-community-rules-full",
        "description": (
            "Auto-generated from Agent Threat Rules (ATR). "
            f"{len(rules)} detection patterns from {len(rule_files)} rules. "
            "Source: https://agentthreatrule.org"
        ),
        "rules": rules,
        "defaults": {"action": "allow"},
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert ATR rules to AGT PolicyDocument YAML."
    )
    parser.add_argument(
        "--atr-dir",
        type=Path,
        required=True,
        help="Path to the ATR rules/ directory.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("atr_community_policy.yaml"),
        help="Output YAML file path (default: atr_community_policy.yaml).",
    )
    args = parser.parse_args()

    if not args.atr_dir.is_dir():
        print(f"ERROR: {args.atr_dir} is not a directory.", file=sys.stderr)
        sys.exit(1)

    policy = convert_atr_directory(args.atr_dir)

    with open(args.output, "w", encoding="utf-8") as fh:
        yaml.dump(policy, fh, default_flow_style=False, allow_unicode=True, sort_keys=False)

    print(f"Wrote {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
