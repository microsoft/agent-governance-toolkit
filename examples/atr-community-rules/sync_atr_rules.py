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

    # CI mode: fail on any invalid regex (use for local validation, not weekly cron)
    python sync_atr_rules.py --atr-dir ./rules/ --strict-regex
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


class InvalidRegexError(ValueError):
    """Raised when an ATR regex pattern fails compile validation."""


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


def _validate_regex(pattern: str, source: str, *, strict: bool) -> bool:
    """
    Best-effort regex validation addressing the ReDoS concern raised in #908 review.

    Checks:
      1. Pattern compiles cleanly (no syntax errors).
      2. Pattern length is below a conservative upper bound (8 KB) — prevents
         a malicious or malformed ATR upstream from shipping pathologically
         long regexes.

    This is a cheap static guard, not a runtime ReDoS defence. True ReDoS
    mitigation would require wrapping each re.search() call in the core
    PolicyEvaluator with a timeout, which is out of scope for this example
    sync utility.

    Returns True if the pattern is acceptable. On failure, either raises
    InvalidRegexError (when ``strict=True``) or logs a warning and returns
    False (when ``strict=False``).

    Note: as of ATR v2.0.12, a small number of rules use Unicode escape
    sequences (\\uXXXX) that are valid in PCRE/JavaScript but not in Python's
    re module. These are legitimate rules and are silently skipped in lenient
    mode. The weekly sync workflow runs WITHOUT --strict-regex so that these
    rules produce a warning rather than aborting the sync.
    """
    MAX_PATTERN_BYTES = 8 * 1024  # 8 KB upper bound

    if len(pattern.encode("utf-8")) > MAX_PATTERN_BYTES:
        msg = (
            f"Rejecting oversized regex ({len(pattern)} bytes > {MAX_PATTERN_BYTES}) "
            f"from {source}"
        )
        if strict:
            raise InvalidRegexError(msg)
        print(f"WARNING: {msg}", file=sys.stderr)
        return False

    try:
        re.compile(pattern)
    except re.error as exc:
        msg = f"Invalid regex in {source}: {exc}"
        if strict:
            raise InvalidRegexError(msg) from exc
        print(f"WARNING: skipping {msg}", file=sys.stderr)
        return False

    return True


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


def convert_atr_directory(atr_dir: Path, *, strict_regex: bool = False) -> dict[str, Any]:
    """
    Walk an ATR rules directory and produce an AGT PolicyDocument dict.

    Each ATR rule may contain multiple detection conditions (regex patterns).
    Every pattern that passes static validation becomes a separate AGT rule.

    Per PR #908 review:
      - Raises FileNotFoundError (not sys.exit) when no rules are found, so
        callers can handle it programmatically (requested by @aymenhmaidiwastaken).
      - Validates every regex at compile time before emitting it (addresses
        the ReDoS concern raised by the AI code-reviewer bot). Pathological
        patterns are dropped with a warning (strict_regex=False) or raise
        InvalidRegexError (strict_regex=True).
    """
    rules: list[dict[str, Any]] = []
    rule_files = sorted(atr_dir.rglob("*.yaml"))

    if not rule_files:
        raise FileNotFoundError(f"No YAML files found in {atr_dir}")

    dropped = 0
    skipped_maturity = 0
    for path in rule_files:
        atr = _load_yaml(path)
        if not atr or "detection" not in atr:
            continue

        # Skip rules that are not production-ready
        if atr.get("status") == "draft" or atr.get("maturity") == "test":
            skipped_maturity += 1
            continue

        patterns = _extract_regex_patterns(atr["detection"])
        for i, pattern in enumerate(patterns):
            if not _validate_regex(pattern, str(path), strict=strict_regex):
                dropped += 1
                continue
            rules.append(_atr_to_agt_rule(atr, pattern, i))

    print(
        f"Converted {len(rules)} detection patterns from {len(rule_files)} ATR files "
        f"(skipped {skipped_maturity} draft/test rules, dropped {dropped} invalid patterns).",
        file=sys.stderr,
    )

    return {
        "version": "1.0",
        "name": "atr-community-rules-full",
        "description": (
            "Auto-generated from Agent Threat Rules (ATR) v2.0.12. "
            f"{len(rules)} detection patterns from {len(rule_files) - skipped_maturity} production-grade rules "
            f"({skipped_maturity} draft/test rules excluded). "
            "Source: https://github.com/Agent-Threat-Rule/agent-threat-rules"
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
    parser.add_argument(
        "--strict-regex",
        action="store_true",
        help=(
            "Fail fast on any invalid or oversized regex instead of skipping it. "
            "Use for local validation; the weekly sync workflow runs without this "
            "flag so that Unicode-escape rules are skipped rather than aborting sync."
        ),
    )
    args = parser.parse_args()

    if not args.atr_dir.is_dir():
        print(f"ERROR: {args.atr_dir} is not a directory.", file=sys.stderr)
        sys.exit(1)

    try:
        policy = convert_atr_directory(args.atr_dir, strict_regex=args.strict_regex)
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    except InvalidRegexError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)

    with open(args.output, "w", encoding="utf-8") as fh:
        yaml.dump(policy, fh, default_flow_style=False, allow_unicode=True, sort_keys=False)

    print(f"Wrote {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
