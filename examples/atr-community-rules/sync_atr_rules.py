#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Compile Agent Threat Rules into a native ACS manifest and Rego bundle."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml


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
    """Raised when an ATR regex cannot be emitted safely."""


@dataclass(frozen=True)
class AtrPattern:
    """One validated ATR detection pattern."""

    atr_id: str
    category: str
    severity: str
    name: str
    field: str
    pattern: str
    message: str


@dataclass(frozen=True)
class CompiledAtrPolicy:
    """Native ACS artefacts generated from ATR patterns."""

    manifest: dict[str, Any]
    rego: str
    pattern_count: int


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as handle:
            value = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError) as exc:
        print(f"WARNING: skipping {path}: {exc}", file=sys.stderr)
        return {}
    return value if isinstance(value, dict) else {}


def _extract_regex_patterns(detection: dict[str, Any]) -> list[str]:
    return [
        condition["value"]
        for condition in detection.get("conditions", [])
        if condition.get("operator") == "regex" and condition.get("value")
    ]


def _validate_regex(pattern: str, source: str, *, strict: bool) -> bool:
    if len(pattern.encode("utf-8")) > 8 * 1024:
        message = f"Regex from {source} exceeds 8192 bytes"
        if strict:
            raise InvalidRegexError(message)
        print(f"WARNING: {message}", file=sys.stderr)
        return False
    try:
        re.compile(pattern)
    except re.error as exc:
        message = f"Invalid regex in {source}: {exc}"
        if strict:
            raise InvalidRegexError(message) from exc
        print(f"WARNING: {message}", file=sys.stderr)
        return False
    return True


def iter_atr_patterns(
    atr_dir: Path,
    *,
    strict_regex: bool = False,
) -> Iterable[AtrPattern]:
    """Yield validated production ATR patterns."""

    files = sorted(atr_dir.rglob("*.yaml"))
    if not files:
        raise FileNotFoundError(f"No YAML files found in {atr_dir}")
    for path in files:
        atr = _load_yaml(path)
        if (
            not atr
            or "detection" not in atr
            or atr.get("status") == "draft"
            or atr.get("maturity") == "test"
        ):
            continue
        atr_id = str(atr.get("id", "unknown"))
        category = str(
            (atr.get("tags") or {}).get("category", "prompt-injection")
        )
        field = CATEGORY_TO_FIELD.get(category, "user_input")
        severity = str(atr.get("severity", "medium")).lower()
        title = str(atr.get("title", "ATR detection"))
        for index, pattern in enumerate(_extract_regex_patterns(atr["detection"])):
            if not _validate_regex(pattern, str(path), strict=strict_regex):
                continue
            base = re.sub(r"[^a-z0-9-]", "-", atr_id.lower())
            name = base if index == 0 else f"{base}-{index}"
            yield AtrPattern(
                atr_id=atr_id,
                category=category,
                severity=severity,
                name=name,
                field=field,
                pattern=pattern,
                message=f"[{atr_id}] {title}",
            )


def compile_patterns(
    patterns: Iterable[AtrPattern],
    *,
    name: str,
    bundle: str,
    package: str,
) -> CompiledAtrPolicy:
    """Compile validated patterns into Rego and an ACS manifest."""

    values = list(patterns)
    lines = [
        "# Copyright (c) Microsoft Corporation.",
        "# Licensed under the MIT License.",
        "",
        f"package {package}",
        "",
        "import rego.v1",
        "",
        'body := input.policy_target.value if is_object(input.policy_target.value)',
        'body := {"user_input": input.policy_target.value} if not is_object(input.policy_target.value)',
        "",
    ]
    for item in values:
        candidate = {
            "name": item.name,
            "message": item.message,
            "severity": item.severity,
        }
        lines.extend(
            [
                f"matches contains {json.dumps(candidate)} if {{",
                f"\ttarget := sprintf(\"%v\", [object.get(body, {json.dumps(item.field)}, \"\")])",
                f"\tregex.match(`{item.pattern}`, target)",
                "}",
                "",
            ]
        )
    lines.extend(
        [
            "match_names := sort([match.name | match := matches[_]]) if count(matches) > 0",
            "",
            "winner := match if {",
            "\tcount(matches) > 0",
            "\tmatch := matches[_]",
            "\tmatch.name == match_names[0]",
            "}",
            "",
            'result := {"decision": "deny", "reason": winner.name, "message": winner.message} if count(matches) > 0',
            'result := {"decision": "allow", "reason": "no_atr_match"} if count(matches) == 0',
            "",
        ]
    )
    policy_id = name.replace("-", "_")
    manifest = {
        "agent_control_specification_version": "0.3.1-beta",
        "metadata": {"name": name, "version": "1.0"},
        "extends": [],
        "policies": {
            policy_id: {
                "type": "rego",
                "bundle": bundle,
                "query": f"data.{package}.result",
            }
        },
        "intervention_points": {
            "input": {
                "policy_target": "$.input.body",
                "policy": {"id": policy_id},
            },
            "output": {
                "policy_target": "$.output.content",
                "policy": {"id": policy_id},
            },
        },
    }
    return CompiledAtrPolicy(
        manifest=manifest,
        rego="\n".join(lines),
        pattern_count=len(values),
    )


def convert_atr_directory(
    atr_dir: Path,
    *,
    strict_regex: bool = False,
) -> CompiledAtrPolicy:
    """Compile one native policy containing every production ATR pattern."""

    return compile_patterns(
        iter_atr_patterns(atr_dir, strict_regex=strict_regex),
        name="atr-community-rules",
        bundle="atr-community-rules-bundle",
        package="agt.examples.atr.community",
    )


def write_compiled(output: Path, compiled: CompiledAtrPolicy) -> None:
    """Write a manifest and sibling Rego bundle directory."""

    policy = next(iter(compiled.manifest["policies"].values()))
    bundle_dir = output.parent / policy["bundle"]
    bundle_dir.mkdir(parents=True, exist_ok=True)
    (bundle_dir / "policy.rego").write_text(compiled.rego, encoding="utf-8")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        "# Copyright (c) Microsoft Corporation.\n"
        "# Licensed under the MIT License.\n"
        + yaml.safe_dump(compiled.manifest, sort_keys=False),
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compile ATR rules into a native ACS manifest"
    )
    parser.add_argument("--atr-dir", type=Path, required=True)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("atr_community_manifest.yaml"),
    )
    parser.add_argument("--strict-regex", action="store_true")
    args = parser.parse_args()

    if not args.atr_dir.is_dir():
        parser.error(f"ATR rules directory not found: {args.atr_dir}")
    compiled = convert_atr_directory(
        args.atr_dir,
        strict_regex=args.strict_regex,
    )
    write_compiled(args.output, compiled)
    print(
        f"Wrote {compiled.pattern_count} ATR patterns to {args.output}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
