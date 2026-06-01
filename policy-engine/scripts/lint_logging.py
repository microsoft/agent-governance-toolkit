#!/usr/bin/env python3
"""Lint the ACS telemetry vocabulary and telemetry emission surface."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
STYLE_GUIDE = REPO_ROOT / "docs" / "logging-style-guide.md"
OBSERVABILITY = REPO_ROOT / "docs" / "observability.md"
TELEMETRY_RS = REPO_ROOT / "core" / "src" / "telemetry.rs"
RUNTIME_RS = REPO_ROOT / "core" / "src" / "runtime.rs"
OTEL_RS = REPO_ROOT / "integrations" / "otel" / "src" / "lib.rs"
REDACTION_FIXTURE = REPO_ROOT / "tests" / "parity" / "telemetry_redaction_canonical.json"

SENSITIVE_TOKENS = {
    "policy_target.value",
    "snapshot.input",
    "snapshot.output",
    "snapshot.model_request",
    "snapshot.model_response",
    "snapshot.messages",
    "snapshot.tool_call.args",
    "snapshot.tool_result",
    "annotations.*",
    "effect.value",
    "effect.spans[].replacement",
    "secrets",
    "pii",
    "tool_args",
    "tool_result",
    "model_output",
    "model_response",
    "raw_payload",
    "payload_value",
}

BASE_FIELDS = {
    "event_type",
    "intervention_point",
    "decision",
    "reason_code",
    "error_class",
    "policy_id",
    "annotators",
    "enforcement_mode",
    "duration_ms",
    "action_identity",
}

OTEL_DISALLOWED_FIELDS = {
    "action_identity",
}

START_MARKER = "<!-- acs telemetry vocabulary start -->"
END_MARKER = "<!-- acs telemetry vocabulary end -->"


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def load_style_vocabulary() -> dict:
    text = STYLE_GUIDE.read_text(encoding="utf-8")
    check_markdown_prose_style(text)
    try:
        block = text.split(START_MARKER, 1)[1].split(END_MARKER, 1)[0]
    except IndexError:
        fail(f"{rel(STYLE_GUIDE)} is missing telemetry vocabulary markers")
    match = re.search(r"```json\s*(\{.*?\})\s*```", block, flags=re.S)
    if not match:
        fail(f"{rel(STYLE_GUIDE)} is missing the JSON telemetry vocabulary block")
    return json.loads(match.group(1))


def fail(message: str) -> None:
    print(f"logging lint violation: {message}")
    raise SystemExit(1)


def check_markdown_prose_style(text: str) -> None:
    in_code = False
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("```"):
            in_code = not in_code
            continue
        if in_code or not stripped:
            continue
        if stripped.startswith(("#", "|", "<!--")):
            continue
        if "—" in line:
            fail(f"{rel(STYLE_GUIDE)}:{line_number} contains an em dash")
        if ":" in line:
            fail(f"{rel(STYLE_GUIDE)}:{line_number} contains a colon in prose")


def check(condition: bool, message: str, violations: list[str]) -> None:
    if not condition:
        violations.append(message)


def telemetry_enum() -> dict[str, str]:
    text = TELEMETRY_RS.read_text(encoding="utf-8")
    return dict(re.findall(r"Self::(\w+)\s*=>\s*\"([a-z0-9_]+)\"", text))


def observability_names() -> set[str]:
    text = OBSERVABILITY.read_text(encoding="utf-8")
    match = re.search(r"Known event kinds are (.*?)\.", text, flags=re.S)
    if not match:
        fail(f"{rel(OBSERVABILITY)} has no Known event kinds sentence")
    return set(re.findall(r"`([a-z0-9_]+)`", match.group(1)))


def fixture_events() -> dict[str, list[str]]:
    fixture = json.loads(REDACTION_FIXTURE.read_text(encoding="utf-8"))
    return {
        event["name"]: event["emitted_attribute_keys"]
        for event in fixture.get("events", [])
    }


def style_events(vocabulary: dict) -> dict[str, dict]:
    events = vocabulary.get("events")
    if not isinstance(events, list):
        fail("style vocabulary has no events array")
    result: dict[str, dict] = {}
    for event in events:
        name = event.get("name")
        if not isinstance(name, str):
            fail("style vocabulary event without a string name")
        if name in result:
            fail(f"style vocabulary duplicates event {name}")
        result[name] = event
    return result


def valid_field_name(field: str) -> bool:
    parts = field.split(".")
    return all(part and all(ch.islower() or ch.isdigit() or ch == "_" for ch in part) for part in parts)


def check_vocabulary(violations: list[str]) -> set[str]:
    vocabulary = load_style_vocabulary()
    guide_events = style_events(vocabulary)
    enum_names = set(telemetry_enum().values())
    observed_names = observability_names()
    fixture = fixture_events()

    check(set(guide_events) == enum_names, "style guide event names differ from TelemetryEventType", violations)
    check(set(guide_events) == observed_names, "style guide event names differ from docs/observability.md", violations)
    check(set(guide_events) == set(fixture), "style guide event names differ from telemetry redaction fixture", violations)

    allowed_fields = set(BASE_FIELDS)
    for event in guide_events.values():
        documented = event.get("documented_attribute_keys", [])
        required = event.get("required_fields", [])
        optional = event.get("optional_fields", [])
        check(documented == fixture.get(event["name"], []), f"{event['name']} documented fields differ from redaction fixture", violations)
        check(set(required).issubset(documented), f"{event['name']} has required fields absent from documented fields", violations)
        check(set(optional).issubset(documented), f"{event['name']} has optional fields absent from documented fields", violations)
        for field in documented:
            check(valid_field_name(field), f"{event['name']} field {field} is not snake case", violations)
            if field.startswith("metadata."):
                allowed_fields.add(field)
            else:
                check(field in BASE_FIELDS, f"{event['name']} field {field} is not an allowed base field", violations)
    return allowed_fields


def scan_rust_emissions(allowed_fields: set[str], violations: list[str]) -> None:
    enum_variants = set(telemetry_enum())
    for path in REPO_ROOT.rglob("*.rs"):
        if any(part in {"target", ".git"} for part in path.parts):
            continue
        text = path.read_text(encoding="utf-8")
        for line_number, line in enumerate(text.splitlines(), start=1):
            for variant in re.findall(r"TelemetryEventType::([A-Z]\w+)", line):
                check(variant in enum_variants, f"{rel(path)}:{line_number} uses unknown TelemetryEventType::{variant}", violations)
            for key in re.findall(r"\.with_metadata\(\s*\"([^\"]+)\"", line):
                field = f"metadata.{key}"
                check(field in allowed_fields, f"{rel(path)}:{line_number} uses undocumented telemetry metadata key {key}", violations)
                lowered = key.lower()
                for token in SENSITIVE_TOKENS:
                    check(token.replace(".", "_").replace("*", "") not in lowered, f"{rel(path)}:{line_number} metadata key {key} looks payload bearing", violations)

    runtime_text = RUNTIME_RS.read_text(encoding="utf-8")
    for match in re.finditer(r"TelemetryEvent::new\(.*?\);", runtime_text, flags=re.S):
        block = match.group(0).lower()
        start_line = runtime_text[: match.start()].count("\n") + 1
        for token in SENSITIVE_TOKENS:
            normalized = token.lower().replace(".", "_").replace("[]", "").replace("*", "")
            if normalized in block and "policy_reason" not in block:
                violations.append(f"{rel(RUNTIME_RS)}:{start_line} telemetry builder references sensitive token {token}")


def scan_otel_attributes(allowed_fields: set[str], violations: list[str]) -> None:
    if not OTEL_RS.exists():
        return
    text = OTEL_RS.read_text(encoding="utf-8")
    otel_allowed = {
        field
        for field in allowed_fields
        if not field.startswith("metadata.") and field not in OTEL_DISALLOWED_FIELDS
    }
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = re.search(r"key:\s*\"([^\"]+)\"", line)
        if match:
            key = match.group(1)
            check(
                key not in OTEL_DISALLOWED_FIELDS,
                f"{rel(OTEL_RS)}:{line_number} emits high-cardinality OTel attribute {key}",
                violations,
            )
            check(key in otel_allowed, f"{rel(OTEL_RS)}:{line_number} emits undocumented OTel attribute {key}", violations)


def main() -> int:
    violations: list[str] = []
    allowed_fields = check_vocabulary(violations)
    scan_rust_emissions(allowed_fields, violations)
    scan_otel_attributes(allowed_fields, violations)

    if violations:
        for violation in violations:
            print(f"logging lint violation: {violation}")
        print(f"lint_logging.py: {len(violations)} violation(s) found")
        return 1
    print("lint_logging.py: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
