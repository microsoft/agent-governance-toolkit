#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Validate policy replay fixtures against the JSON Schema."""

from __future__ import annotations

import json
import sys
from pathlib import Path

SCHEMA_PATH = Path(__file__).parent / "fixture_schema.json"


def validate_fixture(fixture: dict, schema: dict | None = None) -> list[str]:
    """Validate a fixture dict. Returns a list of error strings (empty = valid).

    Requires the ``jsonschema`` package for full schema validation.
    Install with: ``pip install jsonschema`` (included in agent-compliance[dev]).
    Falls back to basic structural checks when jsonschema is not available.
    """
    try:
        import jsonschema
    except ImportError:
        # Fallback: basic structural check without jsonschema
        errors = []
        for field in ("id", "input", "expected_verdict"):
            if field not in fixture:
                errors.append(f"missing required field: {field}")
        return errors

    if schema is None:
        schema = json.loads(SCHEMA_PATH.read_text())
    validator = jsonschema.Draft7Validator(schema)
    return [e.message for e in validator.iter_errors(fixture)]


def validate_file(path: str | Path) -> list[str]:
    """Load and validate a single fixture file."""
    path = Path(path)
    fixture = json.loads(path.read_text())
    return validate_fixture(fixture)


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <fixture.json> [fixture2.json ...]", file=sys.stderr)
        sys.exit(1)

    schema = json.loads(SCHEMA_PATH.read_text())
    exit_code = 0
    for path_str in sys.argv[1:]:
        path = Path(path_str)
        fixture = json.loads(path.read_text())
        errors = validate_fixture(fixture, schema)
        if errors:
            print(f"FAIL  {path}")
            for e in errors:
                print(f"  {e}")
            exit_code = 1
        else:
            print(f"ok    {path}")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
