# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Validate policy replay fixtures against the JSON Schema."""

from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import jsonschema
except ImportError:
    jsonschema = None  # type: ignore[assignment]

SCHEMA_PATH = Path(__file__).parent / "fixture_schema.json"


def _load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def validate_fixture(fixture: dict) -> list[str]:
    """Validate a single fixture dict. Returns list of errors (empty = valid)."""
    if jsonschema is None:
        raise ImportError("jsonschema is required: pip install jsonschema")

    errors: list[str] = []
    schema = _load_schema()
    validator = jsonschema.Draft202012Validator(schema)
    for err in sorted(validator.iter_errors(fixture), key=lambda e: list(e.path)):
        path = ".".join(str(p) for p in err.absolute_path) or "(root)"
        errors.append(f"{path}: {err.message}")
    return errors


def validate_file(path: Path) -> list[str]:
    """Validate a fixture file. Returns list of errors."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        errors: list[str] = []
        for i, item in enumerate(raw):
            for e in validate_fixture(item):
                errors.append(f"[{i}] {e}")
        return errors
    return validate_fixture(raw)


def main() -> None:
    """CLI entry point: validate fixture files passed as arguments."""
    if len(sys.argv) < 2:
        print("Usage: python validate_fixture.py <fixture.json> [...]", file=sys.stderr)
        raise SystemExit(1)

    all_errors: list[str] = []
    for arg in sys.argv[1:]:
        p = Path(arg)
        errors = validate_file(p)
        if errors:
            for e in errors:
                all_errors.append(f"{p}: {e}")
        else:
            print(f"ok  {p}")

    if all_errors:
        print("
Validation errors:", file=sys.stderr)
        for e in all_errors:
            print(f"  {e}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
