# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""The spec/schema documents ship with the package and match the spec tree."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_control_specification import schemas

SUFFIX = ".schema.json"
SPEC_SCHEMA_DIR = Path(__file__).resolve().parents[3] / "spec" / "schema"

# Every schema in the spec tree, under the name schemas.names() reports for it.
# Empty when the tests run against an installed package without the spec tree.
SPEC_SCHEMA_NAMES = (
    tuple(
        sorted(
            path.relative_to(SPEC_SCHEMA_DIR).as_posix()[: -len(SUFFIX)]
            for path in SPEC_SCHEMA_DIR.rglob(f"*{SUFFIX}")
        )
    )
    if SPEC_SCHEMA_DIR.is_dir()
    else ()
)

needs_spec_tree = pytest.mark.skipif(
    not SPEC_SCHEMA_DIR.is_dir(), reason="spec tree not present (installed package)"
)


def test_manifest_schema_ships() -> None:
    assert "manifest" in schemas.names()


@needs_spec_tree
def test_shipped_schemas_are_exactly_the_spec_tree() -> None:
    assert schemas.names() == SPEC_SCHEMA_NAMES


@pytest.mark.parametrize("name", schemas.names())
def test_shipped_schema_is_a_json_schema_document(name: str) -> None:
    document = schemas.load(name)
    assert document.get("$schema", "").startswith("http")
    assert isinstance(document.get("title") or document.get("$id"), str)


@needs_spec_tree
@pytest.mark.parametrize("name", SPEC_SCHEMA_NAMES)
def test_shipped_schema_matches_the_spec_tree(name: str) -> None:
    source = SPEC_SCHEMA_DIR / f"{name}{SUFFIX}"
    assert schemas.text(name) == source.read_text(encoding="utf-8"), (
        f"{name} drifted from spec/schema; copy the file into agent_control_specification/schema/"
    )
    assert schemas.load(name) == json.loads(source.read_text(encoding="utf-8"))


def test_unknown_schema_name_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown schema"):
        schemas.text("nope")
