# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""The ``spec/schema`` JSON documents, shipped with the package.

The files under ``schema/`` are copies of ``policy-engine/spec/schema``; the
test suite fails if they drift. Hosts validate advice, manifests and wire
payloads against these instead of carrying their own copy of the contract.
"""

from __future__ import annotations

import json
from importlib import resources
from importlib.resources.abc import Traversable
from typing import Any

_SUFFIX = ".schema.json"


def _root() -> Traversable:
    return resources.files(__package__) / "schema"


def names() -> tuple[str, ...]:
    """Schema names, such as ``"manifest"`` or ``"wire/verdict"``."""
    found: list[str] = []
    for entry in _root().iterdir():
        if entry.is_dir():
            found.extend(
                f"{entry.name}/{child.name[: -len(_SUFFIX)]}"
                for child in entry.iterdir()
                if child.name.endswith(_SUFFIX)
            )
        elif entry.name.endswith(_SUFFIX):
            found.append(entry.name[: -len(_SUFFIX)])
    return tuple(sorted(found))


def text(name: str) -> str:
    """Return the schema document as JSON text."""
    target = _root()
    for part in f"{name}{_SUFFIX}".split("/"):
        target = target / part
    if not target.is_file():
        raise ValueError(f"unknown schema {name!r}; shipped schemas: {', '.join(names())}")
    return target.read_text(encoding="utf-8")


def load(name: str) -> dict[str, Any]:
    """Return the schema document parsed as JSON."""
    document = json.loads(text(name))
    if not isinstance(document, dict):
        raise ValueError(f"schema {name!r} is not a JSON object")
    return document
