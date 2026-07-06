#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Fail if two built wheels install the same top-level import path.

Two AGT distributions that both ship, say, a ``hypervisor/`` package write to
the same ``site-packages`` path. Whichever wheel is installed second silently
overwrites the first, so a clean install becomes order- and version-dependent
(the "Frankenstein install"). This is exactly the defect that occurred when the
``agent-governance-toolkit-core`` meta wheel force-included sibling source that
the standalone stub wheels *also* shipped.

This scanner inspects the contents of every ``.whl`` under the given paths,
maps each top-level import name to the set of wheels that ship it, and exits
non-zero if any top-level name is shipped by more than one wheel. It is the CI
gate that keeps the standalone deprecation stubs dep-only: if a future change
re-adds ``packages = ["src/..."]`` to a stub, that stub's wheel will ship a
module ``-core`` already owns and this check fails.

Usage::

    python scripts/ci/check_wheel_coherence.py dist/            # scan a dir
    python scripts/ci/check_wheel_coherence.py a.whl b.whl ...  # scan wheels

Exit codes: ``0`` coherent, ``1`` collision detected or no wheels found.
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from collections import defaultdict
from pathlib import Path

# Wheel metadata directories never map to importable top-level packages.
_METADATA_SUFFIXES = (".dist-info", ".data")


def _wheel_dist_name(wheel: Path) -> str:
    """Return the distribution name encoded in a wheel filename.

    ``agent_hypervisor-5.0.0-py3-none-any.whl`` -> ``agent_hypervisor``.
    """
    return wheel.name.split("-", 1)[0]


def top_level_names(wheel: Path) -> set[str]:
    """Return the set of top-level import names a wheel installs.

    A top-level name is the first path component of any archive entry that is
    not wheel metadata (``*.dist-info/``, ``*.data/``). This mirrors what pip
    unpacks into ``site-packages``, so it is what actually collides on disk.
    """
    names: set[str] = set()
    with zipfile.ZipFile(wheel) as zf:
        for entry in zf.namelist():
            head = entry.split("/", 1)[0]
            if head.endswith(_METADATA_SUFFIXES):
                continue
            if not head:
                continue
            names.add(head)
    return names


def collect_wheels(paths: list[str]) -> list[Path]:
    wheels: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            wheels.extend(sorted(p.glob("*.whl")))
        elif p.suffix == ".whl" and p.is_file():
            wheels.append(p)
        else:
            print(f"::warning::ignoring non-wheel path {p}", file=sys.stderr)
    return wheels


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paths",
        nargs="+",
        help="Wheel files and/or directories containing wheels to check.",
    )
    args = parser.parse_args(argv)

    wheels = collect_wheels(args.paths)
    if not wheels:
        print("::error::no wheels found to check", file=sys.stderr)
        return 1

    owners: dict[str, set[str]] = defaultdict(set)
    for wheel in wheels:
        dist = _wheel_dist_name(wheel)
        tops = top_level_names(wheel)
        if tops:
            for name in tops:
                owners[name].add(dist)
        else:
            print(f"  {dist}: dep-only wheel (ships no top-level module)")

    collisions = {name: sorted(dists) for name, dists in owners.items() if len(dists) > 1}

    print("\nTop-level module ownership:")
    for name in sorted(owners):
        print(f"  {name:24s} <- {', '.join(sorted(owners[name]))}")

    if collisions:
        print("\n::error::top-level import paths shipped by more than one wheel:", file=sys.stderr)
        for name, dists in sorted(collisions.items()):
            print(f"::error::  {name} shipped by {', '.join(dists)}", file=sys.stderr)
        print(
            "\nEach top-level module must be owned by exactly one distribution. "
            "Standalone deprecation stubs must stay dep-only (no packages / "
            "bypass-selection) and let agent-governance-toolkit-core own the source.",
            file=sys.stderr,
        )
        return 1

    print(f"\nOK: {len(wheels)} wheel(s) form a coherent set — no top-level module collisions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
